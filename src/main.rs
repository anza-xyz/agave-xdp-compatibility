#[cfg(target_os = "linux")]
mod linux {
    use {
        agave_xdp::{
            device::{NetworkDevice, QueueId},
            tx_loop::tx_loop,
        },
        caps::{
            CapSet,
            Capability::{CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW, CAP_PERFMON},
        },
        clap::Parser,
        crossbeam_channel::bounded,
        log::*,
        rand::{Rng, rng},
        std::{
            net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
            num::ParseIntError,
            process::exit,
            sync::Arc,
            thread,
            time::{Duration, Instant},
        },
    };

    // Same payload sizing used by Solana packet handling (1280 - IPv6 header - UDP header).
    const DNS_RECV_BUF_SIZE: usize = 1280 - 40 - 8;
    const DNS_HEADER_LEN: usize = 12;
    const DNS_QUESTION_TRAILER_LEN: usize = 4; // QTYPE + QCLASS
    const DNS_MAX_LABEL_LEN: usize = 63;
    // Pre-baked DNS query template for "solana.com" A IN.
    // Bytes [0..2] are TXID and are patched per request.
    const DNS_QUERY_TEMPLATE: [u8; DNS_HEADER_LEN + 16] = [
        // Header
        0x00, 0x00, // TXID (patched per query)
        0x01, 0x00, // FLAGS (RD=1)
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Question: solana.com
        0x06, b's', b'o', b'l', b'a', b'n', b'a', // "solana"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // root label
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ];

    #[derive(Debug)]
    struct XdpConfig {
        interface: Option<String>,
        cpus: Vec<usize>,
        zero_copy: bool,
    }

    #[derive(Debug)]
    struct Config {
        xdp_config: XdpConfig,
        endpoint: SocketAddr,
        timeout_ms: u64,
    }

    enum RecvResult {
        Match,
        Mismatch,
        Timeout,
    }

    pub(crate) enum DnsValidationError {
        TxidMismatch,
        Mismatch(&'static str),
    }

    #[derive(Debug, Parser)]
    #[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"))]
    struct CliArgs {
        #[arg(
            value_name = "IPV4",
            help = "Target endpoint IPv4 address for DNS over agave-xdp"
        )]
        endpoint_ip: Ipv4Addr,

        #[arg(
            long = "xdp-interface",
            value_name = "INTERFACE",
            requires = "xdp_cpu_cores",
            help = "The network interface to use for XDP"
        )]
        xdp_interface: Option<String>,

        #[arg(
            long = "xdp-cpu-cores",
            value_name = "CPU_LIST",
            value_parser = |value: &str| {
                parse_cpu_ranges(value).map(|_| value.to_string())
            },
            help = "Enable XDP on the specified CPU cores (cpuset format, for example: 0-2,7)"
        )]
        xdp_cpu_cores: Option<String>,

        #[arg(
            long = "xdp-zero-copy",
            requires = "xdp_cpu_cores",
            help = "Enable XDP zero copy. Requires hardware support"
        )]
        xdp_zero_copy: bool,

        #[arg(
            long = "timeout-ms",
            value_name = "MS",
            default_value_t = 1000,
            help = "Receive timeout in milliseconds"
        )]
        timeout_ms: u64,
    }

    fn recv_until_match(udp: &UdpSocket, txid: u16, timeout_ms: u64) -> RecvResult {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .expect("timeout must be less than u64::MAX");
        let mut buf = vec![0u8; DNS_RECV_BUF_SIZE];
        let mut saw_packet = false;
        loop {
            if Instant::now() > deadline {
                return if saw_packet {
                    RecvResult::Mismatch
                } else {
                    RecvResult::Timeout
                };
            }
            match udp.recv(&mut buf) {
                Ok(n) => {
                    saw_packet = true;
                    match validate_dns_response(&buf[..n], txid) {
                        Ok(()) => return RecvResult::Match,
                        Err(DnsValidationError::Mismatch(reason)) => {
                            error!("Received mismatched DNS response for txid {txid}: {reason}");
                            return RecvResult::Mismatch;
                        }
                        Err(DnsValidationError::TxidMismatch) => {
                            error!(
                                "Received DNS response for different txid while waiting for {txid}"
                            );
                        }
                    }
                }
                Err(_) => {
                    // Ignore timeout and retry until deadline.
                }
            }
        }
    }

    // Parse a cpu range in standard cpuset format, eg:
    //
    // 0-4,9
    // 0-2,7,12-14
    pub fn parse_cpu_ranges(data: &str) -> Result<Vec<usize>, String> {
        data.split(',')
            .map(|range| {
                let mut iter = range
                    .split('-')
                    .map(|s| s.parse::<usize>().map_err(|ParseIntError { .. }| range));
                let start = iter.next().unwrap()?; // str::split always returns at least one element.
                let end = match iter.next() {
                    None => start,
                    Some(end) => {
                        if iter.next().is_some() {
                            return Err(range);
                        }
                        end?
                    }
                };
                Ok(start..=end)
            })
            .try_fold(Vec::new(), |mut cpus, range| {
                let range = range.map_err(|range| format!("--xdp-cpu-cores {range}"))?;
                cpus.extend(range);
                Ok(cpus)
            })
    }

    /// Returns the IPv4 address of the master interface if the given interface is part of a bond.
    pub fn master_ip_if_bonded(interface: &str) -> Option<Ipv4Addr> {
        let master_ifindex_path = format!("/sys/class/net/{interface}/master/ifindex");
        if let Ok(contents) = std::fs::read_to_string(&master_ifindex_path) {
            let idx = contents.trim().parse().unwrap();
            return Some(
                NetworkDevice::new_from_index(idx)
                    .and_then(|dev| dev.ipv4_addr())
                    .unwrap_or_else(|e| {
                        panic!(
                            "failed to open bond master interface for {interface}: master index \
                             {idx}: {e}"
                        )
                    }),
            );
        }
        None
    }

    // Send one DNS query on the kernel UDP path before XDP traffic. This primes route/neighbor/NAT
    // state so first-packet behavior is less likely to hide XDP issues.
    fn warm_up_dns_path(udp: &UdpSocket, timeout_ms: u64) {
        let warmup_txid = random_txid();
        let warmup_payload = build_dns_query(warmup_txid);
        if let Err(err) = udp.send(&warmup_payload) {
            panic!("DNS warmup failed to send query: {err}");
        }
        match recv_until_match(udp, warmup_txid, timeout_ms) {
            RecvResult::Match => {
                debug!("DNS warmup on kernel UDP path succeeded");
            }
            RecvResult::Mismatch => {
                panic!("DNS warmup failed: received mismatched or malformed DNS response");
            }
            RecvResult::Timeout => {
                panic!("DNS warmup failed: timed out waiting for DNS response");
            }
        }
    }

    pub(crate) fn build_dns_query(txid: u16) -> Vec<u8> {
        let mut dns_bytes = DNS_QUERY_TEMPLATE;
        dns_bytes[0..2].copy_from_slice(&txid.to_be_bytes());
        dns_bytes.to_vec()
    }

    pub(crate) fn dns_question_end(packet: &[u8]) -> Option<usize> {
        if packet.len() < DNS_HEADER_LEN {
            return None;
        }
        let mut idx = DNS_HEADER_LEN;
        loop {
            if idx >= packet.len() {
                return None;
            }
            let len = packet[idx] as usize;
            idx = idx.checked_add(1)?;
            if len == 0 {
                break;
            }
            if len > DNS_MAX_LABEL_LEN || idx.checked_add(len)? > packet.len() {
                return None;
            }
            idx += len;
        }
        idx.checked_add(DNS_QUESTION_TRAILER_LEN)
            .filter(|end| *end <= packet.len())
    }

    pub(crate) fn validate_dns_response(
        packet: &[u8],
        txid: u16,
    ) -> Result<(), DnsValidationError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(DnsValidationError::Mismatch("packet too short"));
        }
        let resp_txid = u16::from_be_bytes([packet[0], packet[1]]);
        // txid correlation prevents accepting responses for a different in-flight query.
        if resp_txid != txid {
            return Err(DnsValidationError::TxidMismatch);
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if (flags & 0x8000) == 0 {
            return Err(DnsValidationError::Mismatch("not a DNS response"));
        }
        let rcode = flags & 0x000f;
        if rcode != 0 {
            return Err(DnsValidationError::Mismatch("rcode is non-zero"));
        }
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        if qdcount == 0 {
            return Err(DnsValidationError::Mismatch("missing question section"));
        }
        if ancount == 0 {
            return Err(DnsValidationError::Mismatch("no answers in response"));
        }
        // Require the echoed question to match our pre-baked solana.com A/IN question.
        let resp_q_end = dns_question_end(packet)
            .ok_or(DnsValidationError::Mismatch("invalid response question"))?;
        let request_question = &DNS_QUERY_TEMPLATE[DNS_HEADER_LEN..];
        let response_question = &packet[DNS_HEADER_LEN..resp_q_end];
        if request_question != response_question {
            return Err(DnsValidationError::Mismatch("question mismatch"));
        }
        Ok(())
    }

    fn random_txid() -> u16 {
        // DNS txid is 16-bit; use a uniform non-zero value.
        rng().random_range(1..=u16::MAX)
    }

    fn parse_args() -> Config {
        let args = CliArgs::parse();
        let cpus = if let Some(cpu_list) = args.xdp_cpu_cores.as_deref() {
            parse_cpu_ranges(cpu_list).unwrap_or_else(|err| {
                error!("{err}");
                exit(1);
            })
        } else {
            vec![0]
        };

        let xdp_config = XdpConfig {
            interface: args.xdp_interface,
            cpus,
            zero_copy: args.xdp_zero_copy,
        };
        Config {
            xdp_config,
            endpoint: SocketAddr::new(IpAddr::V4(args.endpoint_ip), 53),
            timeout_ms: args.timeout_ms,
        }
    }

    pub fn main() {
        agave_logger::setup_with_default("info");
        let config = parse_args();
        let xdp_config = &config.xdp_config;
        let zero_copy = xdp_config.zero_copy;

        let dev = match xdp_config.interface.as_ref() {
            Some(iface) => NetworkDevice::new(iface.clone()).unwrap_or_else(|e| {
                error!("Failed to open interface {iface}: {e}");
                exit(1);
            }),
            None => NetworkDevice::new_from_default_route().unwrap_or_else(|e| {
                error!("Failed to resolve default route interface: {e}");
                exit(1);
            }),
        };
        let iface = dev.name().to_string();

        let local_ip = dev
            .ipv4_addr()
            .or_else(|_| {
                master_ip_if_bonded(&iface).ok_or_else(|| {
                    std::io::Error::other("no IPv4 address on interface or bond master")
                })
            })
            .unwrap_or_else(|e| {
                error!("Failed to get IPv4 address for {iface}: {e}");
                exit(1);
            });

        let _ebpf = if zero_copy {
            for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, CAP_PERFMON] {
                if let Err(e) = caps::raise(None, CapSet::Effective, cap) {
                    error!("Failed to raise {cap:?} capability: {e}");
                    exit(1);
                }
            }

            let ebpf = match agave_xdp::load_xdp_program(&dev) {
                Ok(ebpf) => ebpf,
                Err(e) => {
                    error!("Failed to attach XDP program in DRV mode: {e}");
                    exit(1);
                }
            };
            // Keep capabilities raised until AF_XDP socket is created and bound below.
            Some(ebpf)
        } else {
            None
        };

        let endpoint = config.endpoint;
        let IpAddr::V4(endpoint_ip) = endpoint.ip() else {
            error!("Endpoint must be IPv4");
            exit(1);
        };
        // Bind a UDP socket to receive DNS responses from the endpoint.
        let udp = UdpSocket::bind((local_ip, 0)).unwrap_or_else(|e| {
            error!("Failed to bind UDP socket: {e}");
            exit(1);
        });
        udp.set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .unwrap();
        udp.connect(endpoint).unwrap_or_else(|e| {
            error!("Failed to connect UDP socket to endpoint {endpoint}: {e}");
            exit(1);
        });
        // Warm up route/neighbor/NAT state with a normal UDP DNS exchange.
        warm_up_dns_path(&udp, config.timeout_ms);

        let (sender, receiver) = bounded::<(Vec<SocketAddr>, Vec<u8>)>(1);
        let cpu_id = xdp_config.cpus.first().copied().unwrap_or_else(|| {
            error!("No CPU core configured for XDP.");
            exit(1);
        });
        if xdp_config.cpus.len() > 1 {
            warn!("Multiple CPU cores supplied; using CPU {cpu_id} for the compatibility client.");
        }
        let src_port = udp.local_addr().unwrap().port();
        let dev = Arc::new(dev);

        if zero_copy {
            for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, CAP_PERFMON] {
                let _ = caps::drop(None, CapSet::Effective, cap);
            }
        }

        let (drop_sender, _drop_receiver) = bounded(1);

        let tx_thread = thread::spawn(move || {
            tx_loop(
                cpu_id,
                dev.as_ref(),
                QueueId(cpu_id as u64),
                zero_copy,
                None,
                Some(local_ip),
                src_port,
                None,
                receiver,
                drop_sender,
            );
        });

        let txid = random_txid();
        let payload = build_dns_query(txid);
        sender.send((vec![endpoint], payload.clone())).unwrap();
        let result = recv_until_match(&udp, txid, config.timeout_ms);

        drop(sender);
        let _ = tx_thread.join();

        match result {
            RecvResult::Match => {
                info!("XDP DNS compatibility test passed (1/1) against endpoint IP {endpoint_ip}");
            }
            RecvResult::Mismatch => {
                error!("DNS response mismatch for single XDP probe packet");
                info!("XDP DNS compatibility test failed (0/1) against endpoint IP {endpoint_ip}");
                exit(1);
            }
            RecvResult::Timeout => {
                error!("DNS response timeout for single XDP probe packet");
                info!("XDP DNS compatibility test failed (0/1) against endpoint IP {endpoint_ip}");
                exit(1);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    pub fn main() {
        eprintln!("XDP compatibility client is Linux-only.");
        std::process::exit(1);
    }
}

fn main() {
    linux::main();
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::linux::{
        DnsValidationError, build_dns_query, dns_question_end, validate_dns_response,
    };

    fn header_u16(packet: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([packet[offset], packet[offset + 1]])
    }

    // mock a DNS response from a request
    fn make_response_from_request(request: &[u8], txid: u16) -> Vec<u8> {
        let mut response = request.to_vec();
        response[0..2].copy_from_slice(&txid.to_be_bytes());
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, RCODE=0
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response
    }

    #[test]
    fn build_dns_query_sets_expected_header_and_question_fields() {
        let txid = 0x1234;
        let packet = build_dns_query(txid);

        assert_eq!(header_u16(&packet, 0), txid);
        assert_eq!(header_u16(&packet, 2), 0x0100); // RD set
        assert_eq!(header_u16(&packet, 4), 1); // QDCOUNT
        assert_eq!(header_u16(&packet, 6), 0); // ANCOUNT
        assert_eq!(header_u16(&packet, 8), 0); // NSCOUNT
        assert_eq!(header_u16(&packet, 10), 0); // ARCOUNT

        let q_end = dns_question_end(&packet).expect("request question should be well-formed");
        assert_eq!(header_u16(&packet, q_end - 4), 1); // QTYPE A
        assert_eq!(header_u16(&packet, q_end - 2), 1); // QCLASS IN
    }

    #[test]
    fn dns_question_end_rejects_truncated_qname() {
        let txid = 0x4242;
        let mut packet = build_dns_query(txid);
        packet.pop(); // truncate final QCLASS byte
        assert!(dns_question_end(&packet).is_none());
    }

    #[test]
    fn validate_dns_response_accepts_matching_response() {
        let txid = 0x1001;
        let request = build_dns_query(txid);
        let response = make_response_from_request(&request, txid);
        assert!(validate_dns_response(&response, txid).is_ok());
    }

    #[test]
    fn validate_dns_response_ignores_wrong_txid() {
        let txid = 0x1001;
        let request = build_dns_query(txid);
        let response = make_response_from_request(&request, txid.wrapping_add(1));
        assert!(matches!(
            validate_dns_response(&response, txid),
            Err(DnsValidationError::TxidMismatch)
        ));
    }

    #[test]
    fn validate_dns_response_flags_question_mismatch() {
        let txid = 0x1001;
        let mut other = build_dns_query(txid);
        other[17] ^= 0x01; // mutate one byte in QNAME ("solana.com") while keeping wire format valid.
        let response = make_response_from_request(&other, txid);
        assert!(matches!(
            validate_dns_response(&response, txid),
            Err(DnsValidationError::Mismatch("question mismatch"))
        ));
    }
}
