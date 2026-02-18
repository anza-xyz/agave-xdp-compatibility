# XDP Compatibility

This repo provides a client-only DNS check for Agave XDP compatibility.
It sends DNS requests over agave-xdp to a public DNS resolver and validates the
responses. If the check fails, there is likely a host/network/XDP issue.

Please report failures in the Solana Discord in `#validator-support`, with:
1) Host details (kernel version, etc)
2) Command you ran
3) Error output
4) Output of `ethtool -i <IFACE>`

## Usage

For XDP zero-copy, the client binary needs extra capabilities. Build it and set caps:
```
cargo build --release -p xdp-compatibility
sudo setcap cap_net_admin,cap_net_raw,cap_bpf,cap_perfmon+ep target/release/xdp-compatibility
```

Then run the built binary directly:
```
./target/release/xdp-compatibility \
  <DNS resolver IPv4> \
  --xdp-cpu-cores <CPU_LIST> \
  --xdp-interface <IFACE> \
  --timeout-ms 1000 \
  --xdp-zero-copy
```
