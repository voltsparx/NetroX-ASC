# Netx-ASM

Phase 1 foundation: Linux-only sequential SYN probe in pure x86_64 assembly.

## Build (Linux)

```sh
make linux
```

## Run

```sh
sudo ./netx-asm-linux <target_ip> [-p port|start-end|-]
```

## Notes

- Raw sockets require root or the `cap_net_raw` capability.
- The current implementation scans sequentially and prints `PORT OPEN TTL=<n> WIN=<n>` or `PORT CLOSED/FILTERED`.
- Default range is ports 1-1000; use `-p -` for 1-65535.
- Source IP is detected by a temporary UDP `connect` to the target.
