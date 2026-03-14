# Netx-ASM

Phase 1 foundation: Sequential SYN probe in pure x86_64 assembly (Linux + Windows).

## Build (Linux)

```sh
make linux
```

## Build (Windows)

```sh
make windows
```

## Run

```sh
sudo ./netx-asm-linux <target_ip> [-p port|start-end|-]
```

```sh
netx-asm.exe <target_ip> [-p port|start-end|-]
```

## Notes

- Raw sockets require root or the `cap_net_raw` capability.
- Windows requires Administrator privileges for raw sockets.
- The current implementation scans sequentially and prints `PORT OPEN TTL=<n> WIN=<n>` or `PORT CLOSED/FILTERED`.
- Default range is ports 1-1000; use `-p -` for 1-65535.
- Source IP is detected by a temporary UDP `connect` to the target.
- Linux uses `epoll` for non-blocking receive checks between sends.
