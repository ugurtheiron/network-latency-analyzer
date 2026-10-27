# network-latency-analyzer

[![CI](https://github.com/ugurtheiron/network-latency-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/ugurtheiron/network-latency-analyzer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An experimental DPDK application that polls a network card from user space and timestamps TCP packets with the CPU cycle counter (`rte_rdtsc`) to measure network latency in CPU cycles.

> **Status:** early-stage experiment. The latency logic is unfinished; see [Known limitations](#known-limitations).

## How it works

The measurement program is `main.c`. It bypasses the Linux kernel network stack by using [DPDK](https://www.dpdk.org/) poll-mode drivers:

1. Initializes the DPDK Environment Abstraction Layer (`rte_eal_init`). Command-line arguments are handed to EAL.
2. Creates a packet buffer pool (`MBUF_POOL`: 8192 mbufs, per-core cache of 250, 2048-byte buffers).
3. Configures and starts every available Ethernet port with one RX and one TX queue (1024 descriptors each) and enables promiscuous mode.
4. Busy-polls RX queue 0 of the first successfully initialized port in bursts of up to 32 packets. For each IPv4/TCP packet it reads the timestamp counter and matches on hard-coded addresses: packets from `172.31.27.81:2222` are treated as the request, packets from `192.168.0.2:2222` as the reply, and `Latency: <n> cycles` is printed for the reply.
5. Frees every packet buffer.

### Other programs in the repository

| File | What it is |
|---|---|
| `sample.c` | Commented reference version of the same setup code. On a TCP SYN it stores the timestamp counter in the packet's sequence-number field and prints `SYN sent`; on a SYN-ACK it prints an `RTT` computed as the counter minus that field. Not part of the Meson build. |
| `test/main.c` | Memory-pool smoke test: initializes EAL, allocates all 8192 mbufs from a pool, frees them, frees the pool, and prints a message after each step. Has its own `meson.build`. |
| `test2/main.c` | Variant of `main.c` that keeps the start timestamp across packets: it is set on a packet from `172.31.27.81:2222`; when a packet addressed to `192.168.0.2:2222` arrives, the difference is printed in cycles and the timestamp is reset. Has its own `meson.build`. |
| `memo.txt` | Personal study notes on the overhead of the Linux network stack (interrupts, `sk_buff` allocation, context switches), how DPDK avoids it, and DPDK setup topics (huge pages, binding NICs with `dpdk-devbind`). |

## Requirements

- A Linux host with a network card usable by a DPDK poll-mode driver and bound to a DPDK-compatible driver (see the `dpdk-devbind` and huge-page notes in `memo.txt`).
- [DPDK](https://www.dpdk.org/) 23.11 or newer, discoverable through the `libdpdk` pkg-config dependency.
- [Meson](https://mesonbuild.com/) with a build backend (Ninja is Meson's default) and a C compiler.

## Build

The project builds with Meson (`meson.build`). The root target `network_latency_analyzer` is compiled from `main.c` and links DPDK through the `libdpdk` dependency (version `>=23.11`). The `test/` and `test2/` directories carry their own `meson.build` files and are not part of the root build.

Build and run commands are intentionally not listed here: they have not been verified for this repository yet.

## Project structure

```
.
├── main.c          # DPDK latency probe (the root Meson target)
├── meson.build     # Meson build definition (requires libdpdk >= 23.11)
├── sample.c        # Commented reference version (SYN / SYN-ACK idea), not built by Meson
├── memo.txt        # Study notes: Linux network stack overhead, DPDK, huge pages
├── test/           # mbuf pool allocate/free smoke test (own meson.build)
├── test2/          # main.c variant that keeps the start timestamp across packets (own meson.build)
├── LICENSE
└── README.md
```

## Known limitations

- **`main.c` does not yet measure a round trip.** The start timestamp is taken inside the per-packet scope right before the address match, and the "request" branch is empty, so the printed value is the cycle count between two reads on the same packet. `test2/main.c` keeps the start timestamp across packets instead.
- **`sample.c` does not measure a real RTT.** It reads the timestamp back from the SYN-ACK's own sequence-number field, which belongs to a different packet than the SYN it was stored in.
- Results are printed as raw timestamp-counter cycles; there is no conversion to time units.
- The IP addresses and the TCP port (`2222`) are hard-coded; there are no command-line options for them.
- Only one port is polled: every available port is initialized, but only the first one is read. The program exits if no port could be initialized.
- Only IPv4/TCP is handled, and packet headers are parsed without length checks.
- The receive loop runs forever; there is no signal handling or clean shutdown.
- There are no automated tests; CI only checks that the root target compiles. `test/` is a manual smoke test that needs a working DPDK environment.

## License

Released under the [MIT License](LICENSE).
