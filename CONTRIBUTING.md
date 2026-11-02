# Contributing

Thanks for taking the time to look at this project. Bug reports, fixes and small improvements are welcome.

This is an early-stage experiment (see **Known limitations** in the [README](README.md#known-limitations)). Some rough edges are known, for example the hard-coded addresses and the unfinished latency logic, so please check that section before reporting them.

Please do not open public issues for security problems; follow [SECURITY.md](SECURITY.md) instead. Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the direction before you spend time on it.
- The program polls a real network card through DPDK. If you cannot run it on DPDK-capable hardware, say so in your pull request; a change that only compiles is still useful, but the reviewer needs to know it was not run.
- Do not put real IP addresses, packet captures or credentials from networks you do not own into issues, pull requests or commits.

## Prerequisites

The build needs a C compiler, [Meson](https://mesonbuild.com/), a Meson backend (Ninja is the default), `pkg-config` and [DPDK](https://www.dpdk.org/) 23.11 or newer, which `meson.build` looks up through the `libdpdk` pkg-config dependency.

[CI](.github/workflows/ci.yml) runs on `ubuntu-latest` and installs them like this:

```bash
sudo apt-get update
sudo apt-get install -y libdpdk-dev meson ninja-build pkg-config build-essential
```

Running the program additionally needs a Linux host with a network card bound to a DPDK-compatible driver and huge pages. The README and `memo.txt` describe the setup.

## Build

These are the same two commands the CI workflow runs, from the repository root:

```bash
meson setup build
meson compile -C build
```

The root target is `network_latency_analyzer`, compiled from `main.c`. The `build/` and `out/` directories are ignored by git.

## Check your change

There is no `meson test` suite and no linter configured. CI only checks that the root target compiles, so before you push:

- Make sure the two build commands above succeed without new compiler warnings.
- If you changed behavior, describe in the pull request how you ran it (DPDK version, NIC and driver, EAL arguments) and what you saw.

`sample.c` is a reference file that is not part of the Meson build. `test/` and `test2/` are separate Meson projects: each has its own `meson.build`, the root `meson.build` does not include them, and CI does not build them. If you touch one of them, configure and build that directory as its own Meson project and say so in the pull request.

## Code style

- Follow `.editorconfig`: UTF-8, LF line endings, a final newline, no trailing whitespace, and 4 spaces for C (no tabs).
- Match the style of the surrounding code and keep the change focused. Please do not reformat lines you did not change.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short summary in the imperative mood>
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`. Keep one logical change per commit.

## Pull requests

1. Fork the repository and create a branch from `main` (for example `fix/rx-burst-check`).
2. Keep the pull request small and focused. Do not mix formatting changes with behavior changes.
3. Fill in the pull request template: what changed, why, and how you tested it.
4. Make sure CI is green. A maintainer reviews the change and may ask for edits.

## Reporting issues

Use [GitHub Issues](https://github.com/ugurtheiron/network-latency-analyzer/issues/new/choose) and pick the bug report or feature request form. For a bug, the DPDK version, NIC and driver, OS and kernel, and the exact build command matter most. Questions and loose ideas are fine as plain issues too.

## License of contributions

By contributing you agree that your contribution is released under the project's [MIT License](LICENSE).
