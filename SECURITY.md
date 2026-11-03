# Security Policy

## Supported versions

This repository is a single DPDK application without versioned releases. Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report it privately through GitHub:

1. Open the [Security tab](https://github.com/ugurtheiron/network-latency-analyzer/security) of this repository.
2. Choose **Report a vulnerability** and describe the problem. See GitHub's guide on [privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

If that button is not available, open a public issue that says only that you have a security report and ask for a private channel. Do not include details in the issue.

A useful report contains the affected file and function, the DPDK version and NIC/driver you used, the packets or steps needed to reproduce, and the impact you expect. Do not attach packet captures or logs that contain real IP addresses or other people's traffic. You can expect a first reply within a week. This is a personal project, so please be patient.

## Scope

In scope: code in this repository, for example header parsing that reads past the end of a short or malformed packet, out-of-bounds access to port or buffer arrays, and packet buffer leaks that a remote sender can trigger.

Out of scope: vulnerabilities in DPDK itself, NIC drivers or firmware, and the operating system. Please report those to their maintainers.
