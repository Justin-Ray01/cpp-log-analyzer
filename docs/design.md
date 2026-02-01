# cpp-log-analyzer – Design Notes

This document describes the design decisions, parsing logic, and future roadmap
for the `cpp-log-analyzer` project.

---

## Project Goals

The primary goals of this tool are:

- Provide quick insight into Linux authentication logs
- Remain ightweight and dependency-free
- Produce human-readable output by default
- Support machine-readable (JSON) output for automation
- Be easy to compile on both Linux and Windows

This project intentionally avoids external libraries to keep it portable and
easy to understand.

---

## Input Data

The analyzer is designed to parse Linux-style authentication logs such as:

- `/var/log/auth.log` (Debian / Ubuntu)
- `/var/log/secure` (RHEL / CentOS style, partially compatible)

Example log patterns handled:

- SSH failed login:
