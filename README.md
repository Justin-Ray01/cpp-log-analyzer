# cpp-log-analyzer

A lightweight C++17 command-line tool that parses Linux style authentication logs and turns them into an easy-to-read security summary.  
Designed to be human-friendly by default (pretty output) with optional JSON output for automation.

This tool converts raw auth log lines into actionable results in seconds.

---

## Features
- Detects:
  - SSH failed logins** (`Failed password for ... from <ip>`)
  - SSH successful logins** (`Accepted password for ... from <ip>`)
  - sudo authentication failures** (`authentication failure; user=<name>`)
- Summarizes by:
  - Top source IPs
  - Top usernames involved/targeted
- Alerting:
  - `--alert N` triggers an ALERTS section when counts meet/exceed a threshold
- Output modes:
  - Pretty output (default)
  - JSON (`--json`) for scripts/pipelines
- Optional file output:
  - `--out report.txt` or `--out report.json`

---

## Repo Structure
- `src/` — C++ source code (`main.cpp`)
- `sample-logs/` — synthetic demo logs for testing
- `docs/` — design notes and roadmap

---
##Example Output

<img width="1051" height="446" alt="image" src="https://github.com/user-attachments/assets/5d4eee7f-714b-4caf-82c6-47b112309992" />

## Build & Run

### Linux (g++)
```bash
g++ -std=c++17 -O2 -Wall -Wextra -o log_analyzer src/main.cpp
./log_analyzer sample-logs/auth_sample.log --alert 2 --top 5
