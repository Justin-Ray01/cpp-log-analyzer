# cpp-log-analyzer

A lightweight C++ command line tool that pareses Linux-style authentication logs and summarizes suspicious activity.

## Features
- Detects common SSH failed login messages
- Extracts usernames and source IP addresses
- Reports:
  -total failed attempts
  -top IPs
  -top targeted usernames

## Why this matters
Log review is a core skill for any analyst or system administrator. This project demonstrates:
- file I/O
- parsing and data structures
- security-focused reporting

- ## Build & Run
- ### Build
- '''bash
- g++ -std=c++17 -02 -Wall -Wextra -o log_analyzer src/main.cpp
