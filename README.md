# cpp-log-analyzer

A lightweight C++ command line tool that pareses Linux-style authentication logs and summarizes suspicious activity.

## Motivation
This project was built to practice systems-level C++ programming and security log analysis. 
It mirrors common SOC and system administrator workflows by turning raw authentication logs 
into actionable security insights.

## Features
- Detects common SSH failed login messages
- Extracts usernames and source IP addresses
- Reports:
  -total failed attempts
  -top IPs
  -top targeted usernames

## Repo Structure
- 'src/'-C++ source code
- 'sample-logs/'- demo log files for testing
- 'docs/'- design notes and future roadmap


- ## Build & Run
- ### Linux (g++)
```bash
g++ -std=c++17 -O2 -Wall -Wextra -o log_analyzer src/main.cpp
./log_analyzer sample-logs/auth_sample.log --alert 2
