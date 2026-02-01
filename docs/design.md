# Design Notes — C++ Log Analyzer

## Goal
Parse Linux-style authentication logs and summarize suspicious activity.

## Inputs
- Plaintext log file (e.g., /var/log/auth.log)
- Sample logs provided in `sample-logs/`

## Outputs
- Total counts of matched events
- Top source IPs
- Top targeted usernames

## Parsing Approach
- Read file line-by-line
- Match known patterns:
  - "Failed password for"
  - "Failed password for invalid user"
  - "sudo: ... authentication failure"
- Extract:
  - username
  - IP address (from "from X.X.X.X")

## Data Structures
- unordered_map<string,int> for:
  - ip_counts
  - user_counts
