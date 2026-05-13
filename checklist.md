# Log Analysis Lab Checklist

## Setup

- [x] Create `04-log-analysis` lab folder
- [x] Create sample authentication log
- [x] Create parser script
- [x] Create analysis script
- [x] Create writeup notes

## Parsing

- [x] Parse raw log lines with regular expressions
- [x] Extract date, time, level, user, action, status, and IP
- [x] Export parsed events to CSV
- [x] Create `auth_events.csv`

## Detection Features

- [x] Add `is_failed_login`
- [x] Add `is_privileged_user`
- [x] Add `is_private_ip`
- [x] Add `is_external_ip`
- [x] Add `suspicious_event`

## Analysis Outputs

- [x] Create `suspicious_auth_events.csv`
- [x] Create `auth_summary_by_ip.csv`
- [x] Create `auth_risk_summary_by_ip.csv`

## Risk Scoring

- [x] Score failed logins
- [x] Score privileged-user attempts
- [x] Score external-looking IPs
- [x] Score suspicious events
- [x] Assign risk levels
- [x] Identify high, medium, and no-risk IPs

## Data Science Connection

- [x] Convert raw logs into structured CSV
- [x] Engineer security detection features
- [x] Group events by IP address
- [x] Create rule-based risk scoring model
- [x] Produce analyst-style summary tables

## Next Improvements

- [ ] Add timestamps as pandas datetime values
- [ ] Add time-window detection
- [ ] Detect repeated failures within 5 minutes
- [ ] Add visualizations
- [ ] Create a Jupyter notebook version
- [ ] Prepare GitHub-ready README