# Authentication Log Risk Scoring Lab

A defensive cybersecurity lab that parses synthetic authentication logs and identifies suspicious login behavior with Python and pandas.

## Purpose

Practice turning raw authentication logs into structured data, detection features, grouped summaries, and IP-level risk scores.

## Safety Boundaries

- Uses synthetic sample logs only.
- No real private logs.
- No public systems.
- No packet captures.
- Defensive analysis only.

## Workflow

```text
raw auth log → regex parser → CSV dataset → detection features → suspicious event export → grouped IP risk scoring
```

## Key Files

```text
sample-logs/auth_sample.log
scripts/parse_auth_logs.py
scripts/analyze_auth_events.py
targets/auth_events.csv
targets/suspicious_auth_events.csv
targets/auth_summary_by_ip.csv
targets/auth_risk_summary_by_ip.csv
writeup/log-analysis-notes.md
checklist.md
```

## Scripts

### Parse raw logs

```bash
python scripts/parse_auth_logs.py
```

### Analyze authentication events

```bash
python scripts/analyze_auth_events.py
```

## Detection Features

The analysis script creates:

```text
is_failed_login
is_privileged_user
is_private_ip
is_external_ip
suspicious_event
```

## IP Risk Scoring

The risk summary groups events by IP and scores:

```text
failed_logins
privileged_attempts
external_events
suspicious_events
risk_score
risk_level
```

## Results

The sample analysis identified:

```text
2 high-risk IPs
1 medium-risk IP
2 no-risk local IPs
```

## Data Science Connection

This lab follows a basic security analytics workflow:

```text
raw logs → parsed rows → feature engineering → grouping → scoring → analyst summary
```

In a real environment, the same pattern could be applied to authentication telemetry, streaming access logs, or piracy-related signals to surface high-risk activity for further investigation.

## Current Status

Phase 1 complete.

The lab demonstrates log parsing, detection feature engineering, and rule-based IP risk scoring.

In a production environment, this pattern—log parsing, feature engineering, grouping, and risk scoring—could extend to authentication telemetry, streaming access logs, or piracy-related signals to surface high-risk activity for further investigation.