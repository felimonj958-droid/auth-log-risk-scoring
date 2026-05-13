# Log Analysis Lab

## Purpose

Practice defensive cybersecurity analysis by parsing authentication logs and identifying suspicious login behavior.

## Dataset

```text
labs/04-log-analysis/sample-logs/auth_sample.log
```

## Goal

Convert raw log lines into structured data that can be analyzed with Python and pandas.

## Planned Workflow

```text
raw auth log → Python parser → CSV dataset → suspicious login flags → pandas analysis
```

## Suspicious Patterns to Look For

- Multiple failed login attempts from the same IP address.
- Failed login attempts against privileged usernames such as `admin` or `root`.
- Repeated failures in a short time window.
- External-looking IP addresses compared with local private IP addresses.

## Log Parser

### Script Path

```text
labs/04-log-analysis/scripts/parse_auth_logs.py
```

### Input

```text
labs/04-log-analysis/sample-logs/auth_sample.log
```

### Output

```text
labs/04-log-analysis/targets/auth_events.csv
```

### Purpose

The parser converts raw authentication log lines into structured CSV rows.

### Fields Extracted

```text
date
time
level
user
action
status
ip
```

### Data Science Connection

This step converts unstructured log text into tabular data.

The workflow is:

```text
raw log text → regular expression parser → structured CSV → pandas-ready dataset
```

## Auth Analysis Results

### Script Output Summary

```text
Total events: 16
Suspicious events: 12
```

### Files Created

```text
labs/04-log-analysis/targets/suspicious_auth_events.csv
labs/04-log-analysis/targets/auth_summary_by_ip.csv
```

### Summary by IP

```text
ip,total_events,failed_logins,privileged_attempts,suspicious_events
203.0.113.77,5,5,5,5
198.51.100.25,4,4,4,4
203.0.113.10,3,3,0,3
192.168.1.10,2,0,0,0
192.168.1.11,2,0,0,0
```

### Interpretation

The analysis identified 12 suspicious events out of 16 total authentication events.

The IP address `203.0.113.77` had the highest number of suspicious events, with 5 failed login attempts against a privileged user.

The IP address `198.51.100.25` had 4 suspicious events, also involving privileged-user login attempts.

The IP address `203.0.113.10` had 3 failed login attempts from an external-looking IP, but no privileged-user attempts.

The local private IP addresses `192.168.1.10` and `192.168.1.11` had no suspicious events in this sample.

### Detection Meaning

The current rule marks an event as suspicious when:

```text
is_failed_login AND (is_privileged_user OR is_external_ip)
```

This means failed login attempts from external-looking IP addresses are flagged, and failed login attempts against privileged usernames like `admin` or `root` are also flagged.

### Data Science Connection

This lab converted raw log text into structured data, engineered detection features, and grouped events by IP address.

The workflow now looks like:

```text
raw log → parsed CSV → detection features → suspicious event filtering → grouped summary
```

This is similar to a basic security analytics pipeline.

## IP Risk Scoring Results

### File Reviewed

```text
labs/04-log-analysis/targets/auth_risk_summary_by_ip.csv
```

### Results

```text
ip,total_events,failed_logins,privileged_attempts,external_events,suspicious_events,risk_score,risk_level
203.0.113.77,5,5,5,5,5,30,high
198.51.100.25,4,4,4,4,4,24,high
203.0.113.10,3,3,0,3,3,12,medium
192.168.1.10,2,0,0,0,0,0,none
192.168.1.11,2,0,0,0,0,0,none
```

### Highest-Risk IPs

Two IP addresses were classified as `high` risk:

```text
203.0.113.77
198.51.100.25
```

Both IPs had repeated failed login attempts, privileged-user attempts, external-looking IP classification, and suspicious events.

### Medium-Risk IP

One IP address was classified as `medium` risk:

```text
203.0.113.10
```

This IP had repeated failed logins and was external-looking, but it did not target privileged usernames such as `admin` or `root`.

### No-Risk IPs

Two local private IP addresses were classified as `none`:

```text
192.168.1.10
192.168.1.11
```

These IPs had successful login/logout activity and no suspicious events in this sample.

### Interpretation

The risk scoring model successfully prioritized IP addresses based on suspicious authentication behavior.

The highest-risk IPs are the ones with repeated failed login attempts against privileged users from external-looking addresses.

This resembles a simple brute-force or credential-guessing detection workflow.

### Data Science Connection

The script grouped authentication events by IP address, engineered summary features, and applied a weighted scoring rule.

The workflow now looks like:

```text
raw logs → parsed events → detection features → grouped IP summary → risk score → risk level
```

This is a basic security analytics pipeline and a strong foundation for later anomaly detection or supervised classification work.