# Authentication Log Risk Scoring Lab

A defensive cybersecurity lab that generates synthetic authentication telemetry, parses raw logs into structured rows, engineers detection features, and compares rule-based scoring with lightweight machine learning for IP-level risk triage.

## Purpose

This project practices the full workflow from raw authentication logs to detection outputs:

- Parse raw log lines into structured rows.
- Engineer binary detection features.
- Export suspicious events.
- Aggregate activity by source IP.
- Score risk with a simple rules engine.
- Compare the rules baseline with supervised and unsupervised ML.
- Tune a decision threshold using business cost.

## Safety boundaries

- Synthetic sample logs only.
- No real private logs.
- No public systems.
- No packet captures.
- Defensive analysis only.

## Workflow

```text
synthetic auth log generation
→ raw auth log
→ parser
→ CSV dataset
→ detection features
→ suspicious event export
→ grouped IP risk scoring
→ ML comparison
→ cost-sensitive threshold tuning
```

## Files

```text
data/raw_auth_logs.log
data/labels.csv
scripts/generate_synthetic_auth_logs.py
scripts/parse_auth_logs.py
scripts/analyze_auth_events.py
scripts/train_and_evaluate.py
scripts/threshold_tuning.py
targets/auth_events.csv
targets/suspicious_auth_events.csv
targets/auth_summary_by_ip.csv
targets/auth_risk_summary_by_ip.csv
targets/model_metrics.json
targets/logistic_regression_coefficients.csv
targets/model_test_predictions.csv
targets/threshold_sweep.csv
targets/threshold_tuning_summary.json
writeup/log-analysis-notes.md
checklist.md
```

## Synthetic dataset

The lab now uses a synthetic generator that produces 5,000 authentication events with labeled attack IPs and injected brute-force-style bursts.

### Output files

- `data/raw_auth_logs.log` contains the synthetic raw log stream.
- `data/labels.csv` contains IP-level ground truth labels.
- Attack labels are injected independently from the rule logic so evaluation is meaningful.

### Why synthetic data

Synthetic telemetry makes it possible to demonstrate the full pipeline without exposing sensitive logs. It also allows controlled attack injection so the project can report precision, recall, false positives, false negatives, and threshold behavior.

## Parsing raw logs

The parser converts the raw log file into structured CSV rows.

```bash
python scripts/parse_auth_logs.py
```

This produces:

- `targets/auth_events.csv`

The parsed schema is:

```text
date,time,level,user,action,status,ip
```

## Detection features

The analysis script creates these event-level features:

```text
is_failed_login
is_privileged_user
is_private_ip
is_external_ip
suspicious_event
```

These features are then grouped by IP to produce a risk summary.

## IP risk scoring

The IP-level summary includes:

```text
total_events
failed_logins
privileged_attempts
external_events
suspicious_events
risk_score
risk_level
is_attack
attack_type
```

The current scoring logic uses a simple weighted sum to rank IPs by risk.

## Rule baseline

The rule baseline treats medium and high risk IPs as positive detections. This provides a clear, interpretable benchmark before introducing ML.

## ML comparison

The project now compares three approaches on the IP-level labeled summary:

- Rule-based baseline.
- Logistic regression.
- Isolation Forest.

The feature set used for modeling is:

```text
total_events
failed_logins
privileged_attempts
external_events
suspicious_events
risk_score
```

### Current results

On the current held-out split, the project produced:

- Rule baseline: accuracy 0.9452, precision 0.1667, recall 1.0, F1 0.2857.
- Logistic regression: accuracy 1.0, precision 1.0, recall 1.0, F1 1.0, ROC-AUC 1.0.
- Isolation Forest: accuracy 0.9945, precision 0.6667, recall 1.0, F1 0.8, ROC-AUC 1.0.

These results show how a noisy rule baseline can be compared against a supervised model and an anomaly detector on the same telemetry.

## Threshold tuning

The project also includes cost-sensitive threshold tuning for logistic regression.

### Cost model

- False positive cost: 1
- False negative cost: 25

### Result

The current sweep found a best threshold of 0.01 with zero cost on the held-out split.

This section is useful because it frames classification as a decision problem, not just a score report.

## Results

The current benchmark identified:

- 12 labeled attack IPs in the synthetic dataset.
- 1,214 total IPs in the final summary.
- A noisy rule baseline with useful recall but low precision.
- A logistic regression model that cleanly separates the synthetic benchmark.
- An Isolation Forest model that can be discussed as triage-oriented anomaly detection.

## Real-world relevance

This lab maps cleanly to:

- Authentication telemetry triage.
- Account takeover detection.
- Fraud-risk screening.
- Security operations prioritization.

In a real environment, the same pattern would be used to convert raw event streams into ranked risk summaries so investigators can focus on the highest-priority IPs first.

## Run order

```bash
python scripts/generate_synthetic_auth_logs.py
python scripts/parse_auth_logs.py
python scripts/analyze_auth_events.py
python scripts/train_and_evaluate.py
python scripts/threshold_tuning.py
```

## Current status

Synthetic benchmark complete.

The lab now demonstrates:
- log generation,
- log parsing,
- feature engineering,
- grouped risk scoring,
- ML comparison,
- and cost-sensitive threshold tuning.

Next step: move to the Canonical Reasoning / LSAT pipeline and bring that project to the same level of polish.