# Authentication Log Risk Scoring Lab Notes

## Overview

This project began as a small defensive log-parsing exercise and evolved into a controlled cybersecurity detection lab.

The current version generates synthetic authentication telemetry, parses raw logs into structured events, engineers detection features, scores IP-level risk with rules, compares the baseline against machine learning methods, and adds cost-sensitive threshold tuning.

The goal is not to claim production-grade detection performance. The goal is to show detection-engineering workflow, reproducible benchmarking, and thoughtful evaluation on labeled synthetic telemetry.

## Safety boundaries

- Synthetic logs only
- No private or customer data
- No public systems
- No offensive use
- Defensive analytics only

## Project evolution

### Original lab phase

The first version of the project used a tiny sample authentication log and focused on:

- regular-expression log parsing,
- suspicious event flagging,
- grouped summaries by IP,
- and rule-based risk scoring.

That phase was useful for proving the mechanics of the pipeline, but it was too small to support meaningful evaluation.

### Expanded benchmark phase

The project was then extended into a larger synthetic benchmark with:

- 5,000 synthetic authentication events,
- 12 labeled attack IPs,
- IP-level ground truth,
- higher benign noise,
- ML comparison,
- and threshold tuning.

This made it possible to report actual precision, recall, F1, confusion matrices, and threshold cost behavior instead of only describing suspicious rows.

## Pipeline

```text
synthetic auth log generation
→ raw auth log
→ parser
→ structured event CSV
→ feature engineering
→ suspicious event export
→ grouped IP summary
→ rule-based risk scoring
→ supervised / unsupervised ML comparison
→ cost-sensitive threshold tuning
```

## Raw data and labels

### Raw log output

The synthetic generator writes a raw authentication log to:

```text
data/raw_auth_logs.log
```

Each row uses this structure:

```text
date,time,level,user,action,status,ip
```

### Ground-truth labels

The synthetic generator also writes:

```text
data/labels.csv
```

This file contains IP-level labels including:

```text
ip
is_attack
attack_type
injected_events
failed_events
privileged_target_events
```

The labels are important because they are created independently from the rules engine. That allows meaningful evaluation instead of circular scoring.

## Parsing

The parser script converts the raw log file into structured CSV rows.

### Script

```text
scripts/parse_auth_logs.py
```

### Output

```text
targets/auth_events.csv
```

### Extracted fields

```text
date
time
level
user
action
status
ip
```

This stage turns unstructured log lines into pandas-ready tabular data.

## Feature engineering

The analysis stage adds the following detection features:

```text
is_failed_login
is_privileged_user
is_private_ip
is_external_ip
suspicious_event
```

The current suspicious-event rule is:

```text
is_failed_login AND (is_privileged_user OR is_external_ip)
```

This rule is intentionally simple and interpretable. It functions as the baseline logic before any ML model is introduced.

## IP-level aggregation

After feature engineering, the project groups events by source IP and computes these summary features:

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

This IP-level summary is the core modeling table used for both rule-based evaluation and ML experiments.

## Risk scoring logic

The rules engine computes a weighted score using failed logins, privileged-user attempts, external IP activity, and suspicious events.

The purpose of this scoring layer is not to be optimal. It is to provide a transparent baseline for comparison. In real security operations, this kind of initial heuristic is often useful for triage but may also create many false positives.

## Current dataset snapshot

The current benchmark produced:

- 5,000 synthetic authentication events
- 559 suspicious events
- 1,214 unique IPs in the final summary
- 12 labeled attack IPs
- attack rate of about 0.99% at the IP level

This creates a highly imbalanced classification problem, which is realistic for security-style rare-event detection.

## Evaluation setup

The project currently compares three approaches:

- rule-based baseline,
- logistic regression,
- Isolation Forest.

### Modeling features

```text
total_events
failed_logins
privileged_attempts
external_events
suspicious_events
risk_score
```

### Target

```text
is_attack
```

The rule baseline predicts positive when `risk_level` is `medium` or `high`.

## Current results

### Rule baseline

The current rule baseline produced:

- accuracy: 0.9452
- precision: 0.1667
- recall: 1.0
- F1: 0.2857

Confusion matrix:

```text
TN=341, FP=20
FN=0,   TP=4
```

Interpretation:

The baseline catches all attack IPs in the held-out split, but it produces many false positives. That makes it useful for broad triage but weak as a precise detector.

### Logistic regression

The logistic regression model produced:

- accuracy: 1.0
- precision: 1.0
- recall: 1.0
- F1: 1.0
- ROC-AUC: 1.0

Confusion matrix:

```text
TN=361, FP=0
FN=0,   TP=4
```

Interpretation:

On the current synthetic benchmark, logistic regression cleanly separates the attack and non-attack IPs.

This is a strong benchmark result, but it should be interpreted carefully. The benchmark is still synthetic and the attack patterns remain highly separable, so this should be described as a controlled detection-engineering result rather than a production claim.

### Isolation Forest

The Isolation Forest model produced:

- accuracy: 0.9945
- precision: 0.6667
- recall: 1.0
- F1: 0.8
- ROC-AUC: 1.0

Confusion matrix:

```text
TN=359, FP=2
FN=0,   TP=4
```

Interpretation:

Isolation Forest sits between the rules baseline and supervised classification. It preserves strong recall and reduces false positives relative to the rule-based detector, which makes it useful to discuss as a triage-oriented anomaly detector.

## Feature importance / coefficient notes

The highest logistic-regression coefficients in the current run were:

```text
external_events
total_events
suspicious_events
risk_score
failed_logins
privileged_attempts
```

This indicates that external activity volume, total activity, and suspicious-event concentration are the strongest signals in the current benchmark.

## Threshold tuning

The project also includes a cost-sensitive threshold sweep for logistic regression.

### Cost assumptions

```text
false positive cost = 1
false negative cost = 25
```

### Current outcome

The best threshold on the current held-out split was:

```text
0.01
```

With:

```text
best_cost = 0
best_precision = 1.0
best_recall = 1.0
best_f1 = 1.0
best_fp = 0
best_fn = 0
```

Interpretation:

This shows the project can separate prediction from decision policy, which is important in applied ML. However, because the current benchmark remains highly separable, the threshold sweep does not yet show a difficult cost tradeoff. It is still useful because it demonstrates the right evaluation mindset.

## Why the benchmark was hardened

The original synthetic setup was too easy. To reduce trivial separation, the generator was updated to include:

- benign external logins,
- benign failed-login bursts,
- lower concentration of privileged-user targeting,
- occasional successful attacker behavior,
- and more overlap between benign and malicious-looking traffic.

That made the rule baseline noisier and improved the realism of the comparison.

## Real-world mapping

This project maps most directly to:

- authentication telemetry triage,
- account takeover detection,
- fraud-risk screening,
- security operations prioritization,
- and alert ranking workflows.

The broader lesson is that raw event streams need to be transformed into structured rows, engineered into decision features, aggregated into analyst-friendly units, and then evaluated with both interpretable and ML-based approaches.

## Limitations

- The dataset is synthetic, not operational telemetry.
- Attack behavior is injected and still cleaner than many real-world adversary patterns.
- The benchmark is useful for comparison and workflow demonstration, not for claiming production deployment quality.
- Threshold tuning is implemented, but the current benchmark still separates too cleanly for the threshold sweep to become a difficult optimization problem.

## Strong next improvements

The most valuable future improvements would be:

- convert timestamps into pandas datetime values,
- add sliding time-window features,
- detect repeated failures within a 5-minute window,
- create charts for score distributions and confusion matrices,
- test multiple synthetic scenarios with different attack injection rates,
- and add a one-command pipeline runner.

## Bottom line

This project is now much stronger than a simple parser demo.

It demonstrates:
- synthetic telemetry generation,
- defensive feature engineering,
- heuristic risk scoring,
- supervised ML comparison,
- anomaly-detection comparison,
- and cost-sensitive decision tuning.

That combination makes it a credible cybersecurity analytics portfolio project focused on detection engineering and applied ML.