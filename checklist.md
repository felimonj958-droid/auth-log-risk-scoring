# Authentication Log Risk Scoring Lab Checklist

## Project setup

- [x] Create repository structure for auth log risk scoring lab
- [x] Create `data/`, `scripts/`, `targets/`, and `writeup/` folders
- [x] Add defensive scope and safety boundaries
- [x] Add GitHub-ready README

## Synthetic telemetry

- [x] Build `generate_synthetic_auth_logs.py`
- [x] Generate `data/raw_auth_logs.log`
- [x] Generate `data/labels.csv`
- [x] Inject labeled brute-force-style attack activity
- [x] Add benign noisy behavior to increase overlap between attack and non-attack traffic
- [x] Preserve ground truth labels independently from detection rules

## Parsing

- [x] Parse raw log lines into structured rows
- [x] Extract `date`, `time`, `level`, `user`, `action`, `status`, and `ip`
- [x] Export parsed events to CSV
- [x] Create `targets/auth_events.csv`

## Detection features

- [x] Add `is_failed_login`
- [x] Add `is_privileged_user`
- [x] Add `is_private_ip`
- [x] Add `is_external_ip`
- [x] Add `suspicious_event`

## Analysis outputs

- [x] Create `targets/suspicious_auth_events.csv`
- [x] Create `targets/auth_summary_by_ip.csv`
- [x] Create `targets/auth_risk_summary_by_ip.csv`
- [x] Merge `is_attack` and `attack_type` labels into the IP-level summary

## Rule-based scoring

- [x] Score failed logins
- [x] Score privileged-user attempts
- [x] Score external-looking IPs
- [x] Score suspicious events
- [x] Assign IP-level risk scores
- [x] Assign risk levels
- [x] Establish rule-based baseline for evaluation

## ML evaluation

- [x] Build `train_and_evaluate.py`
- [x] Train logistic regression on engineered IP-level features
- [x] Train Isolation Forest for anomaly-detection comparison
- [x] Evaluate rule baseline vs. supervised model vs. anomaly detector
- [x] Save `targets/model_metrics.json`
- [x] Save `targets/logistic_regression_coefficients.csv`
- [x] Save `targets/model_test_predictions.csv`

## Threshold tuning

- [x] Build `threshold_tuning.py`
- [x] Define asymmetric false-positive / false-negative costs
- [x] Sweep thresholds from 0.00 to 1.00
- [x] Save `targets/threshold_sweep.csv`
- [x] Save `targets/threshold_tuning_summary.json`

## Documentation

- [x] Rewrite README to reflect the current benchmark
- [x] Update writeup notes to reflect the expanded pipeline
- [x] Document real-world mapping to authentication telemetry and account takeover triage
- [ ] Confirm final repo push includes updated artifacts

## Current benchmark snapshot

- [x] 5,000 synthetic authentication events generated
- [x] 12 labeled attack IPs injected
- [x] 1,214 IPs in the final IP-level summary
- [x] Rule baseline evaluated
- [x] Logistic regression evaluated
- [x] Isolation Forest evaluated
- [x] Cost-sensitive threshold tuning evaluated

## Next improvements

- [ ] Add timestamp parsing as pandas datetime values
- [ ] Add sliding time-window features
- [ ] Detect repeated failures within 5 minutes
- [ ] Add visualizations for score distributions and confusion matrices
- [ ] Add PR curve / ROC curve outputs
- [ ] Add one-command runner script for the full pipeline
- [ ] Optionally add Docker or docker-compose packaging
- [ ] Test on multiple synthetic scenarios with different attack injection rates