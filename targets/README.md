# targets

Generated artifacts. All files are reproducible by running the five scripts
in the order listed in the root README.

| File | Contents |
|---|---|
| `auth_events.csv` | 5,000 parsed events (date, time, level, user, action, status, ip) |
| `suspicious_auth_events.csv` | Events flagged by detection features |
| `auth_summary_by_ip.csv` | Per-IP aggregation across 1,214 source IPs |
| `auth_risk_summary_by_ip.csv` | Per-IP summary with risk score, risk level, and ground-truth labels |
| `model_metrics.json` | Rule baseline, logistic regression, and Isolation Forest results |
| `logistic_regression_coefficients.csv` | Feature coefficients from the fitted model |
| `model_test_predictions.csv` | Per-IP predictions on the held-out split |
| `threshold_sweep.csv` | Cost at each candidate decision threshold |
| `threshold_tuning_summary.json` | Selected threshold under FP cost 1 : FN cost 25 |