from pathlib import Path
import json
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

DATA_PATH = Path("targets/auth_risk_summary_by_ip.csv")
SWEEP_OUT = Path("targets/threshold_sweep.csv")
SUMMARY_OUT = Path("targets/threshold_tuning_summary.json")

FEATURES = [
    "total_events",
    "failed_logins",
    "privileged_attempts",
    "external_events",
    "suspicious_events",
    "risk_score",
]
TARGET = "is_attack"

FP_COST = 1
FN_COST = 25


def main():
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURES].copy()
    y = df[TARGET].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        stratify=y,
        random_state=42
    )

    model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=42
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]

    rows = []
    for t in np.linspace(0, 1, 101):
        pred = (proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
        rows.append({
            "threshold": round(float(t), 2),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "precision": round(precision_score(y_test, pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, pred, zero_division=0), 4),
            "f1": round(f1_score(y_test, pred, zero_division=0), 4),
            "cost": int(fp * FP_COST + fn * FN_COST),
        })

    sweep = pd.DataFrame(rows)
    best = sweep.sort_values(["cost", "fp", "threshold"]).iloc[0]

    SWEEP_OUT.parent.mkdir(parents=True, exist_ok=True)
    sweep.to_csv(SWEEP_OUT, index=False)

    summary = {
        "false_positive_cost": FP_COST,
        "false_negative_cost": FN_COST,
        "best_threshold": float(best["threshold"]),
        "best_cost": int(best["cost"]),
        "best_precision": float(best["precision"]),
        "best_recall": float(best["recall"]),
        "best_f1": float(best["f1"]),
        "best_fp": int(best["fp"]),
        "best_fn": int(best["fn"]),
    }

    with open(SUMMARY_OUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"Saved sweep to: {SWEEP_OUT}")
    print(f"Saved summary to: {SUMMARY_OUT}")


if __name__ == "__main__":
    main()