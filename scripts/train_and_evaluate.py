from pathlib import Path
import json
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

DATA_PATH = Path("targets/auth_risk_summary_by_ip.csv")
OUTPUT_DIR = Path("targets")

FEATURES = [
    "total_events",
    "failed_logins",
    "privileged_attempts",
    "external_events",
    "suspicious_events",
    "risk_score",
]
TARGET = "is_attack"


def compute_metrics(y_true, y_pred, y_score=None):
    metrics = {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }

    if y_score is not None:
        try:
            metrics["roc_auc"] = round(roc_auc_score(y_true, y_score), 4)
        except Exception:
            metrics["roc_auc"] = None

    return metrics


def evaluate_rule_baseline(df):
    baseline_pred = (df["risk_level"].isin(["medium", "high"])).astype(int)
    return compute_metrics(df[TARGET], baseline_pred)


def evaluate_logistic_regression(X_train, X_test, y_train, y_test):
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42))
    ])

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_score = model.predict_proba(X_test)[:, 1]

    metrics = compute_metrics(y_test, y_pred, y_score=y_score)

    clf = model.named_steps["clf"]
    coef_df = pd.DataFrame({
        "feature": FEATURES,
        "coefficient": clf.coef_[0]
    }).sort_values("coefficient", ascending=False)

    return model, metrics, coef_df, y_pred, y_score


def evaluate_isolation_forest(X_train, X_test, y_test, contamination):
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200
        ))
    ])

    model.fit(X_train)

    raw_pred = model.predict(X_test)
    y_pred = pd.Series(raw_pred).map({1: 0, -1: 1}).values

    anomaly_score = -model.named_steps["clf"].score_samples(
        model.named_steps["scaler"].transform(X_test)
    )

    metrics = compute_metrics(y_test, y_pred, y_score=anomaly_score)
    return model, metrics, y_pred, anomaly_score


def save_outputs(results, coef_df, test_predictions):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_DIR / "model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    coef_df.to_csv(OUTPUT_DIR / "logistic_regression_coefficients.csv", index=False)
    test_predictions.to_csv(OUTPUT_DIR / "model_test_predictions.csv", index=False)


def main():
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURES].copy()
    y = df[TARGET].copy()

    X_train, X_test, y_train, y_test, train_idx, test_idx = train_test_split(
        X, y, df.index,
        test_size=0.3,
        stratify=y,
        random_state=42
    )

    baseline_metrics = evaluate_rule_baseline(df.loc[test_idx])

    lr_model, lr_metrics, coef_df, lr_pred, lr_score = evaluate_logistic_regression(
        X_train, X_test, y_train, y_test
    )

    contamination = max(y_train.mean(), 0.01)
    if_model, if_metrics, if_pred, if_score = evaluate_isolation_forest(
        X_train[y_train == 0],
        X_test,
        y_test,
        contamination=contamination
    )

    test_predictions = df.loc[test_idx, ["ip", "risk_level", "is_attack"]].copy()
    test_predictions["rule_pred"] = (test_predictions["risk_level"].isin(["medium", "high"])).astype(int).values
    test_predictions["logreg_pred"] = lr_pred
    test_predictions["logreg_score"] = lr_score
    test_predictions["iforest_pred"] = if_pred
    test_predictions["iforest_score"] = if_score

    results = {
        "dataset": {
            "rows": int(len(df)),
            "attack_ips": int(df[TARGET].sum()),
            "attack_rate": round(float(df[TARGET].mean()), 4),
            "features": FEATURES,
        },
        "rule_baseline_medium_or_high": baseline_metrics,
        "logistic_regression": lr_metrics,
        "isolation_forest": if_metrics,
    }

    save_outputs(results, coef_df, test_predictions)

    print("Dataset summary")
    print("===============")
    print(f"Rows: {len(df)}")
    print(f"Attack IPs: {int(df[TARGET].sum())}")
    print(f"Attack rate: {df[TARGET].mean():.4f}")
    print()

    print("Rule baseline metrics")
    print("=====================")
    print(json.dumps(baseline_metrics, indent=2))
    print()

    print("Logistic regression metrics")
    print("===========================")
    print(json.dumps(lr_metrics, indent=2))
    print()

    print("Isolation forest metrics")
    print("========================")
    print(json.dumps(if_metrics, indent=2))
    print()

    print("Top logistic regression coefficients")
    print("====================================")
    print(coef_df.to_string(index=False))
    print()

    print(f"Saved metrics to: {OUTPUT_DIR / 'model_metrics.json'}")
    print(f"Saved coefficients to: {OUTPUT_DIR / 'logistic_regression_coefficients.csv'}")
    print(f"Saved predictions to: {OUTPUT_DIR / 'model_test_predictions.csv'}")


if __name__ == "__main__":
    main()