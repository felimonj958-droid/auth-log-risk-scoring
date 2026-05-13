from pathlib import Path

import pandas as pd


CSV_PATH = Path("labs/04-log-analysis/targets/auth_events.csv")
OUTPUT_PATH = Path("labs/04-log-analysis/targets/suspicious_auth_events.csv")
SUMMARY_PATH = Path("labs/04-log-analysis/targets/auth_summary_by_ip.csv")
RISK_SUMMARY_PATH = Path("labs/04-log-analysis/targets/auth_risk_summary_by_ip.csv")


PRIVILEGED_USERS = {"admin", "root"}


def load_events(csv_path):
    return pd.read_csv(csv_path)


def add_detection_features(df):
    df = df.copy()

    df["is_failed_login"] = (
        (df["action"] == "login") &
        (df["status"] == "failed")
    )

    df["is_privileged_user"] = df["user"].isin(PRIVILEGED_USERS)

    df["is_private_ip"] = (
        df["ip"].str.startswith("192.168.") |
        df["ip"].str.startswith("10.") |
        df["ip"].str.startswith("172.16.")
    )

    df["is_external_ip"] = ~df["is_private_ip"]

    df["suspicious_event"] = (
        df["is_failed_login"] &
        (
            df["is_privileged_user"] |
            df["is_external_ip"]
        )
    )

    return df


def summarize_by_ip(df):
    summary = (
        df.groupby("ip")
        .agg(
            total_events=("ip", "count"),
            failed_logins=("is_failed_login", "sum"),
            privileged_attempts=("is_privileged_user", "sum"),
            external_events=("is_external_ip", "sum"),
            suspicious_events=("suspicious_event", "sum"),
        )
        .reset_index()
    )

    summary["risk_score"] = (
        summary["failed_logins"] * 1
        + summary["privileged_attempts"] * 2
        + summary["external_events"] * 1
        + summary["suspicious_events"] * 2
    )

    def risk_level(score):
        if score >= 20:
            return "high"
        if score >= 8:
            return "medium"
        if score >= 1:
            return "low"
        return "none"

    summary["risk_level"] = summary["risk_score"].apply(risk_level)

    summary = summary.sort_values(
        by=["risk_score", "suspicious_events"],
        ascending=[False, False]
    )

    return summary


def save_outputs(feature_df, summary_df):
    suspicious_df = feature_df[feature_df["suspicious_event"]]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    suspicious_df.to_csv(OUTPUT_PATH, index=False)
    summary_df.to_csv(SUMMARY_PATH, index=False)
    summary_df.to_csv(RISK_SUMMARY_PATH, index=False)

    print("Auth Event Analysis")
    print("===================")
    print(f"Total events: {len(feature_df)}")
    print(f"Suspicious events: {len(suspicious_df)}")
    print()
    print("Risk Summary by IP:")
    print(summary_df)
    print()
    print(f"Suspicious events saved to: {OUTPUT_PATH}")
    print(f"Summary by IP saved to: {SUMMARY_PATH}")
    print(f"Risk summary by IP saved to: {RISK_SUMMARY_PATH}")


if __name__ == "__main__":
    events_df = load_events(CSV_PATH)
    feature_df = add_detection_features(events_df)
    summary_df = summarize_by_ip(feature_df)
    save_outputs(feature_df, summary_df)