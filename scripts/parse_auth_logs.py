import csv
from pathlib import Path

LOG_PATH = Path("data/raw_auth_logs.log")
OUTPUT_PATH = Path("targets/auth_events.csv")

FIELDNAMES = ["date", "time", "level", "user", "action", "status", "ip"]


def parse_log_line(line):
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 7:
        return None

    return dict(zip(FIELDNAMES, parts))


def parse_log_file(log_path):
    events = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            line = line.strip()
            if not line:
                continue

            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)

    return events


def save_events_to_csv(events, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(events)

    print(f"Parsed events: {len(events)}")
    print(f"CSV saved to: {output_path}")


if __name__ == "__main__":
    auth_events = parse_log_file(LOG_PATH)
    save_events_to_csv(auth_events, OUTPUT_PATH)