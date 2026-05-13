import csv
import re
from pathlib import Path


LOG_PATH = Path("labs/04-log-analysis/sample-logs/auth_sample.log")
OUTPUT_PATH = Path("labs/04-log-analysis/targets/auth_events.csv")


LOG_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<level>\w+) "
    r"user=(?P<user>\w+) "
    r"action=(?P<action>\w+) "
    r"status=(?P<status>\w+) "
    r"ip=(?P<ip>[\d.]+)"
)


def parse_log_line(line):
    match = LOG_PATTERN.match(line)

    if not match:
        return None

    return match.groupdict()


def parse_log_file(log_path):
    events = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            parsed = parse_log_line(line.strip())

            if parsed:
                events.append(parsed)

    return events


def save_events_to_csv(events, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["date", "time", "level", "user", "action", "status", "ip"]

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"Parsed events: {len(events)}")
    print(f"CSV saved to: {output_path}")


if __name__ == "__main__":
    auth_events = parse_log_file(LOG_PATH)
    save_events_to_csv(auth_events, OUTPUT_PATH)
