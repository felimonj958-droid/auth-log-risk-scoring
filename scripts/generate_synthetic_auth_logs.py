from pathlib import Path
from datetime import datetime, timedelta
import random
import csv
import ipaddress

SEED = 42
TOTAL_EVENTS = 5000
ATTACK_IP_COUNT = 12
ATTACK_EVENT_SHARE = 0.08

OUTPUT_DIR = Path("data")
RAW_LOG_PATH = OUTPUT_DIR / "raw_auth_logs.log"
LABELS_PATH = OUTPUT_DIR / "labels.csv"

INTERNAL_SUBNETS = [
    ipaddress.ip_network("192.168.1.0/24"),
    ipaddress.ip_network("10.0.0.0/24"),
    ipaddress.ip_network("172.16.0.0/24"),
]

EXTERNAL_ATTACK_BLOCKS = [
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

NORMAL_USERS = [
    "user123", "jane", "alex", "maria", "dlee", "asmith", "finance1",
    "ops2", "hr_portal", "analyst7", "guest"
]

PRIVILEGED_USERS = ["admin", "root", "svc_admin", "secops"]

LEVELS = {
    "success": "INFO",
    "failed": "WARN",
}

def random_ip_from_network(net, rng):
    hosts = list(net.hosts())
    return str(rng.choice(hosts))

def choose_internal_ip(rng):
    return random_ip_from_network(rng.choice(INTERNAL_SUBNETS), rng)

def choose_attack_ip(rng):
    return random_ip_from_network(rng.choice(EXTERNAL_ATTACK_BLOCKS), rng)

def weighted_choice(rng, items):
    population = [item for item, _ in items]
    weights = [weight for _, weight in items]
    return rng.choices(population, weights=weights, k=1)[0]

def generate_normal_event(ts, rng):
    user = weighted_choice(
        rng,
        [(u, 8) for u in NORMAL_USERS] + [(u, 2) for u in PRIVILEGED_USERS]
    )

    action = weighted_choice(
        rng,
        [("login", 88), ("logout", 7), ("password_reset", 5)]
    )

    if action == "login":
        if user in PRIVILEGED_USERS:
            status = weighted_choice(rng, [("success", 72), ("failed", 28)])
        else:
            status = weighted_choice(rng, [("success", 89), ("failed", 11)])
    elif action == "logout":
        status = "success"
    else:
        status = weighted_choice(rng, [("success", 80), ("failed", 20)])

    level = LEVELS["failed"] if status == "failed" else LEVELS["success"]

    ip = weighted_choice(
        rng,
        [(choose_internal_ip(rng), 70), (choose_attack_ip(rng), 30)]
    )

    return {
        "timestamp": ts,
        "date": ts.strftime("%Y-%m-%d"),
        "time": ts.strftime("%H:%M:%S"),
        "level": level,
        "user": user,
        "action": action,
        "status": status,
        "ip": ip,
        "is_attack": 0,
        "attack_type": "none",
    }

def generate_benign_failed_burst(start_ts, benign_ip, burst_size, rng):
    events = []
    for i in range(burst_size):
        ts = start_ts + timedelta(seconds=i * rng.randint(10, 45))
        user = rng.choice(NORMAL_USERS + PRIVILEGED_USERS)
        status = weighted_choice(rng, [("failed", 75), ("success", 25)])
        level = LEVELS["failed"] if status == "failed" else LEVELS["success"]

        events.append({
            "timestamp": ts,
            "date": ts.strftime("%Y-%m-%d"),
            "time": ts.strftime("%H:%M:%S"),
            "level": level,
            "user": user,
            "action": "login",
            "status": status,
            "ip": benign_ip,
            "is_attack": 0,
            "attack_type": "none",
        })
    return events

def generate_attack_burst(start_ts, attack_ip, burst_size, rng):
    events = []

    for i in range(burst_size):
        ts = start_ts + timedelta(seconds=i * rng.randint(6, 30))

        user = weighted_choice(
            rng,
            [(u, 5) for u in NORMAL_USERS] + [(u, 4) for u in PRIVILEGED_USERS]
        )

        action = weighted_choice(
            rng,
            [("login", 94), ("password_reset", 6)]
        )

        status = weighted_choice(
            rng,
            [("failed", 78), ("success", 22)]
        )

        level = LEVELS["failed"] if status == "failed" else LEVELS["success"]

        events.append({
            "timestamp": ts,
            "date": ts.strftime("%Y-%m-%d"),
            "time": ts.strftime("%H:%M:%S"),
            "level": level,
            "user": user,
            "action": action,
            "status": status,
            "ip": attack_ip,
            "is_attack": 1,
            "attack_type": "bruteforce_https",
        })

    return events

def generate_attack_cooldown(start_ts, attack_ip, event_count, rng):
    events = []
    for i in range(event_count):
        ts = start_ts + timedelta(minutes=i * rng.randint(3, 12))
        user = rng.choice(NORMAL_USERS)
        action = weighted_choice(rng, [("login", 85), ("logout", 10), ("password_reset", 5)])
        status = weighted_choice(rng, [("success", 70), ("failed", 30)])
        level = LEVELS["failed"] if status == "failed" else LEVELS["success"]

        events.append({
            "timestamp": ts,
            "date": ts.strftime("%Y-%m-%d"),
            "time": ts.strftime("%H:%M:%S"),
            "level": level,
            "user": user,
            "action": action,
            "status": status,
            "ip": attack_ip,
            "is_attack": 1,
            "attack_type": "bruteforce_https",
        })
    return events

def write_raw_log(events, path):
    with open(path, "w", encoding="utf-8") as f:
        for e in sorted(events, key=lambda x: x["timestamp"]):
            f.write(
                f"{e['date']},{e['time']},{e['level']},{e['user']},{e['action']},{e['status']},{e['ip']}\n"
            )

def write_labels(events, path):
    by_ip = {}
    for e in events:
        ip = e["ip"]
        if ip not in by_ip:
            by_ip[ip] = {
                "ip": ip,
                "is_attack": 0,
                "attack_type": "none",
                "injected_events": 0,
                "failed_events": 0,
                "privileged_target_events": 0,
            }

        by_ip[ip]["injected_events"] += 1

        if e["status"] == "failed":
            by_ip[ip]["failed_events"] += 1

        if e["user"] in PRIVILEGED_USERS:
            by_ip[ip]["privileged_target_events"] += 1

        if e["is_attack"] == 1:
            by_ip[ip]["is_attack"] = 1
            by_ip[ip]["attack_type"] = e["attack_type"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ip",
                "is_attack",
                "attack_type",
                "injected_events",
                "failed_events",
                "privileged_target_events",
            ],
        )
        writer.writeheader()
        for row in sorted(by_ip.values(), key=lambda x: (x["is_attack"], x["injected_events"], x["ip"]), reverse=True):
            writer.writerow(row)

def main():
    rng = random.Random(SEED)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    start_time = datetime(2026, 5, 11, 8, 0, 0)

    attack_ips = []
    while len(attack_ips) < ATTACK_IP_COUNT:
        ip = choose_attack_ip(rng)
        if ip not in attack_ips:
            attack_ips.append(ip)

    attack_events_target = int(TOTAL_EVENTS * ATTACK_EVENT_SHARE)
    base_attack_burst = max(10, attack_events_target // ATTACK_IP_COUNT)

    events = []

    normal_target = TOTAL_EVENTS - attack_events_target
    for i in range(normal_target):
        ts = start_time + timedelta(seconds=i * rng.randint(5, 40))
        events.append(generate_normal_event(ts, rng))

    benign_burst_ips = []
    for _ in range(10):
        benign_burst_ips.append(weighted_choice(
            rng,
            [(choose_internal_ip(rng), 3), (choose_attack_ip(rng), 2)]
        ))

    for benign_ip in benign_burst_ips:
        burst_start = start_time + timedelta(minutes=rng.randint(20, 500))
        burst_size = rng.randint(6, 14)
        events.extend(generate_benign_failed_burst(burst_start, benign_ip, burst_size, rng))

    for idx, attack_ip in enumerate(attack_ips):
        burst_start = start_time + timedelta(minutes=rng.randint(10, 600), seconds=idx * 17)
        burst_size = base_attack_burst + rng.randint(-8, 6)
        events.extend(generate_attack_burst(burst_start, attack_ip, burst_size, rng))

        cooldown_size = rng.randint(3, 8)
        cooldown_start = burst_start + timedelta(minutes=rng.randint(20, 90))
        events.extend(generate_attack_cooldown(cooldown_start, attack_ip, cooldown_size, rng))

    events = sorted(events, key=lambda x: x["timestamp"])

    if len(events) > TOTAL_EVENTS:
        events = events[:TOTAL_EVENTS]
    elif len(events) < TOTAL_EVENTS:
        next_ts = events[-1]["timestamp"] if events else start_time
        while len(events) < TOTAL_EVENTS:
            next_ts += timedelta(seconds=rng.randint(5, 30))
            events.append(generate_normal_event(next_ts, rng))

    write_raw_log(events, RAW_LOG_PATH)
    write_labels(events, LABELS_PATH)

    print(f"Wrote {len(events)} events to {RAW_LOG_PATH}")
    print(f"Wrote labels to {LABELS_PATH}")
    print(f"Attack IPs configured: {len(attack_ips)}")
    print(f"Attack event share target: {ATTACK_EVENT_SHARE:.0%}")


if __name__ == "__main__":
    main()