from time import perf_counter
import csv

from auth_layer import exchange_and_verify
from dh_core import generate_parameters, generate_private_key, generate_public_key, generate_shared_key
from mitm_attack import mitm_simulation


def run_standard_session():
    p, g = generate_parameters()
    a = generate_private_key(p)
    b = generate_private_key(p)
    A = generate_public_key(g, a, p)
    B = generate_public_key(g, b, p)
    shared_A = generate_shared_key(B, a, p)
    shared_B = generate_shared_key(A, b, p)
    return shared_A == shared_B


def run_authenticated_session():
    p, g = generate_parameters()
    a = generate_private_key(p)
    b = generate_private_key(p)
    A = generate_public_key(g, a, p)
    B = generate_public_key(g, b, p)
    shared_A = generate_shared_key(B, a, p)
    shared_B = generate_shared_key(A, b, p)
    return exchange_and_verify(shared_A, shared_B, "Alice", "Bob")


def benchmark_standard_dh(trials=500):
    durations = []
    successful_sessions = 0

    for _ in range(trials):
        start = perf_counter()
        keys_match = run_standard_session()
        durations.append(perf_counter() - start)
        if keys_match:
            successful_sessions += 1

    total_time = sum(durations)
    return {
        "success_rate": successful_sessions / trials,
        "average_time": total_time / trials,
        "total_time": total_time,
    }


def benchmark_authenticated_dh(trials=500):
    durations = []
    verified_sessions = 0

    for _ in range(trials):
        start = perf_counter()
        exchange = run_authenticated_session()
        durations.append(perf_counter() - start)
        if exchange["authenticated"]:
            verified_sessions += 1

    total_time = sum(durations)
    return {
        "verification_accuracy": verified_sessions / trials,
        "average_time": total_time / trials,
        "total_time": total_time,
    }


def benchmark_mitm_attack(trials=500):
    attack_successes = 0
    detected_attacks = 0
    durations = []

    for _ in range(trials):
        start = perf_counter()
        shared_A, shared_B = mitm_simulation()
        exchange = exchange_and_verify(shared_A, shared_B, "Alice", "Bob")
        durations.append(perf_counter() - start)

        if shared_A != shared_B:
            attack_successes += 1
        if not exchange["authenticated"]:
            detected_attacks += 1

    total_time = sum(durations)
    return {
        "attack_success_rate": attack_successes / trials,
        "detection_rate": detected_attacks / trials,
        "average_time": total_time / trials,
        "total_time": total_time,
    }


def compute_evaluation_report(trials=500):
    standard = benchmark_standard_dh(trials)
    authenticated = benchmark_authenticated_dh(trials)
    mitm = benchmark_mitm_attack(trials)

    overhead_per_session = authenticated["average_time"] - standard["average_time"]
    overhead_percent = (
        (overhead_per_session / standard["average_time"]) * 100
        if standard["average_time"] > 0
        else 0.0
    )

    return {
        "trials": trials,
        "standard_dh": standard,
        "authenticated_dh": authenticated,
        "mitm_attack": mitm,
        "computational_overhead": {
            "seconds_per_session": overhead_per_session,
            "percent_increase": overhead_percent,
        },
    }


def format_percentage(value):
    return f"{value * 100:.2f}%"


def print_report(report):
    rows = [
        ("Attack Success Rate", format_percentage(report["mitm_attack"]["attack_success_rate"])),
        ("Detection Rate", format_percentage(report["mitm_attack"]["detection_rate"])),
        ("Key Verification Accuracy", format_percentage(report["authenticated_dh"]["verification_accuracy"])),
        ("Standard DH Avg Time", f"{report['standard_dh']['average_time']:.8f} s"),
        ("Authenticated DH Avg Time", f"{report['authenticated_dh']['average_time']:.8f} s"),
        ("Computational Overhead", f"{report['computational_overhead']['seconds_per_session']:.8f} s/session"),
        ("Overhead Increase", f"{report['computational_overhead']['percent_increase']:.2f}%"),
    ]

    width = max(len(label) for label, _ in rows)
    print(f"Trials: {report['trials']}")
    print("Metric".ljust(width), "| Value")
    print("-" * width, "|", "-" * 24)
    for label, value in rows:
        print(label.ljust(width), "|", value)


def save_report_csv(report, path):
    rows = [
        ["metric", "value"],
        ["trials", report["trials"]],
        ["attack_success_rate", report["mitm_attack"]["attack_success_rate"]],
        ["detection_rate", report["mitm_attack"]["detection_rate"]],
        ["key_verification_accuracy", report["authenticated_dh"]["verification_accuracy"]],
        ["standard_average_time_seconds", report["standard_dh"]["average_time"]],
        ["authenticated_average_time_seconds", report["authenticated_dh"]["average_time"]],
        ["computational_overhead_seconds_per_session", report["computational_overhead"]["seconds_per_session"]],
        ["computational_overhead_percent_increase", report["computational_overhead"]["percent_increase"]],
    ]

    with open(path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(rows)


def run_evaluation(trials=500, csv_path=None):
    report = compute_evaluation_report(trials)
    print_report(report)
    if csv_path:
        save_report_csv(report, csv_path)
        print(f"Saved CSV report to: {csv_path}")
    return report


if __name__ == "__main__":
    run_evaluation(500)
