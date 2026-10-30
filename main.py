"""Command-line interface for AI Security Alert Triage."""

import argparse
import json
from pathlib import Path

try:
    from .triage import triage_alerts
except ImportError:  # Allows: python src/main.py
    from triage import triage_alerts


def load_alerts(path: Path):
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, list):
        raise ValueError("Input JSON must be an array of alert objects.")
    return data


def main():
    parser = argparse.ArgumentParser(description="Triage security alerts from JSON.")
    parser.add_argument("--input", default="data/sample_alerts.json",
                        help="Path to JSON alert array.")
    parser.add_argument("--output", help="Optional path for JSON triage report.")
    args = parser.parse_args()

    try:
        results = triage_alerts(load_alerts(Path(args.input)))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    print("\nAI SECURITY ALERT TRIAGE")
    print("=" * 68)
    for item in results:
        print(f'{item["id"]} | {item["priority"]} | Risk: {item["risk_score"]}/100')
        print(f'Title: {item["title"]}')
        print("Reasons:")
        for reason in item["reasons"]:
            print(f"  - {reason}")
        print(f'MITRE: {item["mitre_mapping"]}')
        print("Recommended actions:")
        for action in item["recommended_actions"]:
            print(f"  - {action}")
        print("-" * 68)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
