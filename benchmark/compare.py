#!/usr/bin/env python3
import json
import sys

REGRESSION_THRESHOLD = 0.20

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <baseline.json> <results.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        baseline = json.load(f)
    with open(sys.argv[2]) as f:
        results = json.load(f)

    baseline_map = {r["test"]: r for r in baseline["results"]}
    results_map = {r["test"]: r for r in results["results"]}

    regressions = []
    print("\n=== Benchmark Results ===\n")

    for test_name, base in baseline_map.items():
        if test_name not in results_map:
            continue

        curr = results_map[test_name]
        base_eps = base["events_per_second"]
        curr_eps = curr["events_per_second"]
        change = (curr_eps - base_eps) / base_eps

        status = "OK" if change >= -REGRESSION_THRESHOLD else "REGRESSION"
        print(f"{test_name}:")
        print(f"  Baseline: {base_eps:.1f} ev/s")
        print(f"  Current:  {curr_eps:.1f} ev/s ({change:+.1%})")
        print(f"  Status:   {status}\n")

        if change < -REGRESSION_THRESHOLD:
            regressions.append(test_name)

    if regressions:
        print(f"FAILED: Regression detected in {', '.join(regressions)}")
        sys.exit(1)

    print("PASSED: No significant regressions")

if __name__ == "__main__":
    main()
