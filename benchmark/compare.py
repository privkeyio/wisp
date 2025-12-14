#!/usr/bin/env python3
import json
import sys

REGRESSION_THRESHOLD = 0.20

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <baseline.json> <results.json>")
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            baseline = json.load(f)
        with open(sys.argv[2]) as f:
            results = json.load(f)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}")
        sys.exit(1)

    if "results" not in baseline or "results" not in results:
        print("Error: JSON files must contain 'results' key")
        sys.exit(1)

    baseline_map = {r["test"]: r for r in baseline["results"]}
    results_map = {r["test"]: r for r in results["results"]}

    all_zero = all(r.get("events_per_second", 0) == 0 for r in results["results"])
    if all_zero:
        print("ERROR: Benchmark failed - all tests returned 0 events/sec")
        print("This indicates a benchmark tool failure, not a regression")
        sys.exit(1)

    regressions = []
    print("\n=== Benchmark Results ===\n")

    for test_name, base in baseline_map.items():
        if test_name not in results_map:
            continue

        curr = results_map[test_name]
        base_eps = base["events_per_second"]
        curr_eps = curr["events_per_second"]
        if base_eps == 0:
            print(f"Warning: Baseline events_per_second is 0 for {test_name}, skipping")
            continue
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
