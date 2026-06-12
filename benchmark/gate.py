from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def evaluate_thresholds(metrics: dict[str, Any], thresholds: dict[str, Any]) -> list[str]:
    """Return benchmark threshold violations."""
    violations: list[str] = []
    for name, threshold in thresholds.items():
        if name == "baseline":
            continue
        if name.startswith("max_"):
            metric_name = name.removeprefix("max_")
            comparator = "maximum"
            expected_direction = -1
        elif name.startswith("min_"):
            metric_name = name.removeprefix("min_")
            comparator = "minimum"
            expected_direction = 1
        else:
            continue

        if metric_name not in metrics:
            violations.append(f"missing metric: {metric_name}")
            continue
        try:
            value = float(metrics[metric_name])
            threshold_value = float(threshold)
        except (TypeError, ValueError):
            violations.append(f"non-numeric threshold or metric: {name}")
            continue
        if (value - threshold_value) * expected_direction < 0:
            violations.append(
                f"{metric_name}={value:g} violates {comparator} {threshold_value:g}"
            )
    return violations


def load_yaml(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML object: {path}")
    return data


def load_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def thresholds_from_config(config: dict[str, Any]) -> dict[str, Any]:
    thresholds = config.get("thresholds", config)
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be an object")
    return thresholds


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail when benchmark metrics violate configured thresholds.")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--thresholds", required=True)
    args = parser.parse_args()

    violations = evaluate_thresholds(
        load_json(args.summary),
        thresholds_from_config(load_yaml(args.thresholds)),
    )
    if violations:
        for violation in violations:
            print(violation)
        raise SystemExit(1)
    print("benchmark thresholds passed")


if __name__ == "__main__":
    main()
