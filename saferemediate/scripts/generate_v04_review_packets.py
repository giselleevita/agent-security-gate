"""Generate blinded review packets and an empty dual-label worksheet."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from saferemediate.analysis.review_v04 import PRIMARY_DIMENSIONS, build_blinded_packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--packets", type=Path, required=True)
    parser.add_argument("--worksheet", type=Path, required=True)
    args = parser.parse_args()
    traces = [json.loads(line) for line in args.checkpoint.read_text().splitlines() if line]
    packets = [build_blinded_packet(trace) for trace in traces]
    args.packets.parent.mkdir(parents=True, exist_ok=True)
    args.packets.write_text(
        "\n".join(json.dumps(packet, sort_keys=True) for packet in packets) + "\n",
        encoding="utf-8",
    )
    args.worksheet.parent.mkdir(parents=True, exist_ok=True)
    with args.worksheet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("packet_id", "dimension", "reviewer_id", "label", "rationale"),
        )
        writer.writeheader()
        for packet in packets:
            for dimension in PRIMARY_DIMENSIONS:
                writer.writerow(
                    {
                        "packet_id": packet["packet_id"],
                        "dimension": dimension,
                        "reviewer_id": "",
                        "label": "",
                        "rationale": "",
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
