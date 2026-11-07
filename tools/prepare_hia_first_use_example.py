"""Write a reproducible synthetic first-use task; it is not an unseen real task."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from tools.hia_agent_native_qualification import add_program, exhaustive_u8_workload


def example_task():
    return {"id": "wrapping_u8_public_example_v1",
            "instruction": "Reduce the shared native image for transform(x) while preserving its u8 ABI and (x + 23) modulo 256 behavior for every u8 input. Verify and evaluate the candidate, then adopt only a strictly smaller compatible artifact.",
            "source": add_program(increment=23, redundant_additions=128, module="first_use_public_example"),
            "workload": exhaustive_u8_workload(23),
            "provenance": {"kind": "synthetic_public_example", "real_maintenance_request": False,
                           "unseen_task_attested": False,
                           "purpose": "replayable harness entry example; never counts as fresh-model first-use acceptance"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.resolve().is_relative_to(ROOT):
        parser.error("write task examples outside the source tree")
    raw = (json.dumps(example_task(), sort_keys=True, indent=2) + "\n").encode()
    with output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"path": str(output), "sha256": sha256(raw).hexdigest(),
                      "kind": "synthetic_public_example", "p1_acceptance": "HOLD"}, sort_keys=True))


if __name__ == "__main__":
    main()
