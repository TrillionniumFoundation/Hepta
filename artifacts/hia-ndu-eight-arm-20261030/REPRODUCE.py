#!/usr/bin/env python3
"""Rerun the frozen eight-arm pilot with an admitted native identity and Clang."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "sources"
for name, expected in json.loads((HERE / "FROZEN_SOURCE_IDENTITY.json").read_bytes()).items():
    if sha256((SOURCE / name).read_bytes()).hexdigest() != expected:
        raise SystemExit("frozen source mismatch: " + name)
sys.path.insert(0, str(SOURCE))

from tools.qualify_hia_ndu_graph import qualify

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--identity", type=Path, required=True)
parser.add_argument("--clang", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
protocol = json.loads((HERE / "PROTOCOL.json").read_bytes())
result = qualify(args.output, identity=args.identity, clang=args.clang, protocol=protocol)
print(json.dumps({key: result[key] for key in (
    "all_episodes_completed", "all_outputs_correct", "all_actual_budgets_passed",
    "actual_transitions", "median_episode_cost_ns", "standalone_total_cost_ns")}, indent=2))
