#!/usr/bin/env python3
"""Run the committed two-attempt reduction mechanism experiment exactly once."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[2]

if __name__ == "__main__":
    shared = runpy.run_path(str(ROOT / "experiments/hia_ndu_native_20261027/run_frozen.py"),
                           run_name="hia_frozen_shared")
    raise SystemExit(shared["main"](protocol_path=Path(__file__).with_name("protocol.json")))
