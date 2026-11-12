"""Core-only source release descriptor; not production/native closure approval."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,""}: sys.path.insert(0,str(ROOT))
from tools.hia_selfhost_contract import SOURCE_FILES, CONTRACT_PATH, validate_contract
BOOTSTRAP_FILES=(*SOURCE_FILES,CONTRACT_PATH)

def describe():
    contract=validate_contract()
    return {"schema":"hepta.hia.core-only-release.v1", "profile":contract["profile"],
            "source_identity":contract["source_identity"], "entry":"hia",
            "native_stdio_commands":["capabilities","verify","compile","render-assembly","assemble","check-assembly"],
            "high_level_source_language":"removed", "host_build_requires_python":True,
            "agent_editing_and_persistence_native":False,
            "whole_native_delivery_qualified":False,"production_activated":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["describe","check"])
    parser.parse_args()
    print(json.dumps(describe(),sort_keys=True,indent=2))

if __name__=="__main__": main()
