"""Entry outlining must preserve complete CFGs, traps, initialization and provenance."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_entry_layout import LAYOUT, entry_plan
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET_AARCH64, build_program_native,
    compile_program_llvm, emit_program_llvm,
)
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program

ROOT = Path(__file__).resolve().parents[1]


def trap_example(template):
    data = deepcopy(template)
    function = data["functions"][0]
    function["params"] = [{"name": "n", "type": "usize"}, {"name": "seed", "type": "u32"}]
    function["entry"] = "guard"
    function["blocks"] = [
        {"id": "guard", "params": deepcopy(function["params"]),
         "ops": [
             {"op": "const", "args": [], "out": [{"name": "bound", "type": "usize"}], "attrs": {"value": 7}},
             {"op": "compare.le", "args": ["n", "bound"], "out": [{"name": "choose", "type": "bool"}], "attrs": {}},
         ],
         "term": {"op": "branch", "cond": "choose",
                  "then": {"target": "fast", "args": ["n", "seed"]},
                  "else": {"target": "slow", "args": ["n", "seed"]}}},
        {"id": "fast", "params": [{"name": "fast_n", "type": "usize"}, {"name": "fast_seed", "type": "u32"}],
         "ops": [
             {"op": "const", "args": [], "out": [{"name": "one", "type": "u64"}], "attrs": {"value": 1}},
             {"op": "int.cast", "args": ["fast_n"], "out": [{"name": "denominator", "type": "u64"}], "attrs": {"mode": "wrap"}},
             {"op": "int.div.checked", "args": ["one", "denominator"], "out": [{"name": "quotient", "type": "u64"}], "attrs": {}},
         ], "term": {"op": "ret", "values": ["quotient"]}},
        {"id": "slow", "params": [{"name": "slow_n", "type": "usize"}, {"name": "slow_seed", "type": "u32"}],
         "ops": [{"op": "int.cast", "args": ["slow_seed"], "out": [{"name": "fallback", "type": "u64"}], "attrs": {"mode": "wrap"}}],
         "term": {"op": "ret", "values": ["fallback"]}},
    ]
    return verify_program(data)




if __name__ == "__main__":
    unittest.main()
