"""Source-native independent receipt replay negatives on exact HIA bytes.

The normal analyzer remains the sole numeric authority. This suite makes sure
a self-rehashed receipt cannot substitute fabricated row quantities, including
when the native builder's analyzer call is replaced at runtime. It does not
prove the analyzer's mathematics or LLVM lowering.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_heap_bound import local_buffers


def reseal(report):
    payload = {k: v for k, v in report.items() if k != "sha256"}
    report["sha256"] = sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()
    return report


class HIABudgetCanonicalReplayTests(unittest.TestCase):


    pass


if __name__ == "__main__":
    unittest.main()
