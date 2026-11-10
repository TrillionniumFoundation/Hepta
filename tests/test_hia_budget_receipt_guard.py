"""Fail-closed source-facing static-budget receipt and native admission tests.

These tests check identities and proof-scope claims. They do not independently
prove the analyzer's arithmetic bound or native backend refinement.
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
from tests.test_hia_heap_bound import local_buffers, scalar_call


def reseal(receipt):
    value = {k: v for k, v in receipt.items() if k != "sha256"}
    receipt["sha256"] = sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return receipt


class HIAStaticBudgetReceiptTests(unittest.TestCase):




    pass


if __name__ == "__main__":
    unittest.main()
