"""Source-bound HIA scalar Core v0: canonical producer and native consumer gate.

Only scalar SSA (no owned codegen) is admitted. These are positive and
adversarial identity tests, not whole-language/backend soundness proofs.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


_SOURCE = '''module hia_scalar;
export "C" fn bump(n: i32) -> i32 effects {panic} {
    let mut x: i32 = 0;
    while x < n { x = x + 1; }
    return x;
}
'''
_PROJECT = "d" * 64






class HIAScalarCoreTests(unittest.TestCase):




    pass


if __name__ == "__main__":
    unittest.main()
