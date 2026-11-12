"""v7 recursive owners: actual dynamic lengths, ownership negatives and native ABI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2, SCHEMA_V6,
                              SCHEMA_V7, SCHEMA_V8, composite_core_schema, profile_for_schema,
                              schema_registry, supports_feature)
from tests.test_hia_program import b, c, f, i, ret




def function(document, name):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def block(fn, name):
    return next(item for item in fn["blocks"] if item["id"] == name)


def one_function(operations, returns=()):
    return {"schema": SCHEMA_V7, "module": "chain_negative", "functions": [
        f("entrypoint", [], list(returns), ["alloc", "read", "write", "trap"],
          [b("entry", [], operations, ret())])]}






if __name__ == "__main__":
    unittest.main()
