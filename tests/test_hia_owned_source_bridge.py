"""Rust-gated owned source -> verified Resource IR/Core -> sole native LLVM path."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm


SOURCE = '''module owned_hia;
export "C" fn drop_case() -> u64 effects {alloc,block,panic} {
    let bytes = buffer(4);
    drop(move bytes);
    return 7;
}'''
PROJECT = "f" * 64




class SourceBoundOwnedHIATests(unittest.TestCase):




    pass


if __name__ == "__main__":
    unittest.main()
