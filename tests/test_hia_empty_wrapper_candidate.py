"""Experimental wrapper changes preserve complete Core calls and ABI admission."""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (compile_program_llvm, emit_program_llvm,
                                    HIAProgramLLVMRejected)
from tools.hia_empty_wrapper_candidate import emit_candidate
