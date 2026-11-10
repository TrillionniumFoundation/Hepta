"""Qualification summaries must preserve failures and reject incomplete runs."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected


SELECTED_TOOLS = dict(clang="/tools/clang", cc="/tools/gcc", rustc="/tools/rustc", cargo="/tools/cargo",
                      qemu_aarch64="/tools/qemu-aarch64", qemu_riscv64="/tools/qemu-riscv64",
                      qemu_system_arm="/tools/qemu-system-arm", linker="/tools/ld.lld",
                      lean="/tools/lean", cxx="/tools/g++")


class UnifiedQualificationSummaryTests(unittest.TestCase):






    pass


class UnifiedQualificationWorkflowTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
