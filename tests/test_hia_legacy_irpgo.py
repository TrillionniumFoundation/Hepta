"""Reject fabricated profile activity and changes to the actual HIA build input.

Counter checks use emitted LLVM and retained-format profile text. Target
binding checks capture actual frontend attributes; the supervised failure
control executes one deliberately signalled child. No timing campaign or
model execution is performed.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm




class ActualEntryCounterTests(unittest.TestCase):



    pass




class SupervisedChildFailureTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
