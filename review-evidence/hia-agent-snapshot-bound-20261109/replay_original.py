"""Reproduce the retained accounting failure on the exact unmodified baseline."""
from pathlib import Path
import subprocess
import unittest

import tests.test_hia_repository_agent_trial as tests

BASE = "20eace37747fde9aa0fc9c14cdb0159db30f5161"
source = subprocess.check_output([
    "git", "show", BASE + ":tools/hia_repository_agent_trial.py"])
namespace = {"__file__": str(Path("tools/hia_repository_agent_trial.py").resolve()),
             "__name__": "original_snapshot_trial"}
exec(compile(source, namespace["__file__"], "exec"), namespace)
tests.snapshot_repository = namespace["snapshot_repository"]
suite = unittest.TestSuite([tests.OwnedProcessTests(
    "test_snapshot_counts_retained_bytes_instead_of_an_earlier_path_stat")])
result = unittest.TextTestRunner(verbosity=2).run(suite)
assert result.testsRun == 1 and len(result.failures) == 1
assert not result.errors and not result.skipped
print("Expected original failure retained: snapshot charged 1 byte for 9 retained bytes.")
