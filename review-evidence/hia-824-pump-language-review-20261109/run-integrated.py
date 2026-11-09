"""Run the same twelve reviewed modules once with unique IDs and no skips."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
modules = (
    "test_hia_release", "test_hia_ndu_prepared_ranker",
    "test_hia_ndu_prepared_cost_intervals", "test_hia_ndu_persistent_ranker",
    "test_hia_ndu_persistent_cost_intervals", "test_hia_scalar_controller_controls",
    "test_hia_repository_agent_trial", "test_hia_agent_native_tools",
    "test_hia_agent_native_proof_contract", "test_hia_agent_native_machine_validation",
    "test_hia_safe_core", "test_hia_safe_core_artifact",
)
print("TESTED_COMMIT", subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), flush=True)
print("TESTED_TREE", subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(), flush=True)
from hepta.hia_ndu_optimizer import _bridge_identity
_, identity = _bridge_identity({"binary": os.environ["HEPTA_NDU_BRIDGE"],
    "build_receipt": str(Path(os.environ["HEPTA_NDU_BUILD"]) / "build-receipt.json")})
print("ORIGINAL_CI_NATIVE_IDENTITY", json.dumps(identity, sort_keys=True), flush=True)
suite = unittest.defaultTestLoader.loadTestsFromNames(["tests." + name for name in modules])
def identities(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from identities(item)
        else:
            yield item.id()
ids = list(identities(suite))
if len(ids) != len(set(ids)):
    raise SystemExit("duplicate test identities")
print("UNIQUE_TESTS", len(ids), flush=True)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() and result.testsRun == len(ids)
                 and not result.skipped and not result.expectedFailures else 1)
