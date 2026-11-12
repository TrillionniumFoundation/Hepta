"""The integrated proof engines share Core, but never exchange proof authority."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from hepta.hia_optimization import verify_optimization
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, f, jump, m, resource_program, ret
from tests.test_hia_translation_validation import identity


class IntegratedProofProfileTests(unittest.TestCase):
    def test_changed_acyclic_cfg_is_only_proved_by_the_complete_function_profile(self):
        before = identity("u32")
        name = before["functions"][0]["name"]
        after = m(f(name, [("a", "u32"), ("z", "u32")], ["u32"], ["trap"], [
            b("entry", [("a", "u32"), ("z", "u32")], [], jump("result", "a")),
            b("result", [("answer", "u32")], [], ret("answer")),
        ]))
        # Preserve module identity as required by the selected-function proof.
        after["module"] = before["module"]
        complete = validate_translation(before, after, function=name)
        segmented = verify_optimization(before, after)
        self.assertEqual(complete["status"], "proved", complete)
        self.assertNotEqual(segmented["status"], "verified", segmented)

    def test_unchanged_resource_skeleton_is_not_a_scalar_function_proof(self):
        program = resource_program()
        segmented = verify_optimization(program, program)
        complete = validate_translation(program, program, function="owned")
        self.assertEqual(segmented["status"], "verified", segmented)
        self.assertEqual(complete["status"], "unknown", complete)
        # A versioned successful receipt is still not a candidate Core program.
        scalar = identity("u32")
        self.assertNotEqual(validate_translation(scalar, segmented)["status"], "proved")
        scalar_receipt = validate_translation(scalar, scalar)
        self.assertEqual(scalar_receipt["status"], "proved")
        self.assertNotEqual(verify_optimization(program, scalar_receipt)["status"], "verified")

    def test_both_engines_run_concurrently_with_the_same_pinned_solver(self):
        # Isolate the native solver process so a concurrency failure is a
        # recorded failing test rather than loss of the full collector's log.
        code = '''
import json
from concurrent.futures import ThreadPoolExecutor
import z3
from hepta.hia_optimization import PINNED_Z3_VERSION, verify_optimization
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import resource_program
from tests.test_hia_translation_validation import identity
assert z3.get_version_string() == PINNED_Z3_VERSION == "4.15.4"
def check(index):
    if index % 2:
        p = identity("u64")
        return validate_translation(p, p)["status"] == "proved"
    p = resource_program()
    return verify_optimization(p, p)["status"] == "verified"
with ThreadPoolExecutor(max_workers=4) as pool:
    outcomes = list(pool.map(check, range(24)))
print(json.dumps({"checked": len(outcomes), "all_proved_in_declared_profiles": all(outcomes)}))
'''
        process = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                 text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["checked"], 24)
        self.assertTrue(report["all_proved_in_declared_profiles"])


if __name__ == "__main__":
    unittest.main()
