"""V8 cache dependencies include original formal identities and returned loans."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import unittest

from hepta import hia_program as core
from hepta.hia_incremental import IncrementalVerifier
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch
from tests.test_hia_program import c, i, ret
from tests.test_hia_returned_loan_interfaces import choose_loan, migration
from tests.test_hia_returned_loans import loan_program, multiple_shared
from tests.test_hia_incremental import outcome


def early_release_other_owner():
    """A returns safely while B is released before A's returned child is read.

    Changing only the callee's valid returned origin to B makes the unchanged
    caller invalid. Reusing it under a type/effect-only cache would admit a
    child whose parent and owner are ended while that child is still live.
    """
    source = choose_loan()
    ops = source["functions"][0]["blocks"][0]["ops"]
    release = [op for op in ops if op["op"] in {"loan.end", "owner.drop"}
               and op["args"] in (["right_read"], ["right_owner"])]
    ops[:] = [op for op in ops if op not in release]
    call_at = next(n for n, op in enumerate(ops) if op["op"] == "call")
    ops[call_at + 1:call_at + 1] = release
    return source


class V8IncrementalInterfaces(unittest.TestCase):
    def test_returned_origin_edit_rechecks_unchanged_caller_and_changes_result(self):
        source = choose_loan()
        session = IncrementalVerifier(source)
        changed = deepcopy(source)
        changed["functions"][1] = migration(source)["edits"][0]["definition"]
        checked, report = session.verify(changed)
        self.assertEqual(report["mode"], "incremental")
        self.assertEqual(report["dependency_contract"], "closed-body-and-direct-callee-interface.v4")
        self.assertEqual(report["dependency_invalidations"], {"entrypoint": ["pick"]})
        self.assertEqual(report["functions_body_completed"], ["entrypoint", "pick"])
        self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)
        self.assertEqual(execute_program(source, "entrypoint", [])["result"], 17)
        result = execute_program(checked, "entrypoint", [])
        self.assertEqual(result["result"], 29)
        self.assertEqual(result["resources"]["live_owners"], 0)
        self.assertEqual(result["resources"]["live_local_loans"], 0)

    def test_returned_origin_cannot_reuse_caller_that_released_the_other_owner(self):
        source = early_release_other_owner()
        self.assertEqual(execute_program(source, "entrypoint", [])["result"], 17)
        session = IncrementalVerifier(source)
        baseline = session.base_sha256
        changed = deepcopy(source)
        changed["functions"][1] = migration(source)["edits"][0]["definition"]
        # The new callee is independently well formed; only its cached caller
        # becomes illegal. This is the counterexample to omitting return_loans.
        only_callee = {"schema": source["schema"], "module": "callee",
                       "functions": [changed["functions"][1]]}
        core.verify_program(only_callee)
        expected = outcome(core.verify_program, changed)
        self.assertEqual(expected[0:2], ("rejected", "E_HIA_LOAN"))
        self.assertEqual(outcome(session.verify, changed), expected)
        self.assertEqual(session.last_report["dependency_invalidations"], {"entrypoint": ["pick"]})
        self.assertEqual(session.last_report["functions_body_attempted"], ["entrypoint"])
        self.assertEqual(session.base_sha256, baseline)
        _, restored = session.verify(source)
        self.assertEqual(restored["functions_body_reused"], ["entrypoint", "pick"])
        self.assertEqual(restored["functions_body_completed"], [])

    def test_original_parameter_rename_invalidates_caller_even_with_same_position(self):
        source = choose_loan()
        session = IncrementalVerifier(source)
        changed = deepcopy(source)
        helper = changed["functions"][1]
        helper["params"][0]["name"] = "renamed_origin"
        helper["blocks"][0]["params"][0]["name"] = "renamed_origin"
        helper["blocks"][0]["term"] = ret("renamed_origin")
        helper["return_loans"] = ["renamed_origin"]
        checked, report = session.verify(changed)
        self.assertEqual(report["dependency_invalidations"], {"entrypoint": ["pick"]})
        self.assertEqual(report["functions_body_completed"], ["entrypoint", "pick"])
        self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)
        self.assertEqual(execute_program(checked, "entrypoint", [])["result"], 17)
        broken = deepcopy(changed)
        broken["functions"][1]["return_loans"] = ["left"]
        self.assertEqual(outcome(session.verify, broken), outcome(core.verify_program, broken))
        self.assertEqual(session.base_sha256, checked.sha256)

    def test_changed_caller_body_never_reuses_prior_permission_check(self):
        source = choose_loan()
        session = IncrementalVerifier(source)
        changed = deepcopy(source)
        ops = changed["functions"][0]["blocks"][0]["ops"]
        call_at = next(n for n, op in enumerate(ops) if op["op"] == "call")
        ops[call_at + 1] = i("loan.end", ["left_read"])
        expected = outcome(core.verify_program, changed)
        self.assertEqual(expected[0], "rejected")
        self.assertEqual(outcome(session.verify, changed), expected)
        self.assertEqual(session.last_report["functions_body_attempted"], ["entrypoint"])
        self.assertEqual(session.base_sha256, core.verify_program(source).sha256)

    def test_aliased_actuals_do_not_equate_different_original_formal_origins(self):
        source = multiple_shared("mixed")
        session = IncrementalVerifier(source)
        changed = deepcopy(source)
        changed["functions"][0]["return_loans"] = ["right", "left"]
        expected = outcome(core.verify_program, changed)
        self.assertEqual(expected[0:2], ("rejected", "E_HIA_LOAN"))
        self.assertEqual(outcome(session.verify, changed), expected)
        self.assertEqual(session.base_sha256, core.verify_program(source).sha256)

    def test_cfg_direct_child_and_recursive_origins_survive_body_refactor(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child", "cfg", "recursive"):
                with self.subTest(mode=mode, construction=construction):
                    source = loan_program(mode, construction)
                    session = IncrementalVerifier(source)
                    checked, report = session.verify(source)
                    self.assertEqual(report["functions_body_completed"], [])
                    self.assertEqual(len(report["functions_body_reused"]), 2)
                    result = execute_program(checked, source["exports"][0], [1, 37])
                    self.assertEqual(result["result"], 42 if mode == "mut" else 37)
                    self.assertEqual(result["resources"]["live_local_loans"], 0)
                    bad = deepcopy(source)
                    bad["functions"][0]["return_loans"] = ["invented"]
                    self.assertEqual(outcome(session.verify, bad), outcome(core.verify_program, bad))
                    self.assertEqual(session.base_sha256, checked.sha256)

    def test_interfaces_are_immutable_detached_and_include_every_loan_field(self):
        source = choose_loan()
        functions, _ = core._primitive_structure(source)
        interface = core._function_interfaces(functions)["pick"]
        self.assertEqual(interface.params, ("readbuf", "readbuf"))
        self.assertEqual(interface.param_names, ("left", "right"))
        self.assertEqual(interface.returns, ("readbuf",))
        self.assertEqual(interface.return_loans, ("left",))
        with self.assertRaises(FrozenInstanceError):
            interface.return_loans = ("right",)
        source["functions"][1]["params"][0]["name"] = "tampered"
        source["functions"][1]["return_loans"][0] = "right"
        self.assertEqual(interface.param_names, ("left", "right"))
        self.assertEqual(interface.return_loans, ("left",))

    def test_v8_preserve_policy_rejects_origin_migration_without_replacing_baseline(self):
        source = choose_loan()
        session = IncrementalVerifier(source)
        baseline = session.base_sha256
        for schema in ("hepta.hia.patch.v1", "hepta.hia.patch.v2"):
            request = migration(source, schema=schema, policy="preserve")
            with self.assertRaises(HIAEditRejected):
                session.apply_patch(request)
            with self.assertRaises(HIAEditRejected):
                apply_program_patch(source, request)
            self.assertEqual(session.base_sha256, baseline)
            self.assertEqual(session.last_report["status"], "rejected")
        request = migration(source)
        checked, receipt = session.apply_patch(request)
        ordinary, _ = apply_program_patch(source, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(receipt["interface_changes"], ["pick"])
        self.assertFalse(receipt["claims"]["interface_preserved"])
        self.assertEqual(receipt["verification"]["dependency_invalidations"], {"entrypoint": ["pick"]})

    def test_origin_and_cleanup_can_change_in_one_atomic_patch_only(self):
        source = early_release_other_owner()
        session = IncrementalVerifier(source)
        baseline = session.base_sha256
        request = migration(source)
        with self.assertRaises(core.HIAProgramRejected):
            session.apply_patch(request)
        self.assertEqual(session.base_sha256, baseline)
        request["edits"].append({"action": "replace_function", "function": "entrypoint",
                                 "definition": choose_loan()["functions"][0]})
        checked, receipt = session.apply_patch(request)
        ordinary, _ = apply_program_patch(source, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(receipt["edits"], 2)
        self.assertEqual(execute_program(checked, "entrypoint", [])["result"], 29)

    def test_unknown_schema_or_resource_export_never_uses_cached_bodies(self):
        source = choose_loan()
        for changed in (dict(source, schema="hepta.hia.program.v9"),
                        dict(source, exports=["entrypoint", "pick"])):
            session = IncrementalVerifier(source)
            expected = outcome(core.verify_program, changed)
            self.assertEqual(expected[0], "rejected")
            self.assertEqual(outcome(session.verify, changed), expected)
            self.assertEqual(session.last_report["functions_body_reused"], [])
            self.assertEqual(session.base_sha256, core.verify_program(source).sha256)


if __name__ == "__main__":
    unittest.main()
