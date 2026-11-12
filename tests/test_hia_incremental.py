"""Incremental admission must agree with the ordinary full checker."""
import copy
import json
import pickle
import threading
import unittest
from unittest import mock

from hepta import hia_program as core
from hepta import hia_schema as registry
from hepta.hia_incremental import HIAIncrementalRejected, IncrementalVerifier
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch
from tests.test_hia_edit_batch import loans
from tests.test_hia_program import b, c, f, i, ret


def graph(version=6, extras=0):
    def leaf(name):
        return f(name, [("x", "u32")], ["u32"], [], [b("entry", [("x", "u32")], [
            c("one", "u32", 1), i("int.add.wrap", ["x", "one"], [("v", "u32")])], ret("v"))])

    def caller(name, callee):
        return f(name, [("x", "u32")], ["u32"], [], [b("entry", [("x", "u32")], [
            i("call", ["x"], [("v", "u32")], function=callee)], ret("v"))])

    return {"schema": f"hepta.hia.program.v{version}", "module": "incremental",
            "exports": ["outer"], "functions": [leaf("leaf"), caller("middle", "leaf"),
                caller("outer", "middle"), leaf("separate"),
                *(leaf(f"independent_{n}") for n in range(extras))]}


def outcome(check, value):
    try:
        result = check(value)
        if type(result) is tuple:
            result = result[0]
        return ("accepted", result.canonical_bytes, result.structured_bytes)
    except core.HIAProgramRejected as exc:
        return ("rejected", exc.code, str(exc))


class HIAIncrementalTests(unittest.TestCase):
    def test_constructor_never_trusts_fabricated_verified_program_or_receipt(self):
        bad = loans()
        bad["functions"][0]["blocks"][0]["ops"].pop()
        forged = core.VerifiedProgram(json.dumps(bad).encode())
        with self.assertRaises(core.HIAProgramRejected):
            IncrementalVerifier(forged)
        with self.assertRaises(core.HIAProgramRejected):
            IncrementalVerifier({"schema": "hepta.hia.incremental-verification.v1",
                                 "before_sha256": "0" * 64, "ok": True})

    def test_unchanged_input_rechecks_all_shapes_and_reuses_exact_bodies(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        checked, report = session.verify(json.dumps(doc))
        self.assertEqual(checked.canonical_bytes, core.verify_program(doc).canonical_bytes)
        self.assertEqual(report["mode"], "incremental")
        self.assertTrue(report["global_structure_checked"])
        self.assertEqual(report["function_shapes_checked"], 4)
        self.assertEqual(report["operation_shapes_checked"], 6)
        self.assertEqual(report["functions_body_completed"], [])
        self.assertEqual(report["functions_body_reused"], ["leaf", "middle", "outer", "separate"])
        self.assertEqual(report["operations_in_completed_bodies"], 0)
        self.assertFalse(report["claims"]["behavior_equivalence_proved"])

    def test_one_body_edit_checks_one_function_not_transitive_behavioral_callers(self):
        doc = graph(extras=32)
        observed = []
        original = core._verify_function

        def observe(schema, fn, blocks, interfaces):
            observed.append(fn["name"])
            return original(schema, fn, blocks, interfaces)

        # Instrument before constructing the session so the same checked
        # implementation is used for the initial and incremental attempts.
        with mock.patch.object(core, "_verify_function", observe):
            session = IncrementalVerifier(doc)
            self.assertEqual(len(observed), 36)
            observed.clear()
            changed = copy.deepcopy(doc)
            changed["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 7
            checked, report = session.verify(changed)
            self.assertEqual(observed, ["leaf"])
            self.assertEqual(report["functions_body_completed"], ["leaf"])
            self.assertEqual(len(report["functions_body_reused"]), 35)
            self.assertEqual(report["function_shapes_checked"], 36)
            self.assertEqual(report["operation_shapes_checked"], 70)
            self.assertEqual(report["operations_in_completed_bodies"], 2)
            self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)
        # Changed behavior propagates to a cached caller, demonstrating why
        # the receipt does not claim behavior-equivalent functions or tests.
        self.assertEqual(execute_program(checked, "outer", [5])["result"], 12)
        self.assertEqual(execute_program(doc, "outer", [5])["result"], 6)

    def test_changed_callee_effect_invalidates_unchanged_direct_caller(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        bad = copy.deepcopy(doc)
        bad["functions"][0]["effects"] = ["write"]
        self.assertEqual(outcome(session.verify, bad), outcome(core.verify_program, bad))
        self.assertEqual(session.base_sha256, core.verify_program(doc).sha256)
        report = session.last_report
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["dependency_invalidations"], {"middle": ["leaf"]})
        self.assertEqual(report["functions_body_completed"], ["leaf"])
        self.assertEqual(report["functions_body_attempted"], ["leaf", "middle"])
        for fn in bad["functions"][:3]:
            fn["effects"] = ["write"]
        checked, report = session.verify(bad)
        self.assertEqual(checked.canonical_bytes, core.verify_program(bad).canonical_bytes)
        self.assertEqual(report["functions_body_completed"], ["leaf", "middle", "outer"])
        self.assertEqual(report["functions_body_reused"], ["separate"])

    def test_changed_return_interface_and_removed_callee_reject_like_full(self):
        doc = graph()
        cases = []
        changed = copy.deepcopy(doc)
        leaf = changed["functions"][0]
        leaf["returns"] = ["bool"]
        leaf["blocks"][0]["ops"] = [c("yes", "bool", True)]
        leaf["blocks"][0]["term"] = ret("yes")
        cases.append(changed)
        removed = copy.deepcopy(doc)
        removed["functions"].pop(0)
        cases.append(removed)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                session = IncrementalVerifier(doc)
                expected = outcome(core.verify_program, candidate)
                self.assertEqual(expected[0], "rejected")
                self.assertEqual(outcome(session.verify, candidate), expected)
                self.assertEqual(session.last_report["dependency_invalidations"], {"middle": ["leaf"]})

    def test_add_remove_and_reorder_independent_functions(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        changed = copy.deepcopy(doc)
        addition = copy.deepcopy(changed["functions"][-1])
        addition["name"] = "new_leaf"
        changed["functions"].append(addition)
        checked, report = session.verify(changed)
        self.assertEqual(report["functions_body_completed"], ["new_leaf"])
        self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)
        changed["functions"].pop(3)
        changed["functions"].reverse()
        checked, report = session.verify(changed)
        self.assertEqual(report["functions_body_completed"], [])
        self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)

    def test_mutually_recursive_body_checks_do_not_require_invented_fixpoint(self):
        doc = graph()
        doc["functions"][0]["blocks"][0]["ops"] = [
            i("call", ["x"], [("v", "u32")], function="middle")]
        session = IncrementalVerifier(doc)
        candidate = copy.deepcopy(doc)
        candidate["functions"][0]["blocks"][0]["ops"].insert(0, c("unused", "u8", 7))
        checked, report = session.verify(candidate)
        self.assertEqual(report["functions_body_completed"], ["leaf"])
        self.assertEqual(checked.canonical_bytes, core.verify_program(candidate).canonical_bytes)

    def test_schema_module_and_exports_changes_fall_back_to_full(self):
        doc = graph()
        for field, value in (("schema", "hepta.hia.program.v7"),
                             ("module", "renamed"), ("exports", ["leaf", "outer"])):
            with self.subTest(field=field):
                session = IncrementalVerifier(doc)
                changed = copy.deepcopy(doc)
                changed[field] = value
                checked, report = session.verify(changed)
                self.assertEqual(report["mode"], "full")
                self.assertEqual(report["fallback_reason"], "module_envelope_changed")
                self.assertEqual(len(report["functions_body_completed"]), 4)
                self.assertEqual(checked.canonical_bytes, core.verify_program(changed).canonical_bytes)

    def test_global_shape_and_export_errors_reject_before_body_reuse(self):
        doc = graph()
        duplicate = copy.deepcopy(doc)
        duplicate["functions"].append(copy.deepcopy(duplicate["functions"][0]))
        malformed = copy.deepcopy(doc)
        malformed["functions"][0]["blocks"][0]["ops"][1]["out"][0]["name"] = "one"
        export = copy.deepcopy(doc)
        export["exports"] = ["missing"]
        for candidate in (duplicate, malformed, export):
            with self.subTest(candidate=candidate):
                session = IncrementalVerifier(doc)
                expected = outcome(core.verify_program, candidate)
                self.assertEqual(expected[0], "rejected")
                self.assertEqual(outcome(session.verify, candidate), expected)
                self.assertEqual(session.last_report["functions_body_reused"], [])

    def test_resource_failures_leave_baseline_unchanged_and_next_edit_works(self):
        doc = loans()
        session = IncrementalVerifier(doc)
        baseline = session.base_sha256
        for change in ("leak", "alias", "parent"):
            bad = copy.deepcopy(doc)
            ops = bad["functions"][0]["blocks"][0]["ops"]
            if change == "leak":
                ops.pop()
            elif change == "alias":
                ops[4]["args"] = ["a"]
            else:
                ops[7] = i("owner.drop", ["a"])
            with self.subTest(change=change):
                self.assertEqual(outcome(session.verify, bad), outcome(core.verify_program, bad))
                self.assertEqual(session.last_report["status"], "rejected")
                self.assertEqual(session.base_sha256, baseline)
        good = copy.deepcopy(doc)
        good["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 9
        checked, report = session.verify(good)
        self.assertEqual(report["status"], "verified_unpublished")
        self.assertEqual(execute_program(checked, "work", [])["result"], 0)

    def test_nominal_input_and_its_binding_always_receive_full_verification(self):
        from tests.test_hia_program_composite import stored_loan_program
        nominal = stored_loan_program()
        session = IncrementalVerifier(nominal)
        checked, report = session.verify(nominal)
        self.assertEqual(report["mode"], "full")
        self.assertEqual(report["fallback_reason"], "schema_outside_incremental_contract")
        bound, report = session.verify(checked)
        self.assertEqual(report["fallback_reason"], "structured_candidate")
        self.assertEqual(bound.structured_bytes, core.verify_program(nominal).structured_bytes)
        fake = core.VerifiedProgram(core.verify_program(graph()).canonical_bytes,
                                    checked.structured_bytes)
        self.assertEqual(outcome(session.verify, fake), outcome(core.verify_program, fake))
        self.assertEqual(session.last_report["status"], "rejected")

    def test_unregistered_copied_serialized_and_subclassed_sessions_fail_closed(self):
        empty = object.__new__(IncrementalVerifier)
        with self.assertRaises(HIAIncrementalRejected):
            empty.verify(graph())
        class Other(IncrementalVerifier):
            pass
        with self.assertRaises(HIAIncrementalRejected):
            Other(graph())
        session = IncrementalVerifier(graph())
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation), self.assertRaises(TypeError):
                operation(session)
        with self.assertRaises(HIAIncrementalRejected):
            session.__init__(graph())
        session.close()
        with self.assertRaises(HIAIncrementalRejected):
            session.verify(graph())

    def test_mutating_inputs_and_receipts_never_changes_retained_baseline(self):
        doc = graph()
        pristine = copy.deepcopy(doc)
        session = IncrementalVerifier(doc)
        doc["functions"].clear()
        _, report = session.verify(pristine)
        report["functions_body_reused"].clear()
        observed = session.last_report
        observed["claims"]["caller_digest_grants_admission"] = True
        self.assertEqual(len(session.last_report["functions_body_reused"]), 4)
        self.assertFalse(session.last_report["claims"]["caller_digest_grants_admission"])
        self.assertEqual(session.base_sha256, core.verify_program(pristine).sha256)

    def test_registry_policy_change_invalidates_live_cache(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        registry_before = registry.schema_registry
        def changed_registry():
            result = registry_before()
            result["review_epoch"] = "changed"
            return result
        with mock.patch.object(registry, "schema_registry", changed_registry):
            checked, report = session.verify(doc)
            self.assertEqual(report["mode"], "full")
            self.assertEqual(report["fallback_reason"], "verifier_or_registry_changed")
            self.assertEqual(checked.canonical_bytes, core.verify_program(doc).canonical_bytes)

    def test_changed_checker_rule_cannot_reuse_an_old_pass(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        def reject_new_policy(checker):
            raise core.HIAProgramRejected("new checker rule", "E_HIA_POLICY_CONTROL")
        with mock.patch.object(core._BlockCheck, "finish", reject_new_policy):
            self.assertEqual(outcome(session.verify, doc), outcome(core.verify_program, doc))
        report = session.last_report
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["mode"], "full")
        self.assertIsNone(report["functions_body_completed"])
        self.assertEqual(report["functions_body_reused"], [])

    def test_imported_feature_helper_code_change_cannot_reuse_an_old_pass(self):
        # Opcode availability now belongs to the catalog. Recursive type
        # grammar still uses this imported feature helper and must invalidate.
        doc = {"schema": "hepta.hia.program.v7", "module": "feature_policy",
               "exports": [], "functions": [f("chain", [], [], ["alloc"], [
                   b("entry", [], [i("chain.empty", [], [("owner", "chain")]),
                       i("owner.drop", ["owner"])], ret())])]}
        session = IncrementalVerifier(doc)
        original_digest = session.base_sha256
        helper = core.supports_feature
        previous_code = helper.__code__
        def deny_features(schema, feature):
            return False
        try:
            helper.__code__ = deny_features.__code__
            self.assertIs(core.supports_feature, helper)
            full = outcome(core.verify_program, doc)
            self.assertEqual(full[0:2], ("rejected", "E_HIA_TYPE"))
            self.assertEqual(outcome(session.verify, doc), full)
            self.assertEqual(session.base_sha256, original_digest)
            self.assertEqual(session.last_report["mode"], "full")
            self.assertEqual(session.last_report["functions_body_reused"], [])
        finally:
            helper.__code__ = previous_code
        self.assertEqual(core.verify_program(doc).sha256, original_digest)

    def test_mid_check_policy_change_triggers_complete_same_bytes_fallback(self):
        doc = graph()
        original = core._verify_function
        old_limit = core.MAX_NODES
        mutate = [False]
        def change_during_check(schema, fn, blocks, interfaces):
            original(schema, fn, blocks, interfaces)
            if mutate[0]:
                mutate[0] = False
                core.MAX_NODES -= 1
        try:
            with mock.patch.object(core, "_verify_function", change_during_check):
                session = IncrementalVerifier(doc)
                candidate = copy.deepcopy(doc)
                candidate["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 3
                mutate[0] = True
                checked, report = session.verify(candidate)
                self.assertEqual(report["fallback_reason"], "verifier_or_registry_changed_during_check")
                self.assertEqual(len(report["functions_body_completed"]), 4)
                self.assertEqual(report["functions_body_reused"], [])
                self.assertEqual(checked.canonical_bytes, core.verify_program(candidate).canonical_bytes)
        finally:
            core.MAX_NODES = old_limit

    def test_strict_json_and_legacy_collision_keep_exact_full_diagnostics(self):
        doc = graph()
        cases = [b'{"schema":1,"schema":2}', b'\xff', [], None,
                 {**doc, "proof": "trust me"}, {**doc, "schema": "hepta.hia.program.v999"},
                 {**doc, "schema": "hepta.hia.program.v2", "types": []}]
        for candidate in cases:
            with self.subTest(candidate=candidate):
                session = IncrementalVerifier(doc)
                self.assertEqual(outcome(session.verify, candidate), outcome(core.verify_program, candidate))
                self.assertEqual(session.last_report["status"], "rejected")

    def test_finite_mutation_matrix_agrees_in_all_seven_primitive_versions(self):
        for version in range(1, 9):
            doc = graph(version)
            mutations = []
            for value in (0, 7, 2**32-1, -1, 2**32, True):
                candidate = copy.deepcopy(doc)
                candidate["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = value
                mutations.append(candidate)
            for value in ([], ["write"], ["trap"], ["write", "write"], ["invented"]):
                candidate = copy.deepcopy(doc)
                candidate["functions"][0]["effects"] = value
                mutations.append(candidate)
            for target in ("leaf", "separate", "missing"):
                candidate = copy.deepcopy(doc)
                candidate["functions"][1]["blocks"][0]["ops"][0]["attrs"]["function"] = target
                mutations.append(candidate)
            for index, candidate in enumerate(mutations):
                with self.subTest(version=version, mutation=index):
                    session = IncrementalVerifier(doc)
                    self.assertEqual(outcome(session.verify, candidate), outcome(core.verify_program, candidate))

    def test_session_serializes_concurrent_attempts_without_mixing_cache_states(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        initial = session.base_sha256
        barrier = threading.Barrier(3)
        results, errors = [], []
        def worker(value):
            candidate = copy.deepcopy(doc)
            candidate["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = value
            try:
                barrier.wait(timeout=5)
                checked, report = session.verify(candidate)
                self.assertEqual(checked.canonical_bytes, core.verify_program(candidate).canonical_bytes)
                results.append(report)
            except BaseException as exc:
                errors.append(exc)
        threads = [threading.Thread(target=worker, args=(value,)) for value in (5, 9)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        first = next(r for r in results if r["before_sha256"] == initial)
        second = next(r for r in results if r["before_sha256"] == first["after_sha256"])
        self.assertEqual(session.base_sha256, second["after_sha256"])


class HIAIncrementalPatchTests(unittest.TestCase):
    def request(self, doc, value=7):
        changed = copy.deepcopy(doc["functions"][0]["blocks"][0]["ops"][0])
        changed["attrs"]["value"] = value
        return {"schema": "hepta.hia.patch.v1", "expected_sha256": core.verify_program(doc).sha256,
                "edits": [{"action": "replace_operation", "function": "leaf", "block": "entry",
                           "index": 0, "operation": changed}]}

    def test_atomic_patch_uses_same_grammar_and_distinct_truthful_receipt(self):
        doc = graph()
        request = self.request(doc)
        session = IncrementalVerifier(doc)
        checked, receipt = session.apply_patch(request)
        ordinary, old_receipt = apply_program_patch(doc, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(receipt["schema"], "hepta.hia.incremental-patch-result.v1")
        self.assertEqual(receipt["verification"]["functions_body_completed"], ["leaf"])
        self.assertFalse(receipt["claims"]["all_candidate_bodies_rechecked"])
        self.assertTrue(old_receipt["claims"]["whole_module_rechecked"])
        self.assertTrue(receipt["claims"]["entire_candidate_admitted"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(session.base_sha256, checked.sha256)

    def test_stale_or_malformed_patch_preserves_the_current_session(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        request = self.request(doc)
        checked, _ = session.apply_patch(request)
        for candidate in (request, {"schema": "fake"}, '{"edits":[],"edits":[]}'):
            with self.subTest(candidate=candidate), self.assertRaises(HIAEditRejected):
                session.apply_patch(candidate)
            self.assertEqual(session.base_sha256, checked.sha256)
            self.assertEqual(session.last_report["status"], "rejected")

    def test_forbidden_interface_change_rolls_back_after_candidate_passes(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        request = {"schema": "hepta.hia.patch.v1", "expected_sha256": session.base_sha256,
                   "edits": []}
        for fn in copy.deepcopy(doc["functions"][:3]):
            fn["effects"] = ["write"]
            request["edits"].append({"action": "replace_function", "function": fn["name"],
                                     "definition": fn})
        with self.assertRaisesRegex(HIAEditRejected, "interface change"):
            session.apply_patch(request)
        self.assertEqual(session.base_sha256, core.verify_program(doc).sha256)
        self.assertEqual(session.last_report["status"], "rejected")
        self.assertEqual(session.last_report["functions_body_completed"], ["leaf", "middle", "outer"])
        request.update(schema="hepta.hia.patch.v2", interface_policy="migrate")
        checked, receipt = session.apply_patch(request)
        ordinary, _ = apply_program_patch(doc, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(receipt["interface_changes"], ["leaf", "middle", "outer"])
        self.assertFalse(receipt["claims"]["interface_preserved"])

    def test_atomic_resource_patch_rejects_intermediates_but_accepts_joint_edit(self):
        doc = loans()
        original = core.verify_program(doc)
        edits = []
        for index, owner in ((3, "z"), (4, "a")):
            operation = copy.deepcopy(doc["functions"][0]["blocks"][0]["ops"][index])
            operation["args"] = [owner]
            edits.append({"action": "replace_operation", "function": "work", "block": "entry",
                          "index": index, "operation": operation})
        for edit in edits:
            session = IncrementalVerifier(doc)
            with self.assertRaises(core.HIAProgramRejected):
                session.apply_patch({"schema": "hepta.hia.patch.v1", "expected_sha256": original.sha256,
                                     "edits": [edit]})
            self.assertEqual(session.base_sha256, original.sha256)
        request = {"schema": "hepta.hia.patch.v1", "expected_sha256": original.sha256, "edits": edits}
        session = IncrementalVerifier(doc)
        checked, receipt = session.apply_patch(request)
        ordinary, _ = apply_program_patch(doc, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(receipt["edits"], 2)
        self.assertEqual(execute_program(checked, "work", [])["result"], 0)

    def test_patch_resource_failure_cannot_replace_the_saved_snapshot(self):
        doc = loans()
        session = IncrementalVerifier(doc)
        request = {"schema": "hepta.hia.patch.v1", "expected_sha256": session.base_sha256,
                   "edits": [{"action": "replace_operation", "function": "work", "block": "entry",
                              "index": 10, "operation": c("unused", "u8", 0)}]}
        with self.assertRaises(core.HIAProgramRejected) as incremental_error:
            session.apply_patch(request)
        with self.assertRaises(core.HIAProgramRejected) as full_error:
            apply_program_patch(doc, request)
        self.assertEqual(str(incremental_error.exception), str(full_error.exception))
        self.assertEqual(session.base_sha256, core.verify_program(doc).sha256)
        request["edits"][0].update(index=0, operation=c("size", "usize", 3))
        repaired, receipt = session.apply_patch(request)
        self.assertEqual(receipt["status"], "verified_unpublished")
        self.assertEqual(execute_program(repaired, "work", [])["result"], 0)

    def test_patch_interface_edit_rechecks_only_the_direct_unchanged_dependency(self):
        doc = graph()
        for fn in doc["functions"][1:3]:
            fn["effects"] = ["write"]
        session = IncrementalVerifier(doc)
        definition = copy.deepcopy(doc["functions"][0])
        definition["effects"] = ["write"]
        request = {"schema": "hepta.hia.patch.v2", "interface_policy": "migrate",
                   "expected_sha256": session.base_sha256,
                   "edits": [{"action": "replace_function", "function": "leaf",
                              "definition": definition}]}
        checked, receipt = session.apply_patch(request)
        ordinary, _ = apply_program_patch(doc, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        report = receipt["verification"]
        self.assertEqual(report["functions_body_completed"], ["leaf", "middle"])
        self.assertEqual(report["dependency_invalidations"], {"middle": ["leaf"]})
        self.assertEqual(report["functions_body_reused"], ["outer", "separate"])

    def test_concurrent_patches_to_one_base_admit_exactly_one_and_reject_stale_other(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        requests = [self.request(doc, value) for value in (5, 9)]
        barrier = threading.Barrier(3)
        results, failures = [], []
        def worker(request):
            try:
                barrier.wait(timeout=5)
                results.append(session.apply_patch(request))
            except BaseException as exc:
                failures.append(exc)
        threads = [threading.Thread(target=worker, args=(request,)) for request in requests]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], HIAEditRejected)
        self.assertIn("stale base", str(failures[0]))
        self.assertEqual(session.base_sha256, results[0][0].sha256)

    def test_patch_receipt_and_candidate_mutation_cannot_seed_cache(self):
        doc = graph()
        session = IncrementalVerifier(doc)
        checked, receipt = session.apply_patch(self.request(doc))
        good_hash = session.base_sha256
        detached = checked.as_dict()
        detached["functions"].clear()
        receipt["verification"]["functions_body_completed"].clear()
        receipt["claims"]["all_candidate_bodies_rechecked"] = True
        self.assertEqual(session.base_sha256, good_hash)
        self.assertEqual(session.last_report["functions_body_completed"], ["leaf"])
        with self.assertRaises(HIAEditRejected):
            session.apply_patch(receipt)


if __name__ == "__main__":
    unittest.main()
