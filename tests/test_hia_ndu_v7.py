"""Finite v7 admission, resource and identity controls; no timing experiment."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hepta.hia_checked_reduction_opt import PASS_ID as REDUCTION_PASS
from hepta.hia_fill_loop_opt import PASS_ID as FILL_PASS
from hepta.hia_ndu import (HIANDURejected, PreparedCandidate, canonical, identity,
                          make_plan, observe_semantics, prepare_candidate)
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_schema import (COMPOSITE_SCHEMA_V2, SCHEMA, SCHEMA_V2, SCHEMA_V4,
                              SCHEMA_V6, SCHEMA_V7)
from tests.test_hia_checked_reduction_opt import (observation, reduction_probe_program,
                                                 reduction_program)
from tests.test_hia_fill_loop_opt import fill_loop_program
from tests.test_hia_program import b, c, f, i, ret
from tests.test_hia_swap_opt import source_program


ENTRY = "chain_reduction_probe"
NATIVE_ENTRY = "chain_reduction_native"
POSITIVE_CASES = [[0, (1 << 32) - 1, 1, 255], [7, 31, 4, 173], [31, 7, 3, 17]]
NEGATIVE_CASES = [[2, 1 << 31, 1, 0], [1, (1 << 32) - 1, 1, 0],
                  [0, 0, 0, 0], [2, 1 << 31, 1, 256], [1 << 32, 1, 1, 0]]


def chain_reduction_program():
    """A compiler control with a real node and a formal loan across the loop.

    The four-usize/u8 entry matches the existing NDU instrument ABI. A second,
    exact four-u32/u32 wrapper permits bounded native observations without
    using the timing instrument or changing the arithmetic's u32 semantics.
    This authored fixture is not an industrial workload.
    """
    data = reduction_program("u32")
    data.update(schema=SCHEMA_V7, module="ndu_v7_chain_reduction")
    reduction = data["functions"][0]
    reduction["params"].append({"name": "formal", "type": "readbuf"})
    start, header, body, done = reduction["blocks"]
    start["params"].append({"name": "formal", "type": "readbuf"})
    start["term"]["args"].append("formal")
    header["params"].append({"name": "loop_loan", "type": "readbuf"})
    header["term"]["then"]["args"].append("loop_loan")
    header["term"]["else"]["args"].append("loop_loan")
    body["params"].append({"name": "body_loan", "type": "readbuf"})
    body["term"]["args"].append("body_loan")
    done["params"].append({"name": "done_loan", "type": "readbuf"})
    params = [(name, "usize") for name in ("count", "value", "size", "mask")]
    data["functions"].append(f(ENTRY, params, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("int.cast", ["mask"], [("mask_byte", "u8")], mode="checked"),
            i("int.cast", ["count"], [("count32", "u32")], mode="checked"),
            i("int.cast", ["value"], [("value32", "u32")], mode="checked"),
            i("int.cast", ["size"], [("size32", "u32")], mode="checked"),
            i("buffer.new", ["size"], [("payload", "buffer")]),
            i("borrow.mut", ["payload"], [("writer", "mutbuf")]),
            c("zero", "usize", 0),
            i("buffer.store", ["writer", "zero", "mask_byte"]),
            i("loan.end", ["writer"]),
            i("chain.empty", out=[("empty", "chain")]),
            i("chain.try_push", ["empty", "payload"],
              [("owned", "chain"), ("fallback", "buffer"), ("pushed", "bool")]),
            i("owner.drop", ["fallback"]),
            i("chain.head_read", ["owned"], [("reader", "readbuf")]),
            i("call", ["count32", "value32", "reader"], [("total", "u32")], function="reduce"),
            i("buffer.load", ["reader", "zero"], [("head_byte", "u8")]),
            i("loan.end", ["reader"]),
            i("owner.drop", ["owned"]),
            i("int.add.checked", ["total", "size32"], [("shifted", "u32")]),
            i("int.cast", ["shifted"], [("byte", "u8")], mode="wrap"),
            i("bit.xor", ["byte", "head_byte"], [("answer", "u8")]),
        ], ret("answer")),
    ]))
    params32 = [(name, "u32") for name in ("count", "value", "size", "mask")]
    cast_ops = [i("int.cast", [name], [(name + "64", "usize")], mode="checked")
                for name, _ in params32]
    data["functions"].append(f(NATIVE_ENTRY, params32, ["u32"], ["alloc", "read", "write", "trap"], [
        b("entry", params32, cast_ops + [
            i("call", [name + "64" for name, _ in params32], [("byte", "u8")], function=ENTRY),
            i("int.cast", ["byte"], [("answer", "u32")], mode="checked"),
        ], ret("answer")),
    ]))
    return data


class V7CandidateAdmissionTests(unittest.TestCase):
    def prepare(self):
        source = chain_reduction_program()
        return prepare_candidate(source, make_plan(source, entry=ENTRY, pass_id=REDUCTION_PASS))

    def test_supported_v7_rules_preserve_identity_and_legacy_upgrades(self):
        for factory, entry, rule, old_output in (
            (source_program, "swap_candidate", "byte-swap.v1", SCHEMA_V4),
            (reduction_program, "reduce", REDUCTION_PASS, SCHEMA),
        ):
            with self.subTest(rule=rule):
                old = factory()
                legacy = prepare_candidate(old, make_plan(old, entry=entry, pass_id=rule))
                self.assertEqual(legacy.candidate.as_dict()["schema"], old_output)
                source = factory()
                source["schema"] = SCHEMA_V7
                prepared = prepare_candidate(source, make_plan(source, entry=entry, pass_id=rule))
                self.assertEqual(prepared.replacements, 1)
                self.assertEqual(prepared.baseline.as_dict()["schema"], SCHEMA_V7)
                self.assertEqual(prepared.candidate.as_dict()["schema"], SCHEMA_V7)
                self.assertEqual(prepared.plan["baseline_sha256"], prepared.baseline.sha256)
                self.assertEqual(prepared.plan_sha256, identity(prepared.plan))
                replay = prepare_candidate(prepared.baseline, prepared.plan,
                                           candidate_bytes=prepared.candidate.canonical_bytes)
                self.assertEqual(replay.candidate.sha256, prepared.candidate.sha256)
        fill = fill_loop_program()
        legacy_fill = prepare_candidate(fill, make_plan(fill, entry="fill_probe", pass_id=FILL_PASS))
        self.assertEqual(legacy_fill.candidate.as_dict()["schema"], SCHEMA_V2)

    def test_v7_fill_is_explicitly_outside_its_unchanged_rule_profile(self):
        source = fill_loop_program()
        old_plan = make_plan(source, entry="fill_probe", pass_id=FILL_PASS)
        source["schema"] = SCHEMA_V7
        checked = verify_program(source)
        # Bind a real v7 baseline so this refusal cannot be a stale-plan test.
        old_plan["baseline_sha256"] = checked.sha256
        with self.assertRaisesRegex(HIANDURejected, "does not admit.*v7"):
            make_plan(checked, entry="fill_probe", pass_id=FILL_PASS)
        with self.assertRaisesRegex(HIANDURejected, "does not admit.*v7"):
            prepare_candidate(checked, old_plan)

    def test_actual_chain_node_and_cross_call_loan_keep_complete_observations(self):
        prepared = self.prepare()
        self.assertEqual(prepared.replacements, 1)
        # The outer allocation, loans, node operations, drop and native wrapper
        # are byte-for-byte unchanged; only the internal reduction is rewritten.
        self.assertEqual(prepared.baseline.as_dict()["functions"][1:],
                         prepared.candidate.as_dict()["functions"][1:])
        observed = observe_semantics(prepared, POSITIVE_CASES, negative_cases=NEGATIVE_CASES)
        self.assertTrue(observed["ok"], observed)
        self.assertEqual(observed["baseline_sha256"], prepared.baseline.sha256)
        self.assertEqual(observed["candidate_sha256"], prepared.candidate.sha256)
        self.assertEqual(len(observed["observations"]), 16)
        for row in observed["observations"]:
            self.assertTrue(row["match"])
            if row["group"] == "positive" and row["allocation_fail_at"] is None:
                resources = row["baseline"]["resources"]
                self.assertEqual((resources["chain_nodes_created"], resources["chain_nodes_dropped"]), (1, 1))
                self.assertEqual((resources["allocations"], resources["frees"]), (2, 2))
                self.assertEqual((resources["loans_started"], resources["loans_ended"]), (2, 2))
                for field in ("live_bytes", "live_owners", "live_chains", "live_chain_nodes", "live_local_loans"):
                    self.assertEqual(resources[field], 0)

    def test_node_allocation_refusal_still_precedes_reduction_overflow(self):
        prepared = self.prepare()
        for args in (POSITIVE_CASES[1], NEGATIVE_CASES[0]):
            with self.subTest(args=args):
                before = observation(prepared.baseline, args, entry=ENTRY, allocation_fail_at=2)
                after = observation(prepared.candidate, args, entry=ENTRY, allocation_fail_at=2)
                self.assertEqual(before, after)
                self.assertEqual(before[1], "bounds")
                self.assertEqual(before[0]["resources"]["chain_nodes_created"], 0)
                self.assertEqual(before[0]["resources"]["allocation_attempts"], 2)

    def test_cross_version_plan_and_supplied_candidate_replays_are_rejected(self):
        versions = {}
        for schema in (SCHEMA_V6, SCHEMA_V7):
            source = reduction_program()
            source["schema"] = schema
            versions[schema] = prepare_candidate(source, make_plan(source, entry="reduce", pass_id=REDUCTION_PASS))
        for schema, other in ((SCHEMA_V6, SCHEMA_V7), (SCHEMA_V7, SCHEMA_V6)):
            with self.subTest(schema=schema):
                current, stale = versions[schema], versions[other]
                self.assertNotEqual(current.baseline.sha256, stale.baseline.sha256)
                with self.assertRaisesRegex(HIANDURejected, "stale baseline"):
                    prepare_candidate(current.baseline, stale.plan)
                with self.assertRaisesRegex(HIANDURejected, "differs from"):
                    prepare_candidate(current.baseline, current.plan,
                                      candidate_bytes=stale.candidate.canonical_bytes)

    def test_composite_identity_cannot_be_erased_at_baseline_or_exchange(self):
        structured = reduction_program()
        structured.update(schema=COMPOSITE_SCHEMA_V2, types=[])
        normalized = verify_program(structured)
        plan = make_plan(normalized.canonical_bytes, entry="reduce", pass_id=REDUCTION_PASS)
        with self.assertRaisesRegex(HIANDURejected, "composite"):
            make_plan(normalized, entry="reduce", pass_id=REDUCTION_PASS)
        with self.assertRaisesRegex(HIANDURejected, "composite"):
            prepare_candidate(normalized, plan)
        prepared = prepare_candidate(normalized.canonical_bytes, plan)
        supplied = prepared.candidate.as_dict()
        supplied.pop("exports", None)  # Composite elaboration recreates scalar exports.
        supplied.update(schema=COMPOSITE_SCHEMA_V2, types=[])
        exchange = verify_program(supplied)
        # This is the important negative: executable Core bytes really agree,
        # but the supplied bytes still declare a different input identity.
        self.assertEqual(exchange.canonical_bytes, prepared.candidate.canonical_bytes)
        with self.assertRaisesRegex(HIANDURejected, "composite"):
            prepare_candidate(prepared.baseline, plan, candidate_bytes=exchange.structured_bytes)

    def test_forged_receipts_and_unused_invalid_chain_functions_are_rechecked(self):
        prepared = self.prepare()
        invalid = prepared.baseline.as_dict()
        invalid["functions"].append(f("unused_invalid", [], [], ["alloc"], [
            b("entry", [], [i("chain.empty", out=[("owned", "chain")]),
                             i("owner.drop", ["owned"]), i("owner.drop", ["owned"])], ret()),
        ]))
        for source in (invalid, VerifiedProgram(canonical(invalid))):
            with self.subTest(form=type(source).__name__), self.assertRaises(HIAProgramRejected):
                prepare_candidate(source, prepared.plan)
        invalid_candidate = prepared.candidate.as_dict()
        invalid_candidate["functions"].append(invalid["functions"][-1])
        with self.assertRaises(HIAProgramRejected):
            prepare_candidate(prepared.baseline, prepared.plan, candidate_bytes=canonical(invalid_candidate))

    def test_semantic_observer_rejects_composite_and_forged_candidate_metadata(self):
        structured = reduction_program()
        structured.update(schema=COMPOSITE_SCHEMA_V2, types=[])
        original = verify_program(structured)
        prepared = prepare_candidate(original.canonical_bytes,
            make_plan(original.canonical_bytes, entry="reduce", pass_id=REDUCTION_PASS))
        candidate_input = prepared.candidate.as_dict()
        candidate_input.pop("exports", None)
        candidate_input.update(schema=COMPOSITE_SCHEMA_V2, types=[])
        composite = verify_program(candidate_input)
        self.assertEqual(composite.canonical_bytes, prepared.candidate.canonical_bytes)
        self.assertNotEqual(composite.input_sha256, prepared.candidate.input_sha256)
        # Both controls carry the exact candidate Core bytes. One has a valid
        # but excluded composite identity; the other has inconsistent metadata.
        # Neither public dataclass construction is a fresh admission receipt.
        for name, candidate, error in (
            ("composite", composite, HIANDURejected),
            ("forged", VerifiedProgram(prepared.candidate.canonical_bytes,
                                       original.structured_bytes), HIAProgramRejected),
        ):
            supplied = PreparedCandidate(prepared.baseline, candidate,
                                         prepared.plan_bytes, prepared.replacements)
            with self.subTest(input=name), self.assertRaises(error):
                observe_semantics(supplied, [[2, 3]])

    def test_active_chain_loan_and_non_scalar_entry_rules_are_not_relaxed(self):
        prepared = self.prepare()
        invalid = prepared.baseline.as_dict()
        ops = invalid["functions"][1]["blocks"][0]["ops"]
        call_index = next(index for index, op in enumerate(ops) if op["op"] == "call")
        ops.insert(call_index, i("owner.drop", ["owned"]))
        with self.assertRaises(HIAProgramRejected):
            prepare_candidate(invalid, prepared.plan)
        plan = make_plan(prepared.baseline, entry="reduce", pass_id=REDUCTION_PASS)
        with self.assertRaisesRegex(HIANDURejected, "scalar public entry"):
            prepare_candidate(prepared.baseline, plan)

    def test_valid_resource_edit_is_not_the_registered_candidate(self):
        prepared = self.prepare()
        edited = prepared.candidate.as_dict()
        edited["functions"][1]["blocks"][0]["ops"][:0] = [
            i("chain.empty", out=[("additional", "chain")]), i("owner.drop", ["additional"])]
        changed = verify_program(edited)
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            prepare_candidate(prepared.baseline, prepared.plan, candidate_bytes=changed.canonical_bytes)

    def test_v7_does_not_expand_the_matcher_over_resource_events(self):
        source = chain_reduction_program()
        source["functions"][0]["effects"].append("alloc")
        source["functions"][0]["blocks"][2]["ops"] += [
            i("chain.empty", out=[("per_iteration", "chain")]), i("owner.drop", ["per_iteration"])]
        prepared = prepare_candidate(source, make_plan(source, entry=ENTRY, pass_id=REDUCTION_PASS))
        self.assertEqual(prepared.replacements, 0)
        self.assertEqual(prepared.baseline.canonical_bytes, prepared.candidate.canonical_bytes)
        self.assertTrue(observe_semantics(prepared, [POSITIVE_CASES[1]])["ok"])

    def test_semantic_observer_replays_the_v7_plan_and_candidate(self):
        prepared = self.prepare()
        changed = PreparedCandidate(prepared.baseline, prepared.baseline, prepared.plan_bytes, 1)
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            observe_semantics(changed, POSITIVE_CASES)
        stale_plan = prepared.plan
        stale_plan["baseline_sha256"] = verify_program(reduction_program()).sha256
        changed = PreparedCandidate(prepared.baseline, prepared.candidate, canonical(stale_plan), 1)
        with self.assertRaisesRegex(HIANDURejected, "stale baseline"):
            observe_semantics(changed, POSITIVE_CASES)

    def test_qualifier_rejects_replayed_v6_artifact_identity_before_ndu(self):
        from tools.qualify_hia_ndu import qualify
        prepared = self.prepare()
        old = reduction_probe_program()
        old["schema"] = SCHEMA_V6
        previous = prepare_candidate(old, make_plan(old, entry="reduction_probe", pass_id=REDUCTION_PASS))
        # Synthetic protocol negatives only. No sample is measured or submitted
        # to an evaluator, and the actual v7 VM validation still runs first.
        for role in ("baseline", "candidate"):
            native = {name: {"core_sha256": getattr(prepared, name).sha256,
                             "artifact_sha256": digest * 64, "artifact_bytes": 128}
                      for name, digest in (("baseline", "a"), ("candidate", "b"))}
            native[role]["core_sha256"] = getattr(previous, role).sha256
            measurement = {"ok": True, "counts": {"calls_per_sample": 1}, "native": native,
                           "raw_samples": [{"baseline_ns": 1_000_000, "candidate_ns": 500_000}] * 15}
            with self.subTest(role=role), patch("tools.qualify_hia_ndu.measure_pair", return_value=measurement), \
                    patch("tools.qualify_hia_ndu.invoke_ndu") as evaluator:
                report = qualify(prepared.baseline, prepared.plan, [POSITIVE_CASES[1]],
                                 bridge="not-invoked", expected_bridge_sha256="c" * 64)
                self.assertFalse(report["ok"])
                self.assertEqual(report["status"], "failed_closed_no_change")
                self.assertEqual(report["plan_sha256"], prepared.plan_sha256)
                self.assertTrue(report["semantic_validation"]["ok"])
                self.assertIn("compiled artifact identity differs", report["diagnostics"][-1]["message"])
                self.assertFalse(report["claims"]["real_ndu_evaluator_executed"])
                evaluator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
