"""Fail-closed source-facing static-budget receipt and native admission tests.

These tests check identities and proof-scope claims. They do not independently
prove the analyzer's arithmetic bound or native backend refinement.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_source_bridge import (
    HIAHeptaBridgeRejected, _validate_static_budget_receipt,
    build_checked_hepta_hia_native,
)
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_heap_bound import local_buffers, scalar_call


def reseal(receipt):
    value = {k: v for k, v in receipt.items() if k != "sha256"}
    receipt["sha256"] = sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return receipt


class HIAStaticBudgetReceiptTests(unittest.TestCase):
    def test_current_verified_core_full_receipt_is_admitted(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        genuine = analyze_static_budget(core, **policy)
        self.assertIsNone(_validate_static_budget_receipt(core, policy, genuine))
        multi = verify_program(scalar_call())
        three = {"max_allocator_interactions": 4, "max_call_depth": 2}
        receipt = analyze_static_budget(multi, **three)
        self.assertEqual([r["function"] for r in receipt["functions"]], ["inner", "parent"])
        self.assertIsNone(_validate_static_budget_receipt(multi, three, receipt))

    def test_self_resealed_missing_duplicate_or_reordered_function_denominator_rejected(self):
        core = verify_program(scalar_call())
        limits = {"max_allocator_interactions": 4}
        baseline = analyze_static_budget(core, **limits)
        variants = {
            "empty": lambda r: r.update(functions=[]),
            "one_missing": lambda r: r.update(functions=r["functions"][:1]),
            "duplicate": lambda r: r.update(functions=[r["functions"][0]] * 2),
            "wrong_order": lambda r: r["functions"].reverse(),
            "extra": lambda r: r["functions"].append(dict(r["functions"][0])),
        }
        for name, mutation in variants.items():
            with self.subTest(name=name):
                forgery = deepcopy(baseline)
                mutation(forgery)
                reseal(forgery)  # A valid payload hash is NOT enough.
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    _validate_static_budget_receipt(core, limits, forgery)

    def test_self_resealed_policy_claim_types_and_quantities_rejected(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        genuine = analyze_static_budget(core, **policy)
        variants = {
            "int_false_claim": lambda r: r["claims"].update(native_cpu_time_or_rss_proved=0),
            "false_coverage": lambda r: r["claims"].update(
                requested_live_payload_bytes_upper_bounded=False),
            "fake_soundness": lambda r: r["claims"].update(whole_language_soundness_proved=True),
            "missing_claim": lambda r: r["claims"].pop("finite_acyclic_cfg_and_call_graph_checked"),
            "unknown_claim": lambda r: r["claims"].update(external_memory_safe=True),
            "bool_budget": lambda r: r["functions"][0].update(max_live_heap_bytes=True),
            "wrong_function": lambda r: r["functions"][0].update(function="not_in_core"),
            "over_limit": lambda r: r["functions"][0].update(max_live_heap_bytes=13),
            "bool_policy": lambda r: r["limits"].update(max_live_heap_bytes=True),
            "missing_limit": lambda r: r["limits"].pop("max_live_heap_bytes"),
            "extra_limit": lambda r: r["limits"].update(max_stack_bytes=0),
            "missing_row_quantity": lambda r: r["functions"][0].pop("max_vm_ticks"),
            "extra_row_quantity": lambda r: r["functions"][0].update(max_native_cpu=0),
            "false_identity": lambda r: r.update(core_sha256="0" * 64),
        }
        for name, mutation in variants.items():
            with self.subTest(name=name):
                forged = deepcopy(genuine)
                mutation(forged)
                reseal(forged)
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    _validate_static_budget_receipt(core, policy, forged)

    def test_corrupt_digest_and_type_confusion_refused(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        receipt = analyze_static_budget(core, **policy)
        bad = deepcopy(receipt)
        bad["sha256"] = "0" * 64
        with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
            _validate_static_budget_receipt(core, policy, bad)
        for invalid in (True, 0, "12"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    _validate_static_budget_receipt(core, {"max_live_heap_bytes": invalid}, receipt)

    def test_source_native_rejects_validly_rehashed_empty_budget_before_any_llvm(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        forged = deepcopy(analyze_static_budget(core, **policy))
        forged["functions"] = []
        reseal(forged)
        with tempfile.TemporaryDirectory(prefix="hia-forged-budget-") as directory:
            source = Path(directory) / "source.hepta"
            output = Path(directory) / "must-not-exist.so"
            source.write_text("module budget;", encoding="utf-8")
            project = SimpleNamespace(identity="d" * 64, sources={str(source): "pinned"},
                                      unchanged=lambda: True)
            analysis = SimpleNamespace(
                program=object(), checked=object(), project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"},
                        "compiler_sha256": "e" * 64})
            derived = SimpleNamespace(program=core)
            with (patch("hepta.pipeline.analyze_project", return_value=analysis),
                  patch("hepta.pipeline.compiler_hash", return_value="e" * 64),
                  patch("hepta.hia_source_bridge.lower_checked_scalar_hia",
                        return_value=derived),
                  patch("hepta.hia_static_budget.analyze_static_budget", return_value=forged),
                  patch("hepta.hia_program_llvm.emit_program_llvm") as emitter):
                result = build_checked_hepta_hia_native(
                    source, output, static_resource_limits=policy)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["diagnostics"][0]["code"], "E_HIA_HEPTA_BRIDGE")
            self.assertFalse(output.exists())
            emitter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
