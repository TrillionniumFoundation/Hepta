"""Source-native independent receipt replay negatives on exact HIA bytes.

The normal analyzer remains the sole numeric authority. This suite makes sure
a self-rehashed receipt cannot substitute fabricated row quantities, including
when the native builder's analyzer call is replaced at runtime. It does not
prove the analyzer's mathematics or LLVM lowering.
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
from tests.test_hia_heap_bound import local_buffers


def reseal(report):
    payload = {k: v for k, v in report.items() if k != "sha256"}
    report["sha256"] = sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()
    return report


class HIABudgetCanonicalReplayTests(unittest.TestCase):
    def test_genuine_analyzer_receipt_matches_immutable_core_replay(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        genuine = analyze_static_budget(core, **policy)
        self.assertIsNone(_validate_static_budget_receipt(core, policy, genuine))

    def test_self_rehashed_numeric_understatement_and_overstatement_refused(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        genuine = analyze_static_budget(core, **policy)
        original = genuine["functions"][0]
        variants = {
            "smaller_heap_than_real": ("max_live_heap_bytes", 0),
            "fewer_allocations_than_real": ("max_allocator_interactions", 0),
            "fewer_vm_ticks_than_real": ("max_vm_ticks", 1),
            "more_call_frames_than_real": ("max_call_depth", 2),
        }
        self.assertGreater(original["max_live_heap_bytes"], 0)
        self.assertGreater(original["max_allocator_interactions"], 0)
        self.assertGreater(original["max_vm_ticks"], 1)
        self.assertEqual(original["max_call_depth"], 1)
        for case, (field, forged_value) in variants.items():
            with self.subTest(case=case):
                fake = deepcopy(genuine)
                fake["functions"][0][field] = forged_value
                reseal(fake)
                # Every forged value has the correct type and stays within
                # the user-requested limit. A SHA-only verifier misses it.
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    _validate_static_budget_receipt(core, policy, fake)

    def test_replaced_build_analyzer_cannot_publish_forged_heap_report(self):
        core = verify_program(local_buffers())
        policy = {"max_live_heap_bytes": 12}
        fake = deepcopy(analyze_static_budget(core, **policy))
        fake["functions"][0]["max_live_heap_bytes"] = 0
        reseal(fake)
        with tempfile.TemporaryDirectory(prefix="hia-budget-replay-") as root:
            source = Path(root) / "source.hepta"
            destination = Path(root) / "must-not-exist.so"
            source.write_text("module replay;", encoding="utf-8")
            project = SimpleNamespace(
                identity="c" * 64, sources={str(source): "pinned"},
                unchanged=lambda: True)
            analysis = SimpleNamespace(
                program=object(), checked=object(), project=project,
                report={"ok": True,
                        "checks": {"rust_borrows_types": "rustc_checked"},
                        "compiler_sha256": "b" * 64})
            derived = SimpleNamespace(program=core)
            with (
                patch("hepta.pipeline.analyze_project", return_value=analysis),
                patch("hepta.pipeline.compiler_hash", return_value="b" * 64),
                patch("hepta.hia_source_bridge.lower_checked_scalar_hia",
                      return_value=derived),
                patch("hepta.hia_static_budget.analyze_static_budget", return_value=fake),
                patch("hepta.hia_program_llvm.emit_program_llvm") as emitter,
            ):
                result = build_checked_hepta_hia_native(
                    source, destination, static_resource_limits=policy)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["diagnostics"][0]["code"], "E_HIA_HEPTA_BRIDGE")
            self.assertFalse(destination.exists())
            emitter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
