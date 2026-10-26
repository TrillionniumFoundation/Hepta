"""Source-bound HIA scalar Core v0: canonical producer and native consumer gate.

Only scalar SSA (no owned codegen) is admitted. These are positive and
adversarial identity tests, not whole-language/backend soundness proofs.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.cfg import lower_hsir_cfg
from hepta.hia_core import HIACoreRejected, HIAScalarCore, seal_hia_scalar_core
from hepta.hsir import lower_checked_program
from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source
from hepta.native_resource_gate import qualify_native_resource_source
from hepta.parser import parse
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa

_SOURCE = '''module hia_scalar;
export "C" fn bump(n: i32) -> i32 effects {panic} {
    let mut x: i32 = 0;
    while x < n { x = x + 1; }
    return x;
}
'''
_PROJECT = "d" * 64


def fixture(source=_SOURCE):
    program = parse(source, "hia_scalar.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([item.to_dict() for item in checked.diagnostics])
    hsir = lower_checked_program(program, checked)
    cfg = lower_hsir_cfg(hsir)
    ssa = lower_cfg_scalar_ssa(cfg)
    verification = verify_scalar_ssa(ssa, cfg)
    origin = hsir.as_dict()
    gate = qualify_native_resource_source(
        program, checked, canonical_hsir_sha256=origin["source_semantic_sha256"],
        project_sha256=_PROJECT)
    core = seal_hia_scalar_core(hsir, cfg, ssa, verification, gate,
                                project_sha256=_PROJECT)
    return program, checked, core


def reseal(data):
    wire = json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return HIAScalarCore(wire, sha256(wire.encode("utf-8")).hexdigest())


class HIAScalarCoreTests(unittest.TestCase):
    def test_deterministic_source_bound_core_drives_existing_llvm_backend(self):
        program, checked, core = fixture()
        self.assertEqual(core, fixture()[2])
        data, cfg, ssa, verification = core.decode()
        self.assertEqual(data["schema"], "hepta.hia.scalar-core.v0")
        self.assertEqual(data["verification_sha256"], verification.sha256)
        self.assertTrue(data["claims"]["checked_scalar_cfg_ssa_embedded"])
        self.assertFalse(data["claims"]["owned_ssa_supported"])
        self.assertFalse(data["claims"]["backend_refinement_proved"])
        consumed_ssa, consumed_cfg, confirmed = core.qualified_for(
            program, checked, project_sha256=_PROJECT)
        self.assertEqual((ssa, cfg, verification),
                         (consumed_ssa, consumed_cfg, confirmed))
        native_ir = emit_scalar_ssa_llvm(consumed_ssa, consumed_cfg)
        self.assertEqual(native_ir.source_ssa_sha256, data["ssa_sha256"])
        self.assertEqual(native_ir.verification_sha256, data["verification_sha256"])
        self.assertEqual(native_ir.functions, ("bump",))

    def test_stale_source_or_project_rejects_even_when_graph_and_hash_are_valid(self):
        program, checked, core = fixture()
        other_program, other_checked, other_core = fixture(
            _SOURCE.replace("x + 1", "x + 2"))
        self.assertNotEqual(core.sha256, other_core.sha256)
        other_core.decode()  # Internally valid, but not from the requested source.
        for candidate, p, c, project in (
            (core, other_program, other_checked, _PROJECT),
            (other_core, program, checked, _PROJECT),
            (core, program, checked, "c" * 64),
        ):
            with self.subTest(source=candidate.sha256[:12], project=project[:1]):
                with self.assertRaisesRegex(HIACoreRejected, "E_HIA_CORE"):
                    candidate.qualified_for(p, c, project_sha256=project)

    def test_resealed_claims_resource_and_ssa_tampering_fail_closed(self):
        program, checked, core = fixture()
        payload = json.loads(core.canonical_json)
        cases = {
            "soundness_raised": lambda d: d["claims"].update(whole_language_soundness_proved=True),
            "bool_instead_of_false": lambda d: d["claims"].update(backend_refinement_proved=0),
            "resource_proof_raised": lambda d: d["resource_gate"]["claims"].update(
                native_codegen_consumes_resource_ir=True),
            "resource_identity_lost": lambda d: d["resource_gate"].update(resource_ir_sha256="e" * 64),
            "ssa_identity_lost": lambda d: d.update(ssa_sha256="0" * 64),
            "cfg_origin_rebound": lambda d: d["cfg"].update(source_hsir_sha256="f" * 64),
            "extra_field": lambda d: d.update(silent_unsafe=True),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                altered = json.loads(core.canonical_json)
                mutate(altered)
                forged = reseal(altered)
                with self.assertRaisesRegex(HIACoreRejected, "E_HIA_CORE"):
                    forged.qualified_for(program, checked, project_sha256=_PROJECT)

    def test_unknown_unbounded_duplicate_and_noncanonical_wire_reject(self):
        _, _, core = fixture()
        variants = (
            core.canonical_json.replace('"schema":', '"schema":"duplicate","schema":', 1),
            core.canonical_json + " ",
            core.canonical_json.replace('"claims":', '"claims":NaN,"extra":', 1),
            "{" + " " * (8 * 1024 * 1024) + "}",
            "{" + '"a":' * 140 + "0" + "}" ,
        )
        for index, raw in enumerate(variants):
            with self.subTest(case=index):
                malformed = HIAScalarCore(raw, sha256(raw.encode()).hexdigest())
                with self.assertRaisesRegex(HIACoreRejected, "E_HIA_CORE"):
                    malformed.decode()

    def test_native_source_pipeline_cannot_bypass_core(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "source.hepta"
            output = Path(temp) / "never-published.so"
            src.write_text(_SOURCE, encoding="utf-8")
            program, checked, _ = fixture()
            project = SimpleNamespace(identity=_PROJECT,
                                      sources={str(src): "pinned"},
                                      unchanged=lambda: True)
            analysis = SimpleNamespace(program=program, checked=checked, project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"},
                        "source_sha256": "a" * 64, "compiler_sha256": "b" * 64})
            with (patch("hepta.llvm_ssa_pipeline.analyze_project", return_value=analysis),
                  patch("hepta.llvm_ssa_pipeline.seal_hia_scalar_core",
                        side_effect=HIACoreRejected("E_HIA_CORE: negative control")) as gate,
                  patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm") as native):
                report = build_llvm_ssa_source(src, output)
            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "E_HIA_CORE")
            self.assertFalse(output.exists())
            gate.assert_called_once()
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
