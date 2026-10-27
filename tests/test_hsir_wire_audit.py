"""Fail-closed cross-branch HSIR envelope and digest regression tests."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "audit_hsir_wire.py"
spec = importlib.util.spec_from_file_location("audit_hsir_wire", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def signed(fields):
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return {**fields, "sha256": hashlib.sha256(canonical).hexdigest()}


def source_bound():
    return signed({"schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
                   "module": "sample", "path": "sample.hepta", "source_sha256": "a" * 64,
                   "project_sha256": None, "imports": [], "structs": [], "enums": [],
                   "untyped_expressions": [], "volatile_accesses": [],
                   "foreign_assumptions": [], "resource_contracts": [], "owned_types": [],
                   "functions": [], "external_obligations": [], "all_expressions_typed": True,
                   "claims": {"native_borrow_validation": False,
                              "translation_correctness_proved": False,
                              "whole_language_soundness_proved": False,
                              "foreign_contracts_proved": False}})


def frozen():
    return signed({"schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
                   "program": "sample", "source_sha256": "a" * 64,
                   "imports": [], "structs": [], "enums": [], "resource_contracts": [],
                   "functions": [], "external_assumptions": [], "typed_expression_count": 0,
                   "claims": {"lifetimes_fully_modeled": False,
                              "pointer_provenance_proved": False,
                              "source_semantics_refined": False,
                              "native_backend_equivalence_proved": False}})


class WireAuditTests(unittest.TestCase):
    def test_detects_exact_schema_collision(self):
        report = module.compare(source_bound(), frozen())
        self.assertTrue(report["same_schema_different_wire_format"])
        self.assertEqual(report["wire_layout_status"], "incompatible_requires_versioned_adapter")
        self.assertFalse(report["safe_to_mix_without_adapter"])

    def test_same_profile_not_semantic_proof(self):
        report = module.compare(source_bound(), source_bound())
        self.assertFalse(report["same_schema_different_wire_format"])
        self.assertFalse(report["automatic_merge_approved"])
        self.assertEqual(report["wire_layout_status"], "same_format_only_not_semantic_equivalence")

    def test_digest_mismatch_rejected(self):
        broken = source_bound()
        broken["source_sha256"] = "b" * 64
        with self.assertRaisesRegex(module.HSIRWireRejected, "DIGEST_MISMATCH"):
            module.fingerprint(broken)

    def test_forged_claim_rejected_even_when_rehashed(self):
        broken = source_bound()
        del broken["sha256"]
        broken["claims"]["translation_correctness_proved"] = True
        with self.assertRaisesRegex(module.HSIRWireRejected, "PROOF_CLAIM"):
            module.fingerprint(signed(broken))

    def test_unknown_evidence_claim_rejected(self):
        broken = frozen()
        del broken["sha256"]
        broken["claims"]["new_proof_claim"] = True
        with self.assertRaisesRegex(module.HSIRWireRejected, "PROOF_CLAIM"):
            module.fingerprint(signed(broken))

    def test_ambiguous_wire_discriminator_rejected(self):
        broken = source_bound()
        del broken["sha256"]
        broken["status"] = "checked_frontend_snapshot_not_proved"
        with self.assertRaisesRegex(module.HSIRWireRejected, "AMBIGUOUS_PROFILE"):
            module.fingerprint(signed(broken))

    def test_duplicate_json_field_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "source.json"
            path.write_text('{"schema":"hepta.hsir.v0","schema":"hepta.hsir.v0"}')
            with self.assertRaisesRegex(module.HSIRWireRejected, "DUPLICATE_KEY"):
                module.load(str(path))

    def test_hsir_file_intake_requires_regular_nonempty_bounded_inode(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            valid = base / "real.json"
            valid.write_text(json.dumps(frozen()))
            self.assertEqual(module.load(valid), frozen())
            (base / "symlink.json").symlink_to(valid)
            with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_SOURCE_TYPE"):
                module.load(base / "symlink.json")
            empty = base / "empty.json"
            empty.touch()
            with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_JSON"):
                module.load(empty)
            huge = base / "huge.json"
            with huge.open("wb") as stream:
                stream.truncate(module.MAX_HSIR_INPUT_BYTES + 1)
            with patch.object(module.os, "open", side_effect=AssertionError("should not open")):
                with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_TOO_LARGE"):
                    module.load(huge)
            if hasattr(module.os, "mkfifo"):
                pipe = base / "pipe.json"
                module.os.mkfifo(pipe)
                with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_SOURCE_TYPE"):
                    module.load(pipe)

    @unittest.skipUnless(hasattr(__import__("os"), "O_NOFOLLOW") and
                         hasattr(__import__("os"), "O_NONBLOCK"),
                         "requires no-follow nonblocking file-descriptor support")
    def test_path_swap_to_fifo_rejects_without_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "hsir.json"
            path.write_text(json.dumps(frozen()))
            real_open = module.os.open
            def swap_to_fifo(name, flags, *args, **kwargs):
                # Inspect the guard BEFORE opening the FIFO. A regression
                # fails as a test assertion rather than hanging indefinitely.
                self.assertTrue(flags & module.os.O_NOFOLLOW)
                self.assertTrue(flags & module.os.O_NONBLOCK)
                path.unlink()
                module.os.mkfifo(path)
                return real_open(name, flags, *args, **kwargs)
            with patch.object(module.os, "open", side_effect=swap_to_fifo):
                with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_SOURCE_ID"):
                    module.load(path)

    @unittest.skipUnless(hasattr(__import__("os"), "O_NOFOLLOW") and
                         hasattr(__import__("os"), "O_NONBLOCK"),
                         "requires no-follow nonblocking file-descriptor support")
    def test_path_swap_to_symlink_cannot_retarget_source(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            path, victim = base / "hsir.json", base / "private.json"
            path.write_text(json.dumps(frozen()))
            victim.write_text('{"secret":true}')
            real_open = module.os.open
            def swap_to_symlink(name, flags, *args, **kwargs):
                self.assertTrue(flags & module.os.O_NOFOLLOW)
                self.assertTrue(flags & module.os.O_NONBLOCK)
                path.unlink()
                path.symlink_to(victim)
                return real_open(name, flags, *args, **kwargs)
            with patch.object(module.os, "open", side_effect=swap_to_symlink):
                with self.assertRaises(OSError):
                    module.load(path)
            self.assertEqual(victim.read_text(), '{"secret":true}')

    @unittest.skipUnless(hasattr(__import__("os"), "O_NOFOLLOW") and
                         hasattr(__import__("os"), "O_NONBLOCK"),
                         "requires no-follow nonblocking file-descriptor support")
    def test_path_replacement_after_open_cannot_authorize_new_inode(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            path, saved = base / "hsir.json", base / "saved.json"
            path.write_text(json.dumps(frozen()))
            real_fstat = module.os.fstat
            calls = 0
            def exchange_on_second_fstat(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.rename(saved)
                    path.write_text(json.dumps(source_bound()))
                return real_fstat(fd)
            with patch.object(module.os, "fstat", side_effect=exchange_on_second_fstat):
                with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_SOURCE_ID"):
                    module.load(path)
            self.assertTrue(saved.exists())

    def test_adversarial_depth_rejected_without_unhandled_exception(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "deep.json"
            path.write_text("[" * 20000 + "0" + "]" * 20000)
            with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_JSON"):
                module.load(str(path))

    def test_pr14_actual_cli_export_envelope(self):
        envelope = {"schema": "hepta.hsir.export.v0", "ok": True,
                    "status": "frontend_only", "hsir": source_bound(),
                    "validation": {"status": "frontend_only"}}
        result = module.fingerprint(envelope)
        self.assertEqual(result["wire_profile"], "source_bound_dict_v0")
        self.assertTrue(result["external_validation_metadata_unbound_to_payload"])
        self.assertFalse(result["checked_native"])

    def test_pr36_actual_cli_reference_validation_is_unbound(self):
        payload = {**frozen(), "reference_validation": {"status": "checked"}}
        result = module.fingerprint(payload)
        self.assertEqual(result["wire_profile"], "frozen_snapshot_v0")
        self.assertTrue(result["external_validation_metadata_unbound_to_payload"])
        self.assertFalse(result["checked_native"])
        payload["reference_validation"] = {"status": "fake_passed", "claims": {"safe": True}}
        self.assertEqual(module.fingerprint(payload)["sha256"], result["sha256"])

    def test_pr14_wrapper_cannot_claim_pr36_payload(self):
        envelope = {"schema": "hepta.hsir.export.v0", "ok": True,
                    "status": "checked", "hsir": frozen(), "validation": {}}
        with self.assertRaisesRegex(module.HSIRWireRejected, "EXPORT_ENVELOPE"):
            module.fingerprint(envelope)

    def test_pr36_invalid_cli_sidecar_shape_rejected(self):
        payload = {**frozen(), "reference_validation": ["checked"]}
        with self.assertRaisesRegex(module.HSIRWireRejected, "SIDECAR_ENVELOPE"):
            module.fingerprint(payload)

    def test_real_cli_collision_reports_exit_three(self):
        with tempfile.TemporaryDirectory() as d:
            a, b, out = [pathlib.Path(d) / x for x in ("a.json", "b.json", "out.json")]
            a.write_text(json.dumps({"schema": "hepta.hsir.export.v0", "ok": True,
                                     "status": "frontend_only", "hsir": source_bound(),
                                     "validation": {"status": "frontend_only"}}))
            b.write_text(json.dumps({**frozen(),
                                     "reference_validation": {"status": "checked"}}))
            code = module.main(["--left", str(a), "--right", str(b), "--output", str(out)])
            self.assertEqual(code, 3)
            self.assertTrue(json.loads(out.read_text())["same_schema_different_wire_format"])
            self.assertEqual(module.main(["--left", str(a), "--right", str(b),
                                          "--output", str(out)]), 2)


    def test_valid_unresolved_ffi_obligation(self):
        base = source_bound()
        del base["sha256"]
        base["external_obligations"] = [{
            "function": "extern_entry",
            "reasons": ["foreign_function", "ffi_effect"],
            "status": "caller_obligation_not_dischargeable_by_hsir",
        }]
        self.assertEqual(module.fingerprint(signed(base))["wire_profile"],
                         "source_bound_dict_v0")

    def test_rehashed_forged_ffi_obligations_rejected(self):
        expected = {
            "function": "extern_entry",
            "reasons": ["foreign_function", "ffi_effect"],
            "status": "caller_obligation_not_dischargeable_by_hsir",
        }
        variants = [
            [{**expected, "status": "proof_discharged"}],
            [{**expected, "reasons": []}],
            [{**expected, "reasons": ["proof_discharged"]}],
            [{**expected, "function": True}],
            [{**expected, "proof": True}],
            [{**expected, "reasons": ["ffi_effect", "ffi_effect"]}],
            {"entries": [expected]},
        ]
        for index, obligations in enumerate(variants):
            with self.subTest(variant=index):
                base = source_bound()
                del base["sha256"]
                base["external_obligations"] = obligations
                with self.assertRaisesRegex(module.HSIRWireRejected,
                                            "E_HSIR_OBLIGATION"):
                    module.fingerprint(signed(base))

    def test_valid_pr36_unproved_external_assumptions(self):
        extern = {"kind": "extern_contract", "function": "entry", "abi": "C",
                  "declared_effects": ["ffi"], "parameters": [{"name": "p", "type": "i32"}],
                  "return_type": "i32", "status": "assumed_not_verified",
                  "obligations": list(module.UNPROVED_EXTERNAL_OBLIGATIONS)}
        unsafe = {"kind": "unsafe_obligation", "function": "entry",
                  "operation": "raw_load", "path": "fixture.hepta", "line": 1,
                  "status": "not_proved_by_frontend"}
        for assumptions in ([], [extern], [unsafe], [extern, unsafe]):
            with self.subTest(assumptions=assumptions):
                record = frozen()
                del record["sha256"]
                record["external_assumptions"] = assumptions
                self.assertEqual(module.fingerprint(signed(record))["wire_profile"],
                                 "frozen_snapshot_v0")

    def test_rehashed_pr36_assumption_claims_rejected(self):
        extern = {"kind": "extern_contract", "function": "entry", "abi": "C",
                  "declared_effects": ["ffi"], "parameters": [{"name": "p", "type": "i32"}],
                  "return_type": "i32", "status": "assumed_not_verified",
                  "obligations": list(module.UNPROVED_EXTERNAL_OBLIGATIONS)}
        unsafe = {"kind": "unsafe_obligation", "function": "entry",
                  "operation": "raw_load", "path": "fixture.hepta", "line": 1,
                  "status": "not_proved_by_frontend"}
        variants = [
            [{**extern, "status": "proof_discharged"}],
            [{**unsafe, "status": "verified"}],
            [{**extern, "abi": "Rust"}],
            [{**extern, "obligations": []}],
            [{**extern, "parameters": [{"name": "p", "type": "i32", "verified": True}]}],
            [{**extern, "declared_effects": ["ffi", "ffi"]}],
            [{**extern, "return_type": False}],
            [{**extern, "function": ""}],
            [{**unsafe, "line": True}],
            [{**unsafe, "line": 0}],
            [{**unsafe, "proof": True}],
            [{**unsafe, "kind": "unrecognized"}],
            {"entries": [extern]},
            ["extern_contract"],
        ]
        for index, assumptions in enumerate(variants):
            with self.subTest(variant=index):
                record = frozen()
                del record["sha256"]
                record["external_assumptions"] = assumptions
                with self.assertRaisesRegex(module.HSIRWireRejected,
                                            "E_HSIR_EXTERNAL_ASSUMPTION"):
                    module.fingerprint(signed(record))


    def test_rehashed_unknown_fields_and_false_claims_reject(self):
        for build in (source_bound, frozen):
            with self.subTest(profile=build.__name__):
                payload = build()
                del payload["sha256"]
                payload["compatibility_proved"] = False
                with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_UNKNOWN_FIELDS"):
                    module.fingerprint(signed(payload))
                del payload["compatibility_proved"]
                payload["claims"]["unrecognized_future_proof"] = False
                with self.assertRaisesRegex(module.HSIRWireRejected, "PROOF_CLAIM"):
                    module.fingerprint(signed(payload))

    def test_missing_producer_inventory_is_not_compatible(self):
        for build in (source_bound, frozen):
            payload = build()
            del payload["sha256"]
            del payload["structs"]
            with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_MISSING_FIELDS"):
                module.fingerprint(signed(payload))

if __name__ == "__main__":
    unittest.main()
