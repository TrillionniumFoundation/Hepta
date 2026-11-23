"""Verify checked fallback receipts using the installed HIA command and the actual ELF bytes."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from tests.test_hia_program import arithmetic, b, jump, ret


@unittest.skipUnless(os.environ.get("HIA_TEST_NATIVE_FILTER_RELEASE"), "requires the installed native release")
class CheckedBuildReceiptTests(unittest.TestCase):
    def test_multiblock_core_binds_its_compilation_and_machine_proof(self):
        release = Path(os.environ["HIA_TEST_NATIVE_FILTER_RELEASE"])
        program = arithmetic("int.add.checked", "u8")
        function = program["functions"][0]
        start = function["blocks"][0]
        value, = start["term"]["values"]
        start["term"] = jump("finish", value)
        function["blocks"].append(b("finish", [("result", "u8")], [], ret("result")))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "checked.hepta"
            output = root / "checked.so"
            source.write_text(json.dumps(program))
            cmd = [release / "hia", "build", source, "-o", output, "--backend", "auto", "--kind", "shared"]
            built = subprocess.run(cmd, capture_output=True, env={"PATH": ""}, timeout=90)
            self.assertEqual((built.returncode, built.stderr), (0, b""))
            receipt = json.loads(built.stdout)
            self.assertEqual((receipt["schema"], receipt["selected_strategy"], receipt["status"]),
                             ("hepta.hia.safe-core-build.v1", "checked", "smt_validated_not_executed"))
            self.assertEqual(receipt["runtime_solver_calls"], 0)
            self.assertEqual(receipt["selection_refusals"], [
                {"strategy": "scalar", "reason": "E_HIA_VERIFIED_SCALAR: only one straight-line block is supported"},
                {"strategy": "simd", "reason": "E_HIA_VERIFIED_SIMD: one primitive v8 Core function required"}])
            compilation = receipt["compilation"]
            self.assertEqual(compilation["schema"], "hepta.hia.program.direct-native.v1")
            digest = sha256(output.read_bytes()).hexdigest()
            self.assertEqual((compilation["artifact_sha256"], receipt["artifact_sha256"]), (digest, digest))
            proof = receipt["machine_proof"]
            validation = receipt["validation"]
            self.assertTrue(validation["ok"] and validation["complete"])
            self.assertEqual(validation["validation_mode"], "independent_supplied_bytes")
            self.assertEqual(validation["source_identity"]["supplied_core_sha256"], sha256(source.read_bytes()).hexdigest())
            self.assertEqual(validation["image_binding"]["supplied_object_sha256"], compilation["object_sha256"])
            self.assertEqual(validation["image_binding"]["final_image_sha256"], digest)
            self.assertEqual(validation["checker"]["receipt_sha256"], proof["receipt_sha256"])
            self.assertEqual([o["result"] for o in validation["obligations"]], ["sat"] + ["unsat"] * 4)
            self.assertEqual(validation["unproved_obligations"], [])
            self.assertFalse(receipt["claims"]["serialized_receipt_authorizes_execution"])
            existing = subprocess.run(cmd, capture_output=True, env={"PATH": ""}, timeout=90)
            self.assertNotEqual(existing.returncode, 0)
            self.assertEqual(sha256(output.read_bytes()).hexdigest(), digest)
