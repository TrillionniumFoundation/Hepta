"""Extracted capability rules remain inside every accepted proof source lock."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_scalar_call_validation as calls
from hepta import hia_scalar_totality as totality
from hepta import hia_translation_validation as scalar
from tests.test_hia_program import arithmetic
from tests.test_hia_scalar_totality import guarded_call_division
from tools import qualify_hia_sequential_core as proof


class ScalarProofIdentityTests(unittest.TestCase):
    def implementation_copy(self, directory):
        original = Path(totality.__file__).parent
        names = set(totality._primitive_implementation_identity())
        names.update(totality._call_implementation_identity())
        names.add("hia_capability_flow.py")
        for name in names:
            shutil.copyfile(original / name, directory / name)
        return directory / "hia_scalar_totality.py"

    @staticmethod
    def drift(path):
        # Change real file bytes in a private copy of the proof source lock.
        # Live checker/encoder bindings continue to execute the genuine code.
        path.write_bytes(path.read_bytes() + b"\n# identity drift control\n")

    def test_primitive_totality_refuses_changed_extracted_capability_source(self):
        original = scalar._Encoder.function
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            location = self.implementation_copy(directory)

            def encode(encoder, *args, **kwargs):
                result = original(encoder, *args, **kwargs)
                self.drift(directory / "hia_capability_flow.py")
                return result

            with (patch.object(totality, "__file__", str(location)),
                  patch.object(scalar._Encoder, "function", encode)):
                result = totality.validate_scalar_totality(arithmetic("int.add.wrap", "u32"))
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "implementation_changed_during_proof")
        self.assertIn("hia_capability_flow.py", result["implementation"])
        self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_call_totality_refuses_changed_extracted_capability_source(self):
        original = calls._Calls.function
        changed = False
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            location = self.implementation_copy(directory)

            def encode(encoder, *args, **kwargs):
                nonlocal changed
                result = original(encoder, *args, **kwargs)
                if not changed:
                    self.drift(directory / "hia_capability_flow.py")
                    changed = True
                return result

            with (patch.object(totality, "__file__", str(location)),
                  patch.object(calls._Calls, "function", encode)):
                result = totality.validate_scalar_call_totality(
                    guarded_call_division(), function="calculate")
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "implementation_changed_during_proof")
        self.assertIn("hia_capability_flow.py", result["implementation"])
        self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_composed_proof_refuses_capability_drift_after_valid_totality(self):
        original = proof.validate_scalar_totality
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in {*proof.SOURCE_FILES, "hepta/hia_capability_flow.py"}:
                destination = directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(proof.ROOT / name, destination)

            def prove(*args, **kwargs):
                result = original(*args, **kwargs)
                self.assertEqual(result["status"], "proved", result)
                self.drift(directory / "hepta/hia_capability_flow.py")
                return result

            with (patch.object(proof, "ROOT", directory),
                  patch.object(proof, "validate_scalar_totality", prove)):
                result = proof.verify_sequential_core(arithmetic("int.add.wrap", "u32"))
        self.assertFalse(result["passed"], result)
        self.assertEqual(result["reason"], "proof_implementation_changed")
        self.assertIn("hepta/hia_capability_flow.py", result["source_identity"])
        self.assertFalse(any(result["claims"].values()))


if __name__ == "__main__":
    unittest.main()
