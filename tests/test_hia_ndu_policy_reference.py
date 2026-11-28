"""Independent fixed-original policy and physical-source controls."""
from pathlib import Path
from fractions import Fraction
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
HELPER = "tools/hia_ndu_policy_reference.py"
FIXTURE = "tests/fixtures/hia_ndu_fixed_policy_original_v1/optimizer.py.txt"


class NduPolicyReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in (HELPER, FIXTURE):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        spec = importlib.util.spec_from_file_location(
            "ndu_fixed_policy_" + uuid.uuid4().hex, self.root / HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def tearDown(self):
        self.temporary.cleanup()

    def test_original_arithmetic_matches_independent_fraction(self):
        original = self.module.policy_namespace(self.root)
        numbers = {0, 1, 117, 15625, 999999, 1000000, 123456789, 2000000000000000}
        numbers.update(2147483648000000 + delta for delta in range(-5, 6))
        for n in sorted(numbers):
            with self.subTest(n=n):
                exact = round(Fraction(n * (1 << 32), 1000000))
                if exact > (1 << 63) - 1:
                    with self.assertRaisesRegex(original.OptimizationRejected, "cost exceeds"):
                        original.ns_to_ms_q32(n)
                else:
                    self.assertEqual(original.ns_to_ms_q32(n), exact)
        for n in (True, -1, 1.5, "12", 1 << 63):
            with self.subTest(invalid=repr(n)), self.assertRaisesRegex(
                    original.OptimizationRejected, "nanoseconds must"):
                original.ns_to_ms_q32(n)
        original.unchanged()

    def test_original_response_preserves_unsigned_generation_and_error_priority(self):
        original = self.module.policy_namespace(self.root)
        request = {"objective_sha256": "1" * 64, "generation": (1 << 64) - 1,
                   "candidates": [{"id": "abstain", "hard_violation": False},
                                  {"id": "wrong", "hard_violation": True}]}
        data = json.dumps(request, separators=(",", ":")).encode()
        response = {"schema": "hepta.hia.ndu-native-response.v1",
                    "upstream_commit": "d3c2d760eca5065fc966820379c35c6e8d56e855",
                    "entry_point": "hepta.hia.ndu_evaluator.v1",
                    "reference_entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
                    "objective_sha256": request["objective_sha256"], "generation": request["generation"],
                    "request_sha256": hashlib.sha256(data).hexdigest(), "authority": "ADVISORY_ONLY",
                    "proves_program_safety": False, "global_optimality_established": False,
                    "evaluation_digest_v2": "2" * 64, "evaluation_policy_digest": "3" * 64,
                    "utility_profile_digest": "4" * 64, "advisory_recommendation": "abstain"}
        identity = {"upstream_commit": response["upstream_commit"]}
        def run(value):
            raw = json.dumps(value, separators=(",", ":")).encode()
            return original._validate_native_rank_response(request, data, raw, identity)
        self.assertEqual(run(response), response)
        for key in ("proves_program_safety", "global_optimality_established"):
            changed = dict(response, **{key: 0})
            self.assertEqual(run(changed), changed)
        with self.assertRaisesRegex(original.OptimizationRejected, "does not bind"):
            run(dict(response, schema="bad", advisory_recommendation=[]))
        with self.assertRaisesRegex(original.OptimizationRejected, "malformed digest"):
            run(dict(response, evaluation_digest_v2="bad", advisory_recommendation=[]))
        with self.assertRaises(TypeError):
            run(dict(response, advisory_recommendation=[]))
        with self.assertRaisesRegex(original.OptimizationRejected, "unavailable or unproved"):
            run(dict(response, advisory_recommendation="wrong"))
        original.unchanged()

    def test_missing_fixture_is_refused_in_the_selected_root(self):
        (self.root / FIXTURE).unlink()
        with self.assertRaises(FileNotFoundError):
            self.module.policy_namespace(self.root)

    def test_changed_whole_fixture_is_refused(self):
        path = self.root / FIXTURE
        path.write_bytes(path.read_bytes() + b"\n# different historical source\n")
        with self.assertRaisesRegex(ValueError, "complete original"):
            self.module.policy_namespace(self.root)

    def test_imported_implementation_change_before_prepare_is_refused(self):
        path = self.root / HELPER
        path.write_bytes(path.read_bytes() + b"\n# changed after import\n")
        with self.assertRaisesRegex(ValueError, "executed NDU"):
            self.module.policy_namespace(self.root)

    def test_selected_foreign_implementation_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            other = Path(name)
            for item in (HELPER, FIXTURE):
                path = other / item
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.root / item, path)
            path = other / HELPER
            path.write_bytes(path.read_bytes() + b"\n# foreign selected root\n")
            with self.assertRaisesRegex(ValueError, "another implementation"):
                self.module.policy_namespace(other)

    def test_late_whole_fixture_change_is_refused(self):
        original = self.module.policy_namespace(self.root)
        path = self.root / FIXTURE
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "capture changed"):
            original.unchanged()

    def test_late_implementation_change_is_refused(self):
        original = self.module.policy_namespace(self.root)
        path = self.root / HELPER
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "executed NDU"):
            original.unchanged()

    def test_initial_capture_window_is_rechecked(self):
        mutated = False
        def take(path):
            nonlocal mutated
            raw = path.read_bytes()
            if str(path).endswith(FIXTURE) and not mutated:
                mutated = True
                path.write_bytes(raw + b"\n")
            return raw
        with self.assertRaisesRegex(ValueError, "capture changed"):
            self.module.policy_namespace(self.root, take=take)


if __name__ == "__main__":
    unittest.main()
