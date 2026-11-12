"""Execute the actual pinned Rust NDU evaluator through its bounded transport.

Set HEPTA_NDU_BRIDGE to the built binary. Source provenance tests additionally
use HEPTA_NDU_BUILD and HEPTA_NDU_UPSTREAM; skipped prerequisites are not a pass
claim for the native bridge or its source custody.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "rust/hia-ndu-bridge/upstream.json").read_text())
BINARY = os.environ.get("HEPTA_NDU_BRIDGE")
BUILD = os.environ.get("HEPTA_NDU_BUILD")
UPSTREAM = os.environ.get("HEPTA_NDU_UPSTREAM")
Q32 = 1 << 32


def candidate(name, cost, *, resource=0, uncertainty=0, violation=False):
    return {"id": name, "cost_q32": cost, "uncertainty_q32": uncertainty,
            "resource_q32": resource, "hard_violation": violation,
            "support_sha256": sha256(("independent-support:" + name).encode()).hexdigest()}


def request(*candidates):
    return {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "11" * 32,
            "generation": 7, "resource_cap_q32": 100 * Q32,
            "candidates": [candidate("abstain", 1000 * Q32), *candidates]}


@unittest.skipUnless(BINARY and Path(BINARY).is_file(), "actual native NDU bridge path is required")
class NativeNDUBridgeTests(unittest.TestCase):
    def invoke(self, value, *, raw=False):
        encoded = value if raw else json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        return subprocess.run([BINARY], input=encoded, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10, check=False)

    def success(self, value):
        process = self.invoke(value)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        self.assertEqual(process.stderr, b"")
        result = json.loads(process.stdout)
        self.assertEqual(result["schema"], "hepta.hia.ndu-response.v1")
        self.assertEqual(result["upstream_commit"], PIN["commit"])
        self.assertEqual(result["entry_point"], PIN["entry_point"])
        self.assertEqual(result["authority"], "ADVISORY_ONLY")
        self.assertIs(result["proves_program_safety"], False)
        self.assertIs(result["global_optimality_established"], False)
        self.assertEqual(result["objective_sha256"], value["objective_sha256"])
        self.assertEqual(result["generation"], value["generation"])
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(result["request_sha256"], sha256(encoded).hexdigest())
        for field in ("evaluation_digest_v2", "evaluation_policy_digest", "utility_profile_digest"):
            self.assertRegex(result[field], r"^[a-f0-9]{64}$")
        return result

    def rejection(self, value, *, raw=False):
        process = self.invoke(value, raw=raw)
        self.assertEqual(process.returncode, 2, process.stdout.decode(errors="replace"))
        self.assertEqual(process.stdout, b"")
        result = json.loads(process.stderr)
        self.assertEqual(result["schema"], "hepta.hia.ndu-error.v1")
        self.assertEqual(result["authority"], "NONE")
        self.assertTrue(result["error"])
        return result

    def test_feasible_lower_cost_candidate_is_actual_unique_pareto_advice(self):
        result = self.success(request(candidate("slow", 80 * Q32), candidate("fast", 5 * Q32)))
        self.assertEqual(result["advisory_recommendation"], "fast")
        self.assertEqual(result["pareto_frontier"], ["fast"])
        self.assertEqual(result["disposition"], "UniqueParetoRecommendation")

    def test_illegal_best_score_cannot_outvote_hard_feasibility(self):
        result = self.success(request(candidate("illegal", 0, violation=True), candidate("legal", 9 * Q32)))
        self.assertEqual(result["advisory_recommendation"], "legal")
        self.assertEqual(result["rejected"], [{"id": "illegal", "reasons": "[HardConstraintViolation]"}])

    def test_resource_ceiling_is_hard_and_boundary_is_inclusive(self):
        result = self.success(request(candidate("over", 0, resource=100 * Q32 + 1),
                                      candidate("at_cap", 5 * Q32, resource=100 * Q32)))
        self.assertEqual(result["advisory_recommendation"], "at_cap")
        self.assertIn("ResourceCeilingExceeded", result["rejected"][0]["reasons"])

    def test_equal_costs_do_not_fabricate_a_winner(self):
        result = self.success(request(candidate("a", 5 * Q32), candidate("b", 5 * Q32)))
        self.assertIsNone(result["advisory_recommendation"])
        self.assertEqual(result["disposition"], "ParetoSetRequiresSlowPath")
        self.assertEqual(result["pareto_frontier"], ["a", "b"])

    def test_baseline_is_required_and_infeasible_baseline_rejects_entire_request(self):
        missing = request(candidate("a", 1))
        missing["candidates"].pop(0)
        self.rejection(missing)
        for field, value in (("hard_violation", True), ("resource_q32", 101 * Q32)):
            invalid = request(candidate("a", 1))
            invalid["candidates"][0][field] = value
            with self.subTest(field=field):
                self.rejection(invalid)

    def test_all_nonbaseline_candidates_rejected_keeps_explicit_baseline(self):
        result = self.success(request(candidate("a", 0, violation=True),
                                      candidate("b", 0, resource=101 * Q32)))
        self.assertEqual(result["advisory_recommendation"], "abstain")
        self.assertEqual(result["disposition"], "InfeasibleExplicitAbstain")

    def test_duplicate_ids_including_duplicate_abstain_are_rejected(self):
        self.rejection(request(candidate("x", 1), candidate("x", 2)))
        self.rejection(request(candidate("abstain", 1)))

    def test_candidate_and_raw_byte_budgets_are_enforced(self):
        self.success(request(*(candidate("c" + str(i), i + 1) for i in range(127))))
        self.rejection(request(*(candidate("c" + str(i), i + 1) for i in range(128))))
        empty = request()
        empty["candidates"] = []
        self.rejection(empty)
        error = self.rejection(b" " * (1024 * 1024 + 1), raw=True)
        self.assertIn("byte limit", error["error"])

    def test_unknown_fields_and_schema_fail_closed(self):
        wrong = request()
        wrong["schema"] = "future-unreviewed-schema"
        self.rejection(wrong)
        extra = request()
        extra["allow_unsafe"] = True
        self.rejection(extra)
        nested = request()
        nested["candidates"][0]["proof_passed"] = True
        self.rejection(nested)

    def test_malformed_json_duplicate_fields_and_trailing_documents_reject(self):
        valid = json.dumps(request()).encode()
        for raw in (b"{", b"null", b"[]", b"\xff", valid + b"{}",
                    b'{"schema":"hepta.hia.ndu-request.v1",' + valid[1:]):
            with self.subTest(raw=raw[:80]):
                self.rejection(raw, raw=True)

    def test_exact_integer_domains_missing_fields_and_nonzero_digests_are_required(self):
        for field in ("cost_q32", "resource_q32", "uncertainty_q32"):
            for value in (-1, 1.25, True, 2**63):
                invalid = request()
                invalid["candidates"][0][field] = value
                with self.subTest(field=field, value=value):
                    self.rejection(invalid)
        for value in ("00" * 32, "gg" * 32, "11", ""):
            invalid = request()
            invalid["objective_sha256"] = value
            self.rejection(invalid)
            invalid = request()
            invalid["candidates"][0]["support_sha256"] = value
            self.rejection(invalid)
        invalid = request()
        del invalid["candidates"][0]["support_sha256"]
        self.rejection(invalid)

    def test_result_digest_is_deterministic_and_invariant_to_candidate_order(self):
        original = request(candidate("a", 10), candidate("b", 20))
        reordered = copy.deepcopy(original)
        reordered["candidates"].reverse()
        first, second, third = self.success(original), self.success(original), self.success(reordered)
        self.assertEqual(first, second)
        self.assertNotEqual(first["request_sha256"], third["request_sha256"])
        self.assertEqual({k: v for k, v in first.items() if k != "request_sha256"},
                         {k: v for k, v in third.items() if k != "request_sha256"})

    def test_result_digest_binds_objective_generation_supported_values_and_profile(self):
        original = request(candidate("a", 10), candidate("b", 20))
        first = self.success(original)
        modifications = []
        changed = copy.deepcopy(original)
        changed["objective_sha256"] = "22" * 32
        modifications.append(changed)
        changed = copy.deepcopy(original)
        changed["generation"] += 1
        modifications.append(changed)
        changed = copy.deepcopy(original)
        changed["resource_cap_q32"] += 1
        modifications.append(changed)
        for field, value in (("cost_q32", 11), ("uncertainty_q32", 1),
                             ("resource_q32", 1), ("support_sha256", "33" * 32)):
            changed = copy.deepcopy(original)
            changed["candidates"][1][field] = value
            modifications.append(changed)
        for changed in modifications:
            with self.subTest(changed=changed):
                result = self.success(changed)
                self.assertNotEqual(result["evaluation_digest_v2"], first["evaluation_digest_v2"])

    def test_uncertainty_is_bound_but_does_not_claim_to_be_a_robust_cost_policy(self):
        # The original NDU Pareto comparator uses the supplied utility axis.
        # A caller must apply its own registered confidence policy to costs.
        result = self.success(request(candidate("low_but_uncertain", 1, uncertainty=1000 * Q32),
                                      candidate("certain", 2)))
        self.assertEqual(result["advisory_recommendation"], "low_but_uncertain")


@unittest.skipUnless(BUILD and UPSTREAM and BINARY, "actual build workspace and pinned Git checkout are required")
class NDUBridgeSourceProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build, cls.checkout = Path(BUILD), Path(UPSTREAM)
        cls.receipt = json.loads((cls.build / "build-receipt.json").read_text())
        archive = subprocess.check_output(["git", "archive", PIN["commit"],
                    *("codex-rs/" + crate for crate in PIN["crates"]), "codex-rs/Cargo.toml"], cwd=cls.checkout)
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            cls.original = {item.name: package.extractfile(item).read()
                            for item in package if item.isfile()}

    def test_exact_git_commit_and_complete_original_inventory_match_actual_bytes(self):
        observed = subprocess.check_output(["git", "rev-parse", PIN["commit"] + "^{commit}"],
                                           cwd=self.checkout, text=True).strip()
        self.assertEqual(observed, PIN["commit"])
        self.assertEqual(self.receipt["upstream"], PIN)
        self.assertEqual(self.receipt["original_source_files"],
                         {name: sha256(data).hexdigest() for name, data in self.original.items()})
        sources = [name for name in self.original if "/src/" in name and name.endswith(".rs")]
        self.assertGreater(len(sources), 50)
        for name, original in self.original.items():
            rel = Path(name)
            if name == "codex-rs/Cargo.toml" or len(rel.parts) == 3 and rel.name == "Cargo.toml":
                continue  # The isolated dependency manifests are separately checked.
            actual = self.build / Path(*rel.parts[1:])
            self.assertFalse(actual.is_symlink(), name)
            self.assertEqual(actual.read_bytes(), original, name)

    def test_compiled_embedded_source_manifest_is_in_original_custody(self):
        name = "codex-rs/hepta-contracts/fixtures/AUTHBUS_SOURCE_MANIFEST.v1.json"
        self.assertIn(name, self.original)
        self.assertEqual((self.build / "hepta-contracts/fixtures/AUTHBUS_SOURCE_MANIFEST.v1.json").read_bytes(),
                         self.original[name])

    def test_adapter_sources_binary_and_generated_lock_match_recorded_execution(self):
        for relative in ("src/main.rs", "Cargo.toml", "upstream.json"):
            self.assertEqual((self.build / "hia-ndu-bridge" / relative).read_bytes(),
                             (ROOT / "rust/hia-ndu-bridge" / relative).read_bytes(), relative)
        self.assertEqual(sha256(Path(BINARY).read_bytes()).hexdigest(), self.receipt["binary_sha256"])
        self.assertEqual(sha256((self.build / "Cargo.lock").read_bytes()).hexdigest(),
                         self.receipt["cargo_lock_sha256"])

    def test_complete_adapter_and_build_input_receipts_are_recomputed_from_actual_files(self):
        adapter = ROOT / "rust/hia-ndu-bridge"
        self.assertEqual(self.receipt["adapter_files"],
                         {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
                          for p in adapter.rglob("*") if p.is_file()})
        self.assertEqual((adapter / "Cargo.lock").read_bytes(), (self.build / "Cargo.lock").read_bytes())
        self.assertEqual(self.receipt["builder_sha256"],
                         sha256((ROOT / "tools/build_hia_ndu_bridge.py").read_bytes()).hexdigest())
        self.assertIn("hepta-contracts/fixtures/AUTHBUS_SOURCE_MANIFEST.v1.json", self.receipt["build_inputs"])
        for name, digest in self.receipt["build_inputs"].items():
            self.assertEqual(sha256((self.build / name).read_bytes()).hexdigest(), digest, name)

    def test_adapted_manifests_preserve_original_production_dependency_features(self):
        original_workspace = tomllib.loads(self.original["codex-rs/Cargo.toml"].decode())["workspace"]
        current_workspace = tomllib.loads((self.build / "Cargo.toml").read_text())["workspace"]
        self.assertEqual(current_workspace["resolver"], original_workspace["resolver"])
        for crate in PIN["crates"]:
            original = tomllib.loads(self.original["codex-rs/" + crate + "/Cargo.toml"].decode())
            current = tomllib.loads((self.build / crate / "Cargo.toml").read_text())
            self.assertEqual(current["dependencies"], original["dependencies"], crate)
            self.assertEqual(current.get("features", {}), original.get("features", {}), crate)
            for key in ("version", "edition", "license"):
                self.assertEqual(current["package"][key], original_workspace["package"][key])
            self.assertNotIn("dev-dependencies", current)
            for name, dependency in current["dependencies"].items():
                if dependency.get("workspace"):
                    self.assertEqual(current_workspace["dependencies"][name],
                                     original_workspace["dependencies"][name], name)


if __name__ == "__main__":
    unittest.main()
