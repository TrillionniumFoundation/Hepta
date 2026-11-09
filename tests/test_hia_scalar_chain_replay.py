"""A saved query result must stay attached to the complete original artifact chain."""
from copy import copy, deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools.qualify_hia_scalar_adoption_chain import main as qualify
from tools.replay_hia_scalar_adoption_chain import Packet, check_family, recompute_family, saved_queries, main


ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class ScalarChainReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-chain-replay-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.output = cls.root / "actual-u32"
        qualify(["--output", str(cls.output), "--types", "u32", "--campaign-id", "chain-replay-test"])
        cls.manifest = sha256((cls.output / "original-files.json").read_bytes()).hexdigest()
        cls.packet = Packet(cls.output, cls.manifest)
        cls.report = cls.packet.json("report.json")
        cls.family = cls.report["families"][0]

    def isolated_packet(self):
        # Isolate internal consistency checks from the initial manifest check.
        # These contradictory in-memory test records never authorize execution.
        packet = copy(self.packet)
        packet.files = dict(self.packet.files)
        return packet

    def test_complete_chain_and_fresh_models_never_emit_or_load_native_code(self):
        from hepta.hia_safe_core import validate_safe_core_artifact
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("emission")), \
             patch("hepta.hia_program_native.compile_program_machine", side_effect=AssertionError("linkage")), \
             patch("hepta.hia_agent_runner.run_native_batch", side_effect=AssertionError("native execution")), \
             patch("hepta.hia_safe_core.validate_safe_core_artifact", wraps=validate_safe_core_artifact) as validate:
            checked = check_family(self.packet, self.report, self.family)
            fresh = recompute_family(self.packet, self.report, self.family, self.root / "fresh-proof")
        self.assertEqual(checked["recorded_owner_calls_checked"], 10)
        self.assertEqual(checked["original_artifacts_checked"], 52)
        self.assertEqual(fresh["fresh_queries_checked"], 13)
        self.assertTrue(fresh["saved_queries_reencoded_identically"])
        self.assertFalse(fresh["producer_reemission_used"])
        self.assertFalse(fresh["native_image_loaded"])
        self.assertEqual(validate.call_count, 2)
        for call in validate.call_args_list:
            self.assertIs(type(call.args[1]), bytes)
            self.assertIs(type(call.args[2]), bytes)

    def test_missing_original_receipts_and_unmanifested_report_are_refused(self):
        for name in ("report.json", "u32/adoption.json", "u32/rollback.json", "u32/context.json",
                     "u32/core.hia.json", "u32/core-core_admission-evidence.json"):
            with self.subTest(member=name):
                packet = self.isolated_packet()
                del packet.files[name]
                with self.assertRaisesRegex(ValueError, "unmanifested"):
                    if name == "report.json":
                        packet.json(name)
                    else:
                        check_family(packet, self.report, self.family)

    def test_complete_refs_abi_and_generation_trajectory_must_agree(self):
        changes = [
            lambda row: row["identity_chain"]["final_image"].update(id="another-artifact"),
            lambda row: row["identity_chain"]["object"].update(id="another-object"),
            lambda row: row["identity_chain"]["plan"].update(id="another-plan"),
            lambda row: row["identity_chain"]["abi_signatures"]["capped_add"].update(returns=["u64"]),
            lambda row: row["identity_chain"]["target_profile"].update(sha256="0" * 64),
            lambda row: row["identity_chain"]["machine_proof"].update(id="another-proof"),
            lambda row: row["adoption"]["current"].update(generation="2"),
            lambda row: row["rollback"]["current"].update(epoch="1"),
            lambda row: row["retained_lease_after_rollback"].update(generation="0"),
            lambda row: row["new_lease_after_rollback"].update(artifact=row["planned"]["native_artifact"]),
        ]
        for index, change in enumerate(changes):
            with self.subTest(inconsistent_field=index):
                family = deepcopy(self.family)
                change(family)
                with self.assertRaises(ValueError):
                    check_family(self.packet, self.report, family)

    def test_every_recorded_owner_call_is_rechecked(self):
        packet = self.isolated_packet()
        observations = packet.json("u32/owner-observations.json")
        observations[-1]["observation"]["values"] = [0]
        packet.files["u32/owner-observations.json"] = json.dumps(observations).encode()
        with self.assertRaisesRegex(ValueError, "owner result"):
            check_family(packet, self.report, self.family)

    def test_saved_queries_require_the_exact_complete_obligation_inventory(self):
        for alteration in ("missing", "unknown", "renamed"):
            with self.subTest(alteration=alteration):
                packet = self.isolated_packet()
                family = deepcopy(self.family)
                specification = family["specification"]
                if alteration == "missing":
                    specification["obligations"].pop()
                elif alteration == "unknown":
                    specification["obligations"][-1]["result"] = "unknown"
                else:
                    specification["obligations"][-1]["name"] = "different-property"
                packet.files["u32/specification/specification.json"] = json.dumps(specification).encode()
                with self.assertRaises(ValueError):
                    saved_queries(packet, family)

    def test_broken_journal_cannot_report_a_complete_operation(self):
        packet = self.isolated_packet()
        lines = packet.read("u32/calls.jsonl").splitlines()
        packet.files["u32/calls.jsonl"] = b"\n".join(lines[:-1]) + b"\n"
        with self.assertRaisesRegex(ValueError, "journal is incomplete"):
            check_family(packet, self.report, self.family)

    def assert_dependency_rejected(self, filename, mutate, message):
        packet = self.isolated_packet()
        actual_reference = packet.reference
        reference = self.family["exports"][filename]
        inconsistent = deepcopy(actual_reference(self.family, reference))
        mutate(inconsistent)

        def read(family, selected):
            # Keep original artifact/hash reads intact, then isolate the
            # relationship check from its independently validated dependency.
            return inconsistent if selected == reference else actual_reference(family, selected)

        with patch.object(packet, "reference", side_effect=read):
            with self.assertRaisesRegex(ValueError, message):
                check_family(packet, self.report, self.family)

    def test_plan_evidence_matches_exact_plan_and_both_original_objects(self):
        changes = [
            lambda evidence: evidence["plan"]["block_order"]["capped_add"].reverse(),
            lambda evidence: evidence.update(canonical_object_sha256="0" * 64),
            lambda evidence: evidence.update(planned_object_sha256="0" * 64),
            lambda evidence: evidence["choice_checks"][0].update(checked=False),
            lambda evidence: evidence["canonical_frame_bytes"].update(capped_add=0),
            lambda evidence: evidence["planned_frame_bytes"].update(capped_add=0),
            lambda evidence: evidence.update(same_slots=False),
            lambda evidence: evidence.update(implicit_optimizer_used=True),
        ]
        for index, change in enumerate(changes):
            with self.subTest(inconsistent_plan_field=index):
                self.assert_dependency_rejected("plan-lowering_refinement-evidence.json", change,
                                                "plan proof evidence differs")

    def test_encoding_evidence_matches_rederived_image_and_complete_build_identity(self):
        changes = [
            lambda evidence: evidence.update(rederived_sha256="0" * 64),
            lambda evidence: evidence.update(no_llvm_or_external_assembler=False),
            lambda evidence: evidence["native_build"]["object_artifact"].update(id="another-object"),
            lambda evidence: evidence["native_build"]["function_frames"].update(capped_add=0),
            lambda evidence: evidence["native_build"].update(artifact_bytes=0),
        ]
        for field in ("core_sha256", "input_sha256", "implementation_sha256", "machine_plan_sha256",
                      "object_sha256", "artifact_sha256", "target", "profile", "kind"):
            changes.append(lambda evidence, field=field: evidence["native_build"].update({field: "different"}))
        for index, change in enumerate(changes):
            with self.subTest(inconsistent_encoding_field=index):
                self.assert_dependency_rejected("encoding-encoding_check-evidence.json", change,
                                                "encoding proof evidence differs")

    def test_profile_inventory_cannot_omit_a_complete_profile_definition(self):
        packet = self.isolated_packet()
        actual_artifact = packet.artifact

        def read(family, name, expected=None):
            value = actual_artifact(family, name, expected)
            if name == "installation-manifest.json":
                value = deepcopy(value)
                del value["profiles"]["artifact"]
                del value["profile_manifests"]["artifact"]
            return value

        with patch.object(packet, "artifact", side_effect=read):
            with self.assertRaisesRegex(ValueError, "original profile inventory differs"):
                check_family(packet, self.report, self.family)

    def test_operation_requests_and_order_must_match_the_original_receipts(self):
        changes = [
            ("hia_evaluate", "catalog_sha256", "0" * 64),
            ("hia_evaluate", "context", {**self.family["context"], "id": "another-context"}),
            ("hia_evaluate", "baseline_artifact", self.family["planned"]["native_artifact"]),
            ("hia_evaluate", "candidate_artifact", self.family["canonical"]["native_artifact"]),
            ("hia_evaluate", "build_receipt", self.family["canonical"]["build_receipt"]),
            ("hia_evaluate", "verification_receipts", []),
            ("hia_adopt", "target_slot", "different-slot"),
            ("hia_adopt", "expected_current", {"generation": "1", "epoch": "1"}),
            ("hia_adopt", "candidate_artifact", self.family["canonical"]["native_artifact"]),
            ("hia_adopt", "evaluation_receipt", {**self.family["evaluation"]["evaluation_receipt"], "id": "other"}),
            ("hia_rollback", "target_slot", "different-slot"),
            ("hia_rollback", "expected_current", {"generation": "0", "epoch": "0"}),
            ("hia_rollback", "retained_generation", "1"),
            ("hia_rollback", "reason", "different-reason"),
        ]
        for tool, field, value in changes:
            with self.subTest(tool=tool, field=field):
                packet = self.isolated_packet()
                events = [json.loads(line) for line in packet.read("u32/calls.jsonl").splitlines()]
                for event in events:
                    if event["tool"] == tool:
                        event["arguments"][field] = deepcopy(value)
                packet.files["u32/calls.jsonl"] = b"\n".join(json.dumps(event).encode() for event in events) + b"\n"
                with self.assertRaisesRegex(ValueError, "journal request differs"):
                    check_family(packet, self.report, self.family)

        packet = self.isolated_packet()
        events = [json.loads(line) for line in packet.read("u32/calls.jsonl").splitlines()]
        pairs = [events[index:index + 2] for index in range(0, len(events), 2)]
        adopt = next(index for index, pair in enumerate(pairs) if pair[0]["tool"] == "hia_adopt")
        rollback = next(index for index, pair in enumerate(pairs) if pair[0]["tool"] == "hia_rollback")
        pairs[adopt], pairs[rollback] = pairs[rollback], pairs[adopt]
        for index, pair in enumerate(pairs, 1):
            for event in pair:
                event["sequence"] = index
        packet.files["u32/calls.jsonl"] = b"\n".join(
            json.dumps(event).encode() for pair in pairs for event in pair) + b"\n"
        with self.assertRaisesRegex(ValueError, "journal operation order differs"):
            check_family(packet, self.report, self.family)

    def test_changed_member_bytes_fail_the_selected_manifest(self):
        destination = self.root / "changed-packet"
        shutil.copytree(self.output, destination)
        path = destination / "u32/source.hia.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "retained artifact bytes differ"):
            Packet(destination, self.manifest)

    def test_same_version_with_different_solver_identity_cannot_rebuild_a_proof(self):
        packet = self.isolated_packet()
        family = deepcopy(self.family)
        # Fresh proofs must use the original identified model and solver.
        family["specification"]["solver"]["library_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "fresh specification identity differs: solver"):
            recompute_family(packet, self.report, family, self.root / "different-solver")


@unittest.skipUnless(importlib.util.find_spec("z3") is not None, "pinned Z3 is required")
class HistoricalScalarReplayTests(unittest.TestCase):
    def test_v1_needs_explicit_query_only_mode_and_never_claims_a_complete_chain(self):
        archive = ROOT / "review-evidence/hia-scalar-adoption-chain-20261109/chain-b78868a.tar.gz"
        with tempfile.TemporaryDirectory(prefix="hia-legacy-replay-test-") as temporary:
            root = Path(temporary)
            with tarfile.open(archive) as source:
                source.extractall(root, filter="data")
            packet = root / "chain"
            manifest = sha256((packet / "original-files.json").read_bytes()).hexdigest()
            arguments = ["--input", str(packet), "--expected-manifest-sha256", manifest]
            with self.assertRaisesRegex(ValueError, "historical v1 needs --legacy-query-only"):
                main(arguments + ["--output", str(root / "strict-refusal.json")])
            self.assertEqual(main(arguments + ["--output", str(root / "legacy.json"), "--legacy-query-only"]), 0)
            result = json.loads((root / "legacy.json").read_bytes())
            self.assertEqual(result["status"], "passed_saved_queries_only")
            self.assertEqual(len(result["queries"]), 52)
            self.assertFalse(result["complete_artifact_chain_checked"])
            self.assertFalse(result["fresh_native_execution"])
            self.assertFalse(result["execution_authority_granted"])


if __name__ == "__main__":
    unittest.main()
