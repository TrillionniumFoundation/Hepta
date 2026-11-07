"""Adversarial source identity and clean export checks for Selfhost-Core."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from tools.hia_selfhost_contract import (CONTRACT_PATH, PROFILE, ROOT,
                                       validate_contract)
from tools.replay_hia_selfhost_cold import cold_replay


class SelfhostContractTests(unittest.TestCase):
    def test_contract_binds_support_and_complete_seed_source_closure(self):
        contract = validate_contract()
        self.assertEqual(contract["profile"], PROFILE)
        self.assertEqual(contract["target"]["triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(contract["abi"]["entry"], "f0")
        files = contract["source_identity"]["files"]
        for path in (ROOT / "hepta").rglob("*.py"):
            self.assertEqual(files[path.relative_to(ROOT).as_posix()], sha256(path.read_bytes()).hexdigest())
        self.assertFalse(contract["claims"]["whole_HIA_language_self_hosted"])
        status = {row["area"]: row["status"] for row in contract["support"]}
        self.assertEqual(status["recursion"], "bounded_subset")
        recursion = next(row for row in contract["support"] if row["area"] == "recursion")
        self.assertEqual(recursion["limits"]["additional_frames_per_self_tail_call"], 0)
        self.assertFalse(recursion["limits"]["runtime_termination_proved"])
        self.assertIn("tools/hia_selfhost_tailcalls.py", files)
        resources = next(row for row in contract["support"] if row["area"] == "resources")
        self.assertIn("buffer.swap with both bounds before access", resources["items"])
        self.assertIn("tools/hia_selfhost_resources.py", files)
        self.assertEqual(status["successor_object_output"], "bounded_subset")
        self.assertEqual(status["general_object_linking"], "not_implemented")

    def test_capacity_growth_preserves_workspace_and_core_byte_limits(self):
        from hepta.hia_program import MAX_BYTES, MAX_NODES
        from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES,
            MAX_RELOCATIONS, RELOCATION_UPPER_BOUND, CORE_BYTES_UPPER_BOUND)
        contract = validate_contract()
        self.assertEqual(contract["limits"]["instructions"], MAX_INSTRUCTIONS)
        self.assertEqual(contract["limits"]["core_structural_nodes"], MAX_NODES)
        self.assertEqual(MAX_CORE_NODES, MAX_NODES)
        self.assertEqual(RELOCATION_UPPER_BOUND, 11265)
        self.assertLessEqual(RELOCATION_UPPER_BOUND, MAX_RELOCATIONS)
        self.assertLess(CORE_BYTES_UPPER_BOUND, MAX_BYTES)
        for key in ("source_bytes", "output_capacity_bytes", "workspace_required_bytes"):
            self.assertEqual(contract["limits"][key], 1 << 20)
        self.assertFalse(contract["capacity_derivation"]["capacity_growth_changes_source_output_workspace_bytes"])

    def test_upgrade_refuses_an_unpinned_historical_image_before_execution(self):
        from tools.replay_hia_selfhost_upgrade import upgrade_replay
        with tempfile.TemporaryDirectory(prefix="hia-upgrade-refusal-") as temporary:
            root = Path(temporary)
            (root / "B3.input.bin").write_bytes(b"untrusted source")
            (root / "B3.image.bin").write_bytes(b"untrusted image")
            (root / "B3.receipt.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "pinned upgrade input"):
                upgrade_replay(root, root / "result.json")
            self.assertFalse((root / "result.evidence").exists())

    def test_changed_loader_or_broadened_support_cannot_reuse_the_contract(self):
        declared = validate_contract()
        with tempfile.TemporaryDirectory(prefix="hia-selfhost-contract-") as temporary:
            root = Path(temporary)
            for name in [*declared["source_identity"]["files"], CONTRACT_PATH]:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            validate_contract(root)
            loader = root / "tools/hia_selfhost_child.py"
            original = loader.read_bytes()
            loader.write_bytes(original + b"\n# changed loader\n")
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)
            loader.write_bytes(original)
            broadened = json.loads((root / CONTRACT_PATH).read_text())
            broadened["limits"]["functions"] = 1024
            (root / CONTRACT_PATH).write_text(json.dumps(broadened))
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)

    def test_cold_output_refuses_existing_and_symbolic_paths_before_creating_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-output-refusal-") as temporary:
            root = Path(temporary)
            existing = root / "existing.json"
            existing.write_text("original")
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(existing)
            self.assertEqual(existing.read_text(), "original")
            leaf = root / "leaf.json"
            leaf.symlink_to(root / "absent.json")
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing", target_is_directory=True)
            for output in (leaf, linked / "report.json", dangling / "report.json"):
                with self.subTest(path=output), self.assertRaisesRegex(ValueError, "symbolic links"):
                    cold_replay(output)
            self.assertFalse((root / "absent.json").exists())
            self.assertEqual(list(actual.iterdir()), [])
            self.assertFalse((root / "missing").exists())


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and shutil.which("ld"), "Linux x86-64 and GNU ld required")
class SelfhostColdReplayTests(unittest.TestCase):
    def test_source_only_clean_rebuild_has_original_and_modified_fixed_points(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-replay-test-") as temporary:
            output = Path(temporary) / "cold.json"
            result = cold_replay(output)
            self.assertEqual(result["status"], "COLD_SELFHOST_REPLAY_PASS", result["checks"])
            self.assertEqual(len(set(result["generation_sha256"])), 1)
            first, second, third = result["modified_generation_sha256"]
            self.assertNotEqual(first, second)
            self.assertEqual(second, third)
            self.assertNotEqual(third, result["generation_sha256"][0])
            self.assertFalse(result["isolation"]["virtual_machine"])
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(output)


if __name__ == "__main__":
    unittest.main()
