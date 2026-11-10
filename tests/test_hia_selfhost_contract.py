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
    def test_release_freeze_inventory_covers_the_complete_selfhost_closure(self):
        from tools.hia_release import BOOTSTRAP_FILES
        declared = validate_contract()["source_identity"]["files"]
        # The public freeze reads its own explicit inventory. A newly declared
        # selfhost helper must be present there before a release can be locked.
        self.assertEqual(set(BOOTSTRAP_FILES) - {CONTRACT_PATH},
                         {name for name in declared if not name.startswith("hepta/")})

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
        self.assertIn("tools/hia_selfhost_select.py", files)
        self.assertIn("tools/hia_selfhost_loans.py", files)
        self.assertIn("exact capability graph joins and closed loop/edge transfers", resources["items"])
        operations = next(row for row in contract["support"] if row["area"] == "integer_operations")
        self.assertIn("select (bool condition, matching scalars including unit)", operations["items"])
        self.assertEqual(status["successor_object_output"], "bounded_subset")
        self.assertEqual(status["general_object_linking"], "not_implemented")
        self.assertEqual(status["owned_resources"], "bounded_subset")
        owned = next(row for row in contract["support"] if row["area"] == "owned_resources")
        self.assertEqual(owned["output_format"], "selfhost_elf or explicit scalar-export ELF only")
        self.assertEqual(owned["items"][:4], ["buffer.new", "buffer.try_new", "owner.move", "owner.drop"])
        self.assertFalse(owned["allocation"]["workspace_is_heap"])
        self.assertEqual(owned["allocation"]["imports"], ["calloc", "free"])
        self.assertEqual(owned["excluded"], ["more than three results"])
        self.assertEqual(contract["limits"]["internal_result_area_bytes"], 64)
        self.assertEqual(contract["limits"]["internal_result_stride_bytes"], 16)
        self.assertEqual(contract["limits"]["internal_result_descriptor_words"], 2)
        self.assertEqual(contract["limits"]["function_results"], 3)
        self.assertEqual(contract["abi"]["core_return"], "u32")
        for path in ("tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
                     "tools/qualify_hia_selfhost_owned_elf.py"):
            self.assertIn(path, files)

    def test_capacity_growth_preserves_workspace_and_core_byte_limits(self):
        from hepta.hia_program import MAX_BYTES, MAX_NODES
        from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES,
            MAX_RELOCATIONS, RELOCATION_UPPER_BOUND, CORE_BYTES_UPPER_BOUND)
        contract = validate_contract()
        self.assertEqual(contract["limits"]["instructions"], MAX_INSTRUCTIONS)
        self.assertEqual(contract["limits"]["core_structural_nodes"], MAX_NODES)
        self.assertEqual(MAX_CORE_NODES, MAX_NODES)
        self.assertEqual(RELOCATION_UPPER_BOUND, 11522)
        self.assertEqual(MAX_RELOCATIONS, 12000)
        self.assertFalse(contract["limits"]["block_entry_must_be_first_in_source"])
        self.assertEqual(contract["limits"]["function_entry_block_index_record_offset"], 264)
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


def cold_failure_diagnostic(output, result):
    """Retain actual bounded child diagnosis before temporary cleanup."""
    if result.get("status") == "COLD_SELFHOST_REPLAY_PASS":
        return result["checks"]
    diagnostic = {key: result.get(key) for key in
        ("status", "checks", "returncode", "wall_elapsed_ns", "process_owner")}
    directory = Path(output).with_suffix(".cold")
    for name in ("stdout.log", "stderr.log", "qualification.evidence/phase-index.json"):
        path = directory / name
        if not path.is_file():
            continue
        # The diagnostic cannot consume an unbounded log or replace the
        # original failed assertion with a secondary parser exception.
        try:
            size = path.stat().st_size
            with path.open("rb") as stream:
                stream.seek(max(0, size - 4096))
                tail = stream.read(4096)
                stream.seek(0)
                phase_bytes = stream.read(65537) if name.endswith("phase-index.json") else None
        except OSError as exc:
            diagnostic[name] = {"diagnostic_read_error": str(exc)}
            continue
        diagnostic[name] = {"bytes": size, "tail_sha256": sha256(tail).hexdigest(),
                            "actual_tail": tail.decode("utf-8", "replace")}
        if phase_bytes is not None and len(phase_bytes) <= 65536:
            try:
                phase = json.loads(phase_bytes)
                if isinstance(phase, dict):
                    diagnostic[name].update({k: phase.get(k) for k in ("completed", "exceptions")})
            except (ValueError, UnicodeError):
                diagnostic[name]["phase_json_malformed"] = True
    return diagnostic


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and shutil.which("ld"), "Linux x86-64 and GNU ld required")
class SelfhostColdReplayTests(unittest.TestCase):
    def test_source_only_clean_rebuild_has_original_and_modified_fixed_points(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-replay-test-") as temporary:
            output = Path(temporary) / "cold.json"
            result = cold_replay(output)
            self.assertEqual(result["status"], "COLD_SELFHOST_REPLAY_PASS", cold_failure_diagnostic(output, result))
            self.assertEqual(len(result["checks"]), 11)
            self.assertTrue(result["checks"]["owned_process_tree_cleanup_confirmed"])
            self.assertEqual(result["qualification_wall_limit_seconds"], 180)
            self.assertEqual(result["cleanup_wall_limit_seconds"], 3)
            self.assertEqual(result["process_owner"]["status"], "OWNED_PROCESS_COMPLETED")
            self.assertTrue(result["process_owner"]["cleanup"]["observed_echild"])
            self.assertTrue(result["process_owner"]["cleanup"]["leader_reaped"])
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
