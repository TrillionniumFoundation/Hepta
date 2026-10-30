"""Real changed upstream bodies, honest old-UB failures and finite replay."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_stb_divide_update as q


class StbUpdateReadbackBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = q.ROOT / "tests/fixtures/c_migration/stb_divide_vm_readback.json"
        cls.samples = json.loads(fixture.read_text())["cases"]

    def check(self, sample):
        q.validate_vm_observation(sample["vm"], **{key: sample[key]
            for key in ("program_sha256", "function", "arguments", "expected", "code")})

    def test_archived_vm_samples_replay_without_launching_or_evaluating_code(self):
        self.assertEqual(len(self.samples), 6)
        with patch.object(q, "execute_program", side_effect=AssertionError("readback must not execute VM")), \
             patch.object(q, "run_bounded", side_effect=AssertionError("readback must not launch child")):
            for sample in self.samples:
                self.check(sample)

    def test_embedded_vm_identities_values_traps_and_cost_refuse_actual_record_mutations(self):
        common = {
            "wrong_program": lambda s: s["vm"]["observation"].update(program_sha256="0" * 64),
            "wrong_input": lambda s: s["vm"]["observation"].update(input_sha256="0" * 64),
            "wrong_function": lambda s: s["vm"]["observation"].update(function="other"),
            "wrong_inner_status": lambda s: s["vm"]["observation"].update(status="unobserved"),
            "wrong_outer_status": lambda s: s["vm"].update(status="unobserved"),
            "negative_wall": lambda s: s["vm"].update(wall_ns=-1),
            "boolean_wall": lambda s: s["vm"].update(wall_ns=True),
            "boolean_step": lambda s: s["vm"]["observation"].update(steps=True),
            "missing_ledger": lambda s: s["vm"]["observation"].update(resources={}),
            "boolean_zero_ledger": lambda s: s["vm"]["observation"]["resources"].update(live_bytes=False),
            "invented_proof": lambda s: s["vm"]["observation"]["claims"].update(backend_refinement_proved=True),
            "bool_argument": lambda s: s.update(arguments=[True, 1]),
            "wide_argument": lambda s: s.update(arguments=[q.MAX + 1, 1]),
        }
        for sample in self.samples:
            extra = ({
                "wrong_stable_code": lambda s: s["vm"]["observation"]["error"].update(code="unrelated"),
                "wrong_outer_code": lambda s: s["vm"].update(code="unrelated"),
                "trap_with_values": lambda s: s["vm"]["observation"].update(values=[123]),
            } if sample["code"] else {
                "wrong_values": lambda s: s["vm"]["observation"].update(values=[123]),
                "bool_result": lambda s: s["vm"]["observation"].update(result=True),
                "bool_values": lambda s: s["vm"]["observation"].update(values=[True]),
                "return_with_error": lambda s: s["vm"]["observation"].update(error={"code": "overflow"}),
            })
            for name, change in {**common, **extra}.items():
                with self.subTest(sample=sample["name"], mutation=name):
                    changed = copy.deepcopy(sample)
                    change(changed)
                    with self.assertRaises(ValueError):
                        self.check(changed)

    def repository(self, directory):
        root = Path(directory)
        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Hepta test", "-c",
                "user.email=hepta-test@example.invalid", *args], cwd=root, stderr=subprocess.PIPE)
        git("init", "-q")
        for name in q.SOURCE_FILES | {"hepta/semantic.py"}:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# inert committed source-ledger fixture\n")
        (root / ".gitignore").write_text("hepta/hidden.py\n")
        git("add", ".")
        git("commit", "-qm", "source ledger fixture")
        return root, git

    def test_hidden_worktree_byte_mode_or_link_drift_cannot_claim_exact_commit(self):
        for kind in ("assume_unchanged", "skip_worktree", "ignored_extra", "mode", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="stb-source-binding-") as directory:
                root, git = self.repository(directory)
                original = q.source_state(root)
                q.validate_commit_source(original, original["head"], root=root, check_worktree=True)
                path = root / "hepta/semantic.py"
                if kind in {"assume_unchanged", "skip_worktree", "symlink"}:
                    git("update-index", "--assume-unchanged" if kind == "assume_unchanged" else "--skip-worktree",
                        "--", "hepta/semantic.py")
                    if kind == "symlink":
                        target = root / "tools/qualify_c_stb_divide.py"
                        path.unlink()
                        path.symlink_to(target)
                    else:
                        path.write_text("# modified executable bytes hidden from status\n")
                elif kind == "ignored_extra":
                    (root / "hepta/hidden.py").write_text("# ignored extra source module\n")
                else:
                    git("config", "core.filemode", "false")
                    path.chmod(0o755)
                changed = q.source_state(root)
                self.assertEqual(changed["status"], "")
                with self.assertRaises(ValueError):
                    q.validate_commit_source(changed, changed["head"], root=root, check_worktree=True)
                # A dirty/historical source ledger can be collected for testing;
                # it is the explicit commit-qualification claim that is refused.
                self.assertEqual(changed["head"], original["head"])

    def test_commit_ledger_checks_raw_tree_and_complete_source_inventory(self):
        with tempfile.TemporaryDirectory(prefix="stb-source-ledger-") as directory:
            root, _git = self.repository(directory)
            original = q.source_state(root)
            q.validate_commit_source(original, original["head"], root=root)
            for field in ("tree", "file_digest", "missing_file", "extra_file"):
                with self.subTest(field=field):
                    changed = copy.deepcopy(original)
                    if field == "tree":
                        changed["tree"] = "0" * 40
                    elif field == "file_digest":
                        changed["files"]["hepta/semantic.py"]["sha256"] = "0" * 64
                    elif field == "missing_file":
                        changed["files"].pop("hepta/semantic.py")
                    else:
                        changed["files"]["hepta/extra.py"] = changed["files"]["hepta/semantic.py"]
                    with self.assertRaises(ValueError):
                        q.validate_commit_source(changed, changed["head"], root=root)


class StbUpdateProtocolTests(unittest.TestCase):
    def test_complete_original_headers_have_distinct_fixed_git_identities_and_licenses(self):
        pins = q.verify_inputs()
        self.assertNotEqual(pins["0.93"]["sha256"], pins["0.94"]["sha256"])
        self.assertEqual(pins["0.93"]["bytes"], 14279)
        self.assertEqual(pins["0.94"]["bytes"], 14507)
        with tempfile.TemporaryDirectory(prefix="stb-update-source-control-") as directory:
            fixture = Path(directory)
            shutil.copyfile(q.BASELINE / "UPSTREAM.json", fixture / "UPSTREAM.json")
            shutil.copyfile(q.SUCCESSOR / "stb_divide.h", fixture / "stb_divide.h")
            with patch.object(q, "BASELINE", fixture), self.assertRaisesRegex(ValueError, "original header"):
                q.verify_inputs()

    def test_frozen_common_domain_and_old_undefined_witnesses_are_disjoint(self):
        rows = q.cases()
        self.assertEqual(len(rows), 119)
        self.assertEqual(len({(row["a"], row["b"]) for row in rows}), 119)
        self.assertTrue(all(q.common_defined(row["a"], row["b"]) for row in rows))
        for witness in q.WITNESSES:
            self.assertFalse(q.common_defined(*witness["arguments"]))
            values = q.oracle(*witness["arguments"])
            self.assertEqual(len(values), 6)
            self.assertTrue(all(q.MIN <= value <= q.MAX for value in values))
        for args in ((7, 0), (q.MIN, -1), (True, 1), (0, q.MAX + 1)):
            self.assertFalse(q.common_defined(*args))
            with self.assertRaises(ValueError):
                q.oracle(*args)
        self.assertFalse(q.PROTOCOL["old_undefined_inputs_are_equivalence_successes"])
        self.assertFalse(q.CLAIMS["foreign_noexcept_recovery_qualified"])

    def test_wrong_source_head_fails_before_compilers_and_retains_terminal_cost(self):
        with tempfile.TemporaryDirectory(prefix="stb-update-source-failure-") as directory:
            output = Path(directory) / "attempt"
            with patch.object(q, "run_bounded") as launch:
                report = q.qualify(output, clang="uninvoked-clang", gcc="uninvoked-gcc", source_sha="0" * 40)
                launch.assert_not_called()
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["qualified_implementation_commit"])
            self.assertEqual(report["versions"], [])
            self.assertGreater(report["collected_work_wall_ns"], 0)
            self.assertEqual(report["source_before"], report["source_after"])
            self.assertIn("exact clean implementation commit", report["error"]["message"])
            self.assertEqual(json.loads((output / "qualification.json").read_text()), report)


class StbUpdateNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clang = os.environ.get("CLANG") or os.environ.get("HEPTA_CLANG") or shutil.which("clang-20") or shutil.which("clang")
        gcc = os.environ.get("HEPTA_STB_GCC") or shutil.which("gcc")
        if not clang or not gcc:
            raise unittest.SkipTest("actual Clang20+, GCC UBSan and Linux x86-64 required")
        retained = os.environ.get("HEPTA_STB_UPDATE_TEST_EVIDENCE")
        if retained:
            cls.output = Path(retained).absolute()
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-stb-changed-body-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.output = Path(cls.temporary.name) / "run"
        cls.report = q.qualify(cls.output, clang=clang, gcc=gcc)
        if not cls.report["ok"]:
            raise AssertionError(json.dumps({"output": str(cls.output), **{key: cls.report.get(key)
                for key in ("status", "error", "postflight_error", "readback_error", "collected_work_wall_ns")}}, sort_keys=True))

    def test_complete_changed_component_recaptured_to_distinct_core_and_direct_llvm(self):
        replay = q.validate_qualification(self.output)
        self.assertTrue(replay["verified"])
        old, new = self.report["versions"]
        self.assertEqual(self.report["changed_active_functions"], ["stb_div_floor", "stb_mod_eucl"])
        self.assertNotEqual(old["core_sha256"], new["core_sha256"])
        self.assertNotEqual(old["hia_artifact"], new["hia_artifact"])
        self.assertEqual(self.report["counts"]["common_native_function_observations"], 2856)
        self.assertEqual(self.report["counts"]["common_vm_function_observations"], 1428)
        self.assertTrue(self.report["development_only"])
        self.assertFalse(self.report["qualified_implementation_commit"])
        for version in ("0.93", "0.94"):
            build = json.loads((self.output / version / "native-build.json").read_text())
            self.assertFalse(build["claims"]["rust_codegen_used"])
            self.assertFalse(build["claims"]["fallback_used"])
            self.assertEqual(self.report["versions"][int(version == "0.94")]["active_declarations"], 12)

    def test_old_undefined_failures_and_successor_defined_returns_keep_separate_denominators(self):
        old, new = self.report["versions"]
        processes = self.report["processes"]
        self.assertEqual(len(old["witnesses"]), 4)
        self.assertEqual(len(new["witnesses"]), 4)
        for before, after in zip(old["witnesses"], new["witnesses"]):
            self.assertEqual(before["status"], "original_c_undefined_hia_trapped")
            self.assertEqual(after["status"], "successor_defined_return")
            self.assertNotEqual(processes[before["original_c_process"]]["returncode"], 0)
            self.assertEqual(processes[before["hia_native_process"]]["returncode"], -signal.SIGABRT)
            self.assertFalse(before["common_domain_equivalence_claimed"])
            self.assertFalse(after["common_domain_equivalence_claimed"])
            self.assertEqual(before["vm"]["code"], "overflow")
            self.assertEqual(after["vm"]["observation"]["result"], after["expected_successor_value"])
        self.assertEqual(self.report["counts"]["successor_only_native_function_observations"], 48)
        self.assertFalse(self.report["claims"]["all_input_source_or_backend_refinement_proved"])

    def test_actual_stale_and_resource_legal_wrong_targets_fail_native_observation(self):
        controls, processes = self.report["negative_controls"], self.report["processes"]
        self.assertEqual(processes[controls["stale_target_process"]]["returncode"], -signal.SIGABRT)
        self.assertEqual(processes[controls["wrong_target_process"]]["returncode"], 2)
        self.assertIn("functional mismatch", processes[controls["wrong_target_process"]]["stderr"])

    def test_readback_refuses_promoted_failures_counts_sources_or_unrelated_processes(self):
        mutations = {
            "old_failure_promoted": lambda r: r["versions"][0]["witnesses"][0].update(status="successor_defined_return"),
            "missing_failure": lambda r: r["versions"][0]["witnesses"].pop(),
            "unknown_failure_domain": lambda r: r["versions"][0]["witnesses"][0].update(common_domain_equivalence_claimed=True),
            "old_core_substitution": lambda r: r["versions"][1].update(core_sha256=r["versions"][0]["core_sha256"]),
            "bool_counter": lambda r: r["counts"].update(old_ubsan_failure_processes=True),
            "false_common_count": lambda r: r["versions"][0]["common_native"]["summary"].update(cases=1),
            "unrelated_process": lambda r: r["versions"][0]["common_native"].update(process=0),
            "unretained_stream": lambda r: r["processes"][0].update(stdout_file="../unrelated.txt"),
            "duplicate_invalid_input": lambda r: r["versions"][0]["invalid_target_inputs"].__setitem__(1, r["versions"][0]["invalid_target_inputs"][0]),
            "invented_ffi_recovery": lambda r: r["claims"].update(foreign_noexcept_recovery_qualified=True),
            "development_promoted": lambda r: r.update(qualified_implementation_commit=True),
            "wrong_vm_program": lambda r: r["versions"][0]["witnesses"][0]["vm"]["observation"].update(program_sha256="0" * 64),
            "wrong_vm_function": lambda r: r["versions"][0]["witnesses"][0]["vm"]["observation"].update(function="other"),
            "wrong_vm_trap": lambda r: r["versions"][0]["invalid_target_inputs"][0]["vm"]["observation"]["error"].update(code="overflow"),
            "negative_vm_wall": lambda r: r["versions"][0]["witnesses"][0]["vm"].update(wall_ns=-1),
            "wrong_successor_values": lambda r: r["versions"][1]["witnesses"][0]["vm"]["observation"].update(values=[123]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(self.report)
                mutate(changed)
                with self.assertRaises(ValueError):
                    q.validate_qualification(self.output, changed)

    def test_readback_rehashes_actual_artifact_in_relocated_evidence(self):
        with tempfile.TemporaryDirectory(prefix="stb-update-byte-control-") as directory:
            copied = Path(directory) / "copy"
            shutil.copytree(self.output, copied)
            self.assertTrue(q.validate_qualification(copied)["verified"])
            for version, label in (("0.93", "common"), ("0.94", "successor-only")):
                name = version + "/" + label + "-vm.jsonl"
                path = copied / name
                original = path.read_bytes()
                for change in (
                    lambda row: row["observation"].update(program_sha256="0" * 64),
                    lambda row: row["observation"].update(function="other"),
                    lambda row: row["observation"].update(values=[123]),
                    lambda row: row.update(arguments=[True, 1]),
                ):
                    rows = [json.loads(line) for line in original.splitlines()]
                    change(rows[0])
                    path.write_text("".join(q.wire(row) + "\n" for row in rows))
                    changed = copy.deepcopy(self.report)
                    changed["retained_files"][name] = q.identity(path)
                    # A new outer digest cannot bypass the frozen input or
                    # embedded observation's Core/function/result binding.
                    with self.assertRaises(ValueError):
                        q.validate_qualification(copied, changed)
                path.write_bytes(original)
            artifact = copied / "0.94/hia.so"
            data = artifact.read_bytes()
            artifact.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            with self.assertRaisesRegex(ValueError, "retained file bytes"):
                q.validate_qualification(copied)


if __name__ == "__main__":
    unittest.main()
