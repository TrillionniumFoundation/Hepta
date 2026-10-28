"""Actual Lean qualification and adversarial proof-receipt validation."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import verify_formal as formal


ROOT = Path(__file__).resolve().parents[1]


class FormalInputTests(unittest.TestCase):
    def test_version_looking_fake_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory(prefix="hepta-fake-lean-") as td:
            directory = Path(td)
            marker = directory / "executed"
            fake = directory / "lean"
            # This protocol counterfeit was sufficient for the previous gate:
            # version, eleven fabricated dependencies and two generic errors.
            fake.write_text("#!" + sys.executable + "\n" +
                "import sys\nfrom pathlib import Path\n" +
                "Path(" + repr(str(marker)) + ").write_text('executed')\n" +
                "if '--version' in sys.argv:\n print('Lean (version 4.19.0, fake, Release)')\n sys.exit(0)\n" +
                "text=Path(sys.argv[1]).read_text()\n" +
                "if 'if s.live = true ∧ s.readers = 0 ∧ s.writer = false then\\n      some { s with live := false }' not in text or 'if u.admitted + 1 ≤ b.tasks ∧ u.inputBytes + bytes ≤ b.inputBytes then' not in text:\n print('error: fabricated failure')\n sys.exit(1)\n" +
                "for name in " + repr(sorted(formal.EXPECTED_THEOREMS)) + ":\n print(\"'Hepta.\"+name+\"' depends on axioms: [propext]\")\n",
                encoding="utf-8")
            fake.chmod(0o755)
            output = directory / "report.json"
            with self.assertRaisesRegex(RuntimeError, "pinned Lean binary SHA-256"):
                formal.verify(str(fake), output)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_inventory_is_fixed_not_derived_from_any_eleven_declarations(self):
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        broken = source.replace("theorem no_release_with_readers", "theorem renamed_claim", 1)
        with self.assertRaisesRegex(ValueError, "theorem inventory"):
            formal.checked_text(broken)

    def test_existing_and_appended_dependency_prints_are_unique(self):
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        checked = formal.checked_text(source)
        self.assertEqual(checked.count("#print axioms"), len(formal.EXPECTED_THEOREMS))
        with self.assertRaisesRegex(ValueError, "Duplicate source dependency"):
            formal.checked_text(source + "\n#print axioms Hepta.resource_preservation\n")

    def test_placeholders_checker_options_and_unreviewed_commands_reject(self):
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        for extra in ("example : False := by sorry", "set_option debug.skipKernelTC true",
                      "#eval IO.println \"forged proof output\"", "import UnreviewedProofPlugin"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                formal.checked_text(source + "\n" + extra + "\n")


class FormalNativeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lean = os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean"))
        if not Path(cls.lean).is_file():
            raise unittest.SkipTest("Actual pinned Lean is required; set LEAN to run native proof controls")
        cls.temp = tempfile.TemporaryDirectory(prefix="hepta-formal-native-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.report = formal.verify(cls.lean, Path(cls.temp.name) / "report.json")

    def assert_rejected(self, mutate):
        report = copy.deepcopy(self.report)
        mutate(report)
        with self.assertRaises(ValueError):
            formal.validate_report(report)

    @staticmethod
    def replace_positive(report, stdout, stderr=""):
        report.update(kernel_stdout=stdout, kernel_stderr=stderr,
                      kernel_output=stdout + stderr,
                      kernel_output_sha256=formal.sha((stdout + stderr).encode()))

    def isolated_root(self, directory):
        root = Path(directory) / "isolated"
        (root / "formal").mkdir(parents=True)
        for name in ("HeptaCore.lean", "toolchain-lock.json"):
            (root / "formal" / name).write_bytes((ROOT / "formal" / name).read_bytes())
        return root

    def test_actual_kernel_and_intended_mutations_pass_without_upgraded_claims(self):
        report = self.report
        formal.validate_report(report)
        self.assertEqual(report["schema"], "hepta.formal.v2")
        self.assertEqual(set(report["theorems"]), formal.EXPECTED_THEOREMS)
        self.assertEqual(report["kernel_returncode"], 0)
        self.assertFalse(report["claims"]["whole_language_soundness_proved"])
        for item in report["negative_mutations"]:
            self.assertEqual(item["returncode"], 1)
            failed = formal.MUTATION_FAILURE[item["mutation"]]
            self.assertIn("sorryAx", formal.dependencies(item["log"], broken=True)[failed])

    def test_source_checked_text_tool_and_lock_hashes_are_required(self):
        for field in ("source_sha256", "checked_source_sha256", "lean_binary_sha256", "toolchain_lock_sha256"):
            with self.subTest(field=field):
                self.assert_rejected(lambda report: report.__setitem__(field, "0" * 64))

    def test_positive_returncode_must_be_integer_zero(self):
        for value in (False, 1, None):
            with self.subTest(value=value):
                self.assert_rejected(lambda report: report.__setitem__("kernel_returncode", value))

    def test_version_probe_exit_stderr_and_text_are_checked(self):
        for field, value in (("returncode", False), ("stderr", "error: failed runtime\n"),
                             ("stdout", "Lean (version 0.0.0, fake)\n")):
            with self.subTest(field=field):
                self.assert_rejected(lambda report: report["version_probe"].__setitem__(field, value))

    def test_fabricated_or_duplicate_kernel_reports_reject_even_after_rehash(self):
        for log in ("proofs passed\n", self.report["kernel_stdout"] + self.report["kernel_stdout"].splitlines()[0] + "\n"):
            with self.subTest(log=log[:40]):
                self.assert_rejected(lambda report: self.replace_positive(report, log))

    def test_zero_exit_cannot_hide_stderr_error_or_sorry_warning(self):
        for stderr in ("error: kernel did not check the proof\n", "warning: declaration uses 'sorry'\n"):
            with self.subTest(stderr=stderr):
                self.assert_rejected(lambda report: self.replace_positive(report, report["kernel_stdout"], stderr))

    def test_actual_lean_zero_exit_placeholder_is_not_a_proof(self):
        with tempfile.TemporaryDirectory(prefix="hepta-lean-sorry-") as td:
            proof = Path(td) / "Placeholder.lean"
            proof.write_text("theorem placeholder : False := by sorry\n#print axioms placeholder\n", encoding="utf-8")
            proc = subprocess.run([self.lean, str(proof)], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("sorryAx", proc.stdout + proc.stderr)
            with self.assertRaises(ValueError):
                formal.dependencies(self.report["kernel_stdout"] + proc.stdout + proc.stderr)

    def test_declared_dependencies_cannot_disagree_with_retained_output(self):
        self.assert_rejected(lambda report: report["theorems"].__setitem__("resource_preservation", []))

    def test_arbitrary_negative_error_does_not_invalidate_intended_theorem(self):
        def mutate(report):
            item = report["negative_mutations"][0]
            log = report["kernel_stdout"] + "error: unrelated input could not be opened\n"
            item.update(stdout=log, stderr="", log=log, log_sha256=formal.sha(log.encode()))
        self.assert_rejected(mutate)

    def test_negative_signal_boolean_or_missing_streams_do_not_count(self):
        for field, value in (("returncode", -9), ("returncode", True), ("stderr", None),
                             ("checked_source_sha256", "0" * 64), ("failed_theorem", "Hepta.unrelated")):
            with self.subTest(field=field, value=value):
                self.assert_rejected(lambda report: report["negative_mutations"][0].__setitem__(field, value))

    def test_duplicate_negative_controls_and_upgraded_claims_reject(self):
        self.assert_rejected(lambda report: report["negative_mutations"].__setitem__(1, copy.deepcopy(report["negative_mutations"][0])))
        self.assert_rejected(lambda report: report["claims"].__setitem__("whole_language_soundness_proved", True))
        self.assert_rejected(lambda report: report["claims"].__setitem__("abstract_core_theorems_checked", 1))

    def test_changed_original_proof_after_real_kernel_run_prevents_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-proof-race-") as td:
            root = self.isolated_root(td)
            source = root / "formal/HeptaCore.lean"
            real_run = subprocess.run
            changed = False

            def run_then_change(argv, **kwargs):
                nonlocal changed
                proc = real_run(argv, **kwargs)
                if argv[1] != "--version" and not changed:
                    source.write_bytes(source.read_bytes() + b"\n-- changed after kernel invocation\n")
                    changed = True
                return proc

            output = root / "result.json"
            with patch.object(formal, "ROOT", root), patch.object(formal.subprocess, "run", side_effect=run_then_change):
                with self.assertRaisesRegex(RuntimeError, "changed during qualification"):
                    formal.verify(self.lean, output)
            self.assertTrue(changed)
            self.assertFalse(output.exists())

    def test_changed_checked_input_after_real_kernel_run_prevents_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-proof-input-race-") as td:
            root = self.isolated_root(td)
            real_run = subprocess.run

            def run_then_change(argv, **kwargs):
                proc = real_run(argv, **kwargs)
                if argv[1] != "--version":
                    file = Path(argv[1])
                    file.write_bytes(file.read_bytes() + b"\n-- different checked input\n")
                return proc

            output = root / "result.json"
            with patch.object(formal, "ROOT", root), patch.object(formal.subprocess, "run", side_effect=run_then_change):
                with self.assertRaisesRegex(RuntimeError, "temporary proof input changed"):
                    formal.verify(self.lean, output)
            self.assertFalse(output.exists())

    def test_changed_toolchain_lock_prevents_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-proof-lock-race-") as td:
            root = self.isolated_root(td)
            lock = root / "formal/toolchain-lock.json"
            real_run = subprocess.run

            def run_then_change(argv, **kwargs):
                proc = real_run(argv, **kwargs)
                if argv[1] == "--version":
                    lock.write_bytes(lock.read_bytes() + b"\n")
                return proc

            output = root / "result.json"
            with patch.object(formal, "ROOT", root), patch.object(formal.subprocess, "run", side_effect=run_then_change):
                with self.assertRaisesRegex(RuntimeError, "changed during qualification"):
                    formal.verify(self.lean, output)
            self.assertFalse(output.exists())

    def test_pinned_executable_changed_after_actual_version_probe_rejects(self):
        with tempfile.TemporaryDirectory(prefix="hepta-proof-tool-race-") as td:
            root = self.isolated_root(td)
            install = Path(td) / "lean-copy"
            (install / "bin").mkdir(parents=True)
            real_executable = Path(self.lean).resolve()
            copied = install / "bin/lean"
            shutil.copy2(real_executable, copied)
            (install / "lib").symlink_to(real_executable.parent.parent / "lib", target_is_directory=True)
            real_run = subprocess.run
            executed = []

            def run_then_change(argv, **kwargs):
                proc = real_run(argv, **kwargs)
                executed.append(argv)
                if argv[1] == "--version":
                    # Linux may retain an executable mapping after --version;
                    # writing that inode in place can raise ETXTBSY. Replace the
                    # pinned path atomically, preserving the real post-probe
                    # identity-drift negative test rather than mocking a hash.
                    staged = copied.with_name("lean-mutated")
                    shutil.copy2(copied, staged)
                    with staged.open("ab") as stream:
                        stream.write(b"changed after actual pinned version probe")
                    staged.replace(copied)
                return proc

            output = root / "result.json"
            with patch.object(formal, "ROOT", root), patch.object(formal.subprocess, "run", side_effect=run_then_change):
                with self.assertRaisesRegex(RuntimeError, "changed during qualification"):
                    formal.verify(str(copied), output)
            self.assertEqual(len(executed), 1)
            self.assertFalse(output.exists())

    def test_legacy_count_only_receipt_is_not_relabelled_as_current(self):
        legacy = json.loads((ROOT / "artifacts/formal-validation.json").read_text())
        # The historical artifact's contents can differ between checkouts; a
        # count-only receipt must fail regardless of its superficial schema.
        legacy.pop("checked_source_sha256", None)
        legacy.pop("kernel_returncode", None)
        legacy["schema"] = formal.SCHEMA
        with self.assertRaises(ValueError):
            formal.validate_report(legacy)


if __name__ == "__main__":
    unittest.main()
