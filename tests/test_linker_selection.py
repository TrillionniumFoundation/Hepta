"""Real Rust/GCC linking plus explicit tool-selection fault injection.

The small Python driver fixtures exercise argv and file mutation on this host;
they are not Microsoft linker execution or Windows qualification evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hepta import backend
from hepta.ast import HeptaError
from tools import qualify_c_stb_divide as component


class LinkerSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rustc = backend.find_rustc()
        backend.toolchain_info(cls.rustc)
        driver = shutil.which("gcc")
        if driver is None:
            raise RuntimeError("These real native linker tests require GCC")
        cls.gcc = str(Path(driver).resolve(strict=True))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-linker-selection-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def driver(self, *, mutate_probe=False, mutate_link=False, name="linker with spaces ; literal"):
        # It ultimately execs actual GCC. The explicit selection fixture itself
        # is separately identified, never presented as an upstream tool binary.
        path = self.directory / name
        log = self.directory / (name + ".jsonl")
        body = (
            "import json, os, sys\nfrom pathlib import Path\n"
            f"with open({str(log)!r}, 'a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:] == ['--version']:\n"
            + ("    with open(__file__, 'a') as stream: stream.write('\\n# mutated probe\\n')\n" if mutate_probe else "")
            + "    print('Hepta explicit-selection fixture delegating native links to GCC')\n"
            "    raise SystemExit(0)\n"
            + ("with open(__file__, 'a') as stream: stream.write('\\n# mutated link\\n')\n" if mutate_link else "")
            + f"os.execv({self.gcc!r}, [{self.gcc!r}] + sys.argv[1:])\n"
        )
        path.write_text("#!" + sys.executable + "\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path, log

    def build_and_run(self, linker=None):
        built = backend.compile_rust('fn main() { println!("{}", 6 * 7); }',
            rustc=self.rustc, crate_type="bin", output=self.directory / "native", linker=linker)
        self.assertTrue(built["ok"], built)
        observed = subprocess.run([built["artifact"]], capture_output=True, text=True, timeout=10)
        self.assertEqual((observed.returncode, observed.stdout.strip()), (0, "42"), observed.stderr)
        return built

    def test_default_linker_still_builds_and_runs_without_explicit_identity(self):
        built = self.build_and_run()
        self.assertIsNone(built["linker_identity"])

    def test_explicit_actual_gcc_is_hashed_probed_and_executed(self):
        built = self.build_and_run(self.gcc)
        identity = built["linker_identity"]
        self.assertEqual(built["linker"], self.gcc)
        self.assertEqual(identity["path"], self.gcc)
        self.assertEqual(identity["executable_sha256"], hashlib.sha256(Path(self.gcc).read_bytes()).hexdigest())
        self.assertEqual(identity["sha256_after_compilation"], identity["executable_sha256"])
        self.assertTrue(identity["unchanged_after_probe"])
        self.assertTrue(identity["unchanged_after_compilation"])
        self.assertEqual(identity["probe"]["argv"], [self.gcc, "--version"])
        self.assertEqual(identity["probe"]["returncode"], 0)
        self.assertIn("linker=" + self.gcc, built["flags"])

    def test_explicit_literal_path_overrides_path_without_shell(self):
        selected, log = self.driver()
        built = self.build_and_run(str(selected))
        self.assertEqual(built["linker"], str(selected))
        invocations = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(invocations[0], ["--version"])
        self.assertTrue(any("-o" in argv for argv in invocations[1:]), invocations)
        self.assertEqual(built["linker_identity"]["probe"]["argv"][0], str(selected))

    def test_missing_relative_directory_or_nonexecutable_selection_is_rejected(self):
        unavailable = self.directory / "unavailable"
        ordinary = self.directory / "ordinary"
        ordinary.write_text("not executable")
        ordinary.chmod(0o600)
        for candidate in ("gcc", "", str(unavailable), str(self.directory), str(ordinary)):
            with self.subTest(candidate=candidate):
                with self.assertRaises(HeptaError) as rejected:
                    backend.linker_info(candidate)
                self.assertEqual(rejected.exception.diagnostic.code, "E_LINKER_IDENTITY")

    def test_executable_change_during_real_probe_is_rejected(self):
        selected, log = self.driver(mutate_probe=True)
        with self.assertRaises(HeptaError) as rejected:
            backend.linker_info(str(selected))
        self.assertEqual(rejected.exception.diagnostic.code, "E_LINKER_IDENTITY")
        self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], [["--version"]])

    def test_change_after_binding_is_rejected_before_build(self):
        selected, log = self.driver()
        original = backend.linker_info

        def bind_then_mutate(path):
            result = original(path)
            with selected.open("a") as stream:
                stream.write("\n# deterministic post-binding fault injection\n")
            return result

        with mock.patch.object(backend, "linker_info", side_effect=bind_then_mutate):
            with self.assertRaises(HeptaError) as rejected:
                self.build_and_run(str(selected))
        self.assertEqual(rejected.exception.diagnostic.code, "E_LINKER_IDENTITY")
        self.assertFalse((self.directory / "native").exists())
        self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], [["--version"]])

    def test_real_link_driver_mutation_cannot_publish_over_existing_artifact(self):
        selected, log = self.driver(mutate_link=True)
        destination = self.directory / "native"
        destination.write_bytes(b"previous verified artifact")
        built = backend.compile_rust("fn main() {}", rustc=self.rustc,
            crate_type="bin", output=destination, linker=str(selected))
        self.assertFalse(built["ok"], built)
        self.assertEqual(built["status"], "rejected")
        self.assertIn("E_LINKER_IDENTITY", [item["code"] for item in built["diagnostics"]])
        self.assertFalse(built["linker_identity"]["unchanged_after_compilation"])
        self.assertNotIn("artifact", built)
        self.assertEqual(destination.read_bytes(), b"previous verified artifact")
        self.assertTrue(any("-o" in json.loads(line) for line in log.read_text().splitlines()))

    def test_component_reuses_initial_identity_and_rejects_between_build_drift(self):
        selected, _ = self.driver()
        identity = component.select_rust_linker(str(selected), "Linux")
        built = component.compile_bound_rust("#[no_mangle] pub extern \"C\" fn answer() -> i32 { 42 }",
            rustc=self.rustc, output=self.directory / "target.so", linker_identity=identity)
        self.assertTrue(built["ok"], built)
        self.assertEqual(built["linker_identity"]["executable_sha256"], identity["executable_sha256"])
        with selected.open("a") as stream:
            stream.write("\n# changed between positive and negative builds\n")
        with self.assertRaisesRegex(ValueError, "changed between component builds"):
            component.compile_bound_rust("pub fn answer() -> i32 { 0 }", rustc=self.rustc,
                output=self.directory / "negative.so", linker_identity=identity)
        self.assertFalse((self.directory / "negative.so").exists())

    def test_windows_gate_refuses_absent_and_actual_non_microsoft_linker(self):
        # Explicit guard-model tests on this host, not Windows execution.
        with self.assertRaisesRegex(ValueError, "explicit Visual Studio"):
            component.select_rust_linker(None, "Windows")
        with self.assertRaisesRegex(ValueError, "actual Microsoft Incremental Linker"):
            component.select_rust_linker(self.gcc, "Windows")
        self.assertIsNone(component.select_rust_linker(None, "Linux"))


if __name__ == "__main__":
    unittest.main()
