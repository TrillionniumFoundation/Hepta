"""Preserve known loaded/package-snapshot inputs and the verified owner lock."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import hepta
from hepta.ast import HeptaError
from hepta.backend import find_rustc, toolchain_info


# Bind child CLI processes to the imported package, not this test file's tree.
# The same tests can therefore run against a separate, unchanged baseline.
PACKAGE_ROOT = Path(hepta.__file__).resolve().parents[1]
COMMANDS = ("emit", "header", "build")
INPUT_MESSAGE = "Output cannot overwrite an input used to validate the project"
SCALAR_MAIN = "fn main() -> i32 effects {} { return 42; }\n"


def native_receipt(case, backend, build, generated_sha256, artifact_sha256, execution):
    print("CLI_INPUT_NATIVE", json.dumps({
        "case": case, "backend": backend, "expected_returncode": 42,
        "returncode": execution.returncode, "stdout": execution.stdout.decode(),
        "stderr": execution.stderr.decode(), "artifact_sha256": artifact_sha256,
        "generated_source_sha256": generated_sha256, "toolchain": build["toolchain"],
        "flags": build["flags"],
    }, sort_keys=True), flush=True)


class CLIInputProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc")
        if cls.cc is None:
            raise AssertionError("Real GCC is required for the C prerequisites")
        cls.environment = dict(os.environ, PYTHONPATH=str(PACKAGE_ROOT),
                               PYTHONDONTWRITEBYTECODE="1")
        # The Rust-only skip below must never hide a missing C prerequisite.
        with tempfile.TemporaryDirectory(prefix="hepta-cli-prerequisite-") as directory:
            root = Path(directory)
            source = root / "main.hepta"
            source.write_text(SCALAR_MAIN)
            output = root / "program"
            process = subprocess.run(
                [sys.executable, "-B", "-m", "hepta", "build", str(source),
                 "--backend", "c", "--cc", cls.cc, "--crate-type", "bin", "-o", str(output)],
                cwd=root, env=cls.environment, capture_output=True, text=True, timeout=120)
            if process.returncode != 0 or process.stderr:
                raise AssertionError(process.stdout + process.stderr)
            report = json.loads(process.stdout)
            if report.get("ok") is not True or report["build"]["rustc_used"] is not False:
                raise AssertionError(report)
            artifact_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()
            if (report["build"]["artifact_sha256"] != artifact_sha256
                    or report["build"]["source_sha256"] != report["validation"]["c_sha256"]):
                raise AssertionError("Prerequisite build is not bound to the validated source and actual artifact")
            execution = subprocess.run([str(output)], capture_output=True, timeout=5)
            if (execution.returncode, execution.stdout, execution.stderr) != (42, b"", b""):
                raise AssertionError((execution.returncode, execution.stdout, execution.stderr))
            native_receipt("setUpClass", "c", report["build"], report["validation"]["c_sha256"],
                           artifact_sha256, execution)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cli-input-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner = self.root / "app"
        self.dep = self.root / "dep"
        self.put("app/hepta.toml", '[package]\nname = "app"\nversion = "0.1.0"\n'
                 '[dependencies]\ndep = { path = "../dep" }\n')
        self.put("app/src/main.hepta", "import dep; fn main() -> i32 effects {} { return dep::answer(); }\n")
        self.put("app/src/unused.hepta", "pub fn unused() -> i32 effects {} { return 7; }\n")
        self.put("app/src/unused.hepta.imports.json", '{"unused": "owner sidecar"}\n')
        self.put("dep/hepta.toml", '[package]\nname = "dep"\nversion = "0.1.0"\nkind = "lib"\n')
        self.put("dep/src/lib.hepta", "import bindings; pub fn answer() -> i32 effects {} { return 42; }\n")
        self.put("dep/src/unused.hepta", "pub fn unused() -> i32 effects {} { return 8; }\n")
        self.put("dep/src/unused.hepta.imports.json", '{"unused": "dependency sidecar"}\n')
        header = self.put("dep/api.h", "/* Empty header: no declarations or layouts under test. */\n")
        process, report = self.cli("import-c", header, "--cc", self.cc,
                                   "-o", self.dep / "src/bindings.hepta")
        self.assert_success(process, report)
        for package in (self.dep, self.owner):
            process, report = self.cli("lock", package)
            self.assert_success(process, report)
        process, report = self.cli("check", self.owner, "--backend", "c", "--cc", self.cc,
                                   "--crate-type", "bin", "--locked")
        self.assert_success(process, report)

    def put(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def cli(self, *arguments):
        process = subprocess.run([sys.executable, "-B", "-m", "hepta", *map(str, arguments)],
                                 cwd=self.root, env=self.environment,
                                 capture_output=True, text=True, timeout=120)
        self.assertEqual(process.stderr, "", process.stderr)
        return process, json.loads(process.stdout)

    def command(self, command, destination=None, *, entry=None, locked=True, backend="c", rustc=None, debug=False):
        arguments = [command, entry or self.owner, "--backend", backend, "--crate-type", "bin"]
        arguments += ["--cc", self.cc] if backend == "c" else ["--rustc", rustc]
        if debug:
            arguments.append("--debug")
        if locked:
            arguments.append("--locked")
        if destination is not None:
            arguments += ["-o", destination]
        return arguments

    def snapshot(self):
        return {path.relative_to(self.root).as_posix(): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def assert_success(self, process, report):
        self.assertEqual(process.returncode, 0, report)
        self.assertIs(report["ok"], True, report)

    def assert_refused(self, command, destination, *, new_input=True, **options):
        before = self.snapshot()
        before_directories = {path for path in self.root.rglob("*") if path.is_dir()}
        try:
            process, report = self.cli(*self.command(command, destination, **options))
            after = self.snapshot()
            # Check bytes first: baseline success must expose the actual data loss.
            self.assertEqual(after, before, "The output command changed an input or published another file")
            self.assertEqual({path for path in self.root.rglob("*") if path.is_dir()},
                             before_directories, "The output command created an artifact/debug directory")
            self.assertEqual(process.returncode, 2, report)
            if new_input:
                self.assertEqual(report, {"ok": False, "status": "error", "diagnostics": [
                    {"code": "E_DRIVER", "message": INPUT_MESSAGE, "phase": "driver"}]})
            else:
                # Existing source guards are baseline controls; their old, narrower
                # wording is not the package-input overwrite defect.
                self.assertEqual(set(report), {"ok", "status", "diagnostics"})
                self.assertIs(report["ok"], False)
                self.assertEqual(report["status"], "error")
                self.assertEqual(len(report["diagnostics"]), 1)
                diagnostic = report["diagnostics"][0]
                self.assertEqual(set(diagnostic), {"code", "message", "phase"})
                self.assertEqual((diagnostic["code"], diagnostic["phase"]), ("E_DRIVER", "driver"))
                self.assertIn(diagnostic["message"], (
                    INPUT_MESSAGE, "Output cannot overwrite a Hepta source in the module graph"))
        finally:
            # Restore inputs so baseline corruption cannot contaminate later cases.
            for relative in self.snapshot().keys() - before.keys():
                (self.root / relative).unlink()
            for relative, data in before.items():
                (self.root / relative).write_bytes(data)
            added_directories = {path for path in self.root.rglob("*") if path.is_dir()} - before_directories
            for path in sorted(added_directories, key=lambda path: len(path.parts), reverse=True):
                path.rmdir()

    def assert_output(self, command, destination, *, default_output=False, **options):
        before = self.snapshot()
        resolved = (self.root / destination).resolve()
        relative = resolved.relative_to(self.root).as_posix()
        old = before.pop(relative, None)
        try:
            process, report = self.cli(*self.command(command, None if default_output else destination, **options))
            self.assert_success(process, report)
            after = self.snapshot()
            content = after.pop(relative)
            self.assertEqual(after, before, "An unrelated input changed")
            self.assertTrue(content)
            self.assertNotEqual(content, old)
            self.assertIs(report["validation"]["ok"], True)
            if command == "build":
                self.assertEqual(report["schema"], "hepta.build.v1")
                self.assertEqual(report["build"]["artifact"], str(resolved))
                self.assertEqual(report["build"]["artifact_sha256"], hashlib.sha256(content).hexdigest())
                backend = options.get("backend", "c")
                if backend == "c":
                    self.assertIs(report["build"]["rustc_used"], False)
                    generated_sha256 = report["build"]["source_sha256"]
                    self.assertEqual(generated_sha256, report["validation"]["c_sha256"])
                else:
                    generated_sha256 = report["build"]["rust_sha256"]
                    self.assertEqual(generated_sha256, report["validation"]["rust_sha256"])
                execution = subprocess.run([str(resolved)], capture_output=True, timeout=5)
                self.assertEqual((execution.returncode, execution.stdout, execution.stderr), (42, b"", b""))
                native_receipt(self.id() + ":" + relative, backend, report["build"], generated_sha256,
                               hashlib.sha256(content).hexdigest(), execution)
            else:
                self.assertEqual(report["schema"], "hepta.output.v1")
                self.assertEqual(report["output"], str(resolved))
                if command == "header":
                    self.assertIn(b"#ifndef", content)
                elif options.get("backend", "c") == "c":
                    self.assertIn(b"Hepta independent C11/GCC backend", content)
        finally:
            if old is not None:
                resolved.write_bytes(old)
            elif resolved.exists():
                resolved.unlink()

    def refuse_each(self, targets, *, new_input=True, entry=None):
        for locked in (False, True):
            for command in COMMANDS:
                for target in targets:
                    with self.subTest(locked=locked, command=command, target=target):
                        self.assert_refused(command, self.root / target, locked=locked,
                                            new_input=new_input, entry=entry)

    def test_loaded_root_and_dependency_sources_are_preserved(self):
        self.refuse_each(("app/src/main.hepta", "dep/src/lib.hepta"), new_input=False)

    def test_root_manifest_is_preserved_with_or_without_locked(self):
        self.refuse_each(("app/hepta.toml",))
        for locked in (False, True):
            with self.subTest(locked=locked, command="build", debug=True):
                self.assert_refused("build", self.owner / "hepta.toml", locked=locked, debug=True)

    def test_dependency_manifest_is_preserved_with_or_without_locked(self):
        self.refuse_each(("dep/hepta.toml",))

    def test_unimported_root_source_is_preserved(self):
        self.refuse_each(("app/src/unused.hepta",))

    def test_unimported_dependency_source_is_preserved(self):
        self.refuse_each(("dep/src/unused.hepta",))

    def test_loaded_dependency_sidecar_and_original_header_are_preserved(self):
        self.refuse_each(("dep/src/bindings.hepta.imports.json", "dep/api.h"), new_input=False)

    def test_unimported_root_and_dependency_sidecars_are_preserved(self):
        self.refuse_each(("app/src/unused.hepta.imports.json", "dep/src/unused.hepta.imports.json"))

    def test_locked_owner_lock_is_preserved_from_each_entrypoint(self):
        for entry in (self.owner, self.owner / "hepta.toml", self.owner / "src/main.hepta"):
            for command in COMMANDS:
                with self.subTest(entry=entry.name, command=command):
                    self.assert_refused(command, self.owner / "Hepta.lock", entry=entry)

    def test_canonical_relative_destinations_from_each_entrypoint(self):
        for entry in ("app", "app/hepta.toml", "app/src/main.hepta"):
            for locked in (False, True):
                for command in COMMANDS:
                    with self.subTest(entry=entry, locked=locked, command=command):
                        self.assert_refused(command, "app/src/../../dep/./hepta.toml",
                                            entry=entry, locked=locked)

    def test_unlocked_owner_lock_remains_a_permitted_output(self):
        for command in COMMANDS:
            with self.subTest(command=command):
                self.assert_output(command, self.owner / "Hepta.lock", locked=False)

    def test_dependency_lock_is_not_an_owner_validation_input(self):
        for locked in (False, True):
            for command in COMMANDS:
                with self.subTest(locked=locked, command=command):
                    self.assert_output(command, self.dep / "Hepta.lock", locked=locked)

    def test_standalone_graph_is_protected_but_unused_sibling_is_not(self):
        entry = self.put("standalone/main.hepta", "import used; fn main() -> i32 effects {} { return used::answer(); }\n")
        used = self.put("standalone/used.hepta", "pub fn answer() -> i32 effects {} { return 42; }\n")
        unused = self.put("standalone/unused.hepta", "pub fn unused() -> i32 effects {} { return 9; }\n")
        for command in COMMANDS:
            for target in (entry, used):
                with self.subTest(command=command, refused=target.name):
                    self.assert_refused(command, target, entry=entry, locked=False, new_input=False)
            with self.subTest(command=command, permitted=unused.name):
                self.assert_output(command, unused, entry=entry, locked=False)

    def test_normal_new_and_existing_outputs_still_succeed(self):
        for locked in (False, True):
            for command in COMMANDS:
                for exists in (False, True):
                    with self.subTest(locked=locked, command=command, exists=exists):
                        output = self.root / "ordinary" / (command + ".output")
                        output.parent.mkdir(exist_ok=True)
                        if exists:
                            output.write_bytes(b"replace this unrelated ordinary file\n")
                        self.assert_output(command, output, locked=locked)
                        output.unlink(missing_ok=True)
        for locked in (False, True):
            for exists in (False, True):
                with self.subTest(locked=locked, command="build", exists=exists, default_output=True):
                    output = self.owner / "src/build/main"
                    output.parent.mkdir(exist_ok=True)
                    if exists:
                        output.write_bytes(b"replace this unrelated default output\n")
                    self.assert_output("build", output, default_output=True, locked=locked)
                    output.unlink(missing_ok=True)

    def test_emit_and_header_to_stdout_preserve_all_inputs(self):
        for locked in (False, True):
            for command in ("emit", "header"):
                with self.subTest(locked=locked, command=command):
                    before = self.snapshot()
                    process = subprocess.run(
                        [sys.executable, "-B", "-m", "hepta", *map(str, self.command(command, locked=locked))],
                        cwd=self.root, env=self.environment, capture_output=True, text=True, timeout=120)
                    self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
                    self.assertEqual(process.stderr, "")
                    self.assertIn("#ifndef" if command == "header" else "Hepta independent C11/GCC backend", process.stdout)
                    self.assertEqual(self.snapshot(), before)

    def test_z_actual_pinned_rust_parity_after_c_prerequisites(self):
        try:
            rustc = find_rustc()
            identity = toolchain_info(rustc)
        except HeptaError as error:
            self.skipTest("Actual pinned Rust unavailable after real GCC prerequisites: " + error.diagnostic.message)
        self.assertIn("release: 1.90.0", identity["version"].splitlines())
        for command in COMMANDS:
            for target in ("app/hepta.toml", "dep/src/unused.hepta.imports.json", "app/Hepta.lock"):
                with self.subTest(command=command, target=target):
                    self.assert_refused(command, self.root / target, backend="rust", rustc=rustc)
            with self.subTest(command=command, output="ordinary"):
                output = self.put("rust-" + command, "old unrelated output\n")
                self.assert_output(command, output, backend="rust", rustc=rustc)


if __name__ == "__main__":
    unittest.main()
