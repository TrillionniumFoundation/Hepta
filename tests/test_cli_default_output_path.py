"""Default build destinations obey the existing, resolved-input guard.

All aliases are ordinary, finite symlinks inside self-created temporary trees.
These tests do not claim hardlink, access-control, or concurrent-write safety.
"""
from __future__ import annotations

from contextlib import contextmanager
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


# A test loaded from another checkout must still exercise the imported compiler.
PACKAGE_ROOT = Path(hepta.__file__).resolve().parents[1]
INPUT_ERROR = {"ok": False, "status": "error", "diagnostics": [{
    "code": "E_DRIVER", "phase": "driver",
    "message": "Output cannot overwrite an input used to validate the project"}]}
MAIN = "fn main() -> i32 effects {} { return 42; }\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(root):
    """Record physical files, directories and link text, never traverse links."""
    files, directories, links = {}, set(), {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                links[relative] = os.readlink(path)
            elif path.is_dir():
                directories.add(relative)
            else:
                files[relative] = path.read_bytes()
    return files, directories, links


class CLIDefaultOutputPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc")
        if cls.cc is None:
            raise AssertionError("Real GCC is required before optional Rust parity")
        cls.environment = dict(os.environ, PYTHONPATH=str(PACKAGE_ROOT),
                               PYTHONDONTWRITEBYTECODE="1")
        probe = cls("runTest")
        with tempfile.TemporaryDirectory(prefix="hepta-default-prerequisite-") as directory:
            root = Path(directory).resolve()
            imported = subprocess.run(
                [sys.executable, "-B", "-c", "import hepta.cli; print(hepta.cli.__file__)"],
                cwd=root, env=cls.environment, capture_output=True, text=True, check=True)
            probe.assertEqual(Path(imported.stdout.strip()).resolve(), PACKAGE_ROOT / "hepta/cli.py")
            entry = root / "main.hepta"
            entry.write_text(MAIN)
            # A real native C build, source binding and execution are mandatory.
            probe.assert_output(root, entry, root / "build/main", locked=False)

    def cli(self, root, *arguments, raw=False):
        process = subprocess.run([sys.executable, "-B", "-m", "hepta", *map(str, arguments)],
                                 cwd=root, env=self.environment, capture_output=True,
                                 text=True, timeout=120)
        self.assertEqual(process.stderr, "", process.stderr)
        return process, process.stdout if raw else json.loads(process.stdout)

    def arguments(self, entry, output=None, *, locked=True, backend="c", rustc=None, debug=False,
                  crate_type="bin"):
        args = ["build", entry, "--backend", backend, "--crate-type", crate_type]
        args += ["--cc", self.cc] if backend == "c" else ["--rustc", rustc]
        if locked:
            args.append("--locked")
        if debug:
            args.append("--debug")
        if output is not None:
            args += ["-o", output]
        return args

    @contextmanager
    def project(self):
        with tempfile.TemporaryDirectory(prefix="hepta-default-project-") as directory:
            root = Path(directory).resolve()
            for name, text in {
                "app/hepta.toml": '[package]\nname="app"\nversion="0.1.0"\n'
                                  '[dependencies]\ndep={path="../dep"}\n',
                "app/src/main.hepta": "import dep; fn main()->i32 effects {} { return dep::answer(); }\n",
                "app/src/unused.hepta": "pub fn unused()->i32 effects {} { return 7; }\n",
                "app/src/unused.hepta.imports.json": '{"unused":"owner sidecar"}\n',
                "dep/hepta.toml": '[package]\nname="dep"\nversion="0.1.0"\nkind="lib"\n',
                "dep/src/lib.hepta": "pub fn answer()->i32 effects {} { return 42; }\n",
                "dep/src/unused.hepta": "pub fn unused()->i32 effects {} { return 8; }\n",
                "dep/src/unused.hepta.imports.json": '{"unused":"dependency sidecar"}\n',
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            for name in ("dep", "app"):
                process, report = self.cli(root, "lock", root / name)
                self.assertEqual(process.returncode, 0, report)
                self.assertIs(report["ok"], True)
            yield root, root / "app", root / "app/src/build/main"

    def link(self, alias, target, relative):
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(os.path.relpath(target, alias.parent) if relative else target,
                        target_is_directory=target.is_dir())

    def assert_refused(self, root, entry, output=None, *, expected=INPUT_ERROR, code=2, **options):
        before = snapshot(root)
        process, report = self.cli(root, *self.arguments(entry, output, **options))
        after = snapshot(root)
        # Optional external evidence retains exact corruption bytes before cleanup.
        evidence = os.environ.get("HEPTA_DEFAULT_OUTPUT_EVIDENCE_DIR")
        if before != after and evidence:
            directory = Path(tempfile.mkdtemp(prefix="changed-", dir=evidence))
            for label, state in (("before", before), ("after", after)):
                for name, data in state[0].items():
                    path = directory / label / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            (directory / "receipt.json").write_text(json.dumps({
                "test": self.id(), "arguments": list(map(str, self.arguments(entry, output, **options))),
                "returncode": process.returncode, "report": report, "stderr": process.stderr,
                "directories_before": sorted(before[1]), "directories_after": sorted(after[1]),
                "links_before": before[2], "links_after": after[2],
            }, indent=2) + "\n")
            print("CLI_DEFAULT_FAILURE_BYTES", str(directory), flush=True)
        self.assertEqual(after[0], before[0], "Input bytes or physical file set changed")
        self.assertEqual(after[1], before[1], "An artifact/debug directory was created")
        self.assertEqual(after[2], before[2], "An alias was changed")
        self.assertEqual(process.returncode, code, report)
        self.assertEqual(report, expected)

    def assert_output(self, root, entry, output, *, explicit=False, **options):
        before = snapshot(root)
        target = output.resolve()
        relative = target.relative_to(root).as_posix()
        args = self.arguments(entry, output if explicit else None, **options)
        # Independently hash the emitted source, not just two receipt fields.
        emitted, source = self.cli(root, "emit", *self.arguments(entry, **options)[1:], raw=True)
        self.assertEqual(emitted.returncode, 0, source)
        process, report = self.cli(root, *args)
        self.assertEqual(process.returncode, 0, report)
        self.assertIs(report["ok"], True)
        self.assertEqual(report["schema"], "hepta.build.v1")
        self.assertIs(report["validation"]["ok"], True)
        after = snapshot(root)
        content = after[0].pop(relative)
        old = before[0].pop(relative, None)
        self.assertNotEqual(content, old)
        self.assertEqual(after[0], before[0], "An unrelated physical file changed")
        self.assertEqual(after[2], before[2], "An output alias was changed")
        expected_directories = set(before[1])
        parent = target.parent
        while parent != root:
            expected_directories.add(parent.relative_to(root).as_posix())
            parent = parent.parent
        self.assertEqual(after[1], expected_directories)
        build, validation = report["build"], report["validation"]
        backend = options.get("backend", "c")
        source_key, validation_key = (("source_sha256", "c_sha256") if backend == "c"
                                      else ("rust_sha256", "rust_sha256"))
        self.assertEqual(build[source_key], sha(source.encode()))
        self.assertEqual(build[source_key], validation[validation_key])
        self.assertEqual(build["artifact"], str(target))
        self.assertEqual(build["artifact_sha256"], sha(content))
        if backend == "c":
            self.assertIs(build["rustc_used"], False)
            self.assertIn("-std=c11", build["flags"])
            self.assertIn("-O3", build["flags"])
        execution = subprocess.run([str(target)], capture_output=True, timeout=5)
        self.assertEqual((execution.returncode, execution.stdout, execution.stderr), (42, b"", b""))
        print("CLI_DEFAULT_NATIVE", json.dumps({
            "test": self.id(), "backend": backend, "output": relative,
            "explicit": explicit, "toolchain": build["toolchain"], "flags": build["flags"],
            source_key: build[source_key], "validation": {validation_key: validation[validation_key]},
            "emitted_source_sha256": sha(source.encode()), "artifact_sha256": sha(content),
            "returncode": execution.returncode, "stdout": "", "stderr": "",
        }, sort_keys=True), flush=True)

    def refuse_aliases(self, targets, **options):
        for name in targets:
            for relative in (False, True):
                for explicit in (False, True):
                    with self.subTest(target=name, relative=relative, explicit=explicit):
                        with self.project() as (root, entry, alias):
                            self.link(alias, root / name, relative)
                            self.assert_refused(root, entry, alias if explicit else None, **options)

    def test_default_owner_inputs_match_explicit_aliases(self):
        self.refuse_aliases(("app/hepta.toml", "app/src/main.hepta", "app/src/unused.hepta",
                             "app/src/unused.hepta.imports.json"))
        for explicit in (False, True):
            with self.subTest(crate_type="obj", explicit=explicit):
                with self.project() as (root, entry, alias):
                    alias = alias.with_suffix(".o")
                    self.link(alias, root / "app/hepta.toml", relative=True)
                    self.assert_refused(root, entry, alias if explicit else None, crate_type="obj")

    def test_default_dependency_inputs_match_explicit_aliases(self):
        self.refuse_aliases(("dep/hepta.toml", "dep/src/lib.hepta", "dep/src/unused.hepta",
                             "dep/src/unused.hepta.imports.json"))

    def test_verified_owner_lock_and_unread_lock_scope(self):
        self.refuse_aliases(("app/Hepta.lock",))
        for name, locked in (("app/Hepta.lock", False), ("dep/Hepta.lock", False), ("dep/Hepta.lock", True)):
            for explicit in (False, True):
                with self.subTest(target=name, locked=locked, explicit=explicit):
                    with self.project() as (root, entry, alias):
                        self.link(alias, root / name, relative=True)
                        self.assert_output(root, entry, alias, explicit=explicit, locked=locked)

    def test_standalone_directory_alias_preserves_import(self):
        for relative in (False, True):
            for explicit in (False, True):
                with self.subTest(relative=relative, explicit=explicit):
                    with tempfile.TemporaryDirectory(prefix="hepta-default-standalone-") as directory:
                        root = Path(directory).resolve()
                        entry = root / "worker.hepta.hepta"
                        entry.write_text("import values::worker; fn main()->i32 effects {} { return worker::answer(); }\n")
                        (root / "values").mkdir()
                        (root / "values/worker.hepta").write_text("pub fn answer()->i32 effects {} { return 42; }\n")
                        self.link(root / "build", root / "values", relative)
                        self.assert_refused(root, entry, root / "build/worker.hepta" if explicit else None,
                                            locked=False)

    def test_normal_new_and_existing_defaults(self):
        for locked in (False, True):
            for existing in (False, True):
                with self.subTest(locked=locked, existing=existing):
                    with self.project() as (root, entry, output):
                        if existing:
                            output.parent.mkdir()
                            output.write_bytes(b"previous ordinary output\n")
                        self.assert_output(root, entry, output, locked=locked)

    def test_noninput_output_aliases_remain_permitted(self):
        for relative in (False, True):
            for explicit in (False, True):
                with self.subTest(relative=relative, explicit=explicit):
                    with self.project() as (root, entry, alias):
                        target = root / "ordinary-output"
                        target.write_bytes(b"replace an unrelated native output\n")
                        self.link(alias, target, relative)
                        self.assert_output(root, entry, alias, explicit=explicit)

    def test_debug_refusal_publishes_nothing(self):
        self.refuse_aliases(("app/hepta.toml", "dep/src/unused.hepta", "app/Hepta.lock"), debug=True)

    def test_original_driver_and_package_diagnostics(self):
        with self.project() as (root, entry, alias):
            self.assert_refused(root, entry, root / "app/src/main.hepta")
        self.refuse_aliases(("app/hepta.toml", "dep/src/unused.hepta"), locked=False)
        for locked in (False, True):
            for explicit in (False, True):
                with self.subTest(locked=locked, explicit=explicit):
                    with self.project() as (root, entry, alias):
                        # Package source-directory links remain an earlier error.
                        directory = root / "app/src/ordinary"
                        directory.mkdir()
                        self.link(alias.parent, directory, relative=True)
                        process, expected = self.cli(root, "check", entry, "--backend", "c", "--cc", self.cc,
                                                     *(["--locked"] if locked else []))
                        self.assertEqual(process.returncode, 1, expected)
                        self.assertEqual(expected["status"], "rejected")
                        self.assertEqual(expected["diagnostics"][0]["code"], "E_PACKAGE_SOURCE_LINK")
                        self.assertEqual(expected["diagnostics"][0]["message"],
                                         "Source directory symlinks are not supported by package locks; use a real directory")
                        self.assert_refused(root, entry, alias if explicit else None, locked=locked,
                                            expected=expected, code=1, debug=True)

    def test_z_actual_pinned_rust_parity_after_c_prerequisites(self):
        try:
            rustc = find_rustc()
            identity = toolchain_info(rustc)
        except HeptaError as error:
            self.skipTest("Actual pinned Rust unavailable after real GCC prerequisites: " + error.diagnostic.message)
        self.assertIn("release: 1.90.0", identity["version"].splitlines())
        self.refuse_aliases(("app/hepta.toml", "dep/src/unused.hepta", "app/Hepta.lock"),
                            backend="rust", rustc=rustc)
        with self.project() as (root, entry, output):
            self.assert_output(root, entry, output, backend="rust", rustc=rustc)
        with self.project() as (root, entry, alias):
            target = root / "ordinary-rust-output"
            target.write_bytes(b"previous native output\n")
            self.link(alias, target, relative=True)
            self.assert_output(root, entry, alias, backend="rust", rustc=rustc)


if __name__ == "__main__":
    unittest.main()
