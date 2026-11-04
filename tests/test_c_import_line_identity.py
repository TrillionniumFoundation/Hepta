"""Native C binding identities survive text publication and line-ending changes.

The Windows-newline case models only Python text-stream publication on the
current host. It does not claim that a native Windows importer was executed.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.c_import import import_header
from hepta.cli import main
from hepta.modules import load_project
from hepta.pipeline import analyze_project


ROOT = Path(__file__).resolve().parents[1]
LINE_ENDINGS = (("LF", b"\n"), ("CRLF", b"\r\n"), ("CR", b"\r"))
CONVERTED_ENDINGS = LINE_ENDINGS[1:]


@unittest.skipUnless(shutil.which("gcc"), "GCC required for native C import probes")
class CImportLineIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-import-lines-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.header = self.directory / "api.h"
        self.binding = self.directory / "api.hepta"
        self.sidecar = self.directory / "api.hepta.imports.json"
        self.entry = self.directory / "main.hepta"
        self.header_bytes = b"#define LIMIT 7\ntypedef struct Counter { long value; } Counter;\n"
        self.header.write_bytes(self.header_bytes)
        self.entry.write_bytes(
            b"import api; fn main() -> Unit effects {panic} "
            b"{assert(api::cconst_LIMIT() == 7);}\n"
        )
        # Every fixture executes the real compiler and its native header probe.
        self.imported = import_header(self.header, module="api", cc="gcc")
        self.publish()

    def publish(self, newline=b"\n", *, rehash=False, metadata=None):
        source = self.imported.source.encode("utf-8").replace(b"\n", newline)
        manifest = copy.deepcopy(self.imported.manifest if metadata is None else metadata)
        if rehash:
            manifest["source_sha256"] = hashlib.sha256(source).hexdigest()
        self.binding.write_bytes(source)
        self.sidecar.write_bytes((json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"))
        return source

    def assert_load_rejected(self, expected_code):
        with self.assertRaises(HeptaError) as raised:
            load_project(self.entry)
        self.assertEqual(raised.exception.diagnostic.code, expected_code)

    def cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "hepta", *map(str, arguments)],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )

    def assert_cli_rejected(self, process, expected_code):
        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertFalse(report["ok"], report)
        self.assertIn(expected_code, {item["code"] for item in report["diagnostics"]})

    def assert_full_inventory(self, project):
        expected = {str(path) for path in (self.entry, self.binding, self.sidecar, self.header)}
        self.assertEqual(set(project.sources), expected)
        self.assertEqual(set(project.source_bytes), expected)
        self.assertEqual(len(project.c_imports), 1)
        self.assertTrue(project.unchanged())
        for path in (self.entry, self.binding, self.sidecar, self.header):
            self.assertEqual(project.source_bytes[str(path)], path.read_bytes())
            self.assertEqual(project.sources[str(path)], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_lf_bundle_retains_inventory_and_passes_native_cli(self):
        self.assert_full_inventory(load_project(self.entry))
        checked = self.cli("check", self.entry, "--backend", "c", "--cc", "gcc")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        report = json.loads(checked.stdout)
        self.assertTrue(report["ok"], report)
        self.assertEqual(len(report["project"]["c_imports"]), 1)
        self.assertEqual(report["checks"]["c_types_codegen"], "gcc_checked")

    def test_converted_source_requires_its_exact_byte_hash(self):
        for label, newline in CONVERTED_ENDINGS:
            with self.subTest(newline=label):
                source = self.publish(newline)
                self.assertNotEqual(hashlib.sha256(source).hexdigest(), self.imported.manifest["source_sha256"])
                self.assert_load_rejected("E_C_IMPORT_IDENTITY")

    def test_converted_marker_rejects_missing_sidecar(self):
        for label, newline in CONVERTED_ENDINGS:
            with self.subTest(newline=label):
                self.publish(newline)
                self.sidecar.unlink()
                self.assert_load_rejected("E_C_IMPORT_MANIFEST")

    def test_converted_marker_rejects_malformed_sidecar(self):
        for label, newline in CONVERTED_ENDINGS:
            with self.subTest(newline=label):
                self.publish(newline)
                self.sidecar.write_bytes(b"{not valid JSON")
                self.assert_load_rejected("E_C_IMPORT_MANIFEST")

    def test_rehashed_converted_bundle_retains_inventory_and_change_detection(self):
        for label, newline in CONVERTED_ENDINGS:
            with self.subTest(newline=label):
                self.publish(newline, rehash=True)
                project = load_project(self.entry)
                self.assert_full_inventory(project)
                original_manifest = self.sidecar.read_bytes()
                # Valid JSON whitespace still changes the captured evidence bytes.
                self.sidecar.write_bytes(original_manifest + b" ")
                self.assertFalse(project.unchanged())
                changed = load_project(self.entry)
                self.assertNotEqual(changed.identity, project.identity)
                self.sidecar.write_bytes(original_manifest)
                self.assertTrue(project.unchanged())
                self.header.write_bytes(self.header_bytes + b"\n")
                self.assertFalse(project.unchanged())
                self.header.write_bytes(self.header_bytes)
                self.assertTrue(project.unchanged())

    def test_matching_source_hash_does_not_bypass_host_identity(self):
        for label, newline in LINE_ENDINGS:
            with self.subTest(newline=label):
                manifest = copy.deepcopy(self.imported.manifest)
                manifest["host"]["system"] = "DifferentHost"
                self.publish(newline, rehash=True, metadata=manifest)
                self.assert_load_rejected("E_C_IMPORT_TARGET")

    def test_matching_source_hash_does_not_bypass_header_identity(self):
        for label, newline in LINE_ENDINGS:
            with self.subTest(newline=label):
                self.publish(newline, rehash=True)
                self.header.write_bytes(self.header_bytes.replace(b"LIMIT 7", b"LIMIT 9"))
                self.assert_load_rejected("E_C_IMPORT_IDENTITY")

    def test_generated_bindings_refuse_explicit_foreign_target(self):
        for label, newline in LINE_ENDINGS:
            with self.subTest(newline=label):
                self.publish(newline, rehash=True)
                result = analyze_project(self.entry, native=False, target="thumbv7em-none-eabi")
                self.assertFalse(result.report["ok"], result.report)
                self.assertIn("E_C_IMPORT_TARGET", {item["code"] for item in result.report["diagnostics"]})

    def test_handwritten_extern_without_marker_remains_an_explicit_foreign_assumption(self):
        self.binding.write_bytes(
            b'module api; extern "C" fn foreign_value() -> i32 effects {ffi, unsafe};\r\n'
        )
        self.entry.write_bytes(b"import api; fn main() -> Unit effects {} {}\n")
        self.sidecar.write_bytes(b"not a generated bundle")
        project = load_project(self.entry)
        self.assertEqual(project.c_imports, [])
        self.assertEqual(set(project.sources), {str(self.entry), str(self.binding)})
        declaration = next(function for function in project.program.functions if function.name == "foreign_value")
        self.assertTrue(declaration.extern_c)
        self.assertEqual(set(declaration.effects), {"ffi", "unsafe"})
        result = analyze_project(self.entry, native=False, target="thumbv7em-none-eabi")
        self.assertTrue(result.report["ok"], result.report)

    def test_public_native_run_refuses_stale_imported_constant(self):
        healthy = self.cli("run", self.entry, "--backend", "c", "--cc", "gcc")
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
        for label, newline in CONVERTED_ENDINGS:
            for rehash in (False, True):
                with self.subTest(newline=label, rehashed_source=rehash):
                    self.publish(newline, rehash=rehash)
                    self.header.write_bytes(self.header_bytes.replace(b"LIMIT 7", b"LIMIT 9"))
                    # The consumer still asserts the old value 7. It must never
                    # execute successfully after the recorded header has changed.
                    stale = self.cli("run", self.entry, "--backend", "c", "--cc", "gcc")
                    self.assert_cli_rejected(stale, "E_C_IMPORT_IDENTITY")

    def test_public_cli_import_publishes_the_manifest_source_bytes(self):
        imported = self.cli("import-c", self.header, "--module", "api", "--cc", "gcc", "-o", self.binding)
        self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
        report = json.loads(imported.stdout)
        self.assertTrue(report["ok"], report)
        payload = self.binding.read_bytes()
        self.assertEqual(payload, self.imported.source.encode("utf-8"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), report["validation"]["source_sha256"])
        self.assertEqual(json.loads(self.sidecar.read_bytes()), report["validation"])
        self.assert_full_inventory(load_project(self.entry))

    def test_publication_models_windows_text_newline_without_native_windows_claim(self):
        real_write_text = Path.write_text
        modeled_text_writes = []

        def write_text_with_crlf_default(path, data, *args, **kwargs):
            # A bounded publication-only model: the real Python text writer is
            # used for the two output paths. GCC and all probes remain real and
            # run with the actual host's behavior, identity and native ABI.
            if path in (self.binding, self.sidecar) and kwargs.get("newline") is None:
                kwargs["newline"] = "\r\n"
                modeled_text_writes.append(path)
            return real_write_text(path, data, *args, **kwargs)

        with patch.object(Path, "write_text", write_text_with_crlf_default):
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                code = main(["import-c", str(self.header), "--module", "api", "--cc", "gcc", "-o", str(self.binding)])
        self.assertEqual(code, 0, captured.getvalue())
        report = json.loads(captured.getvalue())
        self.assertTrue(report["ok"], report)
        self.assertIn(self.sidecar, modeled_text_writes)
        self.assertEqual(self.binding.read_bytes(), self.imported.source.encode("utf-8"))
        self.assertEqual(hashlib.sha256(self.binding.read_bytes()).hexdigest(), report["validation"]["source_sha256"])
        self.assert_full_inventory(load_project(self.entry))

    def test_real_git_autocrlf_checkout_cannot_discard_generated_identity(self):
        git = shutil.which("git")
        self.assertIsNotNone(git, "Git is required for the real CRLF checkout regression")
        self.assert_full_inventory(load_project(self.entry))
        # Ambient attributes/config or GIT_DIR/GIT_INDEX_FILE must not change
        # this checkout policy or direct fixture writes to another repository.
        home = self.directory / "git-home"
        home.mkdir()
        git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        git_env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                       GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_ATTR_NOSYSTEM="1")
        subprocess.run([git, "init", "-q", str(self.directory)], check=True, capture_output=True, timeout=10, env=git_env)
        command = [git, "-C", str(self.directory), "-c", "core.autocrlf=true", "-c", "core.safecrlf=false"]
        subprocess.run([*command, "add", "--", "api.h", "api.hepta", "api.hepta.imports.json", "main.hepta"],
                       check=True, capture_output=True, timeout=10, env=git_env)
        for path in (self.header, self.binding, self.sidecar, self.entry):
            path.unlink()
        subprocess.run([*command, "checkout-index", "-a"], check=True, capture_output=True, timeout=10, env=git_env)
        self.assertTrue(self.binding.read_bytes().startswith(b"// hepta:c-import:v1\r\n"))
        self.header.write_bytes(self.header_bytes.replace(b"LIMIT 7", b"LIMIT 9").replace(b"\n", b"\r\n"))
        stale = self.cli("run", self.entry, "--backend", "c", "--cc", "gcc")
        self.assert_cli_rejected(stale, "E_C_IMPORT_IDENTITY")


if __name__ == "__main__":
    unittest.main()
