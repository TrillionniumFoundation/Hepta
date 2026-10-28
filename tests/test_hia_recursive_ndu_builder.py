"""Real Git/process admission controls; the compiler fixture is explicitly simulated.

These tests validate source rejection and evidence preservation. They do not
claim a native Rust build. Separate qualification builds the actual two pins.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.build_hia_recursive_ndu_bridge import build


CARGO_FIXTURE = r'''
import json, os, pathlib, sys
if sys.argv[1:] == ["--version"]:
    print("cargo simulated-builder-fixture")
    raise SystemExit(0)
pathlib.Path(os.environ["HIA_BUILDER_TEST_MARKER"]).write_text("build attempted")
mode = os.environ.get("HIA_BUILDER_TEST_MODE", "")
if mode == "failed":
    sys.stdout.buffer.write(b"raw-out\x00\xff\n")
    sys.stderr.buffer.write(b"raw-err\x00\xfe\n")
    raise SystemExit(17)
identity = {"schema": "hepta.hia.ndu.identity.v1",
    "source_commit": os.environ["HEPTA_NDU_SOURCE_COMMIT"],
    "source_digest": os.environ["HEPTA_NDU_SOURCE_DIGEST"],
    "bridge_digest": os.environ["HEPTA_NDU_BRIDGE_DIGEST"],
    "rustc": os.environ["HEPTA_NDU_RUSTC"],
    "authority": "DENY_ALL", "safety_certificate": False}
if mode == "bad-identity":
    identity["source_commit"] = "0" * 40
binary = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / "release/hepta-hia-ndu-bridge"
binary.parent.mkdir(parents=True, exist_ok=True)
binary.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(identity)) + ")\n")
binary.chmod(0o755)
if mode == "source-drift":
    (pathlib.Path.cwd() / "src/main.rs").write_text("// altered during simulated build\n")
if mode == "ignored-addition":
    (pathlib.Path.cwd() / "src/ignored.rs").write_text("// unexpected source addition\n")
if mode == "tool-drift":
    path = pathlib.Path(sys.argv[0])
    path.write_text(path.read_text() + "\n# altered during simulated build\n")
print("original simulated Cargo stdout")
print("original simulated Cargo stderr", file=sys.stderr)
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "real POSIX process and Git controls required")
class RecursiveNduBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "source"
        self.upstream.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Builder Test Fixture")
        self.git("config", "user.email", "builder-fixture@example.invalid")
        files = {"codex-rs/Cargo.toml": "[workspace]\n",
                 "tools/hia-ndu-bridge/Cargo.toml": "# simulated manifest\n",
                 "tools/hia-ndu-bridge/Cargo.lock": "# pinned simulated lock\n",
                 "tools/hia-ndu-bridge/src/main.rs": "fn main() {}\n"}
        for crate in ("hepta-ndu", "hepta-types", "hepta-contracts"):
            files[f"codex-rs/{crate}/Cargo.toml"] = "# simulated manifest\n"
            files[f"codex-rs/{crate}/src/lib.rs"] = "// tracked fixture\n"
        for name, raw in files.items():
            path = self.upstream / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(raw)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "source admission fixture")
        self.pin = self.git("rev-parse", "HEAD").strip()
        self.cargo = self.base / "simulated-cargo"
        self.cargo.write_text("#!" + sys.executable + "\n" + CARGO_FIXTURE)
        self.cargo.chmod(0o755)
        self.rustc = self.base / "simulated-rustc"
        self.rustc.write_text("#!" + sys.executable + '\nprint("rustc 1.95.0 (simulated fixture)")\n')
        self.rustc.chmod(0o755)
        self.marker = self.base / "cargo-build-attempt"
        self.environment = patch.dict(os.environ, {"HIA_BUILDER_TEST_MARKER": str(self.marker),
                                                   "HIA_BUILDER_TEST_MODE": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.args = argparse.Namespace(ndu_source=self.upstream, output=self.base / "evidence",
            cargo=self.cargo, rustc=self.rustc, cargo_home=None,
            expected_source=self.pin, offline=True)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.upstream, text=True,
                                       stderr=subprocess.PIPE)

    def failure(self):
        return json.loads((self.args.output / "build-failure.json").read_bytes())

    def test_clean_pinned_inputs_external_cache_copy_and_actual_command_streams(self):
        self.args.target_dir = self.base / "cargo-cache"
        result = build(self.args)
        manifest = json.loads(result.read_bytes())
        self.assertEqual(manifest["source_admission"]["before"], manifest["source_admission"]["after"])
        self.assertEqual(manifest["source_admission"]["before"]["head"], self.pin)
        self.assertEqual(len(manifest["source_admission"]["before"]["input_git_blob_sha256"]), 10)
        self.assertEqual(manifest["binary_sha256"], manifest["compiled_binary_sha256"])
        self.assertEqual(Path(manifest["binary"]).parent, self.args.output / "native")
        self.assertFalse((self.args.output / "target").exists())
        self.assertEqual(set(manifest["build_tools"]), {"builder_sha256", "cargo_sha256", "rustc_sha256"})
        commands = json.loads((self.args.output / "build-commands.json").read_bytes())
        cargo = next(row for row in commands if row["argv"][:2] == [str(self.cargo), "build"])
        self.assertEqual((self.args.output / cargo["stdout"]["path"]).read_bytes(), b"original simulated Cargo stdout\n")
        self.assertEqual((self.args.output / cargo["stderr"]["path"]).read_bytes(), b"original simulated Cargo stderr\n")
        for row in commands:
            for channel in ("stdout", "stderr"):
                raw = (self.args.output / row[channel]["path"]).read_bytes()
                self.assertEqual(len(raw), row[channel]["bytes"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row[channel]["sha256"])
        self.assertFalse(manifest["safety_certificate"])

    def test_failed_process_preserves_original_non_utf8_streams_and_exit(self):
        os.environ["HIA_BUILDER_TEST_MODE"] = "failed"
        with self.assertRaisesRegex(RuntimeError, "command .*failed"):
            build(self.args)
        row = self.failure()["commands"][-1]
        self.assertEqual(row["returncode"], 17)
        self.assertEqual((self.args.output / row["stdout"]["path"]).read_bytes(), b"raw-out\x00\xff\n")
        self.assertEqual((self.args.output / row["stderr"]["path"]).read_bytes(), b"raw-err\x00\xfe\n")
        self.assertFalse((self.args.output / "identity.json").exists())

    def test_wrong_pin_and_missing_lock_reject_before_compiler_build(self):
        self.args.expected_source = "0" * 40
        with self.assertRaisesRegex(RuntimeError, "requested pin"):
            build(self.args)
        self.assertFalse(self.marker.exists())
        self.args.output = self.base / "missing-lock-evidence"
        self.args.expected_source = self.pin
        (self.upstream / "tools/hia-ndu-bridge/Cargo.lock").unlink()
        with self.assertRaisesRegex(RuntimeError, "Cargo.lock"):
            build(self.args)
        self.assertFalse(self.marker.exists())

    def test_dirty_working_staged_and_untracked_source_reject_before_build(self):
        source = self.upstream / "tools/hia-ndu-bridge/src/main.rs"
        original = source.read_bytes()
        for mode in ("working", "staged", "untracked"):
            self.args.output = self.base / mode
            with self.subTest(mode=mode):
                source.write_text("// changed\n")
                if mode == "staged":
                    self.git("add", str(source))
                if mode == "untracked":
                    source.write_bytes(original)
                    (self.upstream / "extra.txt").write_text("untracked source context")
                with self.assertRaisesRegex(RuntimeError, "not clean"):
                    build(self.args)
                self.assertFalse(self.marker.exists())
                self.git("reset", "--quiet", "--hard", self.pin)

    def test_git_hidden_changes_and_ignored_compiler_inputs_still_reject(self):
        source = self.upstream / "tools/hia-ndu-bridge/src/main.rs"
        original = source.read_bytes()
        self.git("update-index", "--assume-unchanged", str(source))
        source.write_text("// hidden working-tree change\n")
        self.assertFalse(self.git("status", "--porcelain"))
        with self.assertRaisesRegex(RuntimeError, "pinned Git blob"):
            build(self.args)
        self.assertFalse(self.marker.exists())
        source.write_bytes(original)
        self.git("update-index", "--no-assume-unchanged", str(source))
        (self.upstream / ".git/info/exclude").write_text("ignored.rs\n")
        (source.parent / "ignored.rs").write_text("// ignored compiler input\n")
        self.args.output = self.base / "ignored-evidence"
        self.assertFalse(self.git("status", "--porcelain"))
        with self.assertRaisesRegex(RuntimeError, "no pinned Git blob"):
            build(self.args)
        self.assertFalse(self.marker.exists())

    def test_changes_during_build_reject_without_success_receipt(self):
        for mode in ("source-drift", "ignored-addition", "tool-drift"):
            with self.subTest(mode=mode):
                os.environ["HIA_BUILDER_TEST_MODE"] = mode
                self.args.output = self.base / mode
                (self.upstream / ".git/info/exclude").write_text("ignored.rs\n")
                with self.assertRaisesRegex(RuntimeError, "not clean|source changed|tool changed"):
                    build(self.args)
                self.assertFalse((self.args.output / "identity.json").exists())
                self.assertTrue(self.marker.exists())
                self.git("reset", "--quiet", "--hard", self.pin)
                (self.upstream / "tools/hia-ndu-bridge/src/ignored.rs").unlink(missing_ok=True)
                self.cargo.write_text("#!" + sys.executable + "\n" + CARGO_FIXTURE)

    def test_stale_native_identity_rejects_without_success_receipt(self):
        os.environ["HIA_BUILDER_TEST_MODE"] = "bad-identity"
        with self.assertRaisesRegex(RuntimeError, "stale or invalid"):
            build(self.args)
        self.assertFalse((self.args.output / "identity.json").exists())
        self.assertTrue(self.failure()["commands"])

    def test_existing_evidence_is_never_overwritten(self):
        result = build(self.args)
        before = result.read_bytes()
        with self.assertRaises(FileExistsError):
            build(self.args)
        self.assertEqual(result.read_bytes(), before)
        self.assertFalse((self.args.output / "build-failure.json").exists())

    def test_outputs_inside_upstream_reject_without_modifying_checkout(self):
        self.args.target_dir = self.upstream / "cargo-target"
        with self.assertRaisesRegex(RuntimeError, "outside"):
            build(self.args)
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.git("status", "--porcelain"))


if __name__ == "__main__":
    unittest.main()
