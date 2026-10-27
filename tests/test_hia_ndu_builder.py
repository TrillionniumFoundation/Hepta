"""Build provenance controls; simulated artifacts are not execution evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from tools import build_hia_ndu_bridge as builder


class NduBridgeBuildIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bridge = self.root / "bridge"
        (self.bridge / "src").mkdir(parents=True)
        (self.bridge / "src/main.rs").write_text("fn main() {}\n")
        (self.bridge / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.0.0'\n")
        (self.bridge / "Cargo.lock").write_text("version=4\n")
        self.target = self.bridge / "target"
        (self.target / "release").mkdir(parents=True)
        patcher = mock.patch.object(builder, "BRIDGE", self.bridge)
        patcher.start()
        self.addCleanup(patcher.stop)

    def artifact_output(self, executable):
        event = {"reason": "compiler-artifact", "package_id": "fixture#hia-ndu-bridge@0.1.0",
                 "target": {"name": "hia-ndu-bridge", "kind": ["bin"],
                            "src_path": str(self.bridge / "src/main.rs")},
                 "profile": {"test": False}, "fresh": False,
                 "executable": str(executable)}
        return json.dumps(event) + "\n" + json.dumps({"reason": "build-finished", "success": True})

    def test_selects_reported_artifact_instead_of_existing_stale_default(self):
        stale = self.target / "release/hia-ndu-bridge"
        stale.write_bytes(b"simulated stale artifact: not compiled or executed")
        actual = self.target / "reported-target/release/hia-ndu-bridge"
        actual.parent.mkdir(parents=True)
        actual.write_bytes(b"simulated Cargo-reported artifact: not compiled or executed")
        chosen, _ = builder._select_artifact(self.artifact_output(actual), self.target)
        self.assertEqual(chosen, actual)
        self.assertNotEqual(builder._sha(chosen), builder._sha(stale))

    def test_no_artifact_duplicate_or_failed_build_cannot_qualify_stale_binary(self):
        stale = self.target / "release/hia-ndu-bridge"
        stale.write_bytes(b"simulated old binary")
        output = self.artifact_output(stale)
        first = output.splitlines()[0]
        for malformed in (
            json.dumps({"reason": "build-finished", "success": True}),
            first + "\n" + output,
            output.replace('"success": true', '"success": false'),
            output.replace('"test": false', '"test": true'),
            output.replace('"kind": ["bin"]', '"kind": ["lib"]'),
            output.replace('"fresh": false', '"fresh": false, "fresh": true'),
        ):
            with self.subTest(output=malformed):
                with self.assertRaises(ValueError):
                    builder._select_artifact(malformed, self.target)

    def test_executable_cannot_escape_target_or_use_a_symlink(self):
        outside = self.root / "outside"
        outside.write_bytes(b"simulated unowned binary")
        symlink = self.target / "release/link"
        symlink.symlink_to(outside)
        for invalid in (outside, symlink, self.target / "missing"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    builder._select_artifact(self.artifact_output(invalid), self.target)

    def test_build_environment_and_command_pin_target_and_actual_rustc(self):
        original = {"PATH": "/toolchain", "CARGO_BUILD_TARGET": "other-target",
                    "CARGO_TARGET_DIR": "/stale-target", "RUSTC": "/old-rustc",
                    "RUSTC_WRAPPER": "/wrapper", "RUSTC_WORKSPACE_WRAPPER": "/other-wrapper"}
        env = builder._build_environment(self.target, Path("/actual-rustc"), original)
        self.assertEqual(original["CARGO_BUILD_TARGET"], "other-target")
        self.assertNotIn("CARGO_BUILD_TARGET", env)
        self.assertEqual(env["CARGO_TARGET_DIR"], str(self.target))
        self.assertEqual(env["RUSTC"], "/actual-rustc")
        self.assertEqual(env["RUSTC_WRAPPER"], "")
        self.assertEqual(env["RUSTC_WORKSPACE_WRAPPER"], "")
        command = builder._build_command(Path("/actual-cargo"), self.target)
        self.assertEqual(command[command.index("--target-dir") + 1], str(self.target))
        self.assertIn("--message-format=json-render-diagnostics", command)

    def export_fixture(self):
        upstream = self.bridge / "upstream"
        (upstream / "hepta-ndu/src").mkdir(parents=True)
        (upstream / ".hia-pinned-export").write_text(builder.UPSTREAM)
        source = upstream / "hepta-ndu/src/lib.rs"
        source.write_bytes(b"pub const VALUE: u8 = 1;\n")
        return {"source_sha256": {"codex-rs/hepta-ndu/src/lib.rs": builder._sha(source)},
                "manifest_adaptations": {}}

    def test_persistent_source_or_lock_drift_refuses_publication(self):
        report = self.export_fixture()
        before = builder._build_inputs(report)
        inputs = [self.bridge / "src/main.rs", self.bridge / "Cargo.toml", self.bridge / "Cargo.lock"]
        for path in inputs:
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\n# changed during build\n")
                with self.subTest(path=path):
                    with self.assertRaisesRegex(ValueError, "changed during compilation"):
                        builder._verify_inputs_unchanged(report, before)
            finally:
                path.write_bytes(original)
        self.assertEqual(builder._verify_inputs_unchanged(report, before), before)
        self.assertIn(str(Path(builder.__file__).resolve()), before["local"])

    def test_upstream_drift_and_uninventoried_build_script_are_rejected(self):
        report = self.export_fixture()
        before = builder._build_inputs(report)
        source = self.bridge / "upstream/hepta-ndu/src/lib.rs"
        original = source.read_bytes()
        source.write_bytes(b"pub const VALUE: u8 = 2;\n")
        with self.assertRaisesRegex(ValueError, "pinned export"):
            builder._verify_inputs_unchanged(report, before)
        source.write_bytes(original)
        (source.parent.parent / "build.rs").write_text("fn main() {}\n")
        with self.assertRaisesRegex(ValueError, "pinned export"):
            builder._verify_inputs_unchanged(report, before)

    def test_real_git_replace_cannot_change_export_under_pinned_commit(self):
        source = self.root / "source"
        source.mkdir()

        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=source,
                                           text=True, stderr=subprocess.PIPE).strip()

        git("init", "-q")
        git("config", "user.name", "Builder Test")
        git("config", "user.email", "builder-test@example.invalid")
        workspace = '[workspace.package]\nedition="2024"\nlicense="Apache-2.0"\nversion="0.0.0"\n[workspace.dependencies]\n'
        (source / "codex-rs").mkdir()
        (source / "codex-rs/Cargo.toml").write_text(workspace)
        (self.bridge / "Cargo.toml").write_text(workspace)
        for name in builder.CRATES:
            crate = source / "codex-rs" / name
            (crate / "src").mkdir(parents=True)
            (crate / "src/lib.rs").write_text("pub const VALUE: u8 = 1;\n")
            (crate / "Cargo.toml").write_text(
                '[package]\nname="' + name + '"\nversion="0.0.0"\n[dependencies]\n')
        git("add", ".")
        git("-c", "commit.gpgsign=false", "commit", "-qm", "original fixture")
        pinned = git("rev-parse", "HEAD")
        changed = source / "codex-rs/hepta-ndu/src/lib.rs"
        changed.write_text("pub const VALUE: u8 = 99;\n")
        git("add", ".")
        git("-c", "commit.gpgsign=false", "commit", "-qm", "replacement fixture")
        replacement = git("rev-parse", "HEAD")
        git("replace", pinned, replacement)
        self.assertIn("99", git("show", pinned + ":codex-rs/hepta-ndu/src/lib.rs"))
        with mock.patch.object(builder, "UPSTREAM", pinned):
            report = builder.prepare(source)
            snapshot = builder._export_snapshot(report)
        exported = self.bridge / "upstream/hepta-ndu/src/lib.rs"
        self.assertEqual(exported.read_text(), "pub const VALUE: u8 = 1;\n")
        self.assertEqual(snapshot["hepta-ndu/src/lib.rs"], hashlib.sha256(exported.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
