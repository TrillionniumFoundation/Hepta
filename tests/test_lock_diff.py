"""Lock migration-review evidence: JSON and content hashes, never native execution."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.lock_diff import compare_locks, read_lock_snapshot
from hepta.packages import load_package, package_snapshot, verify_lock, write_lock

ROOT = Path(__file__).resolve().parents[1]


class LockDiffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-lock-diff-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.package("app", kind="bin")
        self.before = self.root / "before.lock"
        self.after = self.root / "after.lock"
        self.snapshot(self.before)
        self.snapshot(self.after)

    def package(self, name, *, kind="lib", dependencies="", version="0.1.0"):
        root = self.root / name
        (root / "src").mkdir(parents=True)
        (root / "hepta.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "{version}"\nkind = "{kind}"\n' + dependencies,
            encoding="utf-8")
        # Deliberately not Hepta syntax: lock review must not parse source files.
        (root / "src" / ("main.hepta" if kind == "bin" else "lib.hepta")).write_bytes(b"opaque input bytes\n")
        return root

    def snapshot(self, destination):
        result = write_lock(self.app)
        shutil.copyfile(self.app / "Hepta.lock", destination)
        return result["snapshot"]

    def save(self, value, *, path=None, rehash=False):
        if rehash:
            value["sha256"] = hashlib.sha256(json.dumps(
                {"packages": value["packages"], "files": value["files"]},
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        (path or self.after).write_text(json.dumps(value), encoding="utf-8")

    def reject(self, value, *, rehash=False):
        self.save(value, rehash=rehash)
        with self.assertRaises(HeptaError) as ctx:
            compare_locks(self.before, self.after)
        self.assertEqual(ctx.exception.diagnostic.code, "E_LOCK_INVALID")
        self.assertEqual(ctx.exception.diagnostic.phase, "package")
        self.assertEqual(ctx.exception.diagnostic.span.path, str(self.after))

    def cli(self, *args):
        env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run([sys.executable, "-m", "hepta", "lock-diff", *map(str, args)],
                                cwd=self.root, env=env, capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.stderr, "", result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_unchanged_exact_report(self):
        source = json.loads(self.before.read_text())
        self.assertEqual(compare_locks(self.before, self.after), {
            "schema": "hepta.lock-diff.v1", "ok": True, "changed": False,
            "compatibility": "not_assessed", "before_sha256": source["sha256"],
            "after_sha256": source["sha256"],
            "packages": {"added": [], "removed": [], "changed": []},
            "dependencies": {"added": [], "removed": [], "retargeted": []},
            "files": {"added": [], "removed": [], "changed": []},
        })

    def test_format_order_encoding_and_bom_are_not_changes(self):
        value = json.loads(self.before.read_text())
        value = dict(reversed(list(value.items())))
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                self.after.write_bytes(json.dumps(value, indent=3).encode(encoding))
                self.assertFalse(compare_locks(self.before, self.after)["changed"])

    def test_source_only_edit_is_visible_without_version_change(self):
        (self.app / "src/main.hepta").write_bytes(b"different unparsed bytes\n")
        self.snapshot(self.after)
        report = compare_locks(self.before, self.after)
        self.assertTrue(report["changed"])
        self.assertEqual(report["packages"]["changed"], [])
        self.assertEqual(report["files"]["changed"], [{"path": "src/main.hepta",
            "before": hashlib.sha256(b"opaque input bytes\n").hexdigest(),
            "after": hashlib.sha256(b"different unparsed bytes\n").hexdigest()}])

    def test_existing_loader_snapshot_with_file_source_root_remains_readable(self):
        (self.app / "main.hepta").write_bytes(b"opaque source")
        (self.app / "hepta.toml").write_text(
            '[package]\nname="app"\nversion="0.1.0"\nsource_root="main.hepta"\nentry="main.hepta"\n')
        snapshot = self.snapshot(self.before)
        self.assertEqual(set(snapshot["files"]), {"hepta.toml"})
        self.assertEqual(read_lock_snapshot(self.before), snapshot)
        self.assertFalse(compare_locks(self.before, self.before)["changed"])

    def test_added_removed_and_sidecar_files(self):
        (self.app / "src/old.hepta").write_bytes(b"old")
        self.snapshot(self.before)
        (self.app / "src/old.hepta").unlink()
        (self.app / "src/new.hepta").write_bytes(b"new")
        (self.app / "src/new.hepta.imports.json").write_bytes(b"metadata")
        self.snapshot(self.after)
        report = compare_locks(self.before, self.after)
        self.assertEqual([x["path"] for x in report["files"]["added"]], ["src/new.hepta", "src/new.hepta.imports.json"])
        self.assertEqual([x["path"] for x in report["files"]["removed"]], ["src/old.hepta"])
        self.assertEqual(report["files"]["changed"], [])

    def test_package_metadata_changes_are_explicit(self):
        manifest = self.app / "hepta.toml"
        manifest.write_text('[package]\nname="renamed"\nversion="2.3.4"\nkind="lib"\nentry="src/entry.hepta"\n')
        (self.app / "src/entry.hepta").write_bytes(b"entry")
        self.snapshot(self.after)
        changes = compare_locks(self.before, self.after)["packages"]["changed"]
        self.assertEqual(changes, [{"path": ".", "changes": {
            "name": {"before": "app", "after": "renamed"},
            "version": {"before": "0.1.0", "after": "2.3.4"},
            "kind": {"before": "bin", "after": "lib"},
            "entry": {"before": "src/main.hepta", "after": "src/entry.hepta"}}}])

    def test_dependency_add_remove_retarget_and_shared_graph(self):
        self.package("shared")
        self.package("left", dependencies='[dependencies]\ncommon={path="../shared"}\n')
        self.package("right", dependencies='[dependencies]\ncommon={path="../shared"}\n')
        manifest = self.app / "hepta.toml"
        base = manifest.read_text()
        manifest.write_text(base + '[dependencies]\nchosen={path="../left"}\nkeep={path="../shared"}\n')
        self.snapshot(self.before)
        manifest.write_text(base + '[dependencies]\nchosen={path="../right"}\nother={path="../shared"}\n')
        self.snapshot(self.after)
        report = compare_locks(self.before, self.after)
        self.assertEqual([p["path"] for p in report["packages"]["added"]], ["../right"])
        self.assertEqual([p["path"] for p in report["packages"]["removed"]], ["../left"])
        self.assertEqual(report["dependencies"], {
            "added": [{"package": ".", "alias": "other", "target": "../shared"},
                      {"package": "../right", "alias": "common", "target": "../shared"}],
            "removed": [{"package": ".", "alias": "keep", "target": "../shared"},
                        {"package": "../left", "alias": "common", "target": "../shared"}],
            "retargeted": [{"package": ".", "alias": "chosen", "before": "../left", "after": "../right"}]})

    def test_existing_target_retarget_and_transitive_version_changes(self):
        left = self.package("left")
        self.package("right")
        manifest = self.app / "hepta.toml"
        manifest.write_text(manifest.read_text() + '[dependencies]\na={path="../left"}\nb={path="../right"}\n')
        self.snapshot(self.before)
        manifest.write_text(manifest.read_text().replace('a={path="../left"}', 'a={path="../right"}') + 'c={path="../left"}\n')
        child = left / "hepta.toml"
        child.write_text(child.read_text().replace('"0.1.0"', '"1.0.0"'))
        self.snapshot(self.after)
        report = compare_locks(self.before, self.after)
        self.assertEqual(report["packages"]["added"], [])
        self.assertEqual(report["packages"]["removed"], [])
        self.assertEqual(report["packages"]["changed"], [{"path": "../left", "changes": {"version": {"before": "0.1.0", "after": "1.0.0"}}}])
        self.assertEqual(report["dependencies"]["retargeted"], [{"package": ".", "alias": "a", "before": "../left", "after": "../right"}])

    def test_unicode_and_relocated_offline_snapshots(self):
        (self.app / "src/审阅😀.hepta").write_bytes(b"unicode path")
        self.snapshot(self.before)
        (self.app / "src/审阅😀.hepta").write_bytes(b"new bytes")
        self.snapshot(self.after)
        expected = compare_locks(self.before, self.after)
        relocated = self.root / "elsewhere"
        relocated.mkdir()
        shutil.copyfile(self.before, relocated / "old")
        shutil.copyfile(self.after, relocated / "new")
        shutil.rmtree(self.app)
        self.assertEqual(compare_locks(relocated / "old", relocated / "new"), expected)
        code, report = self.cli(relocated / "old", relocated / "new")
        self.assertEqual(code, 0)
        self.assertEqual(report, expected)
        self.assertEqual(report["files"]["changed"][0]["path"], "src/审阅😀.hepta")

    def test_only_named_lock_files_are_opened_and_neither_is_changed(self):
        original = Path.read_bytes
        reads = []
        def recording(path):
            reads.append(path)
            return original(path)
        before, after = self.before.read_bytes(), self.after.read_bytes()
        with patch.object(Path, "read_bytes", recording):
            compare_locks(self.before, self.after)
        self.assertEqual(reads, [self.before, self.after])
        self.assertEqual(self.before.read_bytes(), before)
        self.assertEqual(self.after.read_bytes(), after)
        self.assertEqual(compare_locks(self.before, self.before)["changed"], False)

    def test_digest_and_hash_shape_rejections(self):
        original = json.loads(self.after.read_text())
        for value in (None, [], {}, True, "", "A" * 64, "0" * 63, "0" * 64):
            with self.subTest(value=value):
                candidate = copy.deepcopy(original)
                candidate["sha256"] = value
                self.reject(candidate)
        for value in (None, [], True, "A" * 64, "0" * 63):
            with self.subTest(file_hash=value):
                candidate = copy.deepcopy(original)
                candidate["files"]["src/main.hepta"] = value
                self.reject(candidate, rehash=True)
        candidate = copy.deepcopy(original)
        candidate["files"]["src/main.hepta"] = "1" * 64
        self.reject(candidate)

    def test_schema_and_container_rejections(self):
        original = json.loads(self.after.read_text())
        for candidate in ([], None, 1, "text", {}, {**original, "extra": 1}, {**original, "schema": "hepta.lock.v2"},
                          {**original, "packages": []}, {**original, "packages": {}}, {**original, "files": []}):
            with self.subTest(candidate=candidate):
                self.reject(candidate)

    def test_metadata_and_path_rejections(self):
        original = json.loads(self.after.read_text())
        invalid = {"name": (None, [], "bad-name"), "version": (1, [], "01.0.0", "1.0"),
                   "kind": (None, [], {}, "other"), "entry": ([], "../outside.hepta", "/main.hepta", "src/main.txt"),
                   "dependencies": ([], None)}
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    candidate = copy.deepcopy(original)
                    candidate["packages"]["."][field] = value
                    self.reject(candidate, rehash=True)
        for name in ("", "/absolute", "./relative", "a/../b", "a//b", "a/", ".", "nul\x00path"):
            with self.subTest(path=name):
                candidate = copy.deepcopy(original)
                candidate["files"][name] = "0" * 64
                self.reject(candidate, rehash=True)
        candidate = copy.deepcopy(original)
        del candidate["files"]["hepta.toml"]
        self.reject(candidate, rehash=True)

    def test_graph_rejections(self):
        original = json.loads(self.after.read_text())
        for deps in ({"x": "missing"}, {"x": []}, {"bad-alias": "."}, {"x": "."}):
            candidate = copy.deepcopy(original)
            candidate["packages"]["."]["dependencies"] = deps
            self.reject(candidate, rehash=True)
        self.package("other")
        manifest = self.app / "hepta.toml"
        manifest.write_text(manifest.read_text() + '[dependencies]\nother={path="../other"}\n')
        valid = self.snapshot(self.after)
        candidate = copy.deepcopy(valid)
        candidate["packages"]["."]["dependencies"] = {}
        self.reject(candidate, rehash=True)
        candidate = copy.deepcopy(valid)
        candidate["packages"]["."]["kind"] = "lib"
        candidate["packages"]["../other"]["dependencies"] = {"back": "."}
        self.reject(candidate, rehash=True)
        candidate = copy.deepcopy(valid)
        candidate["packages"]["../other"]["kind"] = "bin"
        self.reject(candidate, rehash=True)

    def test_duplicate_keys_invalid_json_and_nonfinite_values(self):
        valid = self.before.read_bytes()
        samples = [b"not json", b"\xff", b'{"schema": 1, "schema": 2}',
                   valid.replace(b'"version": "0.1.0"', b'"version": "0.1.0", "version": "0.1.0"'),
                   valid.replace(b'"kind": "bin"', b'"kind": NaN'),
                   valid.replace(b'"kind": "bin"', b'"kind": Infinity')]
        for sample in samples:
            with self.subTest(sample=sample[:50]):
                self.after.write_bytes(sample)
                with self.assertRaises(HeptaError) as ctx:
                    read_lock_snapshot(self.after)
                self.assertEqual(ctx.exception.diagnostic.code, "E_LOCK_INVALID")

    def test_cli_exit_statuses_diagnostics_and_existing_lock_behavior(self):
        for flag in ([], ["--check"]):
            code, report = self.cli(self.before, self.after, *flag)
            self.assertEqual(code, 0)
            self.assertFalse(report["changed"])
        (self.app / "src/main.hepta").write_bytes(b"changed")
        self.snapshot(self.after)
        for flag, expected in (([], 0), (["--check"], 1)):
            code, report = self.cli(self.before, self.after, *flag)
            self.assertEqual(code, expected)
            self.assertTrue(report["ok"])
            self.assertTrue(report["changed"])
        # Existing lock creation and verification are unchanged.
        self.assertEqual(verify_lock(load_package(self.app)), read_lock_snapshot(self.after))
        self.after.write_text("{}")
        code, report = self.cli(self.before, self.after)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["diagnostics"][0]["code"], "E_LOCK_INVALID")
        code, report = self.cli(self.before, self.root / "missing")
        self.assertEqual(code, 2)
        self.assertEqual(report["diagnostics"][0]["code"], "E_DRIVER")

    def test_report_is_reversible_and_accounts_for_every_file_difference(self):
        rng = random.Random(20261105)
        original = json.loads(self.before.read_text())
        for case in range(80):
            old, new = copy.deepcopy(original), copy.deepcopy(original)
            expected = {"added": [], "removed": [], "changed": []}
            for i in range(12):
                path = f"src/input_{i:02}.hepta"
                before = rng.choice((None, "0" * 64, "1" * 64))
                after = rng.choice((None, "0" * 64, "1" * 64))
                if before is not None:
                    old["files"][path] = before
                if after is not None:
                    new["files"][path] = after
                if before != after:
                    category = "added" if before is None else "removed" if after is None else "changed"
                    expected[category].append(path)
            self.save(old, path=self.before, rehash=True)
            self.save(new, rehash=True)
            with self.subTest(case=case):
                forward = compare_locks(self.before, self.after)
                reverse = compare_locks(self.after, self.before)
                for category in expected:
                    self.assertEqual([x["path"] for x in forward["files"][category]], expected[category])
                self.assertEqual(forward["files"]["added"], reverse["files"]["removed"])
                self.assertEqual(forward["files"]["removed"], reverse["files"]["added"])
                self.assertEqual(forward["changed"], any(expected.values()))
                self.assertEqual(forward["compatibility"], "not_assessed")


if __name__ == "__main__":
    unittest.main()
