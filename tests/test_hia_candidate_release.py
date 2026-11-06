"""Install the actual candidate wheel and reject stale/tampered release bytes."""
from __future__ import annotations

import io
import base64
import csv
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest import mock
import venv
import zipfile

from tools.build_hia_candidate import ROOT, build_candidate, digest, encoded
from tools.verify_hia_candidate import validate_bundle, verify_installed


class CandidateReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-candidate-tests-")
        cls.base = Path(cls.temporary.name)
        cls.root = cls.base / "source"
        cls.root.mkdir()
        shutil.copytree(ROOT / "hepta", cls.root / "hepta", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("pyproject.toml", "tools/build_hia_candidate.py", "tools/verify_hia_candidate.py",
                     "examples/hia_program/counter.hia", "examples/hia_program/parameter_loan_return_v8.hia"):
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        # Exercise nested packages and authored HIA data even when the product
        # application is extended independently of this release regression.
        nested = cls.root / "hepta" / "candidate_fixture"
        nested.mkdir()
        (nested / "__init__.py").write_text("")
        (nested / "fixture.hiaasm").write_text("fixture data\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=HIA release test", "-c", "user.email=hia-test@example.invalid", "commit", "-qm", "candidate fixture")):
            subprocess.run(["git", "-C", str(cls.root), *args], check=True, capture_output=True)
        cls.bundle = cls.base / "candidate"
        cls.receipt = build_candidate(cls.bundle, root=cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copied_bundle(self):
        directory = Path(tempfile.mkdtemp(dir=self.base)) / "bundle"
        shutil.copytree(self.bundle, directory)
        return directory

    def reseal_outer(self, directory):
        manifest_path = directory / "candidate-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for entry in manifest["files"]:
            data = (directory / entry["path"]).read_bytes()
            entry.update(sha256=digest(data), size_bytes=len(data))
        manifest_path.write_bytes(encoded(manifest))
        payload = {entry["path"]: (directory / entry["path"]).read_bytes() for entry in manifest["files"]}
        payload["candidate-manifest.json"] = manifest_path.read_bytes()
        (directory / "SHA256SUMS").write_bytes("".join(
            f"{digest(data)}  {name}\n" for name, data in sorted(payload.items())).encode())

    def rewrite_wheel(self, directory, mutate):
        manifest = json.loads((directory / "candidate-manifest.json").read_bytes())
        path = directory / manifest["wheel"]
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        prefix = next(name[:-len("METADATA")] for name in files if name.endswith(".dist-info/METADATA"))
        mutate(files, prefix)
        record = io.StringIO(newline="")
        writer = csv.writer(record, lineterminator="\n")
        for name, data in sorted(files.items()):
            if name == prefix + "RECORD":
                continue
            value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow((name, "sha256=" + value, len(data)))
        writer.writerow((prefix + "RECORD", "", ""))
        files[prefix + "RECORD"] = record.getvalue().encode()
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.reseal_outer(directory)

    def test_repeated_build_is_byte_identical_and_contains_subpackage_data(self):
        second = self.base / "second"
        receipt = build_candidate(second, root=self.root)
        self.assertEqual(receipt["manifest_sha256"], self.receipt["manifest_sha256"])
        self.assertEqual(receipt["wheel_sha256"], self.receipt["wheel_sha256"])
        self.assertEqual({p.name: p.read_bytes() for p in self.bundle.iterdir()},
                         {p.name: p.read_bytes() for p in second.iterdir()})
        manifest, payload = validate_bundle(second)
        self.assertFalse(manifest["worktree_dirty"])
        self.assertIn("+hia.g", manifest["distribution"]["version"])
        with zipfile.ZipFile(io.BytesIO(payload[manifest["wheel"]])) as wheel:
            self.assertEqual(wheel.read("hepta/candidate_fixture/fixture.hiaasm"), b"fixture data\n")

    def test_installed_wheel_executes_without_source_checkout_imports(self):
        result = verify_installed(self.bundle, expected_manifest_sha256=self.receipt["manifest_sha256"])
        self.assertEqual(result["status"], "passed")
        names = {row["name"] for row in result["observations"]}
        self.assertTrue({"offline_wheel_install", "installed_identity", "interpret", "installed_console_script",
                         "emit_x86_64-unknown-linux-gnu", "emit_aarch64-unknown-linux-gnu",
                         "emit_riscv64-unknown-linux-gnu"}.issubset(names))
        self.assertFalse(result["claims"]["production_release_qualified"])
        self.assertFalse(result["claims"]["cross_target_execution_qualified"])
        manifest, _ = validate_bundle(self.bundle)
        package = [row for row in manifest["source_files"] if row["path"].startswith("hepta/")]
        by_name = {row["name"]: row for row in result["observations"]}
        self.assertIn("installed_layout", by_name)
        for name in ("installed_package_before", "installed_package_after"):
            self.assertEqual(by_name[name]["file_count"], len(package))
            self.assertEqual(by_name[name]["package_manifest_sha256"], digest(encoded(package)))

    def test_valid_timestamp_bytecode_cannot_change_same_source_candidate(self):
        source = self.root / "hepta/hia_routes.py"
        suffix = ('\n_original_inventory = route_inventory\ndef route_inventory():\n'
                  '    value = _original_inventory()\n'
                  '    value["cached_inventory_probe"] = True\n    return value\n')
        code = compile(source.read_text() + suffix, str(source), "exec")
        info = source.stat()
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir(exist_ok=True)
        previous = cache.read_bytes() if cache.exists() else None
        poison = (importlib.util.MAGIC_NUMBER
                  + struct.pack("<III", 0, int(info.st_mtime) & 0xffffffff, info.st_size & 0xffffffff)
                  + marshal.dumps(code))
        exclude = self.root / ".git/info/exclude"
        original_exclude = exclude.read_bytes()
        try:
            cache.write_bytes(poison)
            exclude.write_bytes(original_exclude + b"\n__pycache__/\n")
            repeated = self.base / "timestamp-cache-rebuild"
            receipt = build_candidate(repeated, root=self.root)
            self.assertEqual(receipt["source_manifest_sha256"], self.receipt["source_manifest_sha256"])
            self.assertEqual(receipt["manifest_sha256"], self.receipt["manifest_sha256"])
            self.assertEqual(receipt["wheel_sha256"], self.receipt["wheel_sha256"])
            manifest, _ = validate_bundle(repeated)
            self.assertNotIn("cached_inventory_probe", manifest["compatibility"]["routes"])
            self.assertEqual(cache.read_bytes(), poison)
        finally:
            exclude.write_bytes(original_exclude)
            if previous is None:
                cache.unlink()
            else:
                cache.write_bytes(previous)

    def test_resealed_unknown_manifest_fields_and_promoted_claims_reject(self):
        for change in ("unknown_manifest", "unknown_distribution", "production_claim"):
            with self.subTest(change=change):
                directory = self.copied_bundle()
                path = directory / "candidate-manifest.json"
                manifest = json.loads(path.read_bytes())
                if change == "unknown_manifest":
                    manifest["unexpected"] = "must not become a new receipt capability"
                elif change == "unknown_distribution":
                    manifest["distribution"]["unexpected"] = True
                else:
                    manifest["claims"]["production_release_qualified"] = True
                path.write_bytes(encoded(manifest))
                embedded = encoded({key: value for key, value in manifest.items() if key not in {"wheel", "files"}})
                self.rewrite_wheel(directory, lambda files, prefix: files.__setitem__(prefix + "hia-candidate.json", embedded))
                with self.assertRaises(ValueError):
                    validate_bundle(directory)

    def test_resealed_extra_console_entry_is_not_source_equivalent_metadata(self):
        directory = self.copied_bundle()
        def add_script(files, prefix):
            files[prefix + "entry_points.txt"] += b"unrequested-console = hepta.cli:main\n"
        self.rewrite_wheel(directory, add_script)
        with self.assertRaisesRegex(ValueError, "metadata/source configuration differs: entry_points.txt"):
            validate_bundle(directory)

    def test_resealed_embedded_duplicate_keys_reject(self):
        directory = self.copied_bundle()
        def duplicate_schema(files, prefix):
            name = prefix + "hia-candidate.json"
            files[name] = b'{"schema":"incorrect-first-value",' + files[name][1:]
        self.rewrite_wheel(directory, duplicate_schema)
        with self.assertRaisesRegex(ValueError, "embedded candidate identity must use canonical JSON"):
            validate_bundle(directory)

    def test_installed_subpackage_code_and_data_drift_reject_with_original_manifest_pin(self):
        for relative in ("__init__.py", "fixture.hiaasm"):
            with self.subTest(relative=relative):
                original_run = subprocess.run
                altered = []
                def change_after_install(*args, **kwargs):
                    result = original_run(*args, **kwargs)
                    command = args[0]
                    if "pip" in command and "install" in command and result.returncode == 0:
                        environment = Path(command[0]).parent.parent
                        paths = list(environment.glob("**/site-packages/hepta/candidate_fixture/" + relative))
                        self.assertEqual(len(paths), 1)
                        paths[0].write_text("UNEXPECTED_INSTALLED_BYTES = True\n")
                        altered.append(paths[0])
                    return result
                with mock.patch("tools.verify_hia_candidate.subprocess.run", side_effect=change_after_install):
                    with self.assertRaisesRegex(ValueError, "installed package/source bytes differ"):
                        verify_installed(self.bundle, expected_manifest_sha256=self.receipt["manifest_sha256"])
                self.assertEqual(len(altered), 1)

    def test_installed_package_is_checked_again_after_smoke_execution(self):
        original_run = subprocess.run
        altered = []
        def change_after_console(*args, **kwargs):
            result = original_run(*args, **kwargs)
            command = args[0]
            if len(command) == 3 and command[1:] == ["hia", "routes"] and result.returncode == 0:
                environment = Path(command[0]).parent.parent
                paths = list(environment.glob("**/site-packages/hepta/candidate_fixture/fixture.hiaasm"))
                self.assertEqual(len(paths), 1)
                paths[0].write_text("unexpected data after execution\n")
                altered.append(paths[0])
            return result
        with mock.patch("tools.verify_hia_candidate.subprocess.run", side_effect=change_after_console):
            with self.assertRaisesRegex(ValueError, "installed package/source bytes differ"):
                verify_installed(self.bundle, expected_manifest_sha256=self.receipt["manifest_sha256"])
        self.assertEqual(len(altered), 1)

    def test_verification_receipt_binds_captured_bytes_if_bundle_changes_later(self):
        directory = self.copied_bundle()
        original_create = venv.EnvBuilder.create

        def create_then_replace_manifest(builder, environment):
            original_create(builder, environment)
            (directory / "candidate-manifest.json").write_bytes(b'{"changed":true}\n')

        with mock.patch.object(venv.EnvBuilder, "create", create_then_replace_manifest):
            result = verify_installed(directory, expected_manifest_sha256=self.receipt["manifest_sha256"])
        self.assertEqual(result["manifest_sha256"], self.receipt["manifest_sha256"])
        self.assertNotEqual(result["manifest_sha256"], digest((directory / "candidate-manifest.json").read_bytes()))

    def test_noncanonical_manifest_rejects(self):
        directory = self.copied_bundle()
        path = directory / "candidate-manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            validate_bundle(directory)

    def test_wrong_external_manifest_pin_rejects(self):
        with self.assertRaisesRegex(ValueError, "pinned SHA256"):
            validate_bundle(self.bundle, expected_manifest_sha256="0" * 64)

    def test_changed_wheel_bytes_reject_before_installation(self):
        directory = self.copied_bundle()
        manifest = json.loads((directory / "candidate-manifest.json").read_bytes())
        with (directory / manifest["wheel"]).open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            validate_bundle(directory)

    def test_rehashing_outer_bundle_cannot_hide_changed_package_data(self):
        directory = self.copied_bundle()
        manifest = json.loads((directory / "candidate-manifest.json").read_bytes())
        path = directory / manifest["wheel"]
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        files["hepta/candidate_fixture/fixture.hiaasm"] = b"changed data\n"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.reseal_outer(directory)
        with self.assertRaisesRegex(ValueError, "wheel/source bytes differ"):
            validate_bundle(directory)

    def test_rehashing_outer_bundle_cannot_hide_changed_execution_fixture(self):
        directory = self.copied_bundle()
        (directory / "counter.hia").write_bytes(b'{"changed":true}\n')
        self.reseal_outer(directory)
        with self.assertRaisesRegex(ValueError, "bundle/source bytes differ"):
            validate_bundle(directory)

    def test_symlinked_fixture_rejects(self):
        directory = self.copied_bundle()
        (directory / "counter.hia").unlink()
        (directory / "counter.hia").symlink_to(self.bundle / "counter.hia")
        with self.assertRaisesRegex(ValueError, "regular files"):
            validate_bundle(directory)

    def test_unlisted_bundle_member_rejects(self):
        directory = self.copied_bundle()
        (directory / "surprise.py").write_text("pass\n")
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            validate_bundle(directory)

    def test_documented_relative_sibling_output_is_accepted(self):
        result = subprocess.run([sys.executable, "tools/build_hia_candidate.py", "--output-directory", "../relative-candidate"],
                                cwd=self.root, check=True, capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(result.stdout)["status"], "candidate_built_not_qualified")
        validate_bundle(self.base / "relative-candidate")

    def test_existing_output_is_never_overwritten(self):
        with self.assertRaisesRegex(ValueError, "must be absent"):
            build_candidate(self.bundle, root=self.root)

    def test_dirty_build_is_explicit_and_cannot_pass_clean_verification(self):
        source = self.root / "untracked-development-note"
        source.write_text("uncommitted\n")
        try:
            with self.assertRaisesRegex(ValueError, "source is dirty"):
                build_candidate(self.base / "dirty-refused", root=self.root)
            receipt = build_candidate(self.base / "dirty-explicit", root=self.root, allow_dirty=True)
            self.assertTrue(receipt["worktree_dirty"])
            with self.assertRaisesRegex(ValueError, "uncommitted source"):
                validate_bundle(self.base / "dirty-explicit")
            validate_bundle(self.base / "dirty-explicit", allow_dirty=True)
        finally:
            source.unlink()


if __name__ == "__main__":
    unittest.main()
