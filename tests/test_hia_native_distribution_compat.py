"""Additional refusal controls for the explicit retained Python API fixture."""
from __future__ import annotations
import ast
import base64
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import sys

from tests import hia_native_distribution_compat as compat
from tests import hia_distribution_fixture as original

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CHECKERS = {'derived_python_pin': '5f96f375f5203e977203fc6e179f0749f50febb95194d2e683e0994231f5ceef', '_check_wheel': '3b1e05a8896d6b08ce81546c2e2a3809a61eff5f3ecf182ec05f181714454584'}


class NativeDistributionCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-compatibility-controls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.snapshot = compat.capture_sources(ROOT)
        cls.foreign = cls.directory / "captured-source"
        cls.foreign.mkdir()
        for name, raw in cls.snapshot["raw"].items():
            path = cls.foreign / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("HEPTA_HIA_TEST_DISTRIBUTION_WHEEL", None)
            os.environ.pop("HEPTA_HIA_TEST_DISTRIBUTION_SHA256", None)
            cls.wheel = compat.compatibility_wheel(ROOT, ROOT, sys.executable)
        cls.receipt = cls.wheel.parent.parent / "compatibility.json"
        cls.report_raw = cls.receipt.read_bytes()
        cls.report = json.loads(cls.report_raw)
        cls.profile = cls.report["profile"]
        cls.outputs = {
            role: {"path": Path(item["path"]), "raw": Path(item["path"]).read_bytes()}
            for role, item in cls.report["actual_mechanical_outputs"].items()
        }
        cls.wheel_raw = cls.wheel.read_bytes()
        with zipfile.ZipFile(cls.wheel) as archive:
            cls.files = {name: archive.read(name) for name in archive.namelist()}
        cls.record, = [n for n in cls.files if n.endswith(".dist-info/RECORD")]

    def test_01_complete_compatibility_identity_and_original_native_checker_refusal(self):
        tree = ast.parse((ROOT / "tests/hia_distribution_fixture.py").read_bytes())
        actual = {node.name: sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                  for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name in ORIGINAL_CHECKERS}
        self.assertEqual(actual, ORIGINAL_CHECKERS)
        checked = compat.check_wheel(self.wheel, self.snapshot, self.profile, self.outputs)
        self.assertTrue(checked["complete_record_verified"])
        self.assertTrue(checked["complete_member_set_verified"])
        self.assertEqual(self.report["scope"], "RETAINED_PYTHON_API_COMPATIBILITY_WHEEL")
        for key in ("ordinary_native_wheel_qualified", "native_tar_qualified",
                    "whole_native_delivery_qualified", "production_fallback"):
            self.assertIs(self.report[key], False)
        with self.assertRaisesRegex(KeyError, "provenance.json"):
            original._check_wheel(self.wheel, self.report["native_source_files"])
        with zipfile.ZipFile(self.wheel) as archive:
            with self.assertRaisesRegex(KeyError, "provenance.json"):
                original.derived_python_pin(archive)

    def test_02_complete_foreign_root_requires_native_authority_and_hosted_source(self):
        snapshot = compat.capture_sources(self.foreign)
        self.assertEqual(snapshot["pins"], self.snapshot["pins"])
        self.assertEqual(snapshot["root"], self.foreign)
        for name in ("docs/HIA_NATIVE_SOURCE_AUTHORITY.json", "hepta/hia_program_runtime.py"):
            with self.subTest(name=name):
                path = self.foreign / name
                raw = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        compat.capture_sources(self.foreign)
                finally:
                    path.write_bytes(raw)

    def test_03_foreign_reader_and_terminal_source_or_inventory_drift_are_rejected(self):
        for name in self.snapshot["loaded"]:
            with self.subTest(reader=name):
                path = self.foreign / name
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n")
                try:
                    with self.assertRaisesRegex(ValueError, "reader"):
                        compat.capture_sources(self.foreign)
                finally:
                    path.write_bytes(raw)
        snapshot = compat.capture_sources(self.foreign)
        path = self.foreign / "hepta/hia_program_runtime.py"
        raw = path.read_bytes()
        path.write_bytes(raw + b"\n")
        try:
            with self.assertRaisesRegex(ValueError, "terminal readback"):
                compat.terminal_sources(snapshot)
        finally:
            path.write_bytes(raw)
        extra = self.foreign / "hepta/hia_undeclared_compatibility_control.py"
        extra.write_bytes(b"unexpected = True\n")
        try:
            with self.assertRaises(ValueError):
                compat.terminal_sources(snapshot)
        finally:
            extra.unlink()
        compat.terminal_sources(snapshot)

    def _rewritten(self, label, transform, *, duplicate=None, symbolic=None):
        directory = self.directory / label
        directory.mkdir()
        path = directory / self.wheel.name
        files = dict(self.files)
        transform(files)
        rows = []
        for name, raw in sorted(files.items()):
            if name == self.record:
                rows.append([name, "", ""])
            else:
                digest = base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
                rows.append([name, "sha256=" + digest, str(len(raw))])
        stream = io.StringIO(newline="")
        csv.writer(stream, lineterminator="\n").writerows(rows)
        files[self.record] = stream.getvalue().encode()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, raw in files.items():
                    if name == symbolic:
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                        archive.writestr(info, raw)
                    else:
                        archive.writestr(name, raw)
                if duplicate is not None:
                    archive.writestr(duplicate, files[duplicate])
        return path

    def test_04_resigned_missing_extra_duplicate_and_symbolic_members_are_rejected(self):
        source = "hepta/hia_program_runtime.py"
        cases = [
            ("missing-member", lambda files: files.pop(source), {}),
            ("extra-member", lambda files: files.update({"hepta/foreign.py": b"pass\n"}), {}),
            ("duplicate-member", lambda files: None, {"duplicate": source}),
            ("symbolic-member", lambda files: None, {"symbolic": source}),
        ]
        for name, change, options in cases:
            with self.subTest(name=name):
                path = self._rewritten(name, change, **options)
                with self.assertRaises(ValueError):
                    compat.check_wheel(path, self.snapshot, self.profile, self.outputs)

    def test_05_resigned_source_and_forged_mechanical_output_are_rejected(self):
        def source_change(files):
            files["hepta/hia_program_runtime.py"] += b"\n"
        def mechanical_change(files):
            binary = "hepta/_hia_slot_mechanical" + self.profile["extension_suffix"]
            files[binary] += b"\x00"
            receipt = json.loads(files["hepta/_slot_mechanical_build.json"])
            receipt["binary"] = {"name": Path(binary).name, **compat.pin(files[binary])}
            files["hepta/_slot_mechanical_build.json"] = json.dumps(receipt, sort_keys=True).encode()
        for name, change in (("changed-source", source_change), ("forged-mechanical", mechanical_change)):
            with self.subTest(name=name):
                path = self._rewritten(name, change)
                with self.assertRaises(ValueError):
                    compat.check_wheel(path, self.snapshot, self.profile, self.outputs)

    def test_06_complete_record_hash_and_self_row_are_required(self):
        for name, change in (
            ("invalid-record-digest", lambda raw: raw.replace(b"sha256=", b"sha257=", 1)),
            ("invalid-record-self", lambda raw: raw.replace(
                (self.record + ",,\n").encode(), (self.record + ",sha256=wrong,1\n").encode())),
        ):
            with self.subTest(name=name):
                directory = self.directory / name
                directory.mkdir()
                path = directory / self.wheel.name
                with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                    for member, raw in self.files.items():
                        archive.writestr(member, change(raw) if member == self.record else raw)
                with self.assertRaisesRegex(ValueError, "RECORD"):
                    compat.check_wheel(path, self.snapshot, self.profile, self.outputs)

    def test_07_cached_wheel_receipt_and_physical_mechanical_drift_are_rejected(self):
        for path in (self.wheel, self.receipt, self.outputs["binary"]["path"]):
            with self.subTest(path=str(path)):
                raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
                path.chmod(0o600)
                path.write_bytes(raw + b"\n")
                try:
                    with self.assertRaises(ValueError):
                        compat.compatibility_wheel(ROOT, ROOT, sys.executable)
                finally:
                    path.write_bytes(raw)
                    path.chmod(mode)
        self.assertEqual(compat.compatibility_wheel(ROOT, ROOT, sys.executable), self.wheel)

    def test_08_ordinary_native_selector_and_foreign_staged_sources_are_rejected(self):
        for key in ("HEPTA_HIA_TEST_DISTRIBUTION_WHEEL", "HEPTA_HIA_TEST_DISTRIBUTION_SHA256"):
            with self.subTest(key=key), patch.dict("os.environ", {key: "not-a-compatibility-authority"}):
                with self.assertRaisesRegex(ValueError, "ordinary native wheel provenance"):
                    compat.compatibility_wheel(ROOT, ROOT, sys.executable)
        staging = self.directory / "foreign-staging"
        (staging / "hepta").mkdir(parents=True)
        path = staging / "hepta/hia_program_runtime.py"
        path.write_bytes(b"foreign = True\n")
        with self.assertRaisesRegex(ValueError, "staged different source"):
            compat.compatibility_wheel(ROOT, staging, sys.executable)
        path.unlink()
        extra = staging / "hepta/undeclared.py"
        extra.write_bytes(b"foreign = True\n")
        with self.assertRaisesRegex(ValueError, "undeclared Python source"):
            compat.compatibility_wheel(ROOT, staging, sys.executable)
        extra.unlink()
        path.symlink_to(ROOT / "hepta/hia_program_runtime.py")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            compat.compatibility_wheel(ROOT, staging, sys.executable)
