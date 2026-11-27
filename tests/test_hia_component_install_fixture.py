"""Physical component-wheel and install controls; no native-delivery claim."""
from __future__ import annotations

import ast
import base64
import csv
from hashlib import sha256
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
import zipfile

from tests import hia_component_install_fixture as fixture

ROOT = Path(__file__).resolve().parents[1]


def record(files, name):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for path in sorted(set(files) | {name}):
        raw = files.get(path, b"")
        writer.writerow([path, "", ""] if path == name else [
            path, "sha256=" + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode(),
            str(len(raw))])
    return stream.getvalue().encode()


def archive(files, modes):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as wheel:
        for name, raw in files.items():
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = (0o100755 if modes.get(name) else 0o100644) << 16
            wheel.writestr(item, raw)
    return output.getvalue()


class ComponentWheelControls(unittest.TestCase):
    def test_record_requires_complete_exact_physical_membership(self):
        name = "test-1.dist-info/RECORD"
        files = {"package/value.py": b"original bytes\n"}
        files[name] = record(files, name)
        fixture._record(files, name)
        rows = list(csv.reader(io.StringIO(files[name].decode())))
        cases = {}
        for label, changed in (
                ("duplicate", rows + [rows[0]]),
                ("missing", rows[:-1]),
                ("unknown", rows + [["unknown", "sha256=x", "0"]]),
                ("float-size", [[*rows[0][:2], "15.0"], *rows[1:]]),
                ("zero-prefixed-size", [[*rows[0][:2], "015"], *rows[1:]]),
                ("boolean-size", [[*rows[0][:2], "True"], *rows[1:]]),
                ("blank-member-hash", [[rows[0][0], "", rows[0][2]], *rows[1:]]),
                ("hashed-self", [rows[0], [name, "sha256=x", "0"]]),
                ("traversal", [["../outside", "sha256=x", "0"], *rows]),
                ("extra-column", [[*rows[0], "extra"], *rows[1:]])):
            out = io.StringIO(newline="")
            csv.writer(out, lineterminator="\n").writerows(changed)
            cases[label] = {**files, name: out.getvalue().encode()}
        cases["unrecorded-physical-file"] = {**files, "extra": b"x"}
        cases["changed-member"] = {**files, "package/value.py": b"modified bytes\n"}
        for label, altered in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                fixture._record(altered, name)

    def test_zip_rejects_duplicates_redirects_and_unsafe_paths(self):
        for label, name, mode in (
                ("parent", "../outside", 0o100644),
                ("absolute", "/outside", 0o100644),
                ("symlink", "package/link", 0o120777),
                ("setuid", "package/file", 0o104755),
                ("directory", "package/", 0o40755),
                ("dot-component", "package/./file", 0o100644)):
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, "w") as wheel:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                wheel.writestr(entry, b"bytes")
            with self.subTest(label=label), self.assertRaises(ValueError):
                fixture._zip(raw.getvalue())
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as wheel:
            wheel.writestr("same", b"a")
            wheel.writestr("same", b"b")
        with self.assertRaises(ValueError):
            fixture._zip(raw.getvalue())

    def test_physical_inputs_reject_leaf_and_parent_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="hia-component-link-controls-") as name:
            root = Path(name).resolve()
            (root / "real").mkdir()
            (root / "real/input").write_bytes(b"original")
            (root / "leaf").symlink_to(root / "real/input")
            (root / "parent").symlink_to(root / "real", target_is_directory=True)
            for path in ("leaf", "parent/input"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    fixture._read(root, path)
            (root / "hard").hardlink_to(root / "real/input")
            with self.assertRaises(ValueError):
                fixture._read(root, "hard")

    def test_resource_parser_follows_added_explicit_setup_groups(self):
        names = ("setup.py", "hepta/hia_agent_contract.py",
                 "hepta/hia_executable_capture.py", "hepta/hia_nominal_program_native.py")
        captured = {name: (ROOT / name).read_bytes() for name in names}
        original, package = fixture._resource_paths(captured)
        source = captured["setup.py"].decode()
        anchor = " + NOMINAL_BYTE_BOUNDARY_RESOURCES:"
        self.assertEqual(source.count(anchor), 1)
        changed = source.replace(anchor, " + NOMINAL_BYTE_BOUNDARY_RESOURCES + NEW_EXPLICIT_GROUP:")
        changed = "NEW_EXPLICIT_GROUP = ('examples/hia_bootstrap/extra_control.hepta',)\n" + changed
        expanded, same_package = fixture._resource_paths({**captured, "setup.py": changed.encode()})
        self.assertEqual(expanded, original + ("examples/hia_bootstrap/extra_control.hepta",))
        self.assertEqual(package, same_package)
        with self.assertRaises(ValueError):
            fixture._resource_paths({**captured, "setup.py": changed.replace(
                "'examples/hia_bootstrap/extra_control.hepta'", "'../outside'").encode()})

    def test_actual_component_wheel_install_and_rebound_tamper_controls(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        work = Path(tempfile.mkdtemp(prefix="hia-component-install-controls-")).resolve()
        work.chmod(0o700)
        stage = work / "source"
        stage.mkdir()
        shutil.copytree(ROOT / "hepta", stage / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, "setup.py", "pyproject.toml", "MANIFEST.in"):
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        component = fixture.component_wheel(stage)
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("PYTHONPATH", "PYTHONHOME") and not key.startswith("HEPTA_HIA_")}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        def run(label, arguments):
            result = subprocess.run([sys.executable, "-B", *map(str, arguments)], cwd=work,
                                    env=environment, capture_output=True, timeout=60)
            (work / (label + ".stdout")).write_bytes(result.stdout)
            (work / (label + ".stderr")).write_bytes(result.stderr)
            (work / (label + ".result.json")).write_text(json.dumps({
                "returncode": result.returncode, "timeout_seconds": 60,
                "stdout_sha256": sha256(result.stdout).hexdigest(),
                "stderr_sha256": sha256(result.stderr).hexdigest()}, sort_keys=True) + "\n")
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))
        run("wheel", ["-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--no-index",
                      "--wheel-dir", work / "wheels", component])
        wheel, = (work / "wheels").glob("*.whl")
        installed = work / "installed"
        run("install", ["-m", "pip", "install", "--no-deps", "--no-index", "--no-compile",
                        "--target", installed, wheel])
        report = fixture.verify_component_install(component, installed, installed_from=wheel)
        self.assertIs(report["component_install_verified"], True)
        self.assertIs(report["native_cold_qualified"], False)
        self.assertIs(report["whole_native_delivery_qualified"], False)
        self.assertEqual(report["scope"], fixture.SCOPE)
        authority = json.loads((ROOT / fixture.AUTHORITY).read_bytes())
        self.assertEqual(report["native_authority_input_count"], len(authority["paths"]))
        item = fixture._built[str(component)]
        files = item["files"]
        record_path = item["record"]
        prefix = record_path[:-len("RECORD")]
        member = "hepta/hia_evaluation_native.py"
        original = (installed / member).read_bytes()
        original_record = (installed / record_path).read_bytes()
        controls = []
        def rejected(label, action, restore):
            try:
                action()
                with self.assertRaises(ValueError, msg=label):
                    fixture.verify_component_install(component, installed, installed_from=wheel)
                controls.append(label)
            finally:
                restore()
        def rebound_file():
            (installed / member).write_bytes(original + b"\n# changed\n")
            actual = {name: (installed / name).read_bytes() for name in fixture._inventory(installed)}
            (installed / record_path).write_bytes(record(actual, record_path))
        rejected("changed-installed-file-with-rebound-RECORD", rebound_file, lambda: (
            (installed / member).write_bytes(original),
            (installed / record_path).write_bytes(original_record)))
        rejected("extra-installed-file", lambda: (installed / "extra").write_bytes(b"x"),
                 lambda: (installed / "extra").unlink())
        rejected("missing-installed-file", lambda: (installed / member).unlink(),
                 lambda: (installed / member).write_bytes(original))
        rejected("changed-installed-executable-mode", lambda: (installed / member).chmod(0o755),
                 lambda: (installed / member).chmod(0o644))
        rejected("duplicate-installed-RECORD-row", lambda: (installed / record_path).write_bytes(
            original_record + original_record.splitlines(keepends=True)[0]),
            lambda: (installed / record_path).write_bytes(original_record))
        def symlink():
            (installed / member).unlink()
            (installed / member).symlink_to(ROOT / member)
        rejected("symlink-installed-file", symlink, lambda: (
            (installed / member).unlink(), (installed / member).write_bytes(original)))
        copied = wheel.read_bytes()
        copied_mode = wheel.stat().st_mode & 0o777
        def changed_copy():
            wheel.chmod(0o600)
            wheel.write_bytes(copied + b"extra")
        def restore_copy():
            wheel.write_bytes(copied)
            wheel.chmod(copied_mode)
        rejected("changed-pip-wheel-copy", changed_copy, restore_copy)
        custody = item["custody_path"]
        custody_raw = custody.read_bytes()
        def forged_custody():
            custody.chmod(0o600)
            value = json.loads(custody_raw)
            value["whole_native_delivery_qualified"] = True
            custody.write_text(json.dumps(value))
        rejected("forged-native-qualification-custody", forged_custody, lambda: (
            custody.write_bytes(custody_raw), custody.chmod(0o400)))
        url_path = installed / (prefix + "direct_url.json")
        url_raw = url_path.read_bytes()
        def rebound_url():
            value = json.loads(url_raw)
            value["url"] = component.as_uri()
            url_path.write_text(json.dumps(value))
            actual = {name: (installed / name).read_bytes() for name in fixture._inventory(installed)}
            (installed / record_path).write_bytes(record(actual, record_path))
        rejected("wrong-origin-with-rebound-RECORD", rebound_url, lambda: (
            url_path.write_bytes(url_raw), (installed / record_path).write_bytes(original_record)))
        for label, change in (
                ("source-bytes-with-rebound-wheel-RECORD", lambda value: value.__setitem__(
                    member, value[member] + b"\n# changed\n")),
                ("missing-source-with-rebound-wheel-RECORD", lambda value: value.pop(member)),
                ("extra-member-with-valid-wheel-RECORD", lambda value: value.__setitem__("extra", b"x"))):
            altered = dict(files)
            change(altered)
            altered[record_path] = record(altered, record_path)
            with self.subTest(label=label), self.assertRaises(ValueError):
                fixture._checked_wheel(component, archive(altered, item["modes"]), item["snapshot"])
            controls.append(label)
        staged = stage / member
        saved = staged.read_bytes()
        staged.write_bytes(saved + b"\n# stale staged input\n")
        try:
            with self.assertRaises(ValueError):
                fixture.component_wheel(stage)
            controls.append("stale-partial-stage-rejected-even-after-cache")
        finally:
            staged.write_bytes(saved)
        (stage / "unexpected").write_bytes(b"x")
        try:
            with self.assertRaises(ValueError):
                fixture.component_wheel(stage)
            controls.append("unknown-partial-stage-rejected-even-after-cache")
        finally:
            (stage / "unexpected").unlink()
        def reject_late_mutation(label, boundary, target, call):
            original_call = getattr(fixture, boundary)
            before = target.read_bytes()
            mode = target.stat().st_mode & 0o777
            mutated = False
            def change_after_real_check(*args, **kwargs):
                nonlocal mutated
                value = original_call(*args, **kwargs)
                target.chmod(mode | 0o200)
                target.write_bytes(before + b"\n# late custody mutation\n")
                self.assertNotEqual(target.read_bytes(), before)
                mutated = True
                return value
            try:
                with patch.object(fixture, boundary, change_after_real_check):
                    with self.assertRaises(ValueError, msg=label):
                        call()
                self.assertTrue(mutated, "the actual validation boundary was not reached: " + label)
                controls.append(label)
            finally:
                target.write_bytes(before)
                target.chmod(mode)
        reject_late_mutation("installed-terminal-sidecar", "_verify_installed", custody,
                             lambda: fixture.verify_component_install(
                                 component, installed, installed_from=wheel))
        for label, target in (
                ("cached-terminal-partial-stage", staged),
                ("cached-terminal-git-source", ROOT / member),
                ("cached-terminal-wheel", component),
                ("cached-terminal-custody", custody)):
            reject_late_mutation(label, "_checked_wheel", target,
                                 lambda: fixture.component_wheel(stage))
        final = fixture.verify_component_install(component, installed, installed_from=wheel)
        self.assertEqual(report, final)
        self.assertEqual(len(controls), 19)
        (work / "qualification.json").write_text(json.dumps({
            "positive": report, "negative_controls": controls,
            "original_command_timeout_seconds": 60,
            "component": str(component), "pip_wheel_copy": str(wheel),
            "all_control_mutations_restored": True}, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"component_install_evidence": str(work), "report": report,
                          "negative_controls_passed": len(controls)}, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
