#!/usr/bin/env python3
"""Replay the three finite release findings against the saved, pre-fix tools.

All mutation is confined to a temporary Git repository and fresh virtualenvs.
The source root supplies current HIA modules/fixtures; before/tools supplies the
reviewed historical builder and verifier. This is not a signature-bypass test.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import marshal
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE / "before" / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    builder = load("release_audit_before_builder", "tools/build_hia_candidate.py")
    verifier = load("release_audit_before_verifier", "tools/verify_hia_candidate.py")
    report = {"schema": "hepta.hia.release-audit-reproduction.v1", "python": sys.version,
              "before_tools": {name: builder.digest((HERE / "before" / name).read_bytes())
                               for name in ("tools/build_hia_candidate.py", "tools/verify_hia_candidate.py")},
              "findings": []}
    with tempfile.TemporaryDirectory(prefix="hia-release-audit-before-") as temporary:
        base = Path(temporary)
        root = base / "source"
        root.mkdir()
        shutil.copytree(source_root / "hepta", root / "hepta",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("pyproject.toml", "examples/hia_program/counter.hia",
                     "examples/hia_program/parameter_loan_return_v8.hia"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_root / name, path)
        (root / "tools").mkdir()
        for name in ("build_hia_candidate.py", "verify_hia_candidate.py"):
            shutil.copyfile(HERE / "before/tools" / name, root / "tools" / name)
        nested = root / "hepta/candidate_fixture"
        nested.mkdir()
        (nested / "__init__.py").write_text("")
        (nested / "fixture.hiaasm").write_text("fixture data\n")
        for command in (("init", "-q"), ("add", "."),
                        ("-c", "user.name=HIA release audit", "-c", "user.email=hia-audit@example.invalid",
                         "commit", "-qm", "finite source fixture")):
            subprocess.run(["git", "-C", str(root), *command], check=True, capture_output=True)
        bundle = base / "candidate"
        receipt = builder.build_candidate(bundle, root=root)
        manifest = json.loads((bundle / "candidate-manifest.json").read_bytes())
        report["fixture_source_manifest_sha256"] = manifest["source_manifest_sha256"]
        report["original_manifest_sha256"] = receipt["manifest_sha256"]

        # A real, valid timestamp pyc changes the imported route inventory only.
        route = root / "hepta/hia_routes.py"
        suffix = ('\n_original_inventory = route_inventory\ndef route_inventory():\n'
                  '    value = _original_inventory()\n'
                  '    value["cached_inventory_probe"] = True\n    return value\n')
        code = compile(route.read_text() + suffix, str(route), "exec")
        identity = route.stat()
        cache = Path(importlib.util.cache_from_source(str(route)))
        cache.parent.mkdir(exist_ok=True)
        cache.write_bytes(importlib.util.MAGIC_NUMBER
                          + struct.pack("<III", 0, int(identity.st_mtime) & 0xffffffff, identity.st_size & 0xffffffff)
                          + marshal.dumps(code))
        (root / ".git/info/exclude").write_text("__pycache__/\n")
        cached_bundle = base / "cached-candidate"
        cached_receipt = builder.build_candidate(cached_bundle, root=root)
        cached_manifest = json.loads((cached_bundle / "candidate-manifest.json").read_bytes())
        observation = {"name": "timestamp_pyc_changes_reproducible_candidate",
                       "same_source_seal": manifest["source_manifest_sha256"] == cached_manifest["source_manifest_sha256"],
                       "same_candidate_version": manifest["distribution"]["version"] == cached_manifest["distribution"]["version"],
                       "both_clean": not manifest["worktree_dirty"] and not cached_manifest["worktree_dirty"],
                       "same_wheel": receipt["wheel_sha256"] == cached_receipt["wheel_sha256"],
                       "cached_code_observed": cached_manifest["compatibility"]["routes"].get("cached_inventory_probe") is True}
        assert all(observation[key] for key in ("same_source_seal", "same_candidate_version", "both_clean", "cached_code_observed"))
        assert observation["same_wheel"] is False
        report["findings"].append(observation)

        # This tests contract consistency under a reseal, not an external pin bypass.
        resealed = base / "resealed-candidate"
        shutil.copytree(bundle, resealed)
        altered = json.loads((resealed / "candidate-manifest.json").read_bytes())
        altered["unexpected_manifest_key"] = "accepted by pre-fix validator"
        altered["claims"]["production_release_qualified"] = True
        wheel = resealed / altered["wheel"]
        with zipfile.ZipFile(wheel) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        prefix = next(name[:-len("METADATA")] for name in contents if name.endswith(".dist-info/METADATA"))
        contents[prefix + "hia-candidate.json"] = builder.encoded({k: v for k, v in altered.items() if k not in {"wheel", "files"}})
        contents[prefix + "entry_points.txt"] += b"unrequested-command = hepta.cli:main\n"
        record = io.StringIO(newline="")
        writer = csv.writer(record, lineterminator="\n")
        for name, data in sorted(contents.items()):
            if name == prefix + "RECORD":
                continue
            value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow((name, "sha256=" + value, len(data)))
        writer.writerow((prefix + "RECORD", "", ""))
        contents[prefix + "RECORD"] = record.getvalue().encode()
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in contents.items():
                archive.writestr(name, data)
        for entry in altered["files"]:
            data = (resealed / entry["path"]).read_bytes()
            entry.update(sha256=builder.digest(data), size_bytes=len(data))
        manifest_bytes = builder.encoded(altered)
        (resealed / "candidate-manifest.json").write_bytes(manifest_bytes)
        payload = {entry["path"]: (resealed / entry["path"]).read_bytes() for entry in altered["files"]}
        payload["candidate-manifest.json"] = manifest_bytes
        (resealed / "SHA256SUMS").write_bytes("".join(
            f"{builder.digest(data)}  {name}\n" for name, data in sorted(payload.items())).encode())
        accepted, _ = verifier.validate_bundle(resealed)
        assert accepted["claims"]["production_release_qualified"] is True
        report["findings"].append({"name": "resealed_unknown_claims_and_metadata",
                                   "unknown_key_accepted": "unexpected_manifest_key" in accepted,
                                   "production_claim_accepted": accepted["claims"]["production_release_qualified"],
                                   "extra_console_entry_accepted": True,
                                   "external_manifest_pin_bypass_claimed": False})

        # The input manifest remains exactly pinned; mutate one nested installed file.
        original_run = subprocess.run
        mutation = []
        def change_after_install(*values, **options):
            result = original_run(*values, **options)
            command = values[0]
            if "pip" in command and "install" in command and result.returncode == 0:
                environment = Path(command[0]).parent.parent
                paths = list(environment.glob("**/site-packages/hepta/candidate_fixture/__init__.py"))
                assert len(paths) == 1
                paths[0].write_text("UNEXPECTED_INSTALLED_BYTES = True\n")
                mutation.append(paths[0].relative_to(environment).as_posix())
            return result
        with mock.patch.object(verifier.subprocess, "run", side_effect=change_after_install):
            installed = verifier.verify_installed(bundle, expected_manifest_sha256=receipt["manifest_sha256"])
        assert len(mutation) == 1 and installed["status"] == "passed"
        assert installed["manifest_sha256"] == receipt["manifest_sha256"]
        report["findings"].append({"name": "installed_subpackage_drift_under_original_pin",
                                   "status": installed["status"], "pin_unchanged": True,
                                   "altered_relative_path": mutation[0]})
    output = builder.encoded(report)
    if args.output:
        args.output.write_bytes(output)
    print(output.decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
