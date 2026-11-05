#!/usr/bin/env python3
"""Artifact-only development-sdist composition. Never import project modules."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PARENT = "dca2b7131bb2774eef7f45cac24a844eb9feb1bc"
ORIGIN = "5b7d69304f69423c8c4b4aeaeb156fed7fcf9b75"
COMPONENTS = "tools/development_sdist_components.json"
ORIGINAL_MANIFEST = "tools/packaging_origin_677/MANIFEST.in"
GENERATED = {
    "PKG-INFO", "setup.cfg", "hepta_language.egg-info/PKG-INFO",
    "hepta_language.egg-info/SOURCES.txt",
    "hepta_language.egg-info/dependency_links.txt",
    "hepta_language.egg-info/entry_points.txt",
    "hepta_language.egg-info/top_level.txt",
}
ADDITIONS = {
    "MANIFEST.in", "docs/PACKAGING.md", "tools/check_distribution.py",
    ORIGINAL_MANIFEST, "docs/DEVELOPMENT_SDIST_COMPOSITION.md",
    "tools/qualify_development_sdist.py", COMPONENTS,
}
SENTINELS = {
    "artifacts/not-a-result.json", "evidence/not-a-result.json",
    "experiments/agent_eval/evidence/not-a-result.json",
    "experiments/unrelated_research/not-a-program.py",
    "toolchains/not-a-tool.py", "hepta/__pycache__/not-code.pyc",
    "tools/not-code.pyc", "benchmarks/not-a-binary.bin",
}
RECEIPTS = []


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()
            and ".git" not in p.relative_to(root).parts
            and "__pycache__" not in p.relative_to(root).parts
            and p.suffix != ".pyc"}


def selected(name):
    # Exact source identities below constrain this independently of MANIFEST.in.
    return (name != ".gitignore" and not name.startswith((
        "artifacts/", "evidence/", "experiments/agent_eval/evidence/")))


def contract(files, from_sdist=False):
    c = json.loads(files[COMPONENTS])
    require(c["schema"] == "hepta.development-sdist-composition.v1", "wrong schema")
    require(c["parent_commit"] == PARENT and c["packaging_origin_commit"] == ORIGIN,
            "wrong source commits")
    require(len(c["parent_files"]) == 286 and len(c["origin_files"]) == 3,
            "source identity inventory mismatch")
    require(set(c["additions"]) == ADDITIONS, "addition inventory mismatch")
    require(not set(c["parent_files"]) & ADDITIONS, "parent/addition collision")
    names = set(c["parent_files"]) | ADDITIONS
    expected_names = {n for n in names if selected(n)}
    require(set(files) == (expected_names | GENERATED if from_sdist else names),
            "supplied source inventory mismatch")
    for name, entry in {**c["parent_files"], **c["origin_files"]}.items():
        if from_sdist and not selected(name):
            continue
        data = files[name]
        require(sha(data) == entry["sha256"] and git_blob(data) == entry["git_blob"],
                "source component changed: " + name)
    require(files["MANIFEST.in"].startswith(files[ORIGINAL_MANIFEST]),
            "original manifest prefix changed")
    config = tomllib.loads(files["pyproject.toml"].decode("utf-8"))
    require(config["build-system"]["build-backend"] == "setuptools.build_meta"
            and config["tool"]["setuptools"]["packages"] == ["hepta"]
            and config["project"]["dependencies"] == [], "packaging scope changed")
    fixtures = json.loads(files["experiments/agent_eval/manifest.json"])
    for name, digest in fixtures["files"].items():
        require(sha(files["experiments/agent_eval/" + name]) == digest,
                "frozen evaluator input changed: " + name)
    return {n: files[n] for n in sorted(expected_names)}, c


def materialize(root, files):
    root.mkdir()
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def command(args, cwd):
    env = dict(os.environ)
    for k in tuple(env):
        if k.startswith(("PYTHON", "PIP_")) or k in ("VIRTUAL_ENV", "__PYVENV_LAUNCHER__"):
            env.pop(k)
    env.update(PYTHONDONTWRITEBYTECODE="1", PIP_NO_INDEX="1")
    run = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                         capture_output=True, text=True, timeout=120)
    RECEIPTS.append({"command": [str(a) for a in args], "cwd": str(cwd),
                     "returncode": run.returncode, "stdout": run.stdout,
                     "stderr": run.stderr})
    require(run.returncode == 0, "artifact command failed: " + repr(args)
            + "\n" + run.stdout + run.stderr)
    return run


def build(root, label, files, hook):
    source, output = root / (label + "-source"), root / (label + "-dist")
    materialize(source, files)
    output.mkdir()
    script = f"import setuptools.build_meta as b;b.{hook}({str(output)!r})"
    command([sys.executable, "-I", "-B", "-c", script], source)
    products = list(output.glob("*.tar.gz" if hook == "build_sdist" else "*.whl"))
    require(len(products) == 1, "artifact product inventory mismatch")
    return products[0]


def sdist_members(archive):
    result, roots = {}, set()
    with tarfile.open(archive) as package:
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts,
                    "invalid sdist path")
            roots.add(path.parts[0])
            if member.isdir():
                continue
            require(member.isfile() and len(path.parts) > 1, "nonregular sdist file")
            name = PurePosixPath(*path.parts[1:]).as_posix()
            require(name not in result, "duplicate sdist member")
            result[name] = package.extractfile(member).read()
    require(len(roots) == 1, "sdist root inventory mismatch")
    return result


def check_sdist(actual, expected):
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected) - GENERATED)
    changed = sorted(n for n in set(actual) & set(expected) if actual[n] != expected[n])
    require(not missing, "missing sdist inputs: " + repr(missing))
    require(not extra, "unexpected sdist inputs: " + repr(extra))
    require(not changed, "changed sdist inputs: " + repr(changed))
    require(set(actual) == set(expected) | GENERATED, "generated metadata inventory mismatch")


def wheel_members(archive):
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        require(len(names) == len(set(names)), "duplicate wheel member")
        require(all(not PurePosixPath(n).is_absolute() and ".." not in PurePosixPath(n).parts
                    for n in names), "invalid wheel member")
        return {n: package.read(n) for n in names if not n.endswith("/")}


def check_wheel(files, runtime):
    prefix = "hepta_language-0.2.0.dist-info/"
    metadata = {prefix + n for n in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")}
    require(len(runtime) == 16 and set(files) == set(runtime) | metadata,
            "wheel member inventory mismatch")
    require(all(files[n] == b for n, b in runtime.items()), "wheel runtime changed")
    require(files[prefix + "entry_points.txt"] == b"[console_scripts]\nhepta = hepta.cli:main\n",
            "wheel entrypoint changed")
    rows = list(csv.reader(io.StringIO(files[prefix + "RECORD"].decode())))
    require(len(rows) == len(files) and {r[0] for r in rows} == set(files), "RECORD inventory mismatch")
    for name, digest, length in rows:
        if name == prefix + "RECORD":
            require(digest == length == "", "RECORD self identity mismatch")
        else:
            value = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).decode().rstrip("=")
            require(digest == "sha256=" + value and length == str(len(files[name])),
                    "RECORD payload mismatch")


def main():
    require(__debug__, "optimized Python is outside this qualification")
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-inputs-only", action="store_true")
    args = parser.parse_args()
    source = snapshot(ROOT)
    expected, components = contract(source, from_sdist=args.check_inputs_only)
    if args.check_inputs_only:
        require(snapshot(ROOT) == source, "archive inputs changed")
        print(json.dumps({"complete_pass": True, "scope": "archive input bytes only",
                          "source_files": len(expected), "parent_commit": PARENT,
                          "project_modules_imported": 0, "tests_run": 0}))
        return
    controls, baselines = [], []
    runtime = {n: b for n, b in source.items() if n.startswith("hepta/") and n.endswith(".py")}
    polluted = {**source, **{n: b"packaging-only exclusion sentinel\n" for n in SENTINELS}}
    with tempfile.TemporaryDirectory(prefix="hepta-development-sdist-") as temporary:
        root = Path(temporary)
        archive = build(root, "composed", polluted, "build_sdist")
        contents = sdist_members(archive)
        check_sdist(contents, expected)
        unpacked = root / "unpacked"
        materialize(unpacked, contents)
        input_check = json.loads(command([sys.executable, "-I", "-B",
            unpacked / "tools/qualify_development_sdist.py", "--check-inputs-only"], unpacked).stdout)
        require(input_check["complete_pass"] and input_check["source_files"] == len(expected),
                "unpacked input check incomplete")
        direct = wheel_members(build(root, "direct", polluted, "build_wheel"))
        rebuilt = wheel_members(build(root, "rebuilt", contents, "build_wheel"))
        no_manifest = {n: b for n, b in source.items() if n != "MANIFEST.in"}
        original = wheel_members(build(root, "no-manifest-wheel", no_manifest, "build_wheel"))
        for wheel in (direct, rebuilt, original):
            check_wheel(wheel, runtime)
        require(direct == rebuilt == original, "three-way wheel byte mismatch")
        for label, files in (("no-manifest", no_manifest),
                             ("original-677-manifest", {**source, "MANIFEST.in": source[ORIGINAL_MANIFEST]})):
            observed = sdist_members(build(root, label, files, "build_sdist"))
            missing = sorted(set(expected) - set(observed))
            require("tests/c_array_values_origin.py" in missing
                    and "tools/typed_stdlib_components.json" in missing
                    and "stdlib/bytes/src/lib.hepta" in missing,
                    "expected predecessor incompleteness not reproduced")
            baselines.append({"source_variant": label, "source_members": len(observed),
                              "missing_inputs": missing, "complete": False})
        rules = [
            ("missing_non_test_helper", b"include tests/*.py\n", "tests/c_array_values_origin.py"),
            ("missing_tool_inventory", b"include tools/*.json\n", "tools/typed_stdlib_components.json"),
            ("missing_source_library", b"recursive-include stdlib *.hepta hepta.toml Hepta.lock *.md\n", "stdlib/bytes/src/lib.hepta"),
            ("missing_provenance_document", b"recursive-include docs *.md\n", "docs/C_FLOAT_CASTS.md"),
            ("missing_benchmark_sources", b"recursive-include benchmarks *.hepta *.rs *.c\n", "benchmarks/baseline.c"),
            ("missing_evaluator_fixture", b"include experiments/agent_eval/driver.c\n", "experiments/agent_eval/driver.c"),
        ]
        for label, rule, target in rules:
            require(source["MANIFEST.in"].count(rule) == 1, "control manifest rule changed: " + label)
            changed = source["MANIFEST.in"].replace(rule, b"", 1)
            actual = sdist_members(build(root, label, {**polluted, "MANIFEST.in": changed}, "build_sdist"))
            want = {**expected, "MANIFEST.in": changed}
            require(target not in actual, "control did not omit target: " + label)
            try:
                check_sdist(actual, want)
            except ValueError as exc:
                require(str(exc).startswith("missing sdist inputs:") and target in str(exc),
                        "control rejected for wrong reason")
                controls.append({"control": label, "rejected": True, "target": target, "reason": str(exc)})
            else:
                raise ValueError("missing-input control accepted: " + label)
        for label, target, extra_files in (
            ("included_synthetic_evidence", "evidence/not-a-result.json", {}),
            ("included_historical_result", "artifacts/release-validation.json", {}),
            ("included_unregistered_document", "docs/not-in-contract.md", {"docs/not-in-contract.md": b"unregistered document\n"}),
        ):
            changed = source["MANIFEST.in"] + b"\ninclude " + target.encode() + b"\n"
            actual = sdist_members(build(root, label, {**polluted, **extra_files, "MANIFEST.in": changed}, "build_sdist"))
            want = {**expected, "MANIFEST.in": changed}
            require(target in actual, "control did not include target: " + label)
            try:
                check_sdist(actual, want)
            except ValueError as exc:
                require(str(exc) == "unexpected sdist inputs: " + repr([target]),
                        "control rejected for wrong reason")
                controls.append({"control": label, "rejected": True, "target": target, "reason": str(exc)})
            else:
                raise ValueError("extra-input control accepted: " + label)
        result = {"complete_pass": True, "scope": "distribution artifacts only",
            "parent_commit": PARENT, "packaging_origin_commit": ORIGIN,
            "python": sys.version, "setuptools": importlib.metadata.version("setuptools"),
            "source_files": len(source), "unchanged_parent_files": len(components["parent_files"]),
            "source_sha256": {n: sha(b) for n, b in source.items()},
            "sdist_source_files": len(expected), "sdist_members": len(contents),
            "sdist_sha256": sha(archive.read_bytes()),
            "sdist_member_sha256": {n: sha(b) for n, b in contents.items()},
            "runtime_files": len(runtime), "wheel_members": len(direct),
            "wheel_member_sha256": {n: sha(b) for n, b in direct.items()},
            "three_way_wheel_bytes_equal": True, "unpacked_input_check": input_check,
            "predecessor_incompleteness": baselines, "negative_controls": controls,
            "commands": RECEIPTS, "project_modules_imported": 0, "test_bodies_run": 0,
            "native_compilers_run": 0, "models_or_studies_run": 0,
            "packages_installed": 0, "archives_uploaded": 0,
            "whole_project_blockers_closed": False, "production_release_qualified": False}
    require(snapshot(ROOT) == source, "supplied source changed during artifact qualification")
    result["source_unchanged"] = True
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"complete_pass": False, "error": type(exc).__name__ + ": " + str(exc),
                          "commands": RECEIPTS}, sort_keys=True))
        raise
