#!/usr/bin/env python3
"""Check sdist inputs and wheel bytes without importing project code or tests.

Requires the declared build backend (setuptools >= 68) already installed.
Builds use only owned temporary copies, never install or upload packages, and
never invoke a project test body, compiler, evaluator, or study entry point.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
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
FIXTURE_ROOT = "experiments/agent_eval/"
FIXED = (
    "pyproject.toml", "README.md", "MANIFEST.in", "Makefile",
    "toolchain-lock.json", "docs/PACKAGING.md", "benchmarks/README.md",
    "formal/HeptaCore.lean", "formal/proof-dependencies.txt",
    "formal/toolchain-lock.json", "formal/qemu-toolchain-lock.json",
    "formal/README.md", FIXTURE_ROOT + "manifest.json",
    FIXTURE_ROOT + "README.md",
)
GLOBS = (
    "hepta/*.py", "tests/test*.py", "tools/*.py",
    "benchmarks/*.hepta", "benchmarks/*.rs", "benchmarks/*.c",
    "examples/**/*.hepta", "examples/**/*.c", "examples/**/*.h",
    "examples/**/hepta.toml", "examples/**/Hepta.lock",
    FIXTURE_ROOT + "*.py", FIXTURE_ROOT + "_private/*.py",
    FIXTURE_ROOT + "fixtures/*.py",
)
# These are deliberately not real evidence or programs. A broad graft must not
# silently make them part of the source archive.
SENTINELS = (
    "artifacts/not-a-result.json", "evidence/not-a-result.json",
    FIXTURE_ROOT + "evidence/not-a-result.json",
    "experiments/unrelated_research/not-a-program.py",
    "toolchains/not-a-tool.py", "hepta/__pycache__/not-code.pyc",
    "tools/not-code.pyc", "benchmarks/not-a-binary.bin",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_inputs(root):
    """Independent contract: test helpers, fixtures and existing Make targets."""
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    require(config["build-system"]["build-backend"] == "setuptools.build_meta",
            "unexpected build backend")
    require(config["tool"]["setuptools"]["packages"] == ["hepta"],
            "installed package scope changed")
    paths = set(FIXED)
    for pattern in GLOBS:
        paths.update(p.relative_to(root).as_posix() for p in root.glob(pattern)
                     if p.is_file())
    manifest = json.loads((root / FIXTURE_ROOT / "manifest.json").read_bytes())
    for relative, expected in manifest["files"].items():
        path = PurePosixPath(relative)
        require(not path.is_absolute() and ".." not in path.parts,
                "fixture manifest path is outside its source directory")
        name = FIXTURE_ROOT + relative
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                "existing frozen fixture bytes changed: " + name)
        paths.add(name)
    return {name: (root / name).read_bytes() for name in sorted(paths)}


def materialize(directory, files):
    directory.mkdir()
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def tracked_source(root):
    result = subprocess.run(["git", "ls-files", "--cached", "-z"], cwd=root,
                            capture_output=True, check=True, timeout=30)
    names = [os.fsdecode(name) for name in result.stdout.split(b"\0") if name]
    require(names, "packaging check requires a Git source checkout")
    return {name: (root / name).read_bytes() for name in names}


def build(source, output, hook):
    output.mkdir()
    # -I excludes both the source directory and PYTHONPATH from backend imports.
    # Calling an already installed backend hook does not resolve dependencies.
    script = ("import setuptools.build_meta as backend; "
              "print(getattr(backend, " + repr(hook) + ")(" + repr(str(output)) + "))")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                            cwd=source, env=env, capture_output=True, text=True,
                            timeout=120)
    require(result.returncode == 0, "build failed:\n" + result.stdout + result.stderr)
    suffix = "*.tar.gz" if hook == "build_sdist" else "*.whl"
    products = list(output.glob(suffix))
    require(len(products) == 1, "expected one build product")
    return products[0]


def sdist_files(archive):
    with tarfile.open(archive) as package:
        files = {}
        roots = set()
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts,
                    "unexpected source-archive path")
            roots.add(path.parts[0])
            if member.isdir():
                continue
            require(member.isfile() and len(path.parts) > 1,
                    "expected regular source-archive files")
            name = PurePosixPath(*path.parts[1:]).as_posix()
            require(name not in files, "duplicate source-archive member")
            with package.extractfile(member) as stream:
                files[name] = stream.read()
        require(len(roots) == 1, "expected one source-archive root")
        return files


def check_sdist(files, expected):
    for name, data in expected.items():
        require(name in files, "missing sdist input: " + name)
        require(files[name] == data, "changed sdist input: " + name)
    metadata = {
        "PKG-INFO", "setup.cfg", "hepta_language.egg-info/PKG-INFO",
        "hepta_language.egg-info/SOURCES.txt",
        "hepta_language.egg-info/dependency_links.txt",
        "hepta_language.egg-info/entry_points.txt",
        "hepta_language.egg-info/top_level.txt",
    }
    require(set(files) == set(expected) | metadata,
            "unexpected sdist members: " + repr(sorted(set(files) - set(expected) - metadata)))


def wheel_files(archive):
    with zipfile.ZipFile(archive) as package:
        names = [name for name in package.namelist() if not name.endswith("/")]
        require(len(names) == len(set(names)), "duplicate wheel member")
        return {name: package.read(name) for name in names}


def rejected_control(root, name, files, expected, reason_prefix):
    source, output = root / (name + "-source"), root / (name + "-dist")
    materialize(source, files)
    archive = build(source, output, "build_sdist")
    try:
        check_sdist(sdist_files(archive), expected)
    except ValueError as exc:
        require(str(exc).startswith(reason_prefix),
                "negative control failed for an unrelated reason: " + str(exc))
        return {"control": name, "rejected": True, "reason": str(exc)}
    raise ValueError("incomplete/overbroad archive was accepted: " + name)


def main():
    expected = source_inputs(ROOT)
    tracked = tracked_source(ROOT)
    require(set(expected) <= set(tracked),
            "stage new distribution inputs before checking the tracked source tree")
    with tempfile.TemporaryDirectory(prefix="hepta-packaging-") as temporary:
        root = Path(temporary)
        # Give setuptools the real excluded files too. Building only the
        # expected set would hide an overbroad manifest from the archive check.
        polluted = {**tracked, **{name: b"packaging-only sentinel\n" for name in SENTINELS}}
        source = root / "source"
        materialize(source, polluted)
        archive = build(source, root / "sdist", "build_sdist")
        contents = sdist_files(archive)
        check_sdist(contents, expected)

        unpacked = root / "unpacked"
        materialize(unpacked, contents)
        rebuilt = wheel_files(build(unpacked, root / "rebuilt-wheel", "build_wheel"))
        direct = wheel_files(build(source, root / "direct-wheel", "build_wheel"))
        # The pre-fix packaging configuration is the same project with no
        # MANIFEST.in. Compare every wheel member, including entrypoint metadata.
        baseline = root / "baseline"
        materialize(baseline, {k: v for k, v in tracked.items() if k != "MANIFEST.in"})
        original = wheel_files(build(baseline, root / "original-wheel", "build_wheel"))
        require(rebuilt == direct == original, "wheel members or bytes changed")
        runtime = {name: data for name, data in rebuilt.items() if name.startswith("hepta/")}
        require(runtime == {name: data for name, data in expected.items()
                            if name.startswith("hepta/")}, "wheel runtime source changed")
        require(all(name.startswith("hepta/") or name.startswith("hepta_language-0.2.0.dist-info/")
                    for name in rebuilt), "development assets entered the installed wheel")

        manifest = expected["MANIFEST.in"]
        controls = []
        for name, rule, missing in (
                ("missing_helpers", b"include tools/*.py\n", "tools/"),
                ("missing_benchmark_inputs", b"recursive-include benchmarks *.hepta *.rs *.c\n", "benchmarks/")):
            require(rule in manifest, "negative control no longer applies: " + name)
            changed = {**polluted, "MANIFEST.in": manifest.replace(rule, b"", 1)}
            controls.append(rejected_control(root, name, changed,
                {**expected, "MANIFEST.in": changed["MANIFEST.in"]},
                "missing sdist input: " + missing))
        controls.append(rejected_control(root, "included_evidence",
            {**polluted, "MANIFEST.in": manifest + b"\ninclude evidence/not-a-result.json\n"},
            {**expected, "MANIFEST.in": manifest + b"\ninclude evidence/not-a-result.json\n"},
            "unexpected sdist members: ['evidence/not-a-result.json']"))
        # Unlike a synthetic sentinel, these are actual tracked files excluded
        # from this contract. This also detects expected-only source staging.
        extra_docs = manifest + b"\nrecursive-include docs *.md\n"
        controls.append(rejected_control(root, "included_unlisted_docs",
            {**polluted, "MANIFEST.in": extra_docs},
            {**expected, "MANIFEST.in": extra_docs},
            "unexpected sdist members: ['docs/ADTS_GENERICS.md'"))
        # Omit a manifest-listed non-Python input while preserving original code.
        rule = b"include experiments/agent_eval/driver.c\n"
        require(rule in manifest, "fixture negative control no longer applies")
        controls.append(rejected_control(root, "missing_fixture_input",
            {**polluted, "MANIFEST.in": manifest.replace(rule, b"", 1)},
            {**expected, "MANIFEST.in": manifest.replace(rule, b"", 1)},
            "missing sdist input: experiments/agent_eval/driver.c"))

    require(source_inputs(ROOT) == expected, "source changed during packaging check")
    require(tracked_source(ROOT) == tracked, "tracked source changed during packaging check")
    print(json.dumps({"status": "passed", "scope": "distribution artifacts only",
        "python": sys.version.split()[0], "setuptools": importlib.metadata.version("setuptools"),
        "tracked_source_files": len(tracked),
        "sdist_source_files": len(expected), "sdist_total_files": len(contents),
        "wheel_files": len(rebuilt), "runtime_files": len(runtime),
        "wheel_member_bytes_unchanged": True, "negative_controls": controls,
        "project_test_bodies_run": 0, "native_compilers_run": 0,
        "models_or_studies_run": 0, "archives_uploaded": 0}, indent=2))


if __name__ == "__main__":
    main()
