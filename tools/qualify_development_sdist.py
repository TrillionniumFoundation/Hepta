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


# Exact #710 qualification repair overlay. These bindings do not replace the
# original #713 inventory or the #677 supplier manifest.
REPAIR_UPSTREAM = "a5cbdfda69cd9ba4c29bc9328e87845f88bd6270"
REPAIR_FILES = {'docs/C_ARRAY_ADT_COMPOSITION.md': {'git_blob': 'e8e65a04dcbbd1be566de4864acfacbf05a84745',
                                     'sha256': 'b4a08fab1ec22b15e12ffd0a0ec87b0106d473317be6f64596566e084bc51491'},
 'docs/C_NUMERIC_ADT_COMPOSITION.md': {'git_blob': '3f40be3ef48384484bbe79a5357edea0d9eba11a',
                                       'sha256': '73294433b8a5ddc68c67b5105f39280a239cfb175d1b8db2fe6db68ca2085aee'},
 'docs/C_STORE_ADT_COMPOSITION.md': {'git_blob': 'd91c700078a33c00e31546dadf7c49d96432025f',
                                     'sha256': 'ae171923345176b5939c3dd7c4448e5f4391d205c4da23790582ee43002fd93d'},
 'docs/C_UNIT_VALUES.md': {'git_blob': '4048bb98c5e322d152c9e30ee69e6ea44162ab68',
                           'sha256': '73c9f1cc788f362c9c0b91d3f25b73d6aacf21b7d76dbc8c289ffaa42b82d306'},
 'docs/TYPED_RUST_FIXTURE_REPAIRS.md': {'git_blob': '12eb85d64090f0baf23bb95cbae4f8a2bb2ead7f',
                                        'sha256': '6bf80649f0a79bf8218d9342e1bf9a20a530f02cb314addbe365e8d5ba812b8a'},
 'tests/test_c_float_int_casts.py': {'git_blob': 'f13a9bf7395033583efce236df22912001622339',
                                     'sha256': 'be4ec1326ea0bc58ea983837a4e462fdbb31ea761555df4ad64119fb7bd843b4'},
 'tests/test_c_store_adt_composition.py': {'git_blob': '399fcdb5df6bdd9391efb7c6acc6cb99cc47deb8',
                                           'sha256': '3b53e45675ea469ee683177661cfcff7e3c88a158be58e1a405059b644d361fb'},
 'tests/test_c_unit_values.py': {'git_blob': '52bcd49ee7b6188a4a2312d756da19cd07ed21a5',
                                 'sha256': 'efea085f30adbb4b72837dd612865bff8e87c4e236898151833a370945a919eb'},
 'tools/c_array_adt_rust_test_ids.json': {'git_blob': '386cda3f4ca799f8d177f744f600c1b07eb6d268',
                                          'sha256': '8ecfd0102ed60e2fa4e8d76901d1e9fd77487cd1de7b26573067df0f3d2b4dbc'},
 'tools/c_array_adt_test_ids.json': {'git_blob': 'a09f76e6704ccb515bca3591faf03316c2dcd0d2',
                                     'sha256': '9321c8df43c81583245a95030bccb27162c8ec9359210025a5b81939fb4cd3fe'},
 'tools/c_numeric_adt_rust_test_ids.json': {'git_blob': 'ed8fbf52fb049837173eec8d3427010b2214ebad',
                                            'sha256': '43650f69c524a13401d87707395ece9a10f3d740874f1b2e677dc9f9cbfa12ba'},
 'tools/c_numeric_adt_test_ids.json': {'git_blob': '75f9a953947573df9ae777aa70bd90d99751b4c9',
                                       'sha256': '905a9296eaaf5a11209af4df77e21c6a9bf61a1e8995942a6f576175f893ceb3'},
 'tools/c_store_adt_rust_test_ids.json': {'git_blob': '0820649f4e48402898f61837a5a8f9cad77ed74d',
                                          'sha256': '8c3c25b3429d0a868e4aa50e2f074beb19e0c374a712b3747160986663df22b2'},
 'tools/c_store_adt_test_ids.json': {'git_blob': 'f6882b60c8767614a631db0b5a9424807aaaf45e',
                                     'sha256': '7998900daa422c30161ee8d567c7c4a97a2043012c2ad1434b680efb7606abd3'},
 'tools/c_unit_test_ids.json': {'git_blob': 'afd0ebd33cbdcee61baea92097f05f733431534f',
                                'sha256': '6a5c5dfe62313cb747cc8c8c14c783fb813f92302d53cc78f5d1ee91fac666e5'},
 'tools/qualify_typed_stdlib.py': {'git_blob': '2f65cfcdcb1367446c1d50fb44f4f77eaa69c9bc',
                                   'sha256': '576561c6a2db6c97a86f30d996dde729a2cc822eab8d757b3059d1bb4c9ba428'},
 'tools/rust_fixture_repairs.json': {'git_blob': '9cd941a2a2500b3ba73a042b4736a9e0aa8587c0',
                                     'sha256': '6651438da732145c4f8486580d22e92e71e06746a444fac3293030334e314d6e'},
 'tools/typed_fixture_repairs.json': {'git_blob': '4afe224591b983ffc2b42281bd56497c4c7b24bd',
                                      'sha256': '087227f6d4c874712e0ace46de360b46e858b1960ba02ab101c6c78afa5d1bed'},
 'tools/typed_stdlib_inventory.json': {'git_blob': '8ef5b2386affaac505d7785876f0a7b3e1fd3853',
                                       'sha256': 'd54252bc00c4807c320d46a3e07fa1fc8113c2db75f1dc41bf5399ff9b2ec0de'},
 'tools/typed_stdlib_rust_inventory.json': {'git_blob': '2353ebf9a7990ffbd317d4e93f8ae1a8a1c35179',
                                            'sha256': '95deb8083b367a6be7f08f9e0d41957b7463f8400bb3303842ad6c37c04b221c'},
 'tools/validate_c_array_adt_composition.py': {'git_blob': 'daaa6454d6b2761b7f3c04a9fca86c7b2d71e6df',
                                               'sha256': 'b5f2f4a06761f299ee13c78dd6801c11b565475aeda76ce135380115754476d0'},
 'tools/validate_c_store_adt_composition.py': {'git_blob': 'ee22632b6fdf9bad2111902ee0730c4a9de56d36',
                                               'sha256': '938cbfd61f8e86e90d105d757b3dbda509cc2cb1564a6e4c1c7996af144820cd'},
 'tools/verify_rust_fixture_repairs.py': {'git_blob': 'f827f4d37a42c4e8019b9bc29502f04b1e8f6f53',
                                          'sha256': 'f1d08a9b40dbdd5542a69e5fecbf74921d9845ef6b7b5bb5ee32d89ad22644bb'},
 'tools/verify_store_adt_sources.py': {'git_blob': 'ba7b71f77a040c4748b3fc3abefd2a40d3e7c3ea',
                                       'sha256': '11842b269e02f7a54dc8372da80a6097442f126d0c669a68906a825070fcdd84'},
 'tools/verify_typed_fixture_repairs.py': {'git_blob': '42d2f55b8afb9131fc10b91112d1341af2208cdd',
                                           'sha256': '8e17af5f201c608040c85d23a7d57694f37ad65230e203d96f26fdac440d96d8'},
 'tools/verify_typed_stdlib_sources.py': {'git_blob': 'd8e2203f6cf099692bdcd5d84e6429a3aad4b4fd',
                                          'sha256': 'ffcb0391b6132b77a4f9ff39eff102b30b7fe3c5492419b279e5c3b0efb3c130'}}
REPAIR_ADDITIONS = ('docs/TYPED_RUST_FIXTURE_REPAIRS.md',
 'tools/rust_fixture_repairs.json',
 'tools/typed_fixture_repairs.json',
 'tools/verify_rust_fixture_repairs.py',
 'tools/verify_typed_fixture_repairs.py')
REPAIRED_PARENT_NAMES = ('docs/C_ARRAY_ADT_COMPOSITION.md',
 'docs/C_NUMERIC_ADT_COMPOSITION.md',
 'docs/C_STORE_ADT_COMPOSITION.md',
 'docs/C_UNIT_VALUES.md',
 'tests/test_c_float_int_casts.py',
 'tests/test_c_store_adt_composition.py',
 'tests/test_c_unit_values.py',
 'tools/c_array_adt_rust_test_ids.json',
 'tools/c_array_adt_test_ids.json',
 'tools/c_numeric_adt_rust_test_ids.json',
 'tools/c_numeric_adt_test_ids.json',
 'tools/c_store_adt_rust_test_ids.json',
 'tools/c_store_adt_test_ids.json',
 'tools/c_unit_test_ids.json',
 'tools/qualify_typed_stdlib.py',
 'tools/typed_stdlib_inventory.json',
 'tools/typed_stdlib_rust_inventory.json',
 'tools/validate_c_array_adt_composition.py',
 'tools/validate_c_store_adt_composition.py',
 'tools/verify_store_adt_sources.py',
 'tools/verify_typed_stdlib_sources.py')


def repair_originals(files):
    """Validate current source, then project bytes only for historical hashes.

    No project, test or qualification module is imported or executed. Actual
    repaired source bytes remain the archive/build inputs and expectations.
    """
    for name, entry in REPAIR_FILES.items():
        data = files[name]
        require(sha(data) == entry["sha256"] and git_blob(data) == entry["git_blob"],
                "exact upstream fixture repair changed: " + name)
    restored = {}
    for manifest in ("tools/rust_fixture_repairs.json", "tools/typed_fixture_repairs.json"):
        doc = json.loads(files[manifest])
        for name, entry in doc["files"].items():
            require(name in REPAIRED_PARENT_NAMES and name not in restored,
                    "fixture inverse scope mismatch: " + name)
            if manifest == "tools/rust_fixture_repairs.json":
                repaired = {"sha256": entry["repaired_sha256"], "git_blob": entry["repaired_blob"]}
                original = {"sha256": entry["original_sha256"], "git_blob": entry["original_blob"]}
            else:
                repaired, original = entry["repaired"], entry["original"]
            data = files[name]
            require(sha(data) == repaired["sha256"]
                    and git_blob(data) == repaired["git_blob"],
                    "fixture inverse input changed: " + name)
            text = data.decode("utf-8")
            last = len(text)
            for edit in reversed(entry["edits"]):
                start, end = edit["start"], edit["end"]
                require(0 <= start <= end <= last and text[start:end] == edit["after"],
                        "fixture inverse edit changed: " + name)
                text = text[:start] + edit["before"] + text[end:]
                last = start
            data = text.encode("utf-8")
            require(sha(data) == original["sha256"]
                    and git_blob(data) == original["git_blob"],
                    "fixture original not recovered: " + name)
            restored[name] = data
    require(set(restored) == set(REPAIRED_PARENT_NAMES), "fixture inverse inventory mismatch")
    return restored


def contract(files, from_sdist=False):
    originals = repair_originals(files)
    c = json.loads(files[COMPONENTS])
    require(c["schema"] == "hepta.development-sdist-composition.v1", "wrong schema")
    require(c["parent_commit"] == PARENT and c["packaging_origin_commit"] == ORIGIN,
            "wrong source commits")
    require(len(c["parent_files"]) == 286 and len(c["origin_files"]) == 3,
            "source identity inventory mismatch")
    require(set(c["additions"]) == ADDITIONS, "addition inventory mismatch")
    require(not set(c["parent_files"]) & ADDITIONS, "parent/addition collision")
    names = set(c["parent_files"]) | ADDITIONS | set(REPAIR_ADDITIONS)
    expected_names = {n for n in names if selected(n)}
    require(set(files) == (expected_names | GENERATED if from_sdist else names),
            "supplied source inventory mismatch")
    for name, entry in {**c["parent_files"], **c["origin_files"]}.items():
        if from_sdist and not selected(name):
            continue
        data = originals.get(name, files[name])
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
            "source_files": len(source),
            "unchanged_parent_files": len(components["parent_files"]) - len(REPAIRED_PARENT_NAMES),
            "historical_parent_files_verified": len(components["parent_files"]),
            "projected_parent_files": len(REPAIRED_PARENT_NAMES),
            "fixture_repair_upstream": REPAIR_UPSTREAM,
            "fixture_repair_files": len(REPAIR_FILES),
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
