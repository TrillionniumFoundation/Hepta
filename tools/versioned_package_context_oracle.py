#!/usr/bin/env python3
"""Independent finite versioned-context oracle, using only temporary fixtures.

No recursive Hepta execution, C imports, or native Rust qualification. Expected
roots, edges, diagnostics, and execution values are defined independently here.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from hepta import modules
from hepta.ast import HeptaError
from hepta.packages import load_package, package_snapshot, verify_lock, write_lock
from hepta.pipeline import analyze
from hepta.c_backend import compile_c
from hepta.lock_diff import compare_locks


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def manifest(path, name, version="1.0.0", kind="lib", dependencies=None):
    text = (f'[package]\nname={json.dumps(name)}\nversion={json.dumps(version)}\n'
            f'kind={json.dumps(kind)}\n')
    if dependencies:
        text += "[dependencies]\n"
        for alias, spec in dependencies.items():
            text += alias + " = { " + ", ".join(
                key + "=" + json.dumps(value) for key, value in spec.items()) + " }\n"
    put(path / "hepta.toml", text)


def spec(paths, bound="<3.0.0"):
    return {"package": "calc", "version": ">=1.0.0, " + bound, "candidates": paths}


def graph(base, force_low=False, reverse=False):
    app, bridge = base / "app", base / "bridge"
    candidates = ["src/store/low", "src/store/high"]
    if reverse:
        candidates.reverse()
    for name, version, value in (("low", "1.0.0", 24), ("high", "2.0.0", 42)):
        root = app / ("src/store/" + name)
        manifest(root, "calc", version)
        put(root / "src/helper.hepta", f"pub fn value()->i32 effects {{}} {{ return {value}; }}\n")
        put(root / "src/lib.hepta", "import helper;\npub fn answer()->i32 effects {} { return helper::value(); }\n")
    manifest(bridge, "bridge", dependencies={"pick": spec(
        ["../app/" + path for path in candidates], "<2.0.0" if force_low else "<3.0.0")})
    put(bridge / "src/lib.hepta", "import pick;\npub fn answer()->i32 effects {} { return pick::answer(); }\n")
    manifest(app, "app", kind="bin", dependencies={
        "first": spec(candidates), "second": spec(candidates[::-1]), "zbridge": {"path": "../bridge"}})
    put(app / "src/helper.hepta", "pub fn value()->i32 effects {} { return 7; }\n")
    positive = ("import first;\nimport second;\nimport zbridge;\n"
                "fn main()->i32 effects {} { if first::answer()==second::answer() { "
                "if first::answer()==zbridge::answer() { return first::answer(); } "
                "else { return 2; } } else { return 1; } }\n")
    put(app / "src/main.hepta", positive)
    return app, "low" if force_low else "high", 24 if force_low else 42, positive


def check_package(app, selected):
    package = load_package(app)
    chosen = app / ("src/store/" + selected)
    assert package.dependencies["first"].root == chosen
    assert package.dependencies["first"] is package.dependencies["second"]
    assert package.dependencies["first"] is package.dependencies["zbridge"].dependencies["pick"]
    nodes = package_snapshot(package)["packages"]
    assert set(nodes) == {".", "../bridge", "src/store/" + selected}
    assert nodes["."]["dependencies"] == {
        "first": "src/store/" + selected, "second": "src/store/" + selected, "zbridge": "../bridge"}
    assert nodes["../bridge"]["dependencies"] == {"pick": "src/store/" + selected}
    return chosen


def frontend(project, backend="c"):
    result = analyze(project.source_bytes[str(project.entry)].decode("utf-8"),
                     str(project.entry), loaded_project=project, native=False,
                     backend=backend, crate_type="bin")
    assert result.report["ok"] and result.report["diagnostics"] == [], result.report
    return result


def expect_error(action, expected):
    try:
        action()
    except HeptaError as error:
        actual = error.diagnostic.to_dict()
        assert actual == expected, {"actual": actual, "expected": expected}
        return
    raise AssertionError("Expected rejection: " + str(expected))


def review(root):
    counts = {"context_rejections": 0, "positive_frontends": 0, "native_executions": 0, "lock_upgrades": 0}

    def native(result, expected, label):
        for optimize in (False, True):
            binary = root / f"native-{counts['native_executions']}"
            built = compile_c(result.c, cc="gcc", crate_type="bin", output=binary,
                              optimize=optimize, sanitize=True)
            assert built["ok"], built
            assert ("-O3" if optimize else "-O0") in built["flags"]
            assert "-fsanitize=undefined" in built["flags"]
            assert "-fno-sanitize-recover=all" in built["flags"]
            assert built["source_sha256"] == hashlib.sha256(result.c.encode("utf-8")).hexdigest()
            process = subprocess.run([str(binary)], capture_output=True, timeout=5)
            observation = {"label": label, "optimize": optimize, "expected": expected,
                           "returncode": process.returncode, "stdout": process.stdout.decode("utf-8"),
                           "stderr": process.stderr.decode("utf-8"), "source_sha256": built["source_sha256"],
                           "artifact_sha256": sha(binary), "flags": built["flags"], "toolchain": built["toolchain"]}
            assert process.returncode == expected and process.stdout == b"" and process.stderr == b"", observation
            counts["native_executions"] += 1
            print("VERSIONED_CONTEXT_ORACLE_NATIVE " + json.dumps(observation, sort_keys=True), flush=True)

    for force_low in (False, True):
        for reverse in (False, True):
            label = f"backtrack-{force_low}-reverse-{reverse}"
            app, selected, value, positive = graph(root / label, force_low, reverse)
            entry = app / "src/main.hepta"
            chosen = check_package(app, selected)
            for first_local in (False, True):
                local = f"import store::{selected}::src::lib as unused;\n"
                dependency = "import first;\n"
                source = (local + dependency if first_local else dependency + local)
                source += "fn main()->i32 effects {} { return first::answer(); }\n"
                put(entry, source)
                write_lock(app)
                for locked in (False, True):
                    for form in (app, app / "hepta.toml", entry):
                        lines = source.splitlines(keepends=True)
                        roots = (app, chosen) if first_local else (chosen, app)
                        expected = {
                            "code": "E_MODULE_PACKAGE_CONTEXT",
                            "message": f"Module {chosen / 'src/lib.hepta'} is imported under conflicting package roots: {roots[0]} and {roots[1]}",
                            "span": {"path": str(entry), "start": len(lines[0]),
                                     "end": len(lines[0]) + len(lines[1].rstrip("\n")), "line": 2, "column": 1},
                            "notes": [], "phase": "module"}
                        expect_error(lambda: modules.load_project(form, locked=locked), expected)
                        counts["context_rejections"] += 1
            put(entry, positive)
            write_lock(app)
            for locked in (False, True):
                project = modules.load_project(app, locked=locked)
                check_package(app, selected)
                assert len(project.modules) == 4 and len({module["path"] for module in project.modules}) == 4
                assert project.unchanged()
                other = "high" if selected == "low" else "low"
                assert not any(("/src/store/" + other + "/") in source for source in project.sources)
                for backend in ("c", "rust"):
                    frontend(project, backend)
                    counts["positive_frontends"] += 1
            if not reverse:
                native(frontend(modules.load_project(app, locked=True)), value, label + "-repeated-package")

    app, _, _, _ = graph(root / "candidate-upgrade")
    before = write_lock(app)["snapshot"]
    before_path = root / "before.lock"
    put(before_path, json.dumps(before))
    loaded = modules.load_project(app, locked=True)
    native(frontend(loaded), 42, "before-upgrade")
    manifest(app / "src/store/low", "calc", "2.1.0")
    assert not loaded.unchanged()
    try:
        modules.load_project(app, locked=True)
    except HeptaError as error:
        assert error.diagnostic.code == "E_LOCK_STALE" and error.diagnostic.phase == "package"
    else:
        raise AssertionError("Candidate upgrade did not stale the lock")
    check_package(app, "low")
    after = write_lock(app)["snapshot"]
    after_path = root / "after.lock"
    put(after_path, json.dumps(after))
    before_bytes, after_bytes = before_path.read_bytes(), after_path.read_bytes()
    diff = compare_locks(before_path, after_path)
    assert diff["ok"] and diff["changed"] and diff["compatibility"] == "not_assessed"
    assert [package["path"] for package in diff["packages"]["added"]] == ["src/store/low"]
    assert [package["path"] for package in diff["packages"]["removed"]] == ["src/store/high"]
    assert diff["packages"]["changed"] == []
    assert diff["dependencies"]["added"] == [] and diff["dependencies"]["removed"] == []
    assert diff["dependencies"]["retargeted"] == [
        {"package": ".", "alias": alias, "before": "src/store/high", "after": "src/store/low"}
        for alias in ("first", "second")
    ] + [{"package": "../bridge", "alias": "pick", "before": "src/store/high", "after": "src/store/low"}]
    assert before_path.read_bytes() == before_bytes and after_path.read_bytes() == after_bytes
    assert verify_lock(load_package(app)) == after
    native(frontend(modules.load_project(app, locked=True)), 24, "after-upgrade")
    counts["lock_upgrades"] += 1
    assert counts == {"context_rejections": 48, "positive_frontends": 16, "native_executions": 8, "lock_upgrades": 1}
    return counts


def main():
    if sys.flags.optimize:
        raise SystemExit("Python assertions must remain enabled")
    assert Path(modules.__file__).resolve() == REPO / "hepta/modules.py"
    paths = ["hepta/modules.py", "hepta/packages.py", "hepta/package_resolution.py",
             "hepta/lock_diff.py", "hepta/pipeline.py", "hepta/c_backend.py",
             "tests/test_module_package_context.py", "tests/test_versioned_package_context.py",
             "tools/versioned_package_context_oracle.py"]
    before = {path: sha(REPO / path) for path in paths}
    with tempfile.TemporaryDirectory(prefix="hepta-versioned-context-oracle-") as temporary:
        counts = review(Path(temporary).resolve())
    assert before == {path: sha(REPO / path) for path in paths}
    print("VERSIONED_CONTEXT_ORACLE_PASS " + json.dumps({
        "python": sys.version, "counts": counts, "source_sha256": before,
        "scope": "Finite acyclic context, version selection, and lock-update checks; C native only",
        "full_665_gate": "not_run", "full_698_gate": "not_run", "source_unchanged": True}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
