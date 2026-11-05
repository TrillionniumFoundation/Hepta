"""Independent finite typed payload/package-context oracle; no test helpers."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


LIBRARIES = {"base64": "base64", "codec": "bytes", "order": "ordering", "utf8": "utf8"}
RAW = b"\x00\x08\xc3\xa9a\xf0\x9f\x98\x80a"
TERMINAL = b"return IndexResult { stage: 0, scalars: count, lower: low.index, upper: high.index };"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def array(values):
    return "[" + ",".join(str(value) for value in values) + "]"


def manifest(name, version, kind, dependencies):
    text = f'[package]\nname="{name}"\nversion="{version}"\nkind="{kind}"\n[dependencies]\n'
    for alias, spec in sorted(dependencies.items()):
        text += alias + "={" + ", ".join(key + "=" + json.dumps(value) for key, value in spec.items()) + "}\n"
    return text


def library_spec(name, requirement, prefix):
    return {"package": "hepta_" + name, "version": requirement,
            "candidates": [prefix + name + "2", prefix + name + "1"]}


def app_manifest(selected):
    dependencies = {alias: library_spec(name, ">=0.1.0, <0.3.0", "../")
                    for alias, name in LIBRARIES.items()}
    dependencies["typed"] = {"package": "typed_packet", "version": f"={selected}.0.0",
                             "candidates": ["src/typed2", "src/typed1"]}
    return manifest("independent_typed_context", "0.1.0", "bin", dependencies)


def observations():
    # Explicit fixture expectations, not a call to the compiler or another oracle.
    # Eight UTF-8 bytes encode four scalars; prefix and suffix storage stay visible.
    wire = base64.b64encode(RAW)
    lines = []
    for index, capacity in enumerate((7, 3)):
        lines += [f"fn observe{index}() -> Unit effects {{ panic, write }} {{",
                  f"let input: [u8; {len(wire)}] = {array(wire)};",
                  f"let mut scratch: [u8; 13] = {array([165] * 13)};",
                  f"let mut scalars: [u64; {capacity}] = {array([999] * capacity)};",
                  f"let result = typed::index_packet(read input, 0, {len(wire)}, mut scratch, mut scalars, 97);",
                  "match result {"]
        if index == 0:
            lines += ["Result::Ok(c) => { let completed = c.done; assert(c.value.scalars == 4);",
                      "assert(c.value.lower == 1); assert(c.value.upper == 3); },",
                      "Result::Err(_) => { assert(false); }"]
        else:
            lines += ["Result::Ok(_) => { assert(false); },", "Result::Err(error) => { match error {"]
            for variant in ("Decode", "ShortHeader", "LengthMismatch", "InvalidText"):
                lines.append(f"typed::PacketError::{variant}(_) => {{ assert(false); }},")
            lines += ["typed::PacketError::ScalarCapacity(payload) => { assert(payload == 3); }", "} }"]
        lines.append("}")
        for name, values in (("input", wire), ("scratch", [165] + list(RAW) + [165, 165]),
                             ("scalars", [999, 97, 97, 233, 128512, 999, 999] if index == 0 else [999] * 3)):
            lines += [f"assert({name}[{position}] == {value});" for position, value in enumerate(values)]
        lines.append("}")
    return "\n".join(lines) + "\nfn main() -> Unit effects { panic, write } { observe0(); observe1(); }\n"


def entry_source(local=None, first=True):
    intended = "import typed;\n"
    unused = "" if local is None else f"import typed{local}::src::lib as unused;\n"
    return (unused + intended if first else intended + unused) + observations()


def expected_lock(app, selected):
    typed = f"src/typed{selected}"
    dependencies = {alias: f"../{name}{selected}" for alias, name in LIBRARIES.items()}
    packages = {
        ".": dict(name="independent_typed_context", version="0.1.0", kind="bin", entry="src/main.hepta",
                  dependencies={**dependencies, "typed": typed}),
        typed: dict(name="typed_packet", version=f"{selected}.0.0", kind="lib", entry="src/lib.hepta",
                    dependencies=dependencies),
    }
    # These are all source files under the root's src directory, including the
    # unselected candidate's sources but not its unselected manifest.
    files = ["hepta.toml", "src/main.hepta", "src/packet.hepta", typed + "/hepta.toml"]
    files += [f"src/typed{version}/src/{name}.hepta" for version in (1, 2) for name in ("lib", "packet")]
    for name in LIBRARIES.values():
        path = f"../{name}{selected}"
        packages[path] = dict(name="hepta_" + name, version=f"0.{selected}.0", kind="lib",
                              entry="src/lib.hepta", dependencies={})
        files += [path + "/hepta.toml", path + "/src/lib.hepta"]
    content = {"packages": packages, "files": {name: sha((app / name).read_bytes()) for name in files}}
    return {"schema": "hepta.lock.v1", **content,
            "sha256": sha(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())}


def run(root, native=False):
    root = Path(root).resolve()
    sys.path.insert(0, str(root))
    from hepta.ast import HeptaError
    from hepta.c_backend import compile_c
    from hepta.lock_diff import compare_locks
    from hepta.modules import load_project
    from hepta.packages import load_package, verify_lock, write_lock
    from hepta.pipeline import analyze_project

    inputs = ["examples/packages/typed_packet/src/lib.hepta", "examples/packages/typed_packet/src/packet.hepta"]
    inputs += [f"stdlib/{name}/src/lib.hepta" for name in LIBRARIES.values()]
    source_bytes = {name: (root / name).read_bytes() for name in inputs}
    source_sha = {name: sha(data) for name, data in source_bytes.items()}
    packet = source_bytes[inputs[1]]
    assert packet.count(TERMINAL) == 1
    receipts, snapshots, rejections = [], [], []

    with tempfile.TemporaryDirectory(prefix="hepta-independent-typed-context-") as temporary:
        workspace = Path(temporary)
        app = workspace / "app"
        entry = app / "src/main.hepta"
        for version in (1, 2):
            for name in LIBRARIES.values():
                path = workspace / (name + str(version))
                put(path / "hepta.toml", manifest("hepta_" + name, f"0.{version}.0", "lib", {}))
                put(path / "src/lib.hepta", source_bytes[f"stdlib/{name}/src/lib.hepta"])
            path = app / f"src/typed{version}"
            dependencies = {alias: library_spec(name, f"=0.{version}.0", "../../../")
                            for alias, name in LIBRARIES.items()}
            put(path / "hepta.toml", manifest("typed_packet", f"{version}.0.0", "lib", dependencies))
            put(path / "src/lib.hepta", source_bytes[inputs[0]])
            put(path / "src/packet.hepta", packet)
        put(app / "src/packet.hepta", packet.replace(TERMINAL, TERMINAL.replace(b"stage: 0", b"stage: 5"), 1))

        def write(selected, local=None, first=True):
            put(app / "hepta.toml", app_manifest(selected))
            put(entry, entry_source(local, first))

        def freeze(selected):
            want = expected_lock(app, selected)
            got = write_lock(app)["snapshot"]
            assert got == want, (got, want)
            packages = load_package(app)
            assert packages.dependencies["typed"].root == app / f"src/typed{selected}"
            for alias, name in LIBRARIES.items():
                assert packages.dependencies[alias].root == workspace / (name + str(selected))
                assert packages.dependencies[alias] is packages.dependencies["typed"].dependencies[alias]
            assert verify_lock(packages) == want
            snapshots.append({"selected": selected, "sha256": want["sha256"], "files": sorted(want["files"])})
            return (app / "Hepta.lock").read_bytes()

        def execute(label):
            analysis = analyze_project(app, backend="c", locked=True, crate_type="bin")
            assert analysis.report["ok"], analysis.report
            if not native:
                return
            for optimized in (False, True):
                output = workspace / "typed-observer"
                built = compile_c(analysis.c, cc="gcc", output=output, optimize=optimized, sanitize=True)
                assert built["ok"], built
                assert "-fsanitize=undefined" in built["flags"] and "-fno-sanitize-recover=all" in built["flags"]
                result = subprocess.run([str(output)], capture_output=True, timeout=30)
                wanted = (0, b"", b"")
                assert (result.returncode, result.stdout, result.stderr) == wanted, (label, result.returncode, result.stdout, result.stderr)
                receipts.append({"label": label, "optimized": optimized,
                                 "returncode": result.returncode, "build": built,
                                 "lock_sha256": json.loads((app / "Hepta.lock").read_bytes())["sha256"]})

        def context_error(action, selected, first, label):
            before_source, before_lock = entry.read_bytes(), (app / "Hepta.lock").read_bytes()
            intended = app / f"src/typed{selected}"
            roots = (app, intended) if first else (intended, app)
            try:
                action()
            except HeptaError as error:
                diagnostic = error.diagnostic
                assert diagnostic.code == "E_MODULE_PACKAGE_CONTEXT", diagnostic
                assert diagnostic.phase == "module", diagnostic
                assert diagnostic.message == "Module " + str(intended / "src/lib.hepta") + " is imported under conflicting package roots: " + str(roots[0]) + " and " + str(roots[1]), diagnostic
                assert diagnostic.span.path == str(entry) and diagnostic.span.line == 2 and diagnostic.span.column == 1, diagnostic
                rejections.append(label)
            else:
                raise AssertionError("Conflicting typed context was accepted: " + label)
            assert entry.read_bytes() == before_source and (app / "Hepta.lock").read_bytes() == before_lock

        for selected in (1, 2):
            write(selected)
            freeze(selected)
            execute(f"selected-{selected}-exact-typed-payloads")
            for first in (True, False):
                write(selected, selected, first)
                freeze(selected)
                label = f"selected-{selected}-{'local-first' if first else 'dependency-first'}"
                for locked in (False, True):
                    for form, path in (("directory", app), ("manifest", app / "hepta.toml"), ("entry", entry)):
                        context_error(lambda p=path, l=locked: load_project(p, locked=l), selected, first, f"{label}-{form}-{locked}")
                for backend in ("c", "rust"):
                    context_error(lambda b=backend: analyze_project(app, backend=b, locked=True, native=False, crate_type="bin"),
                                  selected, first, f"{label}-{backend}-frontend")

        # The imported high candidate remains a distinct file when low is selected.
        for first in (True, False):
            write(1, 2, first)
            freeze(1)
            execute("unselected-high-selected-low-" + ("local-first" if first else "dependency-first"))

        # Requirement-only upgrade keeps the entry bytes fixed. The previous lock
        # cannot approve it; refresh describes the collision but cannot repair it.
        write(1, 2, True)
        old_lock = freeze(1)
        old_manifest = (app / "hepta.toml").read_bytes()
        old_source = entry.read_bytes()
        old_path = workspace / "old.lock"
        put(old_path, old_lock)
        put(app / "hepta.toml", app_manifest(2))
        try:
            load_project(app, locked=True)
        except HeptaError as error:
            assert error.diagnostic.code == "E_LOCK_STALE", error.diagnostic
        else:
            raise AssertionError("Upgrade was accepted using a stale lock")
        assert (app / "Hepta.lock").read_bytes() == old_lock and entry.read_bytes() == old_source
        freeze(2)
        report = compare_locks(old_path, app / "Hepta.lock")
        assert report["compatibility"] == "not_assessed" and report["changed"]
        assert report["dependencies"]["retargeted"] == sorted(
            [{"package": ".", "alias": alias, "before": f"../{name}1", "after": f"../{name}2"} for alias, name in LIBRARIES.items()]
            + [{"package": ".", "alias": "typed", "before": "src/typed1", "after": "src/typed2"}],
            key=lambda item: (item["package"], item["alias"]))
        context_error(lambda: load_project(app, locked=True), 2, True, "refreshed-upgrade")
        put(app / "hepta.toml", old_manifest)
        put(app / "Hepta.lock", old_lock)
        assert verify_lock(load_package(app)) == expected_lock(app, 1)
        assert entry.read_bytes() == old_source
        execute("byte-exact-low-rollback")

    assert source_sha == {name: sha((root / name).read_bytes()) for name in inputs}
    assert len(rejections) == 33
    assert len(receipts) == (10 if native else 0)
    result = {"result": "PASS", "native": native,
              "python": sys.version, "source_sha256": source_sha, "snapshots": snapshots,
              "context_rejections": rejections,
              "native_executions": len(receipts), "receipts": receipts,
              "oracle_sha256": sha(Path(__file__).read_bytes()), "whole_project_blockers_closed": False}
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Assertions must remain enabled")
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--native", action="store_true")
    arguments = parser.parse_args()
    run(arguments.root, arguments.native)
