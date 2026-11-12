"""Parse the exact selected submitted Python sources without importing them.

This is an authoring syntax gate only. It executes no generator, HIA compiler,
VM or native component, and grants no semantic or whole-product qualification.
"""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import stat
import subprocess
import sys
import traceback

PREFIX = "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
MANIFEST = PREFIX + "ci/active_source_syntax_manifest_r1.json"

def identity(raw):
    return dict(bytes=len(raw),
                gitsha=hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
                sha256=hashlib.sha256(raw).hexdigest())

def capture(root, relative, expected=None):
    name = PurePosixPath(relative)
    assert relative and not name.is_absolute() and ".." not in name.parts and str(name) == relative
    current = root
    for part in name.parts:
        current = current / part
        assert not current.is_symlink(), str(current)
    path = root / relative
    assert path.resolve().is_relative_to(root)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        pieces = []
        while True:
            piece = os.read(fd, 1 << 20)
            if not piece:
                break
            pieces.append(piece)
        raw = b"".join(pieces)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    path_after = path.lstat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                             value.st_mtime_ns, value.st_ctime_ns)
    assert fields(before) == fields(after) == fields(path_after)
    assert len(raw) == before.st_size
    pin = dict(path=relative, mode=format(before.st_mode, "o"), **identity(raw))
    if expected is not None:
        for key in ("path", "mode", "bytes", "gitsha", "sha256"):
            assert pin[key] == expected[key], (relative, key, pin[key], expected[key])
    return raw, pin

def save(out, relative, raw):
    target = out / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
    assert target.read_bytes() == raw

def main():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert sys.version_info[:3] == (3, 12, 14), sys.version
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    affinity = os.sched_getaffinity(0)
    assert affinity
    os.sched_setaffinity(0, {min(affinity)})
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    out = Path(os.environ["HIA_SOURCE_GATE_OUTPUT"]).resolve()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema="hia-selected-submitted-source-syntax-v1", status="INCOMPLETE",
                  run_id=os.environ.get("GITHUB_RUN_ID"),
                  submitted_head=os.environ.get("GITHUB_SHA"),
                  Python=sys.version, sources=[], source_checks=[], errors=[],
                  Python_AST_files=0, HIA_generations=0, B3_compilations=0,
                  VM_entries=0, native_entries=0, semantic_qualification=False,
                  whole_stack_closed=False, installed_activation=False,
                  limits=dict(cpu_seconds=90, external_wall_seconds=180,
                              address_bytes=1 << 30, cores=1, core_bytes=0),
                  scope="Only the explicitly inventoried source syntax; no import or target execution")
    originals = {}
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                       timeout=5, text=True).strip()
        report["observed_HEAD"] = head
        assert head == report["submitted_head"]
        reader_relative = Path(__file__).resolve().relative_to(root).as_posix()
        for relative in (reader_relative, MANIFEST):
            raw, pin = capture(root, relative)
            originals[relative] = pin
            save(out, "gate-source/" + relative, raw)
        manifest_raw, manifest_pin = capture(root, MANIFEST, originals[MANIFEST])
        inventory = json.loads(manifest_raw)
        assert inventory["schema"] == "hia-recovery-selected-source-syntax-inventory-v1"
        assert inventory["status"] == "SOURCE_SYNTAX_ONLY_NO_SEMANTIC_QUALIFICATION"
        files = inventory["files"]
        paths = [row["path"] for row in files]
        assert paths and paths == sorted(set(paths))
        report["inventory"] = manifest_pin
        report["expected_Python_files"] = len(files)
        for row in files:
            relative = row["path"]
            observed = dict(path=relative, status="INCOMPLETE")
            try:
                assert relative.endswith(".py")
                assert relative.startswith(PREFIX) or relative == "tools/qualify_hia_selfhost.py"
                assert type(row["bytes"]) is int and row["bytes"] >= 0
                raw, pin = capture(root, relative, row)
                if relative in originals:
                    assert originals[relative] == pin
                originals[relative] = pin
                save(out, "exact-source/" + relative, raw)
                syntax = ast.parse(raw, filename=relative, mode="exec")
                observed.update(status="PASS_AST_ONLY", identity=pin,
                                ast_nodes=sum(1 for _ in ast.walk(syntax)))
                report["Python_AST_files"] += 1
            except BaseException as error:
                observed.update(status="FAIL", error_class=type(error).__name__,
                                error=str(error), traceback=traceback.format_exc())
                report["errors"].append(observed.copy())
            report["sources"].append(observed)
            print("HIA_SUBMITTED_SOURCE_SYNTAX " + json.dumps(observed, sort_keys=True), flush=True)
        assert report["Python_AST_files"] == len(files) and not report["errors"]
        report["status"] = "PASS_SOURCE_SYNTAX_ONLY"
    except BaseException as error:
        report["status"] = "FAIL"
        report["errors"].append(dict(error_class=type(error).__name__, error=str(error),
                                     traceback=traceback.format_exc()))
        traceback.print_exc()
    finally:
        for relative, before in sorted(originals.items()):
            try:
                _, after = capture(root, relative, before)
                unchanged = after == before
            except BaseException as error:
                after = None
                unchanged = False
                report["errors"].append(dict(path=relative, error=str(error),
                                             traceback=traceback.format_exc()))
            report["source_checks"].append(dict(before=before, after=after, unchanged=unchanged))
            if not unchanged:
                report["status"] = "FAIL"
        raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
        save(out, "source-syntax-report.json", raw)
        print("HIA_SUBMITTED_SOURCE_SYNTAX_SUMMARY " + json.dumps(
            {key: value for key, value in report.items() if key not in ("sources", "source_checks")},
            sort_keys=True), flush=True)
    return 0 if report["status"] == "PASS_SOURCE_SYNTAX_ONLY" else 1

if __name__ == "__main__":
    raise SystemExit(main())
