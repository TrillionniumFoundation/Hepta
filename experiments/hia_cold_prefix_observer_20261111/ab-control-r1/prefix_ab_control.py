"""One original 75-case prefix through each transport; development only."""
from __future__ import annotations
import argparse
import ast
import copy
import errno
import fcntl
from hashlib import sha1, sha256
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

BASE_COMMIT = "608157e52b0b94e0d294f6b99c4e809869f183aa"
BASE_TREE = "e7c29a60796a1a78946a2c667aa80df86529e532"
CANDIDATE_COMMIT = "c1d5569ff6d7de6ace669b929e02e3e7aac10eac"
CANDIDATE_TREE = "5b99aa6d6840b0b62816f3e586e14e1a204ea99d"
OWNER_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
PYTHON_SHA = "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
PREFIX_SHA = "19371fa229248fdf40f1dfa108344b144268b29a016b926837bc249d5056aced"
QUALIFY_SHA = "a1c76c165856927bfbaded5610568fa79456f15e1eb356dda7a8b882bb602c92"
TEST_SHA = "e64e9ed9e67527c6bd2074176711c557c6ffbcb6333ac3c9168851fa90d6b8c1"
B3_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
M3_SHA = "d606beeaf5503627138073970ea4537975a53fd657c07f89e36cc36d25610ac2"
SOURCE_SHA = "b23924a2817e384a6597a7ed97a8ebe521f8402bc0f3d6ebc8593cb5b3750029"
MODIFIED_SOURCE_SHA = "07957626a208ee3e873540b24cdd0a40adcbcc55de47914692fcf5e31de58661"
ORIGINAL_CHILD_SHA = "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
EXPECTED_CASES = ["modified-backward-bytesum","modified-backward-sample-0","modified-backward-sample-1","modified-backward-sample-2","modified-bytesum","modified-full-call-depth","modified-full-call-depth-run","modified-reject-backward-signature","modified-reject-missing-in-range-callee","modified-reject-mutual-recursion","modified-reject-non-tail-direct-recursion","modified-reject-out-of-range-callee","modified-reject-overflow-callee","modified-reject-unreachable-cycle","modified-sample-0","modified-sample-1","modified-sample-2","original-backward-bytesum","original-backward-sample-0","original-backward-sample-1","original-backward-sample-2","original-bytesum","original-full-call-depth","original-full-call-depth-run","original-reject-backward-signature","original-reject-missing-in-range-callee","original-reject-mutual-recursion","original-reject-non-tail-direct-recursion","original-reject-out-of-range-callee","original-reject-overflow-callee","original-reject-unreachable-cycle","original-sample-0","original-sample-1","original-sample-2","readonly-call","readonly-call-code","reject-absent-block","reject-arrow-adjacency","reject-block-adjacency","reject-branch-separation","reject-call-attribute-separation","reject-call-type","reject-cast-attribute-separation","reject-constant-attribute-separation","reject-duplicate-function","reject-duplicate-ssa","reject-edge-adjacency","reject-edge-type","reject-effects-adjacency","reject-effects-separation","reject-empty-source","reject-entry-adjacency","reject-entry-close-adjacency","reject-entry-open-adjacency","reject-entry-separation","reject-function-adjacency","reject-invalid-byte","reject-leading-zero","reject-missing-end","reject-mutable-alias","reject-opcode-adjacency","reject-out-of-scope","reject-overflow-u32","reject-overflow-u64","reject-quoted-declaration","reject-readonly-branch-alias","reject-readonly-jump-alias","reject-readonly-write","reject-recursive-call-signature","reject-return-adjacency","reject-unknown-opcode","reject-unquoted-call","reject-unreachable-block","short-output","short-workspace"]
SEMANTIC_FIELDS = (
    "status", "result_u64", "abi_status", "core_u32", "return_encoding",
    "source_unchanged", "output_unchanged", "workspace_header",
    "source_sha256", "input_sha256", "input_bytes", "image_sha256",
    "artifact_sha256", "output_sha256", "format",
    "forbidden_compiler_modules_loaded", "limits",
)
SCHEMA = "hia.cold-prefix-native-observer-development.v1"


def require(value, message):
    if not value:
        raise AssertionError(message)


def digest(raw):
    return sha256(raw).hexdigest()


def identity(st):
    return {name: getattr(st, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns")}


def read_regular(path, maximum=64 << 20):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "regular single-link file required: " + str(path))
    require(0 <= before.st_size <= maximum, "file bound exceeded: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        require(identity(opened) == identity(before), "file changed before open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    require(len(raw) == before.st_size and identity(after) == identity(before)
            and identity(path.lstat()) == identity(before), "file changed while read")
    return raw, {"path": str(path), "bytes": len(raw), "sha256": digest(raw),
                 "identity": identity(after)}


def write_new(path, raw, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "short retained write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    reread, record = read_regular(path, max(64 << 20, len(raw)))
    require(reread == raw, "retained bytes differ")
    return record


def save_new(path, value):
    return write_new(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def git_object(kind, raw):
    return sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def tree_sha(rows):
    root = {}
    for path, row in rows.items():
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        require(parts[-1] not in node, "duplicate source path")
        node[parts[-1]] = row
    def encode(node):
        data = bytearray()
        ordered = sorted(node.items(), key=lambda pair:
            (pair[0] + ("/" if "git_blob" not in pair[1] else "")).encode())
        for name, value in ordered:
            if "git_blob" in value:
                mode, value_sha = value["git_mode"], value["git_blob"]
            else:
                mode, value_sha = "40000", encode(value)
            data.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(value_sha))
        return git_object("tree", bytes(data))
    return encode(root)


def source_snapshot(root):
    root = Path(root).resolve(strict=True)
    require(stat.S_ISDIR(root.lstat().st_mode), "source root is not a real directory")
    result = {}
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in dirs:
            require(stat.S_ISDIR((Path(current) / name).lstat().st_mode),
                    "source directory symlink or special node")
        for name in sorted(names):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            if rel == ".git":
                continue
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "source leaf is not a regular single-link file: " + rel)
            h256 = sha256()
            h1 = sha1(b"blob " + str(before.st_size).encode() + b"\0")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            count = 0
            try:
                require(identity(os.fstat(fd)) == identity(before), "source changed before open")
                while True:
                    raw = os.read(fd, 1 << 20)
                    if not raw:
                        break
                    count += len(raw)
                    h256.update(raw)
                    h1.update(raw)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            require(count == before.st_size and identity(before) == identity(after)
                    and identity(path.lstat()) == identity(before), "source changed while hashing")
            result[rel] = {"git_blob": h1.hexdigest(), "sha256": h256.hexdigest(),
                           "bytes": count, "git_mode": "100755" if before.st_mode & 0o111 else "100644"}
    return {"tree": tree_sha(result), "leaves": result,
            "file_count": len(result), "bytes": sum(x["bytes"] for x in result.values())}


def copy_source(original, destination, snapshot):
    destination.mkdir(mode=0o700)
    for rel, record in snapshot["leaves"].items():
        raw, _ = read_regular(original / rel, max(64 << 20, record["bytes"]))
        require(len(raw) == record["bytes"] and digest(raw) == record["sha256"]
                and git_object("blob", raw) == record["git_blob"], "copy source drift")
        write_new(destination / rel, raw, 0o500 if record["git_mode"] == "100755" else 0o400)


def controls(request):
    control = Path(__file__).resolve().parent
    result = {}
    expected = request["control_files"]
    require(type(expected) is dict and set(expected) ==
            {"prefix_ab_control.py", "B3.receipt.original.json", "M3.receipt.original.json"}
            | {"overlay/" + path for path in request["overlay"]}, "control allowlist differs")
    for rel, pin in expected.items():
        require(not Path(rel).is_absolute() and ".." not in Path(rel).parts, "unsafe control path")
        raw, record = read_regular(control / rel)
        require(len(raw) == pin["bytes"] and digest(raw) == pin["sha256"]
                and git_object("blob", raw) == pin["git_blob"], "control bytes differ: " + rel)
        result[rel] = record
    return result


def validate_request(path, expected):
    raw, _ = read_regular(path, 1 << 20)
    require(digest(raw) == expected, "request SHA differs")
    request = json.loads(raw)
    require(request["schema"] == SCHEMA and request["base_commit"] == BASE_COMMIT
            and request["base_tree"] == BASE_TREE
            and request["candidate_commit"] == CANDIDATE_COMMIT
            and request["candidate_tree"] == CANDIDATE_TREE, "source pins differ")
    require(request["owner_seconds"] == 180 and request["cleanup_seconds"] == 3
            and request["per_invocation_seconds"] == 20 and request["original_cold_workers"] == 2
            and request["original_cold_phases"] == 38
            and request["minimum_free_bytes"] == 8 << 30
            and request["minimum_free_inodes"] == 100000, "original fixed bounds differ")
    require(request["python_sha256"] == PYTHON_SHA and sys.version_info[:3] == (3, 14, 4)
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            "fixed isolated interpreter differs")
    require(digest(read_regular(Path(sys.executable).resolve())[0]) == PYTHON_SHA,
            "interpreter bytes differ")
    require(not any(name.startswith("HEPTA_") for name in os.environ), "ambient HIA selector present")
    root = Path(request["root"])
    require(root.is_absolute() and str(root) == "/home/qian-qi/he26-cold-prefix-r1"
            and Path(__file__).resolve().parent == root / "control", "private root differs")
    original = Path(request["original_source"]).resolve(strict=True)
    require(str(original) == "/home/qian-qi/he26v67r2/s", "original source path differs")
    require(root != original and original not in root.parents and root not in original.parents,
            "new output overlaps original source")
    require(request["compilers"]["original"] == {
        "path": "/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/B3.image.bin",
        "bytes": 668608, "sha256": B3_SHA}, "original compiler binding differs")
    require(request["compilers"]["modified"] == {
        "path": "/home/qian-qi/he26v67r2/q/cold.cold/qualification.evidence/M3.image.bin",
        "bytes": 668608, "sha256": M3_SHA}, "modified compiler binding differs")
    controls(request)
    return request, raw


def pin_compilers(request, destination=None):
    result = {}
    for key, pin in request["compilers"].items():
        raw, record = read_regular(pin["path"])
        require(len(raw) == pin["bytes"] and digest(raw) == pin["sha256"], "compiler input drift")
        if destination is not None:
            write_new(destination / (key + ".bin"), raw, 0o400)
        result[key] = record
    return result


def natural_owner(result):
    cleanup = result.get("cleanup", {})
    events = result.get("events", [])
    kinds = {"qualification_started", "owned_child_observed", "qualification_exit_observed", "owned_child_reaped"}
    return (result.get("status") == "OWNED_PROCESS_COMPLETED" and result.get("returncode") == 0
            and result.get("exit_observed_before_deadline") is True and result.get("timed_out") is False
            and result.get("subreaper_enabled") is True
            and not result.get("interrupted_signals") and not result.get("event_overflow")
            and not result.get("owner_error") and isinstance(events, list) and bool(events)
            and all(e.get("kind") in kinds for e in events)
            and cleanup.get("attempted") is True and cleanup.get("complete") is True
            and cleanup.get("observed_echild") is True and cleanup.get("leader_reaped") is True
            and cleanup.get("deadline_exceeded") is False and cleanup.get("errors") == []
            and cleanup.get("remaining_direct_children") == [])


def fixed_env():
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}


def source_controls(source, root):
    module = importlib.import_module("tests.test_hia_selfhost_native_observer")
    require(Path(module.__file__).resolve() == source / "tests/test_hia_selfhost_native_observer.py",
            "wrong scope-test module")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.NativeObserverScopeTests)
    loaded = [test.id() for test in suite]
    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.executed = []
        def startTest(self, test):
            self.executed.append(test.id())
            super().startTest(test)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, resultclass=Result, verbosity=2).run(suite)
    log = write_new(root / "scope-tests.log", stream.getvalue().encode())
    report = {"loaded_test_ids": loaded, "executed_test_ids": result.executed,
              "tests_loaded": len(loaded), "tests_run": result.testsRun,
              "failures": [(t.id(), s) for t, s in result.failures],
              "errors": [(t.id(), s) for t, s in result.errors],
              "skipped": [(t.id(), s) for t, s in result.skipped],
              "expected_failures": [(t.id(), s) for t, s in result.expectedFailures],
              "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
              "log": log}
    save_new(root / "scope-tests.json", report)
    require(len(loaded) == 2 and loaded == result.executed and result.testsRun == 2
            and not any(report[k] for k in ("failures", "errors", "skipped",
                "expected_failures", "unexpected_successes")), "scope controls did not complete")
    return report


def load_qualify(source):
    sys.path.insert(0, str(source))
    q = importlib.import_module("tools.qualify_hia_selfhost")
    require(Path(q.__file__).resolve() == source / "tools/qualify_hia_selfhost.py"
            and digest(read_regular(q.__file__)[0]) == QUALIFY_SHA, "wrong qualifier source")
    require(q.NATIVE_OBSERVER is None and q.NATIVE_LINKED_OBSERVER is None,
            "observer state was not initially empty")
    require(q.invoke.__globals__ is q.__dict__ and q.compile_stage.__globals__ is q.__dict__
            and q._native_observer_scope.__wrapped__.__globals__ is q.__dict__,
            "scope and invocation do not share the loaded module's actual globals")
    require(q.QUALIFICATION_WORKERS == 2 and len(q.QUALIFICATION_FAMILIES) == 19
            and q.CAPACITY == 1 << 20, "qualification inventory or capacity changed")
    require(digest(q.SOURCE.read_bytes()) == SOURCE_SHA
            and digest(q.mutate_compiler(q.SOURCE.read_bytes())) == MODIFIED_SOURCE_SHA
            and digest(q.CHILD.read_bytes()) == ORIGINAL_CHILD_SHA, "original ABI inputs changed")
    return q


def prefix_function(q, source, mode):
    original = read_regular(source / "experiments/hia_cold_prefix_observer_20261111/candidate-r1/original-prefix.py.txt")[0]
    require(len(original) == 3981 and digest(original) == PREFIX_SHA, "original prefix bytes differ")
    text = read_regular(q.__file__)[0].decode()
    begin = text.index("    with _native_observer_scope(native_observer):\n", text.index("def qualify("))
    end = text.index("    # B0 and both three-generation chains above remain strictly sequential.\n", begin)
    selected = text[begin:end]
    recovered = "".join(line[4:] if line.strip() else line for line in selected.splitlines(keepends=True)[1:])
    require(recovered.encode() == original, "candidate did not preserve every original prefix byte")
    body = original.decode() if mode == "legacy" else selected
    header = "def _actual_original_prefix(directory, original, previous, source, sample, stages, checks, native_observer):\n"
    tail = "    return {'checks': checks, 'observations': [*observations, *rejected, readonly_build, readonly, *call_observations, small, workspace]}\n"
    namespace = dict(q.__dict__)
    ast.parse(header + body + tail)
    exec(compile(header + body + tail, str(source / ("retained-prefix-" + mode)), "exec"), namespace)
    return namespace["_actual_original_prefix"]


def run_prefix(request, request_path, request_sha, mode):
    root = Path(request["root"]) / "run"
    source = Path(request["root"]) / "source"
    directory = root / mode
    directory.mkdir(mode=0o700)
    report = {"schema": SCHEMA, "mode": mode, "status": "HOLD", "scope": "ORIGINAL_75_PREFIX_ONLY"}
    q = None
    records, processes = [], []
    try:
        q = load_qualify(source)
        original = root / "inputs/original.bin"
        modified = root / "inputs/modified.bin"
        require(digest(read_regular(original)[0]) == B3_SHA
                and digest(read_regular(modified)[0]) == M3_SHA, "private compiler copies differ")
        observer = root / "observer-build/native-observer.elf"
        observer_raw, observer_record = read_regular(observer)
        report["observer_before"] = observer_record
        active = [None]
        b3_receipt = json.loads(read_regular(Path(__file__).resolve().parent / "B3.receipt.original.json")[0])
        m3_receipt = json.loads(read_regular(Path(__file__).resolve().parent / "M3.receipt.original.json")[0])
        require(b3_receipt["case"] == "B3" and b3_receipt["produced_sha256"] == B3_SHA
                and b3_receipt["produced_bytes"] == 668608 and b3_receipt["input_sha256"] == SOURCE_SHA
                and m3_receipt["case"] == "M3" and m3_receipt["produced_sha256"] == M3_SHA
                and m3_receipt["produced_bytes"] == 668608
                and m3_receipt["input_sha256"] == MODIFIED_SOURCE_SHA, "retained generation receipts differ")
        real_invoke, real_popen = q.invoke, subprocess.Popen
        def observe_popen(*args, **kwargs):
            require(active[0] in EXPECTED_CASES, "process outside a prefix invocation")
            inherited = []
            for fd in kwargs.get("pass_fds", ()):
                info = os.fstat(fd)
                inherited.append({"fd": fd, "bytes": info.st_size,
                                  "seals": fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034))})
            proc = real_popen(*args, **kwargs)
            status = Path("/proc/" + str(proc.pid) + "/stat").read_text()
            ticks = int(status[status.rfind(")") + 2:].split()[19])
            processes.append({"case": active[0], "pid": proc.pid, "start_ticks": ticks,
                              "argv": list(proc.args), "pass_fds": inherited, "_process": proc})
            return proc
        def observe_invoke(directory_arg, label, image, data, **kwargs):
            require(label in EXPECTED_CASES and label not in {r["case"] for r in records},
                    "prefix case is unexpected or repeated")
            require(Path(directory_arg).resolve() == directory, "prefix output escaped its private directory")
            require(type(data) is bytes, "original prefix source is not exact bytes")
            active[0] = label
            before_count = len(processes)
            try:
                result, output = real_invoke(directory_arg, label, image, data, **kwargs)
            finally:
                active[0] = None
            require(len(processes) == before_count + 1, "prefix call did not create exactly one child")
            records.append({"case": label, "input_sha256": digest(data), "input_bytes": len(data),
                            "output_sha256": digest(output), "output_bytes": len(output)})
            return result, output
        with patch.object(q, "invoke", side_effect=observe_invoke), patch.object(subprocess, "Popen", side_effect=observe_popen):
            operation = prefix_function(q, source, mode)
            started = time.monotonic_ns()
            result = operation(directory, original, modified, q.SOURCE.read_bytes(), q.SAMPLE.read_bytes(),
                [None, None, b3_receipt], {}, observer)
            report["prefix_wall_elapsed_ns"] = time.monotonic_ns() - started
        report["scope_restored"] = q.NATIVE_OBSERVER is None and q.NATIVE_LINKED_OBSERVER is None
        require(report["scope_restored"], "prefix observer state leaked")
        require(len(records) == 75 and sorted(r["case"] for r in records) == EXPECTED_CASES
                and len(processes) == 75 and len({p["pid"] for p in processes}) == 75,
                "original full case or fresh-process denominator differs")
        require(result["checks"] and all(type(v) is bool and v for v in result["checks"].values()),
                "an original prefix check failed")
        require(len(result["observations"]) == 75, "an original observation disappeared")
        for item in processes:
            process = item.pop("_process")
            require(type(process.returncode) is int and process.returncode == 0, "native child did not return normally")
            item["returncode"] = process.returncode
            try:
                os.waitpid(item["pid"], os.WNOHANG)
            except ChildProcessError as exc:
                require(exc.errno == errno.ECHILD, "unexpected waitpid refusal")
                item["direct_child_reaped"] = True
            else:
                raise AssertionError("completed child remains waitable")
            if mode == "native":
                require(len(item["argv"]) == 1 and item["argv"][0].startswith("/proc/self/fd/")
                        and len(item["pass_fds"]) == 1
                        and item["pass_fds"][0]["seals"] & 15 == 15
                        and item["pass_fds"][0]["bytes"] == len(observer_raw), "native sealed exec differs")
            else:
                require(item["argv"][1:4] == ["-I", "-S", "-B"]
                        and item["argv"][4] == str(q.CHILD) and item["pass_fds"] == [],
                        "retained independent loader differs")
        receipts = []
        for item in records:
            raw, receipt_record = read_regular(directory / (item["case"] + ".receipt.json"))
            receipt = json.loads(raw)
            require(receipt["status"] == "returned" and receipt["case"] == item["case"]
                    and receipt["forbidden_compiler_modules_loaded"] == []
                    and receipt["input_sha256"] == item["input_sha256"]
                    and receipt["output_sha256"] == item["output_sha256"], "raw receipt differs")
            require(all(field in receipt for field in SEMANTIC_FIELDS), "semantic field missing")
            if mode == "native":
                require(receipt["transport"] == "HIA-emitted-static-ELF-observer-v2"
                        and receipt["fresh_native_exec"] is True
                        and receipt["successor_process_reuse"] is False
                        and receipt["runner_sha256"] == digest(observer_raw), "native transport fell back")
            else:
                require("transport" not in receipt and receipt["runner_sha256"] == ORIGINAL_CHILD_SHA,
                        "legacy transport is not the original loader")
            for suffix in (".input.bin", ".output.bin", ".request.json", ".stdout.log", ".stderr.log"):
                read_regular(directory / (item["case"] + suffix))
            receipts.append({"case": item["case"], "receipt": receipt, "raw_record": receipt_record})
        require(read_regular(observer)[0] == observer_raw, "observer bytes changed")
        report.update(status="PREFIX_COMPLETE", checks=result["checks"], observations=result["observations"],
                      invocation_order=[r["case"] for r in records], invocation_count=len(records),
                      process_count=len(processes), process_identities=processes, receipts=receipts,
                      invocation_wall_elapsed_ns=sum(r["receipt"]["wall_elapsed_ns"] for r in receipts),
                      native_elapsed_ns=sum(r["receipt"]["native_elapsed_ns"] for r in receipts),
                      observer_after=read_regular(observer)[1])
    except BaseException:
        report["failure"] = traceback.format_exc()
    finally:
        report["partial_invocation_order"] = [row["case"] for row in records]
        report["partial_process_observations"] = [
            {**{key: value for key, value in row.items() if key != "_process"},
             "observed_returncode": row["_process"].returncode if "_process" in row else row.get("returncode")}
            for row in processes]
        if q is not None:
            report["final_flat_observer_is_none"] = q.NATIVE_OBSERVER is None
            report["final_linked_observer_is_none"] = q.NATIVE_LINKED_OBSERVER is None
            if not (report["final_flat_observer_is_none"] and report["final_linked_observer_is_none"]):
                report["status"] = "HOLD"
        save_new(directory / "report.json", report)
    print(json.dumps({"mode": mode, "status": report["status"], "invocations": report.get("invocation_count")}))
    return 0 if report["status"] == "PREFIX_COMPLETE" else 1


def pair_reports(root, legacy, native):
    require(legacy["status"] == native["status"] == "PREFIX_COMPLETE"
            and legacy["invocation_order"] == native["invocation_order"]
            and len(legacy["invocation_order"]) == 75
            and legacy["checks"] == native["checks"], "complete paired cases or checks differ")
    old_rows = {r["case"]: r for r in legacy["receipts"]}
    new_rows = {r["case"]: r for r in native["receipts"]}
    require(sorted(old_rows) == sorted(new_rows) == EXPECTED_CASES, "paired case membership differs")
    compared = []
    for case in legacy["invocation_order"]:
        left, right = old_rows[case]["receipt"], new_rows[case]["receipt"]
        for field in SEMANTIC_FIELDS:
            require(left[field] == right[field], "semantic mismatch: " + case + "/" + field)
        files = []
        for suffix in (".input.bin", ".output.bin"):
            a, ar = read_regular(root / "legacy" / (case + suffix))
            b, br = read_regular(root / "native" / (case + suffix))
            require(a == b, "actual byte mismatch: " + case + suffix)
            files.append({"suffix": suffix, "bytes": len(a), "sha256": digest(a),
                          "actual_all_bytes_compared": True, "legacy": ar, "native": br})
        require(("produced_sha256" in left) == ("produced_sha256" in right), "compiler result disappeared")
        if "produced_sha256" in left:
            require(left["produced_sha256"] == right["produced_sha256"]
                    and left["produced_bytes"] == right["produced_bytes"], "compiled image metadata differs")
            a, ar = read_regular(root / "legacy" / (case + ".image.bin"))
            b, br = read_regular(root / "native" / (case + ".image.bin"))
            require(a == b and digest(a) == left["produced_sha256"]
                    and len(a) == left["produced_bytes"], "actual compiled image bytes differ")
            files.append({"suffix": ".image.bin", "bytes": len(a), "sha256": digest(a),
                          "actual_all_bytes_compared": True, "legacy": ar, "native": br})
        compared.append({"case": case, "semantic_fields": list(SEMANTIC_FIELDS), "files": files})
    return compared


def worker(request, request_path, request_sha):
    root = Path(request["root"]) / "run"
    source = Path(request["root"]) / "source"
    original = Path(request["original_source"])
    report = {"schema": SCHEMA, "status": "HOLD", "scope": "DEVELOPMENT_PREFIX_ONLY_NOT_COLD",
              "full_cold_executed": False, "fresh_B0_or_generation_chain_executed": False,
              "compiler_origin": "original exact608 desktop cold timeout HOLD; retained artifacts only",
              "candidate_commit": CANDIDATE_COMMIT, "candidate_tree": CANDIDATE_TREE}
    originals_before = None
    inputs_before = None
    candidate_before = None
    control_before = None
    try:
        storage = os.statvfs(root)
        require(storage.f_bavail * storage.f_frsize >= 8 << 30 and storage.f_favail >= 100000,
                "original preparation storage thresholds unavailable")
        report["storage"] = {"free_bytes": storage.f_bavail * storage.f_frsize,
                             "free_inodes": storage.f_favail}
        control_before = controls(request)
        originals_before = source_snapshot(original)
        require(originals_before["tree"] == BASE_TREE and originals_before["file_count"] == 3925,
                "old exact608 source leaves differ")
        report["original_source_before"] = save_new(root / "original-source-before.json", originals_before)
        copy_source(original, source, originals_before)
        for rel, pin in request["overlay"].items():
            raw, _ = read_regular(Path(__file__).resolve().parent / "overlay" / rel)
            require(digest(raw) == pin["sha256"] and len(raw) == pin["bytes"]
                    and git_object("blob", raw) == pin["git_blob"], "overlay identity differs")
            target = source / rel
            if target.exists():
                require(rel in ("tools/qualify_hia_selfhost.py", "tests/test_hia_selfhost_native_observer.py"),
                        "unapproved replacement")
                old, _ = read_regular(target)
                require(digest(old) == originals_before["leaves"][rel]["sha256"], "private old leaf changed")
                target.unlink()
            write_new(target, raw, 0o400)
        candidate_before = source_snapshot(source)
        require(candidate_before["tree"] == CANDIDATE_TREE and candidate_before["file_count"] == 3928,
                "candidate leaf materialization differs")
        report["candidate_source_before"] = save_new(root / "candidate-source-before.json", candidate_before)
        inputs_before = pin_compilers(request, root / "inputs")
        report["original_compilers_before"] = inputs_before
        q = load_qualify(source)
        report["source_controls"] = source_controls(source, root)
        require(q.NATIVE_OBSERVER is None and q.NATIVE_LINKED_OBSERVER is None, "source controls leaked state")
        observer_dir = root / "observer-build"
        observer_dir.mkdir(mode=0o700)
        from tools.hia_selfhost_native_observer import independent_reference, build
        reference_started = time.monotonic_ns()
        reference = independent_reference()
        report["fresh_observer_VM_reference_elapsed_ns"] = time.monotonic_ns() - reference_started
        report["fresh_observer_VM_reference"] = save_new(observer_dir / "independent-reference.json", reference)
        report["reference_order_scope"] = "fresh VM before this development observer build; no new B0/chain or cold claim"
        build_started = time.monotonic_ns()
        observer, observer_build = build(observer_dir, root / "inputs/original.bin", reference)
        report["fresh_observer_build_elapsed_ns"] = time.monotonic_ns() - build_started
        require(q.NATIVE_OBSERVER is None and q.NATIVE_LINKED_OBSERVER is None, "observer build selected a prefix owner")
        report["observer_build"] = observer_build
        report["observer"] = read_regular(observer)[1]
        outputs = {}
        for mode in ("legacy", "native"):
            command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                       "--mode", mode, "--request", str(request_path), "--request-sha256", request_sha]
            stdout = root / (mode + ".stdout.log")
            stderr = root / (mode + ".stderr.log")
            with stdout.open("xb") as out, stderr.open("xb") as err:
                started = time.monotonic_ns()
                result = subprocess.run(command, cwd=source, env=fixed_env(), stdin=subprocess.DEVNULL,
                                        stdout=out, stderr=err)
            outputs[mode] = {"command": command, "returncode": result.returncode,
                             "parent_wall_elapsed_ns": time.monotonic_ns() - started,
                             "stdout": read_regular(stdout)[1], "stderr": read_regular(stderr)[1]}
            report["prefix_processes"] = outputs
            require(result.returncode == 0, mode + " full prefix failed; no retry")
            raw, record = read_regular(root / mode / "report.json", 4 << 20)
            outputs[mode]["report_record"] = record
            outputs[mode]["report"] = json.loads(raw)
        compared = pair_reports(root, outputs["legacy"]["report"], outputs["native"]["report"])
        report["paired_observations"] = save_new(root / "paired-observations.json", compared)
        report["full_original_case_count"] = len(compared)
        report["same_original_checks"] = outputs["legacy"]["report"]["checks"]
        report["legacy_prefix_wall_elapsed_ns"] = outputs["legacy"]["report"]["prefix_wall_elapsed_ns"]
        report["native_prefix_wall_elapsed_ns"] = outputs["native"]["report"]["prefix_wall_elapsed_ns"]
        report["wall_difference_ns_not_a_cold_result"] = report["legacy_prefix_wall_elapsed_ns"] - report["native_prefix_wall_elapsed_ns"]
        report["status"] = "BOTH_TRANSPORTS_MATCHED_DEVELOPMENT"
    except BaseException:
        report["failure"] = traceback.format_exc()
        report["status"] = "HOLD"
    finally:
        try:
            after = source_snapshot(original)
            report["original_source_after"] = save_new(root / "original-source-after.json", after)
            report["original_source_preserved"] = after == originals_before
            require(report["original_source_preserved"], "original source drift")
            if candidate_before is not None:
                after_candidate = source_snapshot(source)
                report["candidate_source_after"] = save_new(root / "candidate-source-after.json", after_candidate)
                report["candidate_source_preserved"] = after_candidate == candidate_before
                require(report["candidate_source_preserved"], "candidate source drift")
            report["original_compilers_after"] = pin_compilers(request)
            report["original_compilers_preserved"] = report["original_compilers_after"] == inputs_before
            require(report["original_compilers_preserved"], "original compiler input drift")
            report["control_after"] = controls(request)
            report["control_preserved"] = report["control_after"] == control_before
            require(report["control_preserved"], "control input drift")
        except BaseException:
            report["final_capture_failure"] = traceback.format_exc()
            report["status"] = "HOLD"
        save_new(root / "worker-report.json", report)
    print(json.dumps({"status": report["status"], "cases": report.get("full_original_case_count"),
                      "legacy_wall_ns": report.get("legacy_prefix_wall_elapsed_ns"),
                      "native_wall_ns": report.get("native_prefix_wall_elapsed_ns")}))
    return 0 if report["status"] == "BOTH_TRANSPORTS_MATCHED_DEVELOPMENT" else 1


def driver(request, request_path, request_sha):
    root = Path(request["root"]) / "run"
    root.mkdir(mode=0o700)
    report = {"schema": SCHEMA, "status": "HOLD", "scope": "DEVELOPMENT_ONLY_NOT_QUALIFICATION"}
    before = None
    try:
        before = controls(request)
        report["control_before"] = before
        write_new(root / "request.original.json", read_regular(request_path)[0])
        owner_path = Path(request["original_source"]) / "tools/hia_selfhost_process_owner.py"
        raw, _ = read_regular(owner_path)
        require(digest(raw) == OWNER_SHA, "original process owner differs")
        spec = importlib.util.spec_from_file_location("_original_prefix_process_owner", owner_path)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--mode", "worker",
                   "--request", str(request_path), "--request-sha256", request_sha]
        life = owner.run_owned(command, cwd=Path(request["root"]), env=fixed_env(),
            stdout_path=root / "worker.stdout.log", stderr_path=root / "worker.stderr.log",
            receipt_path=root / "process-owner.json", qualification_seconds=180, cleanup_seconds=3)
        report["owner"] = life
        report["natural_owner_success"] = natural_owner(life)
        require(digest(read_regular(owner_path)[0]) == OWNER_SHA, "owner source changed")
        report["owner_source_preserved"] = True
        raw, record = read_regular(root / "worker-report.json", 8 << 20)
        result = json.loads(raw)
        report["worker_report"] = record
        report["worker_status"] = result.get("status")
        require(report["natural_owner_success"]
                and result.get("status") == "BOTH_TRANSPORTS_MATCHED_DEVELOPMENT"
                and result.get("full_original_case_count") == 75
                and all(result.get(name) is True for name in
                    ("original_source_preserved", "candidate_source_preserved",
                     "original_compilers_preserved", "control_preserved")), "incomplete A/B or ownership")
        report["status"] = "PREFIX_A_B_DEVELOPMENT_PASS"
    except BaseException:
        report["failure"] = traceback.format_exc()
        report["status"] = "HOLD"
    finally:
        try:
            after = controls(request)
            report["control_after"] = after
            report["control_preserved"] = after == before
            require(report["control_preserved"], "driver control drift")
        except BaseException:
            report["final_capture_failure"] = traceback.format_exc()
            report["status"] = "HOLD"
        save_new(root / "DRIVER.json", report)
    print(json.dumps({"status": report["status"], "worker_status": report.get("worker_status"),
                      "natural_owner_success": report.get("natural_owner_success")}))
    return 0 if report["status"] == "PREFIX_A_B_DEVELOPMENT_PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("driver", "worker", "legacy", "native"), required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args()
    request, _ = validate_request(args.request, args.request_sha256)
    if args.mode == "driver":
        return driver(request, args.request, args.request_sha256)
    if args.mode == "worker":
        return worker(request, args.request, args.request_sha256)
    return run_prefix(request, args.request, args.request_sha256, args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
