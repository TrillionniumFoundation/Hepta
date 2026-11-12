"""Read every byte/mode of the exact R13 clean-builder original archive.
Read-only source recovery: no project imports, AST, code generation, compiler,
assembler, original test, installer, or native target is executed.
"""
from __future__ import annotations

import time
START_NS = time.monotonic_ns()
import argparse
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import sys
import tarfile
import traceback

sys.dont_write_bytecode = True
CONFIG_SHA256 = "61a08494ceeb3b3142ecd312881375d206e0fe0ed8d5d685fd90a69f8051d9f5"
CONFIG_GITSHA = "c78665dee0eac5c7d9bbf03f5ae77359bebacab9"
EXPECTED_ARCHIVE_SHA256 = "721d89da963f863e3760d9577f3585b0cd9d6f3c71a36ee597d975baf12e388b"
EXPECTED_ARCHIVE_BYTES = 57162628
EXPECTED_MEMBERS = 814
EXPECTED_FILES = 661
EXPECTED_DIRECTORIES = 153
EXPECTED_RAW_BYTES = 171212656
CPU_LIMIT = 90
WALL_NS = 180000000000
AS_LIMIT = 1 << 30
CHUNK = 1 << 20


def cpu_seconds():
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + child.ru_utime + child.ru_stime


def usage():
    return {"aggregate_cpu_seconds": cpu_seconds(),
            "elapsed_ns": time.monotonic_ns() - START_NS,
            "self_maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "children_maxrss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}


def budget():
    current = usage()
    if not (0 <= current["aggregate_cpu_seconds"] < CPU_LIMIT):
        raise RuntimeError("reader aggregate CPU budget exceeded: " + repr(current))
    if not (0 <= current["elapsed_ns"] < WALL_NS):
        raise RuntimeError("reader full output wall budget exceeded: " + repr(current))
    return current


def deadline(_signum, _frame):
    raise TimeoutError("reader original 180-second wall limit")


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("expected ordinary file: " + str(path))
    return info


def content_record(path):
    info = regular(path)
    digest = sha256()
    git = sha1(b"blob " + str(info.st_size).encode("ascii") + b"\0")
    count = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            count += len(block)
            digest.update(block)
            git.update(block)
    after = regular(path)
    if (count != info.st_size or after.st_size != info.st_size
            or after.st_mode != info.st_mode
            or after.st_dev != info.st_dev or after.st_ino != info.st_ino):
        raise ValueError("file changed while read: " + str(path))
    return {"bytes": count, "sha256": digest.hexdigest(),
            "gitsha": git.hexdigest(), "mode": stat.S_IMODE(after.st_mode)}


def require_record(actual, expected, label):
    for field in ("bytes", "sha256", "gitsha", "mode"):
        if field in expected and actual[field] != expected[field]:
            raise ValueError("identity differs " + label + " " + field)


def safe_relative(name):
    if type(name) is not str or not name or "\0" in name:
        raise ValueError("invalid original member path")
    pure = PurePosixPath(name)
    if pure.is_absolute() or pure.as_posix() != name:
        raise ValueError("noncanonical original member path: " + repr(name))
    if any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError("unsafe original member path: " + repr(name))
    return pure


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, sort_keys=True, indent=2) + "\n"
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
    if path.read_bytes() != text.encode("utf-8"):
        raise OSError("receipt readback differs: " + str(path))


class Recovery:
    def __init__(self, repo, out, config_path):
        self.repo = repo
        self.out = out
        self.config_path = config_path
        self.primary = None
        self.secondary = []
        self.inputs = {}
        self.outputs = {}
        self.directories = {}
        self.pending = {}
        self.original_members = []
        self.exports = []
        self.archive_complete = False
        self.members_complete = False
        self.after_complete = False
        self.operation_complete = False
        self.usage_after_output = None
        self.original_metadata = {}
        self.phase = "initialization"

    def failure(self, stage, exc):
        item = {"stage": stage, "class": type(exc).__name__, "message": str(exc),
                "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))}
        if self.primary is None:
            self.primary = item
        else:
            self.secondary.append(item)
        return item

    def attempt(self, label, operation):
        try:
            return operation()
        except BaseException as exc:
            self.failure(label, exc)
            return None

    def input(self, path, expected):
        # Register before the first observation so a partial read is still checked.
        self.inputs[str(path)] = dict(expected)
        actual = content_record(path)
        require_record(actual, expected, str(path))
        self.inputs[str(path)] = dict(actual)
        return actual

    def register(self, path, expected):
        actual = content_record(path)
        require_record(actual, expected, str(path))
        self.outputs[str(path)] = dict(actual)
        self.pending.pop(str(path), None)
        return actual

    def copy(self, source, target, expected):
        self.pending[str(target)] = {"source": str(source), "expected": dict(expected)}
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as before, target.open("xb") as after:
            while True:
                block = before.read(CHUNK)
                if not block:
                    break
                after.write(block)
        os.chmod(target, expected.get("mode", 0o644))
        return self.register(target, expected)

    def verify_after(self):
        failures = []
        for label, rows in (("input", self.inputs), ("output", self.outputs)):
            for name, expected in rows.items():
                try:
                    require_record(content_record(Path(name)), expected, label + ":" + name)
                except BaseException as exc:
                    failures.append(self.failure("after-" + label, exc))
        for name, mode in self.directories.items():
            try:
                info = Path(name).lstat()
                if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
                    raise ValueError("original directory mode differs: " + name)
            except BaseException as exc:
                failures.append(self.failure("after-directory", exc))
        if self.pending:
            failures.append(self.failure("after-pending",
                ValueError("partially materialized originals remain: " + repr(sorted(self.pending)))))
        self.after_complete = not failures and not self.pending
        return failures

    def summary(self):
        complete = (self.archive_complete and self.members_complete and self.after_complete
                    and not self.pending)
        return {
            "schema": "hepta.hia.clean-builder-original-source-readback.r1",
            "status": "PASS" if self.operation_complete and self.primary is None
                      and complete and self.usage_after_output is not None else "FAIL",
            "scope": "EXACT_R13_ORIGINAL_SOURCE_RECOVERY_ONLY",
            "phase": self.phase, "primary_error": self.primary,
            "secondary_errors": self.secondary,
            "archive_bytes": EXPECTED_ARCHIVE_BYTES,
            "archive_sha256": EXPECTED_ARCHIVE_SHA256,
            "complete_original_archive_and_814_members_retained_and_afterchecked": complete,
            "observed_members": len(self.original_members),
            "observed_files": sum(row["kind"] == "file" for row in self.original_members),
            "observed_directories": sum(row["kind"] == "directory" for row in self.original_members),
            "observed_raw_file_bytes": sum(row.get("bytes", 0) for row in self.original_members),
            "exports": self.exports, "input_count": len(self.inputs),
            "retained_output_count": len(self.outputs),
            "pending_outputs": self.pending,
            "limits": {"aggregate_cpu_seconds": CPU_LIMIT,
                       "full_wall_seconds": WALL_NS / 1e9,
                       "address_space_bytes": AS_LIMIT},
            "usage_after_output": self.usage_after_output,
            "historical_target_results_replayed": False,
            "stored_CAS_bytes_preserved": complete,
            "logical_CAS_decompression_performed": False,
            "original_source_imported": False, "AST_executed": False,
            "source_generation_executed": False, "B3_executed": False,
            "native_target_executed": False, "refs_updated": False,
            "builder_self_rebuild_implemented": False,
            "whole_native_delivery_qualified": False,
        }

    def run(self):
        self.phase = "configuration"
        own = Path(__file__).resolve()
        self.input(own, content_record(own))
        self.input(self.config_path, {"sha256": CONFIG_SHA256, "gitsha": CONFIG_GITSHA})
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        if config["schema"] != "hepta.hia.clean-builder-original-source-inputs.r1":
            raise ValueError("wrong source-recovery input schema")
        if config["archive"] != {
            "name": "hia-native-clean-build-r1-development.tar.xz",
            "bytes": EXPECTED_ARCHIVE_BYTES, "sha256": EXPECTED_ARCHIVE_SHA256,
            "members": EXPECTED_MEMBERS, "files": EXPECTED_FILES,
            "directories": EXPECTED_DIRECTORIES, "raw_file_bytes": EXPECTED_RAW_BYTES
        }:
            raise ValueError("original archive constants differ")
        if config["limits"] != {"aggregate_cpu_seconds": CPU_LIMIT,
                "full_wall_seconds": 180, "address_space_bytes": AS_LIMIT}:
            raise ValueError("original reader limits differ")
        self.copy(own, self.out / "reader-source.py", self.inputs[str(own)])
        self.copy(self.config_path, self.out / "original-inputs.json",
                  self.inputs[str(self.config_path)])
        meta = self.out / "originals"
        meta.mkdir()
        for row in config["metadata"]:
            relative = safe_relative(row["path"])
            source = self.repo / relative
            self.input(source, row)
            target = meta / (row["name"] + ".json")
            self.copy(source, target, row)
            self.original_metadata[row["name"]] = json.loads(target.read_text(encoding="utf-8"))
        custody = self.original_metadata["custody"]
        handoff = self.original_metadata["handoff"]
        if (custody["status"] != "ALL_MEMBERS_EXACT_READBACK"
                or custody["member_count"] != EXPECTED_MEMBERS
                or custody["file_count"] != EXPECTED_FILES
                or custody["raw_file_bytes"] != EXPECTED_RAW_BYTES
                or custody["archive_bytes"] != EXPECTED_ARCHIVE_BYTES
                or custody["archive_sha256"] != EXPECTED_ARCHIVE_SHA256
                or handoff["archive_bytes"] != EXPECTED_ARCHIVE_BYTES
                or handoff["archive_sha256"] != EXPECTED_ARCHIVE_SHA256):
            raise ValueError("original custody/handoff identity differs")
        expected = {}
        for row in custody["members"]:
            safe_relative(row["path"])
            if row["path"] in expected or row["kind"] not in ("file", "directory"):
                raise ValueError("duplicate or unsupported original member")
            expected[row["path"]] = row
        if (len(expected) != EXPECTED_MEMBERS
                or sum(row["kind"] == "file" for row in expected.values()) != EXPECTED_FILES
                or sum(row["kind"] == "directory" for row in expected.values()) != EXPECTED_DIRECTORIES
                or sum(row.get("bytes", 0) for row in expected.values()) != EXPECTED_RAW_BYTES):
            raise ValueError("complete original member totals differ")
        export_names = [row["path"] for row in config["exports"]]
        if len(export_names) != 21 or len(set(export_names)) != 21:
            raise ValueError("expected exactly 21 original text exports")
        for row in config["exports"]:
            if expected.get(row["path"]) != row:
                raise ValueError("export does not match original custody: " + row["path"])
        parts = config["parts"]
        if len(parts) != 19 or sum(row["bytes"] for row in parts) != EXPECTED_ARCHIVE_BYTES:
            raise ValueError("original 19-part totals differ")
        archive = meta / config["archive"]["name"]
        self.phase = "reconstruct-complete-original-archive"
        self.pending[str(archive)] = {"expected": config["archive"]}
        with archive.open("xb") as target:
            for index, row in enumerate(parts):
                if not row["path"].endswith(".part" + str(index).zfill(3)):
                    raise ValueError("part order differs")
                source = self.repo / safe_relative(row["path"])
                self.input(source, row)
                with source.open("rb") as stream:
                    while True:
                        block = stream.read(CHUNK)
                        if not block:
                            break
                        target.write(block)
                budget()
        os.chmod(archive, 0o644)
        self.register(archive, {"bytes": EXPECTED_ARCHIVE_BYTES,
                      "sha256": EXPECTED_ARCHIVE_SHA256, "mode": 0o644})
        self.archive_complete = True
        self.phase = "complete-original-members"
        restored = self.out / "restored"
        restored.mkdir()
        seen = set()
        original_dirs = []
        with tarfile.open(archive, mode="r|xz") as stream:
            for member in stream:
                name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                relative = safe_relative(name)
                if name not in expected or name in seen:
                    raise ValueError("unexpected or duplicate original tar member: " + name)
                row = expected[name]
                if member.mode != row["mode"]:
                    raise ValueError("original tar member mode differs: " + name)
                if member.isdir():
                    if row["kind"] != "directory" or member.size != 0:
                        raise ValueError("directory kind/size differs: " + name)
                    path = restored / relative
                    path.mkdir(parents=True, exist_ok=True)
                    original_dirs.append((path, row["mode"]))
                    observed = {"path": name, "kind": "directory", "mode": row["mode"]}
                elif member.isfile() and not member.issparse():
                    if row["kind"] != "file" or member.size != row["bytes"]:
                        raise ValueError("file kind/size differs: " + name)
                    path = restored / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    self.pending[str(path)] = {"original_member": name, "expected": row}
                    source = stream.extractfile(member)
                    if source is None:
                        raise ValueError("no original member bytes: " + name)
                    digest = sha256()
                    size = 0
                    with source, path.open("xb") as target:
                        while True:
                            block = source.read(CHUNK)
                            if not block:
                                break
                            size += len(block)
                            if size > row["bytes"]:
                                raise ValueError("oversize original member: " + name)
                            digest.update(block)
                            target.write(block)
                    if size != row["bytes"] or digest.hexdigest() != row["sha256"]:
                        raise ValueError("complete original member hash differs: " + name)
                    os.chmod(path, row["mode"])
                    actual = self.register(path, row)
                    observed = {"path": name, "kind": "file", **actual}
                else:
                    raise ValueError("unsupported original tar type: " + name)
                seen.add(name)
                self.original_members.append(observed)
                budget()
        if seen != set(expected):
            raise ValueError("original archive member set differs")
        for path, mode in sorted(original_dirs, key=lambda item: len(item[0].parts), reverse=True):
            os.chmod(path, mode)
            self.directories[str(path)] = mode
        if (len(self.original_members) != EXPECTED_MEMBERS
                or sum(row.get("bytes", 0) for row in self.original_members) != EXPECTED_RAW_BYTES):
            raise ValueError("observed complete original totals differ")
        self.members_complete = True
        self.phase = "original-text-export"
        for row in config["exports"]:
            path = restored / safe_relative(row["path"])
            actual = content_record(path)
            require_record(actual, row, str(path))
            raw = path.read_bytes()
            # Decode solely to establish a text export; never import or parse its source.
            raw.decode("utf-8", "strict")
            record = {"path": row["path"], **actual}
            self.exports.append(record)
            print("HIA_CLEAN_BUILD_ORIGINAL " + json.dumps(
                {**record, "base64": base64.b64encode(raw).decode("ascii")},
                sort_keys=True, separators=(",", ":")), flush=True)
            budget()
        self.operation_complete = True

    def finish(self):
        self.phase = "unconditional-original-after-check"
        self.attempt("complete-original-after-check", self.verify_after)
        self.attempt("write-input-custody",
            lambda: save_json(self.out / "input-custody.json", self.inputs))
        self.attempt("write-original-member-ledger",
            lambda: save_json(self.out / "original-members.json", self.original_members))
        self.attempt("write-output-custody",
            lambda: save_json(self.out / "retained-output-custody.json", self.outputs))
        self.attempt("write-pending",
            lambda: save_json(self.out / "pending-originals.json", self.pending))
        # Preserve the earliest error independently; later receipt I/O is secondary.
        self.attempt("write-primary-error",
            lambda: save_json(self.out / "primary-error.json", self.primary))
        self.attempt("budget-before-summary", budget)
        self.phase = "final-output"
        self.usage_after_output = self.attempt("measure-before-output", budget)
        self.attempt("write-provisional-summary",
            lambda: save_json(self.out / "summary.json", self.summary()))
        compact = {
            "schema": "hepta.hia.clean-builder-original-source-readback.compact.r1",
            "status": self.summary()["status"], "original_members": len(self.original_members),
            "original_files": sum(row["kind"] == "file" for row in self.original_members),
            "original_raw_bytes": sum(row.get("bytes", 0) for row in self.original_members),
            "exports": len(self.exports),
            "complete_originals": self.summary()["complete_original_archive_and_814_members_retained_and_afterchecked"],
            "target_executions": 0,
            "primary_error": None if self.primary is None else {
                key: self.primary[key] for key in ("stage", "class", "message")}
        }
        self.attempt("compact-stdout",
            lambda: print("HIA_CLEAN_BUILD_ORIGINAL_READBACK " +
                          json.dumps(compact, sort_keys=True), flush=True))
        self.usage_after_output = self.attempt("strict-budget-after-complete-stdout", budget)
        self.attempt("write-final-summary",
            lambda: save_json(self.out / "summary.json", self.summary()))
        self.usage_after_output = self.attempt("strict-budget-after-final-receipt-readback", budget)
        if self.primary is not None:
            # Independent best-effort rewrites must never replace the primary.
            self.attempt("rewrite-failed-summary",
                lambda: save_json(self.out / "summary.json", self.summary()))
            self.attempt("rewrite-primary-error",
                lambda: save_json(self.out / "primary-error.json", self.primary))
            self.attempt("write-secondary-errors",
                lambda: save_json(self.out / "secondary-errors.json", self.secondary))
            self.attempt("strict-final-failure-budget", budget)
            return 1
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, default=Path(__file__).with_name("original-inputs.json"))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (AS_LIMIT, AS_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT, CPU_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, (WALL_NS - (time.monotonic_ns() - START_NS)) / 1e9))
    repo, out, inputs = args.repo.resolve(), args.out.resolve(), args.inputs.resolve()
    if out == repo or out.is_relative_to(repo):
        raise ValueError("source recovery output must be outside the checkout")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("source recovery requires an empty new output directory")
    state = Recovery(repo, out, inputs)
    try:
        state.run()
    except BaseException as exc:
        state.failure(state.phase, exc)
    try:
        return state.finish()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        raise SystemExit(1)
