"""One exact CLI source overlay and owned Python 3.14.4 DEVELOPMENT suite.

All eleven immutable downloads are verified before any candidate source edit.
Only the separately prepared CLI source copy is changed. The immutable e09
baseline, wire candidate and old qualification sources are never edited.
"""
from __future__ import annotations
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import ssl
import stat
import subprocess
import sys
import time
import traceback
import urllib.request

BASE = Path("/home/qian-qi/he26v66devr2")
ROOT = BASE / "cli/run-r4-r1"
SOURCE = BASE / "cli/s"
BASELINE = BASE / "s"
PYTHON = Path("/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python")
PYTHON_SHA = "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
B3 = BASE / "inputs/B3.image.bin"
B3_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
HEAD = "2963cfbffffd9c2d1e87dafbb82466c0daf21615"
TREE = "3e22e800f7dce50e0731736732715f33cc09ba3f"
BASE_HEAD = "e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6"
BASE_TREE = "bfcbb39e22371cbb2292c89a2fa1ca010353a56f"
BASE_MANIFEST = BASE / "inputs/canonical-e09-development-package.json"
BASE_MANIFEST_SHA = "7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af"
PREPARATION_SHA = "51eabb5fd13572cf981c70cf60b1da1ade05b389651350c031ad715aa798b6dd"
PREPARATION_GUARD_SHA = "8e9ffe07b423f20538efea124f7e1666e6ed8823bd0076ec985eaf4a4be2f060"
OLD_PINS_SHA = "abff0927d89f94bfdac0d600315e45dca0ceb719b7d3c28c0af17a7e270c1ffc"
MANIFEST = ROOT / "control/source-pins.json"
FILES = (
    "hepta/cli.py", "hepta/hia_cli_native.py", "tools/build_hia_cli_native.py",
    "tools/generate_hia_cli_control.py", "tools/hia_cli_control_phases.py",
    "tools/generate_hia_cli_format.py", "tools/hia_cli_unicode_tables.json",
    "examples/hia_bootstrap/cli_control.hiaasm", "examples/hia_bootstrap/cli_format.hiaasm",
    "tests/test_hia_cli_native.py",
    "experiments/hia_cli_control_recovery_20261111/run_complete_development.py",
)
os.umask(0o077)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_regular(path, digest=None, *, maximum=8 << 20, mode=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= maximum,
                "not a bounded private regular file: " + str(path))
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, "file mode differs")
        raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                "file changed while reading")
    require(identity(path.lstat()) == identity(before), "file pathname changed while reading")
    actual = sha256(raw).hexdigest()
    require(digest is None or actual == digest, "file SHA-256 differs: " + str(path))
    return raw, {"path": str(path), "bytes": len(raw), "sha256": actual,
                 "identity": list(identity(before)), "mode": stat.S_IMODE(before.st_mode)}


def create(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    check, _ = read_regular(path, sha256(raw).hexdigest(), maximum=max(8 << 20, len(raw)), mode=mode)
    require(check == raw, "created file readback differs")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def save(report):
    temporary = ROOT / "report.next.json"
    create(temporary, wire(report), 0o600)
    os.replace(temporary, ROOT / "report.json")
    sync_directory(ROOT)


def safe_name(name):
    require(type(name) is str and name and "\0" not in name and "\\" not in name,
            "invalid relative source path")
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and
            all(part not in ("", ".", "..", ".git") for part in p.parts),
            "noncanonical relative source path")
    return name


def directories(rows):
    return {str(parent) for name in rows for parent in PurePosixPath(name).parents
            if str(parent) != "."}


def scan(root, rows, label, readonly=False):
    found, dirs = set(), set()
    directory_mode = 0o500 if readonly else 0o700
    for folder, children, files in os.walk(root, followlinks=False):
        p = Path(folder)
        status = p.lstat()
        require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid()
                and stat.S_IMODE(status.st_mode) == directory_mode,
                "source directory ownership/mode differs: " + str(p))
        if p != root:
            dirs.add(p.relative_to(root).as_posix())
        for name in children + files:
            child = p / name
            st = child.lstat()
            require(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode),
                    "source contains link or special node: " + str(child))
        found.update((p / name).relative_to(root).as_posix() for name in files)
    require(found == set(rows) and dirs == directories(rows), "source membership differs: " + label)
    records = {}
    for name, row in sorted(rows.items()):
        mode = int(row["mode"], 8) & 0o777
        if readonly:
            mode &= ~0o222
        raw, record = read_regular(root / name, row["sha256"], maximum=max(8 << 20, row["size"]), mode=mode)
        require(len(raw) == row["size"] and
                sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob_sha1"],
                "source Git blob differs: " + name)
        records[name] = record
    receipt = ROOT / "receipts" / (label + ".json")
    create(receipt, wire(records))
    return {"path": str(receipt), "sha256": sha256(receipt.read_bytes()).hexdigest(),
            "files": len(records), "directories": len(dirs), "records": records}


def same_bytes_and_modes(a, b):
    return set(a) == set(b) and all((a[n]["bytes"], a[n]["sha256"], a[n]["mode"]) ==
                                   (b[n]["bytes"], b[n]["sha256"], b[n]["mode"]) for n in a)


def natural_guardian(value):
    x = value.get("lifecycle", {})
    cleanup = x.get("cleanup", {})
    return (value.get("status") == "EXTERNAL_OWNED_PROCESS_COMPLETED"
            and value.get("input_identity_preserved") is True
            and x.get("status") == "OWNED_PROCESS_COMPLETED" and x.get("returncode") == 0
            and x.get("exit_observed_before_deadline") is True and x.get("timed_out") is False
            and not x.get("interrupted_signals") and not x.get("owner_error")
            and not x.get("event_overflow") and bool(x.get("events"))
            and all(e.get("kind") in {"qualification_started", "owned_child_observed",
                                     "qualification_exit_observed", "owned_child_reaped"} for e in x["events"])
            and cleanup.get("attempted") is True and cleanup.get("complete") is True
            and cleanup.get("leader_reaped") is True and cleanup.get("observed_echild") is True
            and not cleanup.get("errors") and not cleanup.get("remaining")
            and not cleanup.get("deadline_exceeded"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("fixed source download redirected")


def download(row, deadline):
    name = safe_name(row["path"])
    url = "https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/" + HEAD + "/" + name
    target = ROOT / "downloads" / ("%02d.bin" % FILES.index(name))
    partial = target.with_suffix(".partial")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
                                                   "User-Agent": "hia-explicit-cli-development"}, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    require(time.monotonic() < deadline, "absolute ingress deadline elapsed")
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    total = 0
    digest = sha256()
    git = sha1(b"blob " + str(row["bytes"]).encode() + b"\0")
    with os.fdopen(fd, "wb") as stream:
        with opener.open(request, timeout=30) as response:
            require(response.status == 200 and response.geturl() == url,
                    "fixed source response status/URL differs")
            require(response.headers.get("Content-Encoding", "identity") in ("", "identity"),
                    "encoded source response refused")
            length = response.headers.get("Content-Length")
            require(length is None or length == str(row["bytes"]), "source response length differs")
            while True:
                require(time.monotonic() < deadline, "absolute ingress deadline elapsed")
                part = response.read1(min(65536, row["bytes"] + 1 - total))
                if not part:
                    break
                total += len(part)
                require(total <= row["bytes"], "source download exceeded pinned size")
                stream.write(part)
                digest.update(part)
                git.update(part)
        require(time.monotonic() < deadline, "absolute ingress deadline elapsed")
        require(total == row["bytes"] and digest.hexdigest() == row["sha256"]
                and git.hexdigest() == row["git_blob"], "download identity differs")
        stream.flush()
        os.fsync(stream.fileno())
    os.link(partial, target, follow_symlinks=False)
    os.unlink(partial)
    sync_directory(target.parent)
    raw, record = read_regular(target, row["sha256"], maximum=row["bytes"], mode=0o400)
    require(sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob"],
            "independent download Git blob readback differs")
    return raw, {"source_path": name, "url": url, "readback": record}


def parent_fd(name):
    parts = PurePosixPath(safe_name(name)).parts
    fd = os.open(SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in parts[:-1]:
            try:
                os.mkdir(component, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            status = os.fstat(next_fd)
            require(status.st_uid == os.geteuid() and stat.S_IMODE(status.st_mode) == 0o700,
                    "candidate directory ownership/mode differs")
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def install(row, raw, old=None):
    name = safe_name(row["path"])
    fd, leaf = parent_fd(name)
    temporary = leaf + ".hia-pending-2963cfbf"
    try:
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o644, dir_fd=fd)
        with os.fdopen(output, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temp_path = SOURCE / str(PurePosixPath(name).parent) / temporary
        verified, _ = read_regular(temp_path, row["sha256"], maximum=row["bytes"], mode=0o644)
        require(verified == raw, "candidate staged bytes differ")
        if old is None:
            os.link(temporary, leaf, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=fd)
        else:
            current, record = read_regular(SOURCE / name, old["sha256"], mode=0o644)
            require(record["identity"] == old["identity"], "old candidate inode/metadata changed before replacement")
            require(list(identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False))) == old["identity"],
                    "old candidate binding changed before replacement")
            os.replace(temporary, leaf, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        verified, installed = read_regular(SOURCE / name, row["sha256"], maximum=row["bytes"], mode=0o644)
        require(verified == raw, "installed source differs")
        return installed
    finally:
        os.close(fd)


def immutable_inputs():
    old = json.loads(read_regular(BASE / "control/old-input-pins.json", OLD_PINS_SHA)[0])
    require(len(old) == 12, "original old-input pin count differs")
    pins = dict(old)
    pins.update({str(BASE / "preparation.json"): PREPARATION_SHA,
                 str(BASE / "guard/guardian.json"): PREPARATION_GUARD_SHA,
                 str(BASE_MANIFEST): BASE_MANIFEST_SHA, str(B3): B3_SHA,
                 str(PYTHON.resolve()): PYTHON_SHA})
    return {path: read_regular(Path(path), digest, maximum=32 << 20)[1] for path, digest in sorted(pins.items())}


def main():
    report = {"schema": "hia.cli.desktop-overlay-development.v1", "status": "HOLD",
              "source_commit": HEAD, "source_tree": TREE, "source": str(SOURCE),
              "base_commit": BASE_HEAD, "base_tree": BASE_TREE,
              "complete_git_object_closure": False, "checked_global_contract_current": False,
              "scope": "EXPLICIT_DEVELOPMENT_ONLY", "whole_native_delivery_qualified": False,
              "old_r3_observations_reused": False, "tests_started": False,
              "native_profile_expanded": False, "cold_180_second_gate_modified": False,
              "outer_guardian_acceptance_required": True, "downloads": [], "installed": []}
    expected = baseline_before = before = after = None
    started = time.monotonic_ns()
    save(report)
    try:
        require(Path(sys.executable).resolve() == PYTHON.resolve()
                and tuple(sys.version_info[:3]) == (3, 14, 4), "wrong formal Python profile")
        report["python"] = {"version": sys.version, **read_regular(PYTHON.resolve(), PYTHON_SHA, maximum=32 << 20)[1]}
        report["immutable_inputs_before"] = immutable_inputs()
        prepared = json.loads(read_regular(BASE / "preparation.json", PREPARATION_SHA)[0])
        guardian = json.loads(read_regular(BASE / "guard/guardian.json", PREPARATION_GUARD_SHA)[0])
        require(prepared["status"] == "DEVELOPMENT_SOURCE_MATERIALIZED_PENDING_OUTER_GUARDIAN"
                and natural_guardian(guardian), "original source preparation was not naturally closed")
        package = json.loads(read_regular(BASE_MANIFEST, BASE_MANIFEST_SHA)[0])
        require(package["canonical_commit"] == BASE_HEAD and package["canonical_tree"] == BASE_TREE
                and package["member_count"] == 1666 and package["declared_source_count"] == 661
                and package["complete_git_object_closure"] is False,
                "base declared-source package differs")
        base_rows = {safe_name(row["path"]): row for row in package["files"]}
        require(len(base_rows) == 1666, "duplicate base member")
        baseline_before = scan(BASELINE, base_rows, "immutable-baseline-before", True)
        before = scan(SOURCE, base_rows, "candidate-before")
        manifest_raw, report["overlay_manifest"] = read_regular(MANIFEST, mode=0o400)
        overlay = json.loads(manifest_raw)
        require(overlay["source_commit"] == HEAD and overlay["source_tree"] == TREE
                and overlay["base_commit"] == BASE_HEAD and overlay["base_tree"] == BASE_TREE,
                "overlay canonical identity differs")
        rows = overlay["files"]
        require([row["path"] for row in rows] == list(FILES) and len(rows) == 11,
                "exact overlay file set/order differs")
        require(overlay["old_existing_paths"] == [{
            "path": "hepta/cli.py", "bytes": 10605,
            "git_blob": "e81e607dcb052c77e3c1cf9fe946f70109e5d8e9",
            "sha256": "32bd495c8927286005fd6f2eeb224ea6df9752fe15e3ca8a18ce45836c2a0904"}]
                and overlay["all_other_paths_must_be_absent"] is True,
                "permitted replacement differs")
        for row in rows:
            name = safe_name(row["path"])
            require(type(row["bytes"]) is int and 0 < row["bytes"] < 1 << 20,
                    "overlay size outside its fixed bound")
            if name != "hepta/cli.py":
                require(name not in base_rows and not os.path.lexists(SOURCE / name),
                        "new overlay destination already exists")
        report["candidate_before"] = {k: v for k, v in before.items() if k != "records"}
        report["baseline_before"] = {k: v for k, v in baseline_before.items() if k != "records"}
        save(report)
        deadline = time.monotonic() + 240
        raw_files = {}
        for row in rows:
            raw, observation = download(row, deadline)
            raw_files[row["path"]] = raw
            report["downloads"].append(observation)
            save(report)
        report["all_downloads_verified_before_first_source_mutation"] = True
        save(report)
        original, original_record = read_regular(SOURCE / "hepta/cli.py", overlay["old_existing_paths"][0]["sha256"], mode=0o644)
        require(original_record == before["records"]["hepta/cli.py"], "candidate changed after initial scan")
        create(ROOT / "originals/hepta-cli.py", original)
        report["original_cli_backup"] = read_regular(ROOT / "originals/hepta-cli.py", original_record["sha256"])[1]
        for row in rows[1:]:
            report["installed"].append(install(row, raw_files[row["path"]]))
        report["installed"].append(install(rows[0], raw_files["hepta/cli.py"], original_record))
        expected = dict(base_rows)
        for row in rows:
            expected[row["path"]] = {"path": row["path"], "mode": "100644", "size": row["bytes"],
                                     "git_blob_sha1": row["git_blob"], "sha256": row["sha256"]}
        after = scan(SOURCE, expected, "candidate-installed")
        for name, record in before["records"].items():
            if name != "hepta/cli.py":
                require(after["records"][name] == record, "untouched original candidate member changed")
        report["candidate_installed"] = {k: v for k, v in after.items() if k != "records"}
        report["only_eleven_declared_source_paths_changed"] = True
        save(report)
        environment = {"PATH": os.defpath, "HOME": str(ROOT / "home"), "TMPDIR": str(ROOT / "tmp"),
                       "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
        command = [str(PYTHON), "-B", str(SOURCE / FILES[-1]), "--source", str(SOURCE),
                   "--compiler", str(B3), "--output", str(ROOT / "q"), "--source-revision", HEAD]
        report["command"] = command
        report["tests_started"] = True
        save(report)
        with (ROOT / "receipts/suite-launch.stdout.log").open("xb") as stdout, \
             (ROOT / "receipts/suite-launch.stderr.log").open("xb") as stderr:
            process = subprocess.run(command, cwd=SOURCE, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, close_fds=True, timeout=190)
        report["suite_process_returncode"] = process.returncode
        nested = json.loads(read_regular(ROOT / "q/owned-suite.json")[0])
        result = json.loads(read_regular(ROOT / "q/suite.json")[0])
        require(process.returncode == 0 and nested["status"] == "PASS_DEVELOPMENT_ONLY"
                and all(nested["checks"].values()) and nested["source_preserved"] is True
                and nested["compiler_preserved"] is True,
                "owned complete CLI suite did not pass")
        ids = result["loaded_test_ids"]
        require(bool(ids) and len(set(ids)) == len(ids) and result["executed_test_ids"] == ids
                and result["tests_run"] == len(ids) and result["status"] == "PASS_DEVELOPMENT_ONLY"
                and not any(result[key] for key in ("failures", "errors", "skipped",
                           "expected_failures", "unexpected_successes"))
                and any(name.endswith(".test_python_color_environment_precedence_and_colored_wrapping") for name in ids)
                and result["native_returns"], "full CLI ID/color/native denominator not satisfied")
        report["suite"] = {"owned": read_regular(ROOT / "q/owned-suite.json")[1],
                           "result": read_regular(ROOT / "q/suite.json")[1],
                           "tests_run": result["tests_run"], "loaded_test_ids": ids}
        report["status"] = "DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN"
    except BaseException as error:
        report.update(status="HOLD", error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
    finally:
        try:
            report["immutable_inputs_after"] = immutable_inputs()
            require(report["immutable_inputs_before"] == report["immutable_inputs_after"],
                    "immutable preparation/compiler/input identity changed")
            if baseline_before is not None:
                final_baseline = scan(BASELINE, base_rows, "immutable-baseline-after", True)
                require(final_baseline["records"] == baseline_before["records"],
                        "immutable baseline changed")
                report["immutable_baseline_preserved"] = True
                report["baseline_after"] = {k: v for k, v in final_baseline.items() if k != "records"}
            if after is not None:
                final = scan(SOURCE, expected, "candidate-after-suite")
                require(final["records"] == after["records"], "installed candidate changed during product execution")
                report["candidate_source_preserved"] = True
                report["candidate_after"] = {k: v for k, v in final.items() if k != "records"}
        except BaseException as error:
            report["status"] = "HOLD"
            report["final_observation_error"] = {"type": type(error).__name__, "message": str(error),
                                                "traceback": traceback.format_exc()}
        report["elapsed_ns"] = time.monotonic_ns() - started
        save(report)
        print(json.dumps({key: report.get(key) for key in
              ("status", "source_commit", "tests_started", "suite_process_returncode",
               "candidate_source_preserved", "immutable_baseline_preserved", "elapsed_ns")}), flush=True)
    return 0 if report["status"] == "DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
