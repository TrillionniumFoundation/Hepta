#!/usr/bin/env python3
"""Fixed Git merge observation. No product code, compilation or tests run."""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request


REPOSITORY = "TrillionniumFoundation/Hepta"
OURS = "51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8"
THEIRS = "a733926a2786a3d4a37304bd2d18ebb2eac57ac9"
BASES = ("5831f52fada45e076f8f68f198a15c0585e6104f",
         "93d66bcc3acb88212c9b153d7852ba22eeab24c8")
SCOPE = "TEXTUAL_MERGE_REHEARSAL_NOT_QUALIFICATION"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def oid(kind, data):
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def encoded_path(path):
    result = {"path_base64": base64.b64encode(path).decode("ascii")}
    try:
        result["path"] = path.decode("utf-8")
    except UnicodeDecodeError:
        result["path"] = None
    return result


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class Capture:
    def __init__(self, root, token):
        root.mkdir(parents=True, exist_ok=False)
        self.root = root
        self.repo = root / "repository"
        self.evidence = root / "evidence"
        self.raw = self.evidence / "raw"
        self.raw.mkdir(parents=True)
        self.token = token
        self.basic = base64.b64encode(("x-access-token:" + token).encode()).decode("ascii")
        self.commands = []
        self.api_receipts = []
        self.sequence = 0
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("GIT_") and k not in
                    {"HIA_REHEARSAL_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"}}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
                        GIT_MERGE_AUTOEDIT="no", GIT_EDITOR="/usr/bin/true",
                        GIT_PAGER="cat", GIT_ALLOW_PROTOCOL="https",
                        LC_ALL="C.UTF-8", TZ="UTC")

    def put(self, relative, data):
        check(type(data) is bytes, "evidence must be exact bytes")
        for secret in (self.token.encode(), self.basic.encode()):
            check(not secret or secret not in data, "credential appeared in evidence; original withheld")
        destination = self.raw / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            check(destination.read_bytes() == data, "conflicting evidence write: " + relative)
        else:
            destination.write_bytes(data)
            destination.chmod(0o644)
        return {"file": relative, "bytes": len(data), "sha256": sha(data), "blob": oid("blob", data)}

    def json(self, relative, value):
        return self.put(relative, canonical(value))

    def run(self, arguments, *, label, cwd=None, limit=180, allowed=(0,), stdin=None, auth=True, enforce=True):
        self.sequence += 1
        prefix = f"commands/{self.sequence:04d}-{label}"
        environment = dict(self.env)
        if auth:
            environment.update(GIT_CONFIG_COUNT="1",
                               GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                               GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + self.basic)
        started = now()
        clock = time.monotonic_ns()
        process = subprocess.Popen(arguments, cwd=cwd, env=environment,
                                   stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        timed_out = False
        cleanup = []
        try:
            stdout, stderr = process.communicate(stdin, timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                    cleanup.append({"signal": int(sig), "sent": True})
                except ProcessLookupError:
                    cleanup.append({"signal": int(sig), "already_exited": True})
                try:
                    stdout, stderr = process.communicate(timeout=3)
                    break
                except subprocess.TimeoutExpired:
                    cleanup.append({"signal": int(sig), "wait_expired": True})
            else:
                self.json(prefix + ".unreaped.json", {"pid": process.pid, "cleanup": cleanup})
                raise RuntimeError("bounded Git command cleanup incomplete")
        record = {"argv": arguments, "cwd": str(cwd) if cwd else None,
                  "started_at": started, "finished_at": now(), "limit_seconds": limit,
                  "elapsed_ns": time.monotonic_ns() - clock,
                  "returncode": process.returncode, "timed_out": timed_out,
                  "cleanup": cleanup, "stdout": self.put(prefix + ".stdout", stdout),
                  "stderr": self.put(prefix + ".stderr", stderr)}
        if stdin is not None:
            record["stdin"] = self.put(prefix + ".stdin", stdin)
        self.commands.append(record)
        self.json(prefix + ".json", record)
        print(f"captured {label}: rc={process.returncode}, timeout={timed_out}", flush=True)
        if enforce:
            check(not timed_out, "Git command exceeded its observation limit: " + label)
            check(process.returncode in allowed, "unexpected Git return code: " + label)
        return stdout, record

    def git(self, arguments, **kwargs):
        return self.run(["git", *arguments], cwd=self.repo, **kwargs)

    def object(self, kind, object_id, label):
        data, _ = self.git(["cat-file", kind, object_id], label=label)
        check(oid(kind, data) == object_id, "Git object byte identity mismatch: " + object_id)
        return self.put("objects/" + object_id + "." + kind, data)

    def tree(self, commit, expected=None, count=None, label="tree"):
        tree, _ = self.git(["rev-parse", commit + "^{tree}"], label=label + "-identity")
        tree = tree.strip().decode("ascii")
        check(re.fullmatch("[0-9a-f]{40}", tree), "invalid tree object identity")
        if expected is not None:
            check(tree == expected, "fixed source tree differs")
        raw, _ = self.git(["ls-tree", "-r", "-t", "-z", "--full-tree", commit], label=label + "-inventory")
        entries = {}
        for item in raw.split(b"\0"):
            if not item:
                continue
            header, path = item.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split()
            check(path and not path.startswith(b"/") and b".." not in path.split(b"/"), "unsafe tree path")
            check(path not in entries, "duplicate tree path")
            entries[path] = {"mode": mode, "type": kind, "oid": object_id}
        children = {}
        for path, entry in entries.items():
            parent, _, name = path.rpartition(b"/")
            children.setdefault(parent, []).append((name, entry))
        for path, entry in [(b"", {"type": "tree", "oid": tree}), *entries.items()]:
            if entry["type"] != "tree":
                continue
            members = sorted(children.get(path, []), key=lambda pair: pair[0] + (b"/" if pair[1]["type"] == "tree" else b""))
            payload = b"".join((member["mode"].lstrip("0") or "0").encode("ascii") + b" " + name + b"\0" + bytes.fromhex(member["oid"])
                               for name, member in members)
            check(oid("tree", payload) == entry["oid"], "complete tree reconstruction mismatch")
        leaves = {p: v for p, v in entries.items() if v["type"] != "tree"}
        if count is not None:
            check(len(leaves) == count, "source file count differs")
        self.json("sources/" + label + ".json", {"commit": commit, "tree": tree,
                  "files": len(leaves), "entries": [{**encoded_path(p), **v} for p, v in sorted(entries.items())],
                  "all_tree_objects_independently_reconstructed": True})
        return leaves

    def source_archive(self, leaves, expected_bytes):
        temporary = self.root / "main-source-original.tar"
        self.git(["archive", "--format=tar", "--output=" + str(temporary), OURS], label="export-exact-main")
        target = self.evidence / "MAIN-51BC-SOURCE.tar.gz"
        original = hashlib.sha256()
        extent = 0
        with temporary.open("rb") as source, target.open("xb") as sink:
            with gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0) as compressed:
                while block := source.read(1024 * 1024):
                    original.update(block)
                    extent += len(block)
                    compressed.write(block)
        restored = hashlib.sha256()
        with gzip.open(target, "rb") as source:
            while block := source.read(1024 * 1024):
                restored.update(block)
        check(original.digest() == restored.digest(), "lossless main tar gzip mismatch")
        observed, total, members = set(), 0, []
        with tarfile.open(target, "r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                path = member.name.encode("utf-8", "surrogateescape")
                check(path in leaves and path not in observed, "unexpected or duplicate main archive member")
                expected = leaves[path]
                if member.isfile():
                    data = archive.extractfile(member).read()
                    mode = "100755" if member.mode & 0o111 else "100644"
                elif member.issym():
                    data = member.linkname.encode("utf-8", "surrogateescape")
                    mode = "120000"
                else:
                    raise RuntimeError("unsupported main source archive member type")
                check(expected["type"] == "blob" and mode == expected["mode"] and oid("blob", data) == expected["oid"], "main archive byte/mode mismatch")
                observed.add(path)
                total += len(data)
                members.append({**encoded_path(path), "mode": mode, "bytes": len(data), "sha256": sha(data), "blob": expected["oid"]})
        check(observed == set(leaves) and total == expected_bytes, "main archive extent differs")
        member_receipt = self.json("sources/MAIN-ARCHIVE-MEMBERS.json", members)
        receipt = {"commit": OURS, "files": len(observed), "raw_file_bytes": total,
                   "original_tar_bytes": extent, "original_tar_sha256": original.hexdigest(),
                   "gzip_file": target.name, "gzip_bytes": target.stat().st_size,
                   "gzip_sha256": file_sha(target), "all_paths_modes_git_blobs_verified": True,
                   "member_manifest": member_receipt,
                   "custody": "Complete separate Actions artifact member; not included in the raw rehearsal chunk archive"}
        self.json("sources/MAIN-ARCHIVE-VERIFICATION.json", receipt)
        temporary.unlink()
        return receipt

    def index(self):
        raw, _ = self.git(["ls-files", "--stage", "-z"], label="index-all-stages")
        entries = []
        for item in raw.split(b"\0"):
            if item:
                header, path = item.split(b"\t", 1)
                mode, object_id, stage = header.decode("ascii").split()
                check(stage in ("0", "1", "2", "3"), "invalid index stage")
                entries.append((path, {"mode": mode, "oid": object_id, "stage": int(stage)}))
        self.json("merge/INDEX.json", [{**encoded_path(p), **v} for p, v in entries])
        self.put("merge/INDEX.raw", (self.repo / ".git" / "index").read_bytes())
        return entries

    def worktree(self, conflict_paths, extra_paths, stage0):
        result = []
        root = os.fsencode(self.repo)
        for directory, dirs, files in os.walk(root, followlinks=False):
            if directory == root:
                dirs[:] = [name for name in dirs if name != b".git"]
            links = [name for name in dirs if os.path.islink(os.path.join(directory, name))]
            dirs[:] = [name for name in dirs if name not in links]
            for name in sorted(files + links):
                absolute = os.path.join(directory, name)
                path = os.path.relpath(absolute, root)
                info = os.lstat(absolute)
                if stat.S_ISLNK(info.st_mode):
                    data, mode = os.readlink(absolute), "120000"
                else:
                    check(stat.S_ISREG(info.st_mode), "nonordinary worktree file")
                    with open(absolute, "rb") as stream:
                        data = stream.read()
                    mode = "100755" if info.st_mode & 0o111 else "100644"
                entry = {**encoded_path(path), "mode": mode, "bytes": len(data),
                         "sha256": sha(data), "oid": oid("blob", data)}
                indexed = stage0.get(path)
                entry["matches_stage0"] = indexed is not None and (mode, entry["oid"]) == (indexed["mode"], indexed["oid"])
                if path in conflict_paths or path in extra_paths or not entry["matches_stage0"]:
                    entry["retained_bytes"] = self.put("worktree/" + entry["oid"] + ".blob", data)
                result.append(entry)
        self.json("merge/WORKTREE.json", result)
        return result

    def api(self, method, suffix, body=None):
        check((method == "POST" and suffix == "") or
              (method == "GET" and re.fullmatch("/[0-9a-f]{40}", suffix)), "unapproved API mutation")
        payload = canonical(body) if body is not None else None
        request = urllib.request.Request("https://api.github.com/repos/" + REPOSITORY + "/git/blobs" + suffix,
                    data=payload, method=method,
                    headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                             "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
        receipt = {"method": method, "blob_suffix": suffix, "started_at": now(),
                   "request_body_sha256": sha(payload) if payload is not None else None}
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
                data = response.read()
                receipt.update(status=response.status, response_bytes=len(data), response_sha256=sha(data))
            return json.loads(data)
        except urllib.error.HTTPError as error:
            data = error.read()
            receipt.update(status=error.code, error_body_base64=base64.b64encode(data).decode("ascii"))
            raise
        finally:
            receipt["finished_at"] = now()
            self.api_receipts.append(receipt)
            (self.evidence / "API-RECEIPTS.json").write_bytes(canonical(self.api_receipts))

    def upload_blob(self, data):
        expected = oid("blob", data)
        created = self.api("POST", "", {"encoding": "base64", "content": base64.b64encode(data).decode("ascii")})
        check(created.get("sha") == expected, "immutable blob create ACK differs")
        fetched = self.api("GET", "/" + expected)
        check(fetched.get("sha") == expected and fetched.get("encoding") == "base64"
              and type(fetched.get("size")) is int and fetched["size"] == len(data), "blob GET identity differs")
        returned = base64.b64decode("".join(fetched["content"].split()), validate=True)
        check(returned == data and oid("blob", returned) == expected, "full blob readback differs")
        return {"blob": expected, "bytes": len(data), "sha256": sha(data), "full_readback_equal": True}

    def package(self, chunk_bytes):
        files = sorted(p for p in self.raw.rglob("*") if p.is_file())
        manifest = [{"path": p.relative_to(self.raw).as_posix(), "bytes": p.stat().st_size,
                     "mode": stat.S_IMODE(p.stat().st_mode), "sha256": sha(p.read_bytes())} for p in files]
        self.json("RAW-MANIFEST.json", {"files": manifest})
        files = sorted(p for p in self.raw.rglob("*") if p.is_file())
        target = self.evidence / "COMPLETE-REHEARSAL.tar.gz"
        with target.open("xb") as sink:
            with gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|") as archive:
                    for path in files:
                        data = path.read_bytes()
                        info = tarfile.TarInfo(path.relative_to(self.raw).as_posix())
                        info.size, info.mode, info.mtime = len(data), 0o644, 0
                        archive.addfile(info, io.BytesIO(data))
        expected = {p.relative_to(self.raw).as_posix(): p for p in files}
        with tarfile.open(target, "r:gz") as archive:
            actual = set()
            for member in archive:
                check(member.isfile() and member.name not in actual, "invalid raw archive member")
                check(member.name in expected, "unexpected raw archive member")
                check(member.mode == 0o644 and archive.extractfile(member).read() == expected[member.name].read_bytes(), "raw member bytes or mode differ")
                actual.add(member.name)
            check(actual == set(expected), "complete raw archive membership differs")
        with gzip.open(target, "rb") as stream:
            while stream.read(1024 * 1024):
                pass
        archive_hash = file_sha(target)
        total = target.stat().st_size
        parts = []
        index = {"schema": "hepta.textual-merge-lossless-custody.v1", "scope": SCOPE,
                 "archive": {"file": target.name, "bytes": total, "sha256": archive_hash},
                 "logical_files": len(files), "parts": parts, "complete": False}
        (self.evidence / "CUSTODY-INDEX.json").write_bytes(canonical(index))
        with target.open("rb") as stream:
            offset = 0
            while block := stream.read(chunk_bytes):
                wrapper = {"schema": "hepta.lossless-binary-chunk.v1", "archive_sha256": archive_hash,
                           "index": len(parts), "offset": offset, "bytes": len(block),
                           "sha256": sha(block), "data_base64": base64.b64encode(block).decode("ascii")}
                receipt = self.upload_blob(canonical(wrapper))
                parts.append({"index": len(parts), "offset": offset, "bytes": len(block),
                              "sha256": sha(block), "wrapper": receipt})
                offset += len(block)
                (self.evidence / "CUSTODY-INDEX.json").write_bytes(canonical(index))
        check(offset == total, "archive upload extent mismatch")
        index["complete"] = True
        data = canonical(index)
        (self.evidence / "CUSTODY-INDEX.json").write_bytes(data)
        receipt = self.upload_blob(data)
        (self.evidence / "CUSTODY-INDEX-RECEIPT.json").write_bytes(canonical(receipt))
        print("IMMUTABLE_CUSTODY_INDEX=" + json.dumps(receipt, sort_keys=True), flush=True)
        return receipt


def verify_harness(capture, inputs):
    root = Path(__file__).resolve().parent.parent
    head, _ = capture.run(["git", "-C", str(root), "rev-parse", "HEAD"], label="harness-head", auth=False)
    head = head.strip().decode("ascii")
    check(head == os.environ["GITHUB_SHA"], "checked out harness differs from triggered commit")
    check(os.environ["GITHUB_REF"] == "refs/heads/" + inputs["branch"], "unexpected triggering ref")
    commit, _ = capture.run(["git", "-C", str(root), "cat-file", "commit", head], label="harness-commit", auth=False)
    check(oid("commit", commit) == head, "harness commit raw bytes differ")
    headers = commit.split(b"\n\n", 1)[0].splitlines()
    check([line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")] == [inputs["harness_parent"]], "harness parent differs")
    raw, _ = capture.run(["git", "-C", str(root), "ls-tree", "-r", "-z", "--full-tree", "HEAD"], label="harness-files", auth=False)
    expected = {"tools/rehearse_fixed_merge.py", "inputs/FIXED-INPUTS.json", "README.md", ".github/workflows/textual-merge-rehearsal.yml"}
    observed = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        header, path = item.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split()
        path = path.decode("utf-8")
        check(path in expected and path not in observed and mode == "100644" and kind == "blob", "harness tree must contain exactly four ordinary files")
        data = (root / path).read_bytes()
        check(oid("blob", data) == object_id, "harness worktree differs from its committed bytes")
        capture.put("harness/committed/" + path, data)
        observed.add(path)
    check(observed == expected, "incomplete harness file set")


def observe(capture, inputs):
    check(platform.system() == "Linux" and platform.machine() == "x86_64", "unexpected execution platform")
    os_release = Path("/etc/os-release").read_text()
    check('ID=ubuntu' in os_release and 'VERSION_ID="24.04"' in os_release, "expected actual Ubuntu 24.04")
    capture.put("environment/os-release", os_release.encode())
    capture.json("environment/runtime.json", {"python": sys.version, "platform": platform.platform(),
                 "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                 "harness_sha": os.environ.get("GITHUB_SHA"), "scope": SCOPE})
    capture.run(["git", "--version"], label="git-version", auth=False)
    verify_harness(capture, inputs)
    capture.repo.mkdir()
    empty_hooks = capture.root / "empty-hooks"
    empty_hooks.mkdir()
    capture.git(["init", "--template=" + str(empty_hooks)], label="initialize-temporary-repository", auth=False)
    for key, value in [("core.hooksPath", str(empty_hooks)), ("core.autocrlf", "false"),
                       ("core.attributesFile", os.devnull),
                       ("core.fileMode", "true"), ("core.fsmonitor", "false"),
                       ("rerere.enabled", "false"), ("rerere.autoupdate", "false"),
                       ("merge.autoStash", "false"), ("credential.helper", ""),
                       ("user.name", "HIA textual merge rehearsal"),
                       ("user.email", "noreply@users.noreply.github.com")]:
        capture.git(["config", "--local", key, value], label="isolated-config-" + key.replace(".", "-"), auth=False)
    capture.git(["remote", "add", "origin", "https://github.com/" + REPOSITORY + ".git"], label="fixed-read-remote", auth=False)
    capture.git(["config", "--local", "remote.origin.promisor", "true"], label="promisor-remote", auth=False)
    capture.git(["config", "--local", "remote.origin.partialclonefilter", "blob:none"], label="partial-clone-filter", auth=False)
    config, _ = capture.git(["config", "--local", "--list", "--show-origin"], label="sanitized-local-config", auth=False)
    check(not re.search(rb"(?:merge\..*\.driver|filter\..*\.(?:clean|smudge|process))=", config), "external Git driver present")
    capture.git(["fetch", "--filter=blob:none", "--no-tags", "--no-recurse-submodules", "origin", OURS, THEIRS], label="fetch-two-fixed-histories", limit=inputs["command_limits_seconds"]["fetch"])
    sources = {}
    for label in ("ours", "theirs"):
        record = inputs[label]
        capture.object("commit", record["commit"], "original-commit-" + label)
        sources[label] = capture.tree(record["commit"], record["tree"], record["files"], label)
    bases, _ = capture.git(["merge-base", "--all", OURS, THEIRS], label="actual-merge-bases")
    actual_bases = bases.decode("ascii").splitlines()
    check(len(actual_bases) == len(BASES) and set(actual_bases) == set(BASES), "actual best merge bases differ from fixed input")
    for base in BASES:
        label = "base-" + base
        capture.object("commit", base, "original-commit-" + label)
        sources[label] = capture.tree(base, label=label)
    capture.git(["checkout", "--detach", OURS], label="checkout-fixed-main", limit=180)
    clean, _ = capture.git(["status", "--porcelain=v2", "-z", "--untracked-files=all"], label="before-clean-status")
    check(clean == b"", "initial fixed-main checkout not clean")
    export = capture.source_archive(sources["ours"], inputs["ours"]["raw_file_bytes"])
    capture.put("merge/INDEX.before.raw", (capture.repo / ".git" / "index").read_bytes())
    _, merge = capture.git(["merge", "--no-commit", "--no-ff", THEIRS], label="textual-merge", limit=inputs["command_limits_seconds"]["merge"], allowed=(0, 1), enforce=False)
    head, _ = capture.git(["rev-parse", "HEAD"], label="unchanged-detached-head")
    check(head.strip().decode("ascii") == OURS, "rehearsal unexpectedly created a merge commit")
    for name in ("HEAD", "ORIG_HEAD", "MERGE_HEAD", "MERGE_MODE", "MERGE_MSG", "AUTO_MERGE", "config"):
        path = capture.repo / ".git" / name
        if path.is_file():
            capture.put("merge/git-" + name, path.read_bytes())
    entries = capture.index()
    unmerged = [(p, v) for p, v in entries if v["stage"] != 0]
    conflicts = {p for p, _ in unmerged}
    expected_merge_outcome = not merge["timed_out"] and merge["returncode"] in (0, 1) and ((merge["returncode"] == 1) == bool(conflicts))
    for arguments, label in [(["ls-files", "--unmerged", "-z"], "index-conflict-stages"),
                              (["status", "--porcelain=v2", "-z", "--untracked-files=all"], "merge-status"),
                              (["diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", OURS], "staged-raw-delta"),
                              (["diff", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv"], "worktree-raw-delta"),
                              (["diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", OURS], "staged-binary-patch"),
                              (["diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv"], "unstaged-binary-patch"),
                              (["diff", "--cc", "--binary", "--full-index", "--no-ext-diff", "--no-textconv"], "combined-conflict-patch")]:
        capture.git(arguments, label=label)
    objects = set()
    for _, value in unmerged:
        key = ("commit" if value["mode"] == "160000" else "blob", value["oid"])
        if key not in objects:
            capture.object(*key, label="conflict-object-" + str(len(objects)))
            objects.add(key)
    automatic = []
    stage0 = {p: v for p, v in entries if v["stage"] == 0}
    input_object_ids = {v["oid"] for source in sources.values() for v in source.values()}
    for path, value in sorted(stage0.items()):
        before = sources["ours"].get(path)
        changed = before is None or (before["mode"], before["oid"]) != (value["mode"], value["oid"])
        record = {**encoded_path(path), **value, "changed_from_main": changed,
                  "semantic_qualification": False,
                  "matches_at_same_path": [name for name, source in sources.items() if path in source
                       and (source[path]["mode"], source[path]["oid"]) == (value["mode"], value["oid"])]}
        if changed and value["oid"] not in input_object_ids:
            kind = "commit" if value["mode"] == "160000" else "blob"
            record["retained_new_object"] = capture.object(kind, value["oid"], label="auto-object-" + str(len(automatic)))
        automatic.append(record)
    deleted = sorted(set(sources["ours"]) - set(stage0) - conflicts)
    capture.json("merge/AUTOMERGED-STAGE0.json", {"paths": automatic, "deleted_from_main": [encoded_path(p) for p in deleted], "semantic_qualification": False})
    all_paths, _ = capture.git(["ls-files", "--others", "--exclude-standard", "-z"], label="merge-untracked-paths")
    extra = {p for p in all_paths.split(b"\0") if p}
    worktree = capture.worktree(conflicts, extra, stage0)
    capture.json("merge/CONFLICT-PATHS.json", [{**encoded_path(p), "stages": [v for q, v in unmerged if q == p],
                   "worktree_present": any(base64.b64decode(v["path_base64"]) == p for v in worktree)} for p in sorted(conflicts)])
    auto, _ = capture.git(["rev-parse", "--verify", "AUTO_MERGE^{tree}"], label="auto-merge-tree-identity", allowed=(0, 128, 1))
    if re.fullmatch(rb"[0-9a-f]{40}\n", auto):
        capture.tree(auto.strip().decode("ascii"), label="auto-merge-worktree-tree")
    for label in ("ours", "theirs"):
        record = inputs[label]
        final, _ = capture.git(["rev-parse", record["commit"] + "^{tree}"], label="final-source-identity-" + label)
        check(final.strip().decode("ascii") == record["tree"], "fixed source tree changed")
    return {"scope": SCOPE, "capture_status": ("COMPLETE_WITH_CONFLICTS" if conflicts else "COMPLETE_WITHOUT_CONFLICTS") if expected_merge_outcome else "FAILED_MERGE_OBSERVATION",
            "expected_merge_outcome": expected_merge_outcome,
            "merge_returncode": merge["returncode"], "conflict_paths": len(conflicts), "conflict_stages": len(unmerged),
            "stage0_paths": len(stage0), "automatic_changed_paths": sum(v["changed_from_main"] for v in automatic),
            "deleted_paths": len(deleted), "extra_worktree_paths": len(extra),
            "main_source_archive": export, "semantic_qualification": False,
            "product_execution": False, "product_ref_changed": False,
            "source_commits": {"ours": OURS, "theirs": THEIRS, "merge_bases": list(BASES)},
            "actual_merge_base_order": actual_bases,
            "multiple_base_strategy": "Unmodified git merge handles the two best bases; no single ancestor is forced"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.pop("HIA_REHEARSAL_TOKEN", "")
    check(token, "missing fixed repository evidence token")
    capture = Capture(args.root, token)
    report = {"scope": SCOPE, "capture_status": "FAILED", "semantic_qualification": False}
    exit_code = 1
    try:
        input_bytes = args.inputs.read_bytes()
        driver_bytes = Path(__file__).read_bytes()
        check(sha(input_bytes) == os.environ["EXPECTED_INPUTS_SHA256"], "frozen inputs changed")
        check(sha(driver_bytes) == os.environ["EXPECTED_DRIVER_SHA256"], "frozen driver changed")
        capture.put("harness/FIXED-INPUTS.json", input_bytes)
        capture.put("harness/rehearse_fixed_merge.py", driver_bytes)
        inputs = json.loads(input_bytes)
        check(inputs["repository"] == REPOSITORY and inputs["scope"] == SCOPE
              and inputs["ours"]["commit"] == OURS and inputs["theirs"]["commit"] == THEIRS
              and inputs["expected_merge_bases"] == list(BASES)
              and inputs["export_exact_main_archive"] is True, "fixed input contract differs")
        report = observe(capture, inputs)
        exit_code = 0 if report["expected_merge_outcome"] else 1
    except BaseException:
        report["exception"] = traceback.format_exc()
    finally:
        report["finished_at"] = now()
        report["commands"] = capture.commands
        capture.json("REPORT.json", report)
        (capture.evidence / "REPORT.json").write_bytes(canonical(report))
        try:
            report_receipt = capture.upload_blob(canonical(report))
            (capture.evidence / "REPORT-BLOB.json").write_bytes(canonical(report_receipt))
            custody = capture.package(524288)
            print("REHEARSAL_REPORT=" + json.dumps(report_receipt, sort_keys=True), flush=True)
            print("REHEARSAL_SCOPE=" + SCOPE, flush=True)
            print("CAPTURE_STATUS=" + report["capture_status"], flush=True)
            check(custody["full_readback_equal"], "custody incomplete")
        except BaseException:
            (capture.evidence / "PERSISTENCE-FAILURE.txt").write_text(traceback.format_exc())
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
