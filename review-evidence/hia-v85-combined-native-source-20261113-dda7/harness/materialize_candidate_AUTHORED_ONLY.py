#!/usr/bin/env python3
"""Construct and regenerate the fixed HIA candidate; preserve every real result."""
from __future__ import annotations

import argparse
import ast
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
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
OURS = "016f00bbbafddec8112ef6762eb799e83c8e5d00"
THEIRS = "a733926a2786a3d4a37304bd2d18ebb2eac57ac9"
BASES = ("5831f52fada45e076f8f68f198a15c0585e6104f",
         "93d66bcc3acb88212c9b153d7852ba22eeab24c8")
SCOPE = "COMBINED_SOURCE_REGENERATION_AND_SOURCE_TESTS"


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


def materialize_fixed_tree_blobs(capture, sources, limit):
    expected = {}
    for label, tree in sources.items():
        for path, entry in tree.items():
            check(entry["type"] == "blob", "fixed input has an unsupported non-blob leaf")
            expected.setdefault(entry["oid"], []).append({"source": label, **encoded_path(path), "mode": entry["mode"]})
    object_ids = sorted(expected)
    request = ("\n".join(object_ids) + "\n").encode("ascii")

    def local_inventory(label):
        output, _ = capture.git(["--no-lazy-fetch", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                                label=label, stdin=request)
        lines = output.decode("ascii").splitlines()
        check(len(lines) == len(object_ids), "local object inventory extent differs")
        rows = []
        missing = []
        for object_id, line in zip(object_ids, lines, strict=True):
            words = line.split()
            check(words and words[0] == object_id, "local inventory changed requested identity/order")
            if words == [object_id, "missing"]:
                missing.append(object_id)
                rows.append({"oid": object_id, "available": False})
            else:
                check(len(words) == 3 and words[1] == "blob" and words[2].isdigit(), "fixed source object has wrong type/size")
                rows.append({"oid": object_id, "available": True, "type": words[1], "bytes": int(words[2])})
        return rows, missing

    before, missing = local_inventory("fixed-tree-blobs-before")
    if missing:
        capture.git(["-c", "fetch.negotiationAlgorithm=noop", "fetch", "--filter=blob:none", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "origin", "--stdin"],
                    label="prefetch-only-fixed-tree-blobs", limit=limit,
                    stdin=("\n".join(missing) + "\n").encode("ascii"))
    after, absent = local_inventory("fixed-tree-blobs-after")
    capture.json("sources/FIXED-TREE-BLOB-MATERIALIZATION.json", {
        "scope": "Only the four fixed input trees; no full history blob fetch",
        "sources": list(sources), "unique_blobs": len(object_ids),
        "requested_missing_blobs": missing, "remaining_missing_blobs": absent,
        "before": before, "after": after, "source_paths_by_blob": expected})
    check(not absent, "fixed tree source blobs are still missing")

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            check(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def relative_path(value):
    check(type(value) is str, "path must be str")
    path = PurePosixPath(value)
    check(value == str(path) and not path.is_absolute() and path.parts
          and all(p not in ("", ".", "..") for p in path.parts)
          and "\\" not in value and "\0" not in value, "unsafe path")
    return path

def fetch_blob(capture, object_id, cache):
    if object_id in cache:
        return cache[object_id]
    check(re.fullmatch("[0-9a-f]{40}", object_id) is not None, "invalid blob pin")
    if object_id in getattr(capture, "original_oids", set()):
        raw = subprocess.check_output(["git", "--no-lazy-fetch", "cat-file", "blob", object_id],
                                      cwd=capture.repo, env=capture.env, timeout=30)
        check(oid("blob", raw) == object_id, "local original blob bytes differ")
        capture.put("input-blobs/" + object_id + ".blob", raw)
        cache[object_id] = raw
        return raw
    record = capture.api("GET", "/" + object_id)
    check(record["sha"] == object_id and record["encoding"] == "base64", "blob API identity differs")
    raw = base64.b64decode("".join(record["content"].split()), validate=True)
    check(len(raw) == record["size"] and oid("blob", raw) == object_id, "blob bytes differ")
    capture.put("input-blobs/" + object_id + ".blob", raw)
    cache[object_id] = raw
    return raw

def packet_rows(packet, layout):
    if layout == "array-byte":
        return [(r["path"], r["text"], {"bytes": r["bytes"], "git_blob": r["blob"]}, r)
                for r in packet["files"]]
    if layout == "array-identity":
        return [(r["path"], r["text"], r["identity"], r) for r in packet["files"]]
    if layout == "array-after":
        return [(r["path"], r["after"]["text"], r["after"], r) for r in packet["files"]]
    if layout == "object-text-after":
        return [(p, r["text"], r["after"], r) for p, r in packet["files"].items()]
    if layout == "object-after":
        return [(p, r["after"]["text"], r["after"], r) for p, r in packet["files"].items()]
    raise ValueError("unreviewed packet layout " + repr(layout))

def compose(capture, inputs, cache):
    sources = {}
    origins = {}
    observed = []
    for pin in inputs["packets"]:
        raw = fetch_blob(capture, pin["blob"], cache)
        check(len(raw) == pin["bytes"], "packet extent differs: " + pin["label"])
        if "sha256" in pin:
            check(sha(raw) == pin["sha256"], "packet SHA256 differs")
        packet = strict_json(raw)
        rows = packet_rows(packet, pin["layout"])
        check(len(rows) == pin["files"], "packet row count differs")
        seen = set()
        for path, text, meta, original in rows:
            relative_path(path)
            check(path not in seen, "duplicate packet path")
            seen.add(path)
            raw_source = text.encode("utf-8")
            blob = meta.get("git_blob", meta.get("git_blob_sha1"))
            check(len(raw_source) == meta["bytes"] and oid("blob", raw_source) == blob,
                  "authored source identity differs: " + path)
            if "sha256" in meta:
                check(sha(raw_source) == meta["sha256"], "authored SHA256 differs: " + path)
            if path in sources:
                change = {"path": path, "from_packet": origins[path]["packet"],
                          "to_packet": pin["label"], "from": oid("blob", sources[path]), "to": blob}
                check(change in inputs["allowed_overrides"] and change not in observed,
                      "unreviewed source override: " + repr(change))
                observed.append(change)
            sources[path] = raw_source
            origins[path] = {"packet": pin["label"], "blob": blob, "bytes": len(raw_source),
                             "mode": meta.get("mode", original.get("mode", "100644"))}
    check(sorted(observed, key=lambda x:(x["path"],x["from_packet"])) ==
          sorted(inputs["allowed_overrides"], key=lambda x:(x["path"],x["from_packet"])),
          "exact override set differs")
    check(len(sources) == inputs["expected_authored_files"], "authored file count differs")
    capture.json("composition/AUTHORED-SOURCES.json", {"origins": origins, "overrides": observed})
    return sources, origins

def initialize(capture, inputs):
    capture.repo.mkdir()
    hooks = capture.root / "empty-hooks"
    hooks.mkdir()
    capture.git(["init", "--template=" + str(hooks)], label="initialize", auth=False)
    for key, value in (
        ("core.hooksPath", str(hooks)), ("core.autocrlf", "false"),
        ("core.attributesFile", os.devnull), ("core.fileMode", "true"),
        ("core.fsmonitor", "false"), ("rerere.enabled", "false"),
        ("rerere.autoupdate", "false"), ("merge.autoStash", "false"),
        ("credential.helper", ""), ("user.name", "HIA combined source development"),
        ("user.email", "noreply@users.noreply.github.com")):
        capture.git(["config", "--local", key, value], label="config-" + key.replace(".", "-"), auth=False)
    capture.git(["remote", "add", "origin", "https://github.com/" + REPOSITORY + ".git"], label="origin", auth=False)
    capture.git(["config", "--local", "remote.origin.promisor", "true"], label="promisor", auth=False)
    capture.git(["config", "--local", "remote.origin.partialclonefilter", "blob:none"], label="filter", auth=False)
    capture.git(["fetch", "--filter=blob:none", "--no-tags", "--no-recurse-submodules", "origin", OURS, THEIRS],
                label="fetch-fixed-histories", limit=600)
    sources = {}
    for name, commit in (("ours", OURS), ("theirs", THEIRS)):
        pin = inputs[name]
        check(pin["commit"] == commit, "fixed head differs")
        capture.object("commit", commit, "original-commit-" + name)
        sources[name] = capture.tree(commit, pin["tree"], pin["files"], name)
    raw, _ = capture.git(["merge-base", "--all", OURS, THEIRS], label="best-merge-bases")
    bases = raw.decode("ascii").splitlines()
    check(len(bases) == len(BASES) and set(bases) == set(BASES), "best merge bases differ")
    for base in BASES:
        sources["base-" + base] = capture.tree(base, label="base-" + base)
    materialize_fixed_tree_blobs(capture, sources, 600)
    capture.original_oids = {entry["oid"] for tree in sources.values() for entry in tree.values()}
    capture.git(["checkout", "--detach", OURS], label="checkout-fixed-main", limit=180)
    clean, _ = capture.git(["status", "--porcelain=v2", "-z", "--untracked-files=all"], label="initial-status")
    check(clean == b"", "initial source is not clean")
    _, merged = capture.git(["merge", "--no-commit", "--no-ff", THEIRS], label="actual-two-base-merge",
                            limit=300, allowed=(0,1), enforce=False)
    check(not merged["timed_out"] and merged["returncode"] in (0,1), "merge did not complete")
    raw, _ = capture.git(["ls-files", "--unmerged", "-z"], label="actual-unmerged-index")
    conflicts = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t",1)
        mode, blob, stage = prefix.decode("ascii").split()
        path = raw_path.decode("utf-8")
        relative_path(path)
        conflicts.setdefault(path, []).append({"mode": mode, "blob": blob, "stage": int(stage)})
    capture.json("composition/ACTUAL-CONFLICTS.json", conflicts)
    return sources, conflicts

def write_source(capture, path, raw, mode):
    relative = relative_path(path)
    check(mode in ("100644", "100755"), "unsupported authored mode")
    target = capture.repo / relative
    for parent in target.parents:
        if parent == capture.repo:
            break
        check(not parent.is_symlink(), "symlink source ancestor")
    check(not target.is_symlink(), "symlink source target")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        before = target.read_bytes()
        capture.put("preimages/" + oid("blob", before) + "/" + path, before)
    target.write_bytes(raw)
    target.chmod(0o755 if mode == "100755" else 0o644)

def apply_sources(capture, inputs, cache, authored, origins, original_trees, conflicts):
    keep = {r["path"]: r for r in inputs["exact_retained"]}
    seeds = {r["path"]: r for r in inputs["regeneration_seeds"]}
    check(len(keep) == len(inputs["exact_retained"]) and len(seeds) == len(inputs["regeneration_seeds"]), "duplicate explicit resolution")
    check(not (set(keep) & set(authored)) and not (set(seeds) & set(authored))
          and not (set(keep) & set(seeds)), "resolution ownership collision")
    available = set(authored) | set(keep) | set(seeds)
    check(set(conflicts) <= available, "unresolved merge paths: " + repr(sorted(set(conflicts)-available)))
    for path, pin in sorted({**keep, **seeds}.items()):
        raw = fetch_blob(capture, pin["blob"], cache)
        if "bytes" in pin:
            check(len(raw) == pin["bytes"], "retained source extent differs")
        write_source(capture, path, raw, pin["mode"])
    for path, raw in sorted(authored.items()):
        write_source(capture, path, raw, origins[path]["mode"])
    for pin in inputs["physical_migration"]:
        source = capture.repo / relative_path(pin["path"])
        check(source.is_file() and not source.is_symlink(), "legacy physical source absent")
        raw = source.read_bytes()
        check(oid("blob", raw) == pin["blob"], "legacy physical preimage differs: " + pin["path"])
        capture.put("physical-migration/original/" + pin["path"], raw)
        target = capture.repo / relative_path(pin["target"])
        if pin["action"] == "relocate-exact-bytes":
            if target.exists():
                check(target.read_bytes() == raw, "canonical target already differs: " + pin["target"])
            else:
                write_source(capture, pin["target"], raw, pin["mode"])
        elif pin["action"] in ("deduplicate-identical-legacy-path", "owner-regeneration-before-legacy-path-retirement"):
            check(target.is_file(), "regenerated canonical target missing")
        else:
            raise ValueError("unreviewed physical migration action")
    for pin in inputs["asset_references"]:
        raw = fetch_blob(capture, pin["sha"], cache)
        check(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "reviewed asset pin differs")
        target = capture.repo / relative_path(pin["path"])
        if target.exists() and target.read_bytes() == raw:
            continue
        write_source(capture, pin["path"], raw, pin["mode"])
    capture.git(["add", "-A"], label="stage-explicit-resolutions", auth=False)
    raw, _ = capture.git(["ls-files", "--unmerged", "-z"], label="resolved-index", auth=False)
    check(raw == b"", "unmerged index remains after explicit resolution")
    return {"conflicts_resolved": len(conflicts), "authored_files": len(authored),
            "exact_retained": len(keep), "regeneration_seeds": len(seeds)}

def syntax_all(capture):
    raw, _ = capture.git(["ls-files", "-z"], label="syntax-tracked-paths", auth=False)
    records, failures = [], []
    for name in raw.split(b"\0"):
        if not name or not name.endswith(b".py"):
            continue
        path = name.decode("utf-8")
        data = (capture.repo / relative_path(path)).read_bytes()
        row = {"path": path, "bytes": len(data), "blob": oid("blob", data), "sha256": sha(data)}
        try:
            tree = ast.parse(data, filename=path)
            compile(tree, path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError, TypeError) as error:
            row.update(status="FAIL", error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
            failures.append(row)
        else:
            row.update(status="PASS", code_executed=False)
        records.append(row)
    report = {"status": "FAIL" if failures else "PASS", "python": sys.version,
              "files": records, "failures": failures, "product_imports_executed": 0}
    capture.json("checks/ALL-PYTHON-SYNTAX.json", report)
    check(not failures and records, "combined whole-tree Python syntax failed")
    return {"checked": len(records), "failures": len(failures)}

def python_command(capture, arguments, label, limit=300, enforce=True):
    check(all(type(a) is str and "\0" not in a for a in arguments), "invalid explicit command")
    return capture.run([sys.executable, "-B", *arguments], cwd=capture.repo, label=label,
                       auth=False, limit=limit, enforce=enforce)

def regenerate(capture, inputs):
    for index, command in enumerate(inputs["pre_generation_commands"]):
        python_command(capture, command, "pre-generation-" + str(index), limit=300)
    for index, name in enumerate(inputs["generators"]):
        check(re.fullmatch("[a-z0-9_]+", name) is not None, "invalid generator module")
        python_command(capture, ["-m", "tools.generate_hia_" + name],
                       "generate-" + str(index) + "-" + name, limit=300)
    retired = []
    for pin in inputs["physical_migration"]:
        old = capture.repo / relative_path(pin["path"])
        target = capture.repo / relative_path(pin["target"])
        check(oid("blob", old.read_bytes()) == pin["blob"], "legacy source changed during generation")
        check(target.is_file() and not target.is_symlink(), "canonical output not generated")
        target_data = target.read_bytes()
        if pin["action"] == "relocate-exact-bytes" and not pin["target"].startswith("examples/hia_bootstrap/"):
            check(oid("blob", target_data) == pin["blob"], "non-generated physical relocation changed bytes")
        retired.append({"old_path": pin["path"], "old_blob": pin["blob"],
                        "target": pin["target"], "target_blob": oid("blob", target_data),
                        "target_bytes": len(target_data), "development_tree_only": True})
        old.unlink()
    capture.json("physical-migration/COMPLETED.json", retired)
    for index, command in enumerate(inputs["post_generation_commands"]):
        python_command(capture, command, "post-generation-" + str(index), limit=300)
    capture.git(["add", "-A"], label="stage-regenerated-candidate", auth=False)
    tree, _ = capture.git(["write-tree"], label="regenerated-tree", auth=False)
    tree_sha = tree.decode("ascii").strip()
    check(re.fullmatch("[0-9a-f]{40}", tree_sha) is not None, "invalid generated tree identity")
    for index, name in enumerate(inputs["generators"]):
        python_command(capture, ["-m", "tools.generate_hia_" + name],
                       "reproduce-" + str(index) + "-" + name, limit=300)
    for index, command in enumerate(inputs["post_generation_commands"]):
        python_command(capture, command, "reproduce-post-" + str(index), limit=300)
    capture.git(["diff", "--exit-code"], label="exact-regeneration-readback", auth=False)
    status, _ = capture.git(["ls-files", "--others", "--exclude-standard", "-z"], label="unregistered-generated-files", auth=False)
    check(status == b"", "generator emitted an unregistered file on reproduction")
    return {"tree": tree_sha, "generator_count": len(inputs["generators"]),
            "real_generation_passes": 2, "physical_paths_retired_in_development_tree": len(retired)}

def source_gate(capture, inputs, harness_root):
    plan = capture.root / "SOURCE-REGISTRATION.json"
    plan.write_bytes(canonical(inputs["source_registration"]))
    report = capture.raw / "checks" / "SOURCE-TESTS.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    _, result = python_command(capture, [str(harness_root / "tools" / "run_source_gate.py"),
                         "--registration", str(plan), "--source", str(capture.repo),
                         "--output", str(report)], "complete-source-tests", limit=1800, enforce=False)
    if report.is_file():
        value = strict_json(report.read_bytes())
    else:
        value = {"status": "INCOMPLETE", "returncode": result["returncode"], "timed_out": result["timed_out"]}
    capture.git(["diff", "--exit-code"], label="source-tests-kept-tracked-bytes", auth=False)
    return value, result["returncode"] == 0 and not result["timed_out"] and value.get("status") == "PASS"

def tree_api(capture, method, suffix, body=None):
    check((method == "POST" and suffix == "") or
          (method == "GET" and re.fullmatch("/[0-9a-f]{40}\\?recursive=1", suffix)),
          "unapproved tree API operation")
    payload = canonical(body) if body is not None else None
    request = urllib.request.Request("https://api.github.com/repos/" + REPOSITORY + "/git/trees" + suffix,
        data=payload, method=method,
        headers={"Authorization": "Bearer " + capture.token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    receipt = {"method": method, "tree_suffix": suffix, "started_at": now(),
               "request_body_sha256": sha(payload) if payload is not None else None}
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            raw = response.read()
            receipt.update(status=response.status, response_bytes=len(raw), response_sha256=sha(raw))
        capture.put("tree-api/" + ("create.json" if method == "POST" else "readback.json"), raw)
        return strict_json(raw)
    finally:
        receipt["finished_at"] = now()
        capture.api_receipts.append(receipt)
        (capture.evidence / "API-RECEIPTS.json").write_bytes(canonical(capture.api_receipts))

def upload_candidate_tree(capture, inputs, original_trees, tree_sha):
    leaves = capture.tree(tree_sha, expected=tree_sha, label="candidate-final")
    ours = original_trees["ours"]
    known = {r["oid"] for tree in original_trees.values() for r in tree.values()}
    uploaded = {}
    changes = []
    for path in sorted(set(ours) | set(leaves)):
        old, new = ours.get(path), leaves.get(path)
        if old == new:
            continue
        if new is None:
            changes.append({"path": path.decode("utf-8"), "mode": old["mode"], "type": old["type"], "sha": None})
            continue
        check(new["type"] == "blob", "candidate has an unsupported non-blob leaf")
        blob = new["oid"]
        if blob not in known and blob not in uploaded:
            raw = subprocess.check_output(["git", "--no-lazy-fetch", "cat-file", "blob", blob],
                                          cwd=capture.repo, env=capture.env, timeout=30)
            check(oid("blob", raw) == blob, "candidate blob changed")
            uploaded[blob] = capture.upload_blob(raw)
        changes.append({"path": path.decode("utf-8"), "mode": new["mode"], "type": "blob", "sha": blob})
    capture.json("publication/UPLOADED-BLOBS.json", uploaded)
    capture.json("publication/TREE-DELTA.json", changes)
    response = tree_api(capture, "POST", "", {"base_tree": inputs["ours"]["tree"], "tree": changes})
    check(response["sha"] == tree_sha, "server candidate tree differs from local exact tree")
    fetched = tree_api(capture, "GET", "/" + tree_sha + "?recursive=1")
    check(fetched.get("truncated") is False, "candidate tree readback truncated")
    remote = {row["path"].encode("utf-8"): {"mode":row["mode"],"type":row["type"],"oid":row["sha"]}
              for row in fetched["tree"] if row["type"] != "tree"}
    check(remote == leaves, "full candidate tree leaves differ after readback")
    return {"tree": tree_sha, "files": len(leaves), "changed_paths": len(changes),
            "new_blobs_full_readback": len(uploaded), "complete_tree_readback": True,
            "commit_created": False, "ref_changed": False}

def persist_evidence(capture, result):
    capture.json("RESULT.json", result)
    buffer = io.BytesIO()
    members = []
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(capture.raw.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            relative = path.relative_to(capture.raw).as_posix()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
            members.append({"path":relative,"bytes":len(data),"sha256":sha(data),"blob":oid("blob",data)})
    compressed = gzip.compress(buffer.getvalue(), compresslevel=6, mtime=0)
    chunks = []
    for at in range(0, len(compressed), 524288):
        raw = compressed[at:at+524288]
        chunks.append({"index":len(chunks),"offset":at,**capture.upload_blob(raw)})
    manifest = {"schema":"hepta.combined-source-build-evidence.v1",
                "encoding":"ordered-gzip-tar-chunks","bytes":len(compressed),"sha256":sha(compressed),
                "members":members,"chunks":chunks,"result":result}
    pin = capture.upload_blob(canonical(manifest))
    (capture.evidence / "EVIDENCE-MANIFEST.json").write_bytes(canonical(manifest))
    (capture.evidence / "EVIDENCE-PIN.json").write_bytes(canonical(pin))
    return pin

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.pop("HIA_REHEARSAL_TOKEN", "")
    check(bool(token), "missing GitHub repository capability")
    capture = Capture(args.root, token)
    result = {"schema":"hepta.combined-source-build-result.v1","status":"INCOMPLETE",
              "scope":SCOPE,"started_at":now(),"python":sys.version,
              "product_tests_executed":0,"native_execution_count":None,"native_qualification_jobs_executed":0,"cold_qualifications":0,
              "whole_native":False,"default_changed":False,"legacy_host_implementation_deleted":False,
              "product_ref_changed":False,"failures":[]}
    try:
        raw = args.inputs.read_bytes()
        driver = Path(__file__).read_bytes()
        check(oid("blob",raw) == os.environ["EXPECTED_INPUTS_GIT_BLOB"], "input manifest differs")
        check(oid("blob",driver) == os.environ["EXPECTED_DRIVER_GIT_BLOB"], "driver differs")
        inputs = strict_json(raw)
        capture.put("harness/INPUTS.json",raw)
        capture.put("harness/DRIVER.py",driver)
        harness_root = Path(__file__).resolve().parents[1]
        for pin in inputs["harness_files"]:
            body = (harness_root / relative_path(pin["path"])).read_bytes()
            check(len(body)==pin["bytes"] and oid("blob",body)==pin["blob"], "harness auxiliary differs")
            capture.put("harness/"+pin["path"],body)
        check(platform.system()=="Linux" and platform.machine()=="x86_64", "wrong platform")
        cache = {}
        authored, origins = compose(capture,inputs,cache)
        originals, conflicts = initialize(capture,inputs)
        result["composition"] = apply_sources(capture,inputs,cache,authored,origins,originals,conflicts)
        result["syntax"] = syntax_all(capture)
        result["generation"] = regenerate(capture,inputs)
        result["source_tests"], source_pass = source_gate(capture,inputs,harness_root)
        result["product_tests_executed"] = result["source_tests"].get("tests_run",0)
        result["candidate"] = upload_candidate_tree(capture,inputs,originals,result["generation"]["tree"])
        result["status"] = "SOURCE_PASS" if source_pass else "SOURCE_FAIL"
    except BaseException as error:
        result["status"] = "FAIL"
        result["failures"].append({"type":type(error).__name__,"error":str(error),"traceback":traceback.format_exc()})
    result["finished_at"] = now()
    try:
        pin = persist_evidence(capture,result)
        print(json.dumps({"HIA_COMBINED_SOURCE_RESULT":result,"evidence":pin},sort_keys=True),flush=True)
    except BaseException as error:
        result["evidence_persistence_error"] = {"type":type(error).__name__,"error":str(error),"traceback":traceback.format_exc()}
        (capture.evidence/"PERSISTENCE-FAILURE.json").write_bytes(canonical(result))
        print(json.dumps({"HIA_COMBINED_SOURCE_RESULT":result},sort_keys=True),flush=True)
        return 1
    return 0 if result["status"]=="SOURCE_PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
