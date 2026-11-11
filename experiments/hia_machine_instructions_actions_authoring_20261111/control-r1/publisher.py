"""Publish one reviewed authoring run to a new Git ref; never update an existing ref.

This program runs in a separate publisher job. It never executes candidate
source, opens a shell, starts a subprocess, or passes its token to authoring.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import traceback
import urllib.error
import urllib.request

REPOSITORY = "TrillionniumFoundation/Hepta"
BASE_COMMIT = "0d653c0987e941c7f6afb4db67e23fccf854f4e0"
BASE_TREE = "821414603284a005f0957a1f0ac93c48c3c51e5a"
POLICY_SHA256 = "4e4d69d0036479155ba13c304c12458994d42914b7422a28076e8f601653d355"
TRIGGER = "codex/hia-instructions-actions-r5-run-20261111-e26e"
RESULT_PREFIX = "codex/hia-instructions-actions-r5-result-"
EVIDENCE_PREFIX = "experiments/hia_machine_instructions_actions_authoring_20261111/"
WORKFLOW_PATH = ".github/workflows/hia-instructions-authoring-isolated.yml"
GOOD = "SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_FILES = 10000

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def digest(raw):
    return sha256(raw).hexdigest()

def blob(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def relative(value):
    require(type(value) is str and value and "\\" not in value and "\0" not in value, "invalid path")
    p = PurePosixPath(value)
    require(not p.is_absolute() and p.as_posix() == value
            and all(v not in {"", ".", ".."} for v in p.parts), "noncanonical path")
    return value

def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def read_regular(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "nonregular downloaded file")
    require(before.st_size <= MAX_FILE_BYTES, "transport file exceeds declared bound; original artifact retained")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        require(stamp(os.fstat(stream.fileno())) == stamp(before), "downloaded file changed while opening")
        raw = stream.read()
        require(stamp(os.fstat(stream.fileno())) == stamp(before), "downloaded file changed while reading")
    require(stamp(path.lstat()) == stamp(before), "downloaded pathname changed")
    return raw, before

def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def json_file(files, name):
    require(name in files, "missing original " + name)
    return json.loads(files[name])

def natural_owner(result):
    c = result.get("cleanup", {})
    events = result.get("events", [])
    kinds = {"qualification_started", "owned_child_observed", "qualification_exit_observed", "owned_child_reaped"}
    return (result.get("status") == "OWNED_PROCESS_COMPLETED"
        and result.get("returncode") == 0 and result.get("qualification_seconds") == 180
        and result.get("cleanup_seconds") == 3 and result.get("subreaper_enabled") is True
        and result.get("exit_observed_before_deadline") is True and result.get("timed_out") is False
        and not result.get("interrupted_signals") and not result.get("event_overflow")
        and not result.get("owner_error") and isinstance(events, list) and bool(events)
        and all(e.get("kind") in kinds for e in events)
        and c.get("attempted") is True and c.get("complete") is True
        and c.get("observed_echild") is True and c.get("leader_reaped") is True
        and c.get("deadline_exceeded") is False and c.get("errors") == []
        and c.get("remaining_direct_children") == [])

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None

class API:
    def __init__(self, token, out):
        self.token = token
        self.out = out
        self.opener = urllib.request.build_opener(NoRedirect)
        self.sequence = 0
        self.created_blobs = {}

    def call(self, method, path, payload=None):
        require(path.startswith("/repos/" + REPOSITORY + "/"), "unapproved API resource")
        self.sequence += 1
        number = self.sequence
        request_record = {"method": method, "path": path, "payload": payload,
                          "mutation_retry": False, "authorization_header_retained": False}
        create(self.out / ("%04d.request.json" % number), wire(request_record))
        raw = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        req = urllib.request.Request("https://api.github.com" + path, data=raw, method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
                     "User-Agent": "HIA-isolated-authoring-publication"})
        try:
            with self.opener.open(req, timeout=30) as response:
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            body = error.read()
            status = error.code
        except BaseException:
            create(self.out / ("%04d.transport-unknown.json" % number),
                   wire({"method": method, "path": path, "effect": "UNKNOWN" if method != "GET" else "READ_UNKNOWN",
                         "exception": traceback.format_exc(), "replayed": False}))
            raise
        require(self.token.encode() not in body, "server response contains authorization material")
        create(self.out / ("%04d.response.bin" % number), body)
        create(self.out / ("%04d.response.json" % number),
               wire({"status": status, "bytes": len(body), "sha256": digest(body)}))
        parsed = json.loads(body)
        if not 200 <= status < 300:
            raise APIError(status, parsed)
        return parsed

    def get(self, suffix):
        return self.call("GET", "/repos/" + REPOSITORY + suffix)

    def post(self, suffix, value):
        return self.call("POST", "/repos/" + REPOSITORY + suffix, value)

    def blob(self, raw):
        expected = blob(raw)
        if expected in self.created_blobs:
            require(self.created_blobs[expected] == raw, "Git hash collision")
            return expected
        try:
            answer = self.post("/git/blobs", {"encoding": "base64", "content": base64.b64encode(raw).decode()})
            require(answer.get("sha") == expected, "Git blob acknowledgement differs")
        except BaseException:
            # The blob ID is independently known. This GET cannot dispatch or
            # repeat a mutation; failure leaves the original effect UNKNOWN.
            result = self.get("/git/blobs/" + expected)
            require(result.get("encoding") == "base64"
                    and base64.b64decode(result["content"], validate=False) == raw
                    and result.get("sha") == expected, "unknown blob could not be reconciled")
        result = self.get("/git/blobs/" + expected)
        require(result.get("sha") == expected and result.get("encoding") == "base64",
                "blob readback identity differs")
        decoded = base64.b64decode(result["content"], validate=False)
        require(decoded == raw and result.get("size") == len(raw), "blob full readback differs")
        self.created_blobs[expected] = raw
        return expected

class APIError(RuntimeError):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__("GitHub API returned HTTP " + str(status))

def git_tree_id(rows):
    directories = {}
    for path, entry in rows.items():
        pieces = relative(path).split("/")
        current = directories
        for piece in pieces[:-1]:
            current = current.setdefault(piece, {})
            require(type(current) is dict, "file/directory name collision")
        require(pieces[-1] not in current, "duplicate Git tree path")
        current[pieces[-1]] = (entry["mode"], entry["sha"])
    def finish(node):
        values = []
        for name, value in node.items():
            encoded = name.encode("utf-8")
            if type(value) is dict:
                mode, identity, key = "40000", finish(value), encoded + b"/"
            else:
                mode, identity = value
                key = encoded + b"\0"
            values.append((key, mode.encode() + b" " + encoded + b"\0" + bytes.fromhex(identity)))
        raw = b"".join(value for _, value in sorted(values))
        return sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return finish(directories)

def leaves(api, tree):
    value = api.get("/git/trees/" + tree + "?recursive=1")
    require(value.get("truncated") is False and value.get("sha") == tree, "tree listing truncated or changed")
    rows = {}
    for item in value["tree"]:
        if item["type"] == "tree":
            continue
        require(item["type"] == "blob" and item["mode"] == "100644", "unsupported Git leaf")
        name = relative(item["path"])
        require(name not in rows, "duplicate tree leaf")
        rows[name] = {"path": name, "sha": item["sha"], "mode": item["mode"], "size": item["size"]}
    return rows

def artifact_files(root):
    require(root.is_dir() and not root.is_symlink(), "author artifact is unavailable")
    found = {}
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), "artifact directory symlink")
        for name in names:
            path = Path(directory) / name
            key = relative(path.relative_to(root).as_posix())
            raw, _ = read_regular(path)
            require(key not in found, "duplicate artifact path")
            total += len(raw)
            require(total <= MAX_BUNDLE_BYTES and len(found) < MAX_FILES, "artifact transport bound exceeded")
            found[key] = raw
    return found

def verify_bundle(files):
    manifest = json_file(files, "AUTHOR-BUNDLE.json")
    require(manifest["schema"] == "hia.instructions-actions.original-bundle.v1", "bundle schema differs")
    rows = manifest["files"]
    require(type(rows) is list and manifest["file_count"] == len(rows), "bundle count differs")
    require({r["path"] for r in rows} == set(files) - {"AUTHOR-BUNDLE.json"}
            and len({r["path"] for r in rows}) == len(rows), "bundle membership differs")
    for r in rows:
        raw = files[relative(r["path"])]
        require(r["kind"] == "regular" and len(raw) == r["bytes"]
                and digest(raw) == r["sha256"] and blob(raw) == r["git_blob"],
                "original artifact bytes differ: " + r["path"])
    require(sum(len(files[r["path"]]) for r in rows) == manifest["total_bytes"], "bundle total differs")
    return manifest

def source_candidates(policy, files, base):
    exported = json_file(files, "CANDIDATE-EXPORT.json")
    snapshot_raw = files["captured-source-leaves.json"]
    snapshot = json.loads(snapshot_raw)
    require(exported["base_commit"] == BASE_COMMIT and exported["base_tree"] == BASE_TREE
            and exported["actual_head"] == BASE_COMMIT
            and exported["allowed_paths"] == policy["candidate_paths"]
            and exported["source_snapshot_sha256"] == digest(snapshot_raw), "source export binding differs")
    observed = {r["path"]: r for r in snapshot}
    require(len(observed) == len(snapshot), "source snapshot contains duplicate paths")
    allowed = set(policy["candidate_paths"])
    for name in set(base) | set(observed):
        relative(name)
        if name in allowed:
            continue
        old, new = base.get(name), observed.get(name)
        require(old is not None and new is not None and new["mode"] == old["mode"]
                and new["git_blob"] == old["sha"], "outside-allowlist source change: " + name)
    for r in policy["files"]:
        raw = files.get("candidate/" + r["path"])
        require(raw is not None and len(raw) == r["bytes"] and digest(raw) == r["sha256"]
                and blob(raw) == r["sha"], "frozen input was not exactly materialized")
    result = {}
    for r in exported["files"]:
        name = relative(r["path"])
        require(name in allowed and name not in result and r["artifact_path"] == "candidate/" + name,
                "candidate path outside exact allowlist")
        raw = files[r["artifact_path"]]
        require(r["mode"] == "100644" and r["posix_mode"] == 0o644
                and len(raw) == r["bytes"] and digest(raw) == r["sha256"]
                and blob(raw) == r["git_blob"], "candidate bytes/mode differ")
        actual = observed.get(name)
        require(actual is not None and all(actual[k] == r[k] for k in (
            "path", "mode", "git_blob", "sha256", "bytes", "posix_mode")), "candidate/source snapshot differs")
        raw.decode("utf-8")  # Only reviewed text-source paths may enter product slots.
        result[name] = raw
    require(set(result) == allowed & set(observed), "candidate export omits an observed allowed leaf")
    return result, exported, snapshot

def author_success(policy, files, exported, snapshot, result, author_job_result, control_commit, context):
    control = json_file(files, "AUTHOR-CONTROL.json")
    worker = json_file(files, "worker-report.json")
    owner = json_file(files, "lifecycle.json")
    request = json_file(files, "request.json")
    setup = json_file(files, "SETUP.json")
    require(request["control_commit"] == control_commit and setup["control"]["commit"] == control_commit
            and setup["context"] == request["context"], "authoring used a different control")
    expected_context = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": context["event_commit"],
        "GITHUB_EVENT_NAME": "create", "GITHUB_REF": "refs/heads/" + TRIGGER,
        "GITHUB_RUN_ID": context["run_id"], "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": context["workflow_ref"], "GITHUB_WORKFLOW_SHA": context["event_commit"],
        "event_payload_sha256": context["event_payload_sha256"]}
    require(request["context"] == expected_context, "author artifact belongs to another workflow run")
    command = request["command"]
    require(len(command) == 7 and command[0] == setup["runtime"]["executable"]
            and command[1:4] == ["-I", "-S", "-B"]
            and command[4].endswith("/" + policy["control_path"] + "/source_worker.py")
            and command[5] == request["root"] and command[6] == request["source"],
            "authoring command is not the frozen isolated worker")
    expected_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    require(request["env"] == expected_env, "author child environment differs")
    require(setup["runtime"]["python"].startswith("3.14.4 ")
            and worker["python"].startswith("3.14.4 ")
            and worker["base_product_commit"] == BASE_COMMIT
            and worker["base_product_tree"] == BASE_TREE, "runtime/base binding differs")
    require(control["worker_report_sha256"] == digest(files["worker-report.json"])
            and control["candidate_export_sha256"] == digest(files["CANDIDATE-EXPORT.json"])
            and control["request_sha256"] == digest(files["request.json"])
            and control["setup_sha256"] == digest(files["SETUP.json"]), "author receipt bindings differ")
    require(setup["request_sha256"] == digest(files["request.json"])
            and request["policy_sha256"] == POLICY_SHA256, "setup/request policy binding differs")
    require(all(control["lifecycle"].get(k) == value for k, value in owner.items())
            and control["lifecycle"].get("supervisor_returncode") == 0,
            "owner wrapper contradicts its original receipt")
    require(control["lifecycle"]["receipt_sha256"] == digest(files["lifecycle.json"]),
            "outer readback is not the original owner receipt")
    require(owner["request_sha256"] == digest(files["lifecycle.json.request.json"])
            and owner["implementation_sha256"] == policy["owner_sha256"], "owner request/implementation differs")
    owner_request = json_file(files, "lifecycle.json.request.json")
    require(owner_request["command"] == request["command"] and owner_request["env"] == request["env"]
            and owner_request["cwd"] == request["source"]
            and owner_request["qualification_seconds"] == 180 and owner_request["cleanup_seconds"] == 3,
            "owner original command/budgets differ")
    require(all(document.get(key) is False for document in (worker, control) for key in
                ("native_compilation_executed", "product_tests_executed",
                 "matching_current_cold", "whole_native_delivery")), "scope was promoted or omitted")
    good = (author_job_result == "success" and control.get("status") == GOOD
            and worker.get("status") == GOOD and control.get("natural_owner_success") is True
            and natural_owner(owner) and control.get("owner_source_preserved") is True
            and control.get("control_preserved") is True and worker.get("frozen_inputs_preserved") is True
            and worker.get("complete_core_roundtrip") is True
            and len(snapshot) == 3941 and set(result) == set(policy["candidate_paths"])
            and worker.get("candidate_changed_paths") == policy["candidate_paths"]
            and worker.get("candidate_index_tree") == exported["actual_index_tree"])
    if not good:
        return False
    require(json_file(files, "candidate-source-leaves.json") == snapshot, "final full source snapshot differs")
    require(len(worker["instruction_modes"]) == 41 and len(set(worker["instruction_modes"])) == 41,
            "instruction mode denominator differs")
    commands = worker["commands"]
    require([c["label"] for c in commands] == policy["command_labels"]
            and all(c["returncode"] == 0 and "exception" not in c for c in commands), "author command sequence differs")
    for command in commands:
        for stream in ("stdout", "stderr"):
            r = command[stream]
            raw = files[r["path"]]
            require(len(raw) == r["bytes"] and digest(raw) == r["sha256"], "original command log differs")
    caps = worker["source_caps"]
    for key in ("source_bytes", "source_lines", "functions", "blocks", "operations"):
        require(type(caps["totals"][key]) is int and 0 <= caps["totals"][key] <= policy["original_caps"][key],
                "original total cap exceeded")
    require(len(caps["per_function"]) == caps["totals"]["functions"], "function cap denominator differs")
    for row in caps["per_function"]:
        require(row["parameters"] <= 16 and row["blocks"] <= 256 and row["unique_ssa_names"] <= 2048,
                "original per-function cap exceeded")
    source = files["candidate/examples/hia_bootstrap/machine_instructions.hiaasm"]
    require(worker["generated_source"]["sha256"] == digest(source)
            and worker["generated_source"]["git_blob"] == blob(source), "generated source binding differs")
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--control-commit", required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    api_logs = args.output / "api"
    api_logs.mkdir(mode=0o700)
    receipt = {"schema": "hia.instructions-actions.git-publication.v1", "status": "HOLD",
               "native_compilation_executed": False, "product_tests_executed": False,
               "matching_current_cold": False, "whole_native_delivery": False,
               "existing_refs_updated": False, "post_mutations_replayed": False}
    token = os.environ.pop("GITHUB_TOKEN", None)
    try:
        require(type(token) is str and bool(token), "publisher token unavailable")
        require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY
                and os.environ["GITHUB_EVENT_NAME"] == "create"
                and os.environ["GITHUB_REF"] == "refs/heads/" + TRIGGER
                and os.environ["GITHUB_RUN_ATTEMPT"] == "1", "unexpected publisher event")
        run_id = os.environ["GITHUB_RUN_ID"]
        require(run_id.isdigit(), "invalid run ID")
        event_commit = os.environ["GITHUB_SHA"]
        require(HEX40.fullmatch(event_commit) and HEX40.fullmatch(args.control_commit)
                and os.environ["GITHUB_WORKFLOW_SHA"] == event_commit, "workflow/control identity differs")
        event_raw, _ = read_regular(Path(os.environ["GITHUB_EVENT_PATH"]))
        event = json.loads(event_raw)
        require(event.get("ref_type") == "branch" and event.get("ref") == TRIGGER, "create payload differs")
        policy_raw, _ = read_regular(args.policy)
        require(digest(policy_raw) == POLICY_SHA256, "publisher policy differs")
        policy = json.loads(policy_raw)
        require(policy["base_commit"] == BASE_COMMIT and policy["base_tree"] == BASE_TREE
                and policy["trigger_branch"] == TRIGGER and len(policy["candidate_paths"]) == 18
                and len(policy["files"]) == 15, "fixed publisher source scope differs")
        api = API(token, api_logs)
        base_commit = api.get("/git/commits/" + BASE_COMMIT)
        require(base_commit["tree"]["sha"] == BASE_TREE, "canonical base commit/tree differs")
        base = leaves(api, BASE_TREE)
        require(len(base) == 3933 and git_tree_id(base) == BASE_TREE,
                "canonical base complete tree hash/count differs")
        control_commit = api.get("/git/commits/" + args.control_commit)
        workflow_commit = api.get("/git/commits/" + event_commit)
        require([p["sha"] for p in workflow_commit["parents"]] == [args.control_commit],
                "event commit is not the reviewed workflow-only successor")
        before_control = leaves(api, control_commit["tree"]["sha"])
        after_control = leaves(api, workflow_commit["tree"]["sha"])
        require(set(after_control) - set(before_control) == {WORKFLOW_PATH}
                and not set(before_control) - set(after_control), "unexpected workflow commit file delta")
        for name, entry in before_control.items():
            require(after_control[name] == entry, "workflow commit changed reviewed control")
        require("[skip ci]" in workflow_commit["message"].lower(), "workflow commit omitted skip marker")
        self_raw, _ = read_regular(Path(__file__))
        require(before_control[policy["control_path"] + "/publisher.py"]["sha"] == blob(self_raw)
                and before_control[policy["control_path"] + "/policy.json"]["sha"] == blob(policy_raw),
                "publisher implementation/policy is not the reviewed control commit")
        context = {"repository": REPOSITORY, "event": "create", "event_commit": event_commit,
                   "control_commit": args.control_commit, "run_id": run_id, "attempt": 1,
                   "event_payload_sha256": digest(event_raw),
                   "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
                   "base_commit": BASE_COMMIT, "base_tree": BASE_TREE}
        receipt["context"] = context
        files = {}
        candidate = {}
        source_pass = False
        artifact_collected_completely = False
        validation = {"status": "HOLD", "author_job_result": os.environ.get("AUTHOR_JOB_RESULT"),
                      "candidate_root_files_admitted": False}
        try:
            files = artifact_files(args.artifact)
            artifact_collected_completely = True
            manifest = verify_bundle(files)
            require(blob(files["control-manifest.original.json"]) ==
                    before_control[policy["control_path"] + "/CONTROL-MANIFEST.json"]["sha"],
                    "author artifact control manifest differs from canonical control")
            require(files["policy.original.json"] == policy_raw, "artifact substituted policy")
            candidate, exported, snapshot = source_candidates(policy, files, base)
            validation["candidate_root_files_admitted"] = True
            source_pass = author_success(policy, files, exported, snapshot, candidate,
                                         os.environ.get("AUTHOR_JOB_RESULT"), args.control_commit, context)
            candidate_tree_rows = dict(base)
            for path, raw in candidate.items():
                candidate_tree_rows[path] = {"mode": "100644", "sha": blob(raw)}
            observed_tree = git_tree_id(candidate_tree_rows)
            if source_pass:
                require(observed_tree == exported["actual_index_tree"],
                        "independently reconstructed candidate tree differs from actual Git index")
            validation["actual_filesystem_tree"] = observed_tree
            validation.update(status=GOOD if source_pass else "HOLD",
                              complete_original_bundle_sha256=digest(files["AUTHOR-BUNDLE.json"]),
                              source_leaf_count=len(snapshot), candidate_files=len(candidate),
                              original_files=len(manifest["files"]))
        except BaseException:
            source_pass = False
            candidate = {}
            validation["candidate_root_files_admitted"] = False
            validation["exception"] = traceback.format_exc()
        receipt["author_validation"] = validation
        evidence = EVIDENCE_PREFIX + "run-" + run_id + "-attempt-1/"
        branch = RESULT_PREFIX + run_id + "-1"
        entries = {}
        recovery = []
        def put(path, raw):
            relative(path)
            require(path.startswith(evidence) or path in policy["candidate_paths"], "unapproved publication path")
            require(path not in entries, "duplicate published path")
            identity = api.blob(raw)
            entries[path] = {"path": path, "mode": "100644", "type": "blob", "sha": identity}
        for name, raw in sorted(candidate.items()):
            put(name, raw)
        for name, raw in sorted(files.items()):
            record = {"original_path": name, "bytes": len(raw), "sha256": digest(raw),
                      "git_blob": blob(raw), "pieces": []}
            try:
                raw.decode("utf-8")
                direct = len(raw) <= 262144
            except UnicodeError:
                direct = False
            if direct:
                path = evidence + "original/" + relative(name)
                put(path, raw)
                record["pieces"].append({"path": path, "encoding": "raw-utf8", "offset": 0,
                                         "bytes": len(raw), "sha256": digest(raw)})
            else:
                for number, at in enumerate(range(0, len(raw), 49152)):
                    piece = raw[at:at + 49152]
                    path = evidence + "encoded/" + relative(name) + ".part%05d.base64" % number
                    encoded = base64.b64encode(piece) + b"\n"
                    put(path, encoded)
                    record["pieces"].append({"path": path, "encoding": "base64", "offset": at,
                        "bytes": len(piece), "sha256": digest(piece), "encoded_sha256": digest(encoded)})
            recovery.append(record)
        plan = {"schema": "hia.instructions-actions.publication-plan.v1",
                "context": context, "author_validation": validation,
                "candidate_paths_written": sorted(candidate),
                "evidence_prefix": evidence, "create_only_ref": "refs/heads/" + branch,
                "parents": [BASE_COMMIT, event_commit], "base_tree": BASE_TREE,
                "original_files": recovery, "original_file_count": len(recovery),
                "downloaded_artifact_fully_collected": artifact_collected_completely,
                "complete_utf8_or_base64_recovery_of_listed_files": True,
                "author_bundle_integrity_verified": "complete_original_bundle_sha256" in validation,
                "native_compilation_executed": False, "product_tests_executed": False,
                "matching_current_cold": False, "whole_native_delivery": False,
                "previous_desktop_unknown_or_failure_reclassified": False}
        put(evidence + "PUBLICATION-PLAN.json", wire(plan))
        put(evidence + "policy.original.json", policy_raw)
        put(evidence + "event.original.json", event_raw)
        put(evidence + "VALIDATION.json", wire(validation))
        put(evidence + "README.md", (
            "# Isolated instruction authoring\n\n"
            "Status: " + validation["status"] + ".\n\n"
            "This branch records a new GitHub Actions authoring run. It does not rerun or resolve "
            "any earlier desktop operation. No native compiler or product test ran here. "
            "The 180-second owner and original Core capacities remain unchanged. "
            "Publication success is custody, not native qualification.\n\n"
            "PUBLICATION-PLAN.json identifies every original file and its complete UTF-8 or "
            "49,152-byte base64 recovery pieces. An absent/invalid author artifact is recorded "
            "as HOLD, and never supplies candidate product files. The publisher's own final "
            "API acknowledgement is retained in its separate workflow artifact and logs.\n"
        ).encode())
        create(args.output / "PUBLICATION-PLAN.json", wire(plan))
        expected = dict(base)
        for path, entry in entries.items():
            raw = api.created_blobs[entry["sha"]]
            expected[path] = {"path": path, "mode": "100644", "sha": entry["sha"], "size": len(raw)}
        tree_sha = git_tree_id(expected)
        try:
            created_tree = api.post("/git/trees", {"base_tree": BASE_TREE, "tree": list(entries.values())})
            require(created_tree["sha"] == tree_sha, "tree acknowledgement differs")
        except BaseException:
            # The complete tree hash was independently computed. Only GET
            # this exact object after an uncertain POST; never repeat POST.
            recovered = api.get("/git/trees/" + tree_sha)
            require(recovered["sha"] == tree_sha, "unknown tree could not be reconciled")
        actual = leaves(api, tree_sha)
        require(actual == expected, "full publication tree readback differs")
        for item in policy["base_workflows"]:
            require(actual[item["path"]]["sha"] == item["git_blob"], "original workflow changed")
        receipt["tree"] = tree_sha
        receipt["full_tree_leaves_verified"] = len(actual)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        commit_request = {"message": "[skip ci] Preserve r5 isolated authoring " + run_id + "/1: " + validation["status"],
                          "tree": tree_sha, "parents": [BASE_COMMIT, event_commit],
                          "author": {"name": "github-actions[bot]",
                              "email": "41898282+github-actions[bot]@users.noreply.github.com", "date": now},
                          "committer": {"name": "github-actions[bot]",
                              "email": "41898282+github-actions[bot]@users.noreply.github.com", "date": now}}
        # A commit POST with an unknown acknowledgement is never repeated.
        committed = api.post("/git/commits", commit_request)
        commit_sha = committed["sha"]
        check = api.get("/git/commits/" + commit_sha)
        require(check["tree"]["sha"] == tree_sha
                and [p["sha"] for p in check["parents"]] == [BASE_COMMIT, event_commit],
                "canonical publication commit differs")
        receipt["commit"] = commit_sha
        receipt["create_only_ref"] = "refs/heads/" + branch
        try:
            api.post("/git/refs", {"ref": "refs/heads/" + branch, "sha": commit_sha})
        except BaseException:
            # POST is never replayed. Only this exact ref is read to reconcile
            # an uncertain acknowledgement; a different target remains HOLD.
            existing = api.get("/git/ref/heads/" + branch)
            require(existing["object"]["sha"] == commit_sha, "create-only ref conflict or unknown effect")
        final = api.get("/git/ref/heads/" + branch)
        require(final["object"]["sha"] == commit_sha, "published ref differs")
        receipt["publication_verified"] = True
        receipt["status"] = "AUTHORING_SOURCE_PUBLISHED" if source_pass else "AUTHORING_HOLD_PUBLISHED"
    except BaseException:
        receipt["exception"] = traceback.format_exc()
        receipt["effect_may_be_unknown"] = True
    finally:
        token = None
        create(args.output / "PUBLISHER-RECEIPT.json", wire(receipt))
        print(json.dumps({k: receipt.get(k) for k in (
            "schema", "status", "commit", "tree", "create_only_ref", "publication_verified",
            "author_validation", "exception")}, sort_keys=True), flush=True)
    return 0 if receipt["status"] == "AUTHORING_SOURCE_PUBLISHED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
