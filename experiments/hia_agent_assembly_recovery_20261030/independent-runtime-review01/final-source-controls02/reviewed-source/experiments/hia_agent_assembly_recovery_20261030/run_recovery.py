#!/usr/bin/env python3
"""One independently registered CI replication; never resume the failed v4."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from experiments.hia_agent_assembly_recovery_20261030 import resource_gate

STUDY = Path("experiments/hia_agent_assembly_v4_20261030")
MAX_DOWNLOAD_SECONDS = 900
MAX_RUNTIME_BYTES = 512 * 1024**2
MAX_RUNTIME_MEMBERS = 512
_RUN_DEADLINE = None


def remaining_time():
    if _RUN_DEADLINE is None:
        return None
    remaining = _RUN_DEADLINE - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("outer replication infrastructure deadline exceeded")
    return remaining


def read(path):
    return json.loads(Path(path).read_bytes())


def identity(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        return {"path": str(path), "bytes": path.stat().st_size,
                "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def child_environment():
    # The read-only Actions API credential is unnecessary in model/compiler
    # processes. Never save the general environment or authentication headers.
    result = {key: value for key, value in os.environ.items()
              if not any(word in key for word in ("TOKEN", "PASSWORD", "SECRET"))}
    result.update(LLAMA_ARG_REPACK="0", PYTHONDONTWRITEBYTECODE="1")
    return result


def validate_launch(protocol, environment, event, head_sha):
    demand(environment.get("GITHUB_ACTIONS") == "true"
           and environment.get("RUNNER_ENVIRONMENT") == "github-hosted",
           "actual completions require the registered hosted CI environment")
    demand(environment.get("GITHUB_RUN_ATTEMPT") == "1", "rerunning a workflow attempt is forbidden")
    demand(environment.get("GITHUB_REPOSITORY") == protocol["repository"]
           and environment.get("GITHUB_REF_NAME") == protocol["branch"],
           "unregistered repository or branch")
    demand(environment.get("GITHUB_SHA") == head_sha, "checkout differs from event head")
    name = environment.get("GITHUB_EVENT_NAME")
    marker = protocol["launch_marker"]
    if name == "push":
        commit = event.get("head_commit") or {}
        demand(commit.get("id") == head_sha and type(commit.get("message")) is str
               and commit["message"].count(marker) == 1,
               "only this push head's unique launch marker can start the study")
    elif name == "workflow_dispatch":
        demand(event.get("inputs", {}).get("launch_marker") == marker,
               "explicit dispatch requires the exact launch marker")
    else:
        raise ValueError("pull requests and other events cannot start model completions")
    return {"event": name, "head_sha": head_sha, "branch": protocol["branch"],
            "run_id": int(environment["GITHUB_RUN_ID"]), "run_attempt": 1,
            "marker": marker}


def select_unique_launch(protocol, current, runs):
    """An earlier consumed or ambiguous dispatch run blocks every new attempt.

    Workflow concurrency serializes this check. Non-marker push runs do not
    consume the study, so normal evidence commits can safely create skipped
    workflow entries. Dispatch inputs are not exposed by the list API: an
    earlier dispatch is conservatively considered consumed, never ignored.
    """
    candidates = []
    for run in runs:
        if run.get("head_branch") != protocol["branch"]:
            continue
        event = run.get("event")
        commit = run.get("head_commit")
        if event == "push":
            demand(type(commit) is dict and type(commit.get("message")) is str,
                   "earlier push marker eligibility is unknown")
        message = commit.get("message", "") if type(commit) is dict else ""
        eligible = (event == "workflow_dispatch" or
                    event == "push" and type(message) is str
                    and message.count(protocol["launch_marker"]) == 1)
        if eligible:
            demand(type(run.get("id")) is int and type(run.get("run_number")) is int,
                   "run identity is unknown")
            candidates.append(run)
    demand(any(run["id"] == current["id"] for run in candidates), "current run is absent from launch history")
    first = min(candidates, key=lambda run: (run["run_number"], run["id"]))
    demand(first["id"] == current["id"], "this study launch was already consumed or a prior dispatch is ambiguous")
    demand(current.get("run_attempt") == 1, "Actions API reports a repeated attempt")
    return {"first_eligible_run_id": first["id"],
            "eligible_run_ids": [run["id"] for run in sorted(candidates, key=lambda row: row["run_number"])],
            "history_decision": "first consumed launch only; no status-dependent retry"}


def github_json(url, token, evidence=None, label=None):
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hepta-agent-recovery-evidence"})
    started = time.monotonic_ns()
    record = {"url": url, "absolute_deadline_seconds": 30, "automatic_retry": False}
    try:
        with preparation_deadline(30):
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(8 * 1024**2 + 1)
        if evidence is not None:
            evidence.mkdir(parents=True, exist_ok=True)
            with (evidence / (label + ".response.raw")).open("xb") as stream:
                stream.write(data)
        record.update(response_bytes=len(data), response_sha256=hashlib.sha256(data).hexdigest())
        demand(len(data) <= 8 * 1024**2, "Actions metadata exceeded its fixed bound")
        return json.loads(data), record["response_sha256"]
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        record["wall_ns"] = time.monotonic_ns()-started
        if evidence is not None:
            save(evidence / (label + ".request-metadata.json"), record)


def verify_launch_history(protocol, launch, evidence):
    token = os.environ.get("HEPTA_RECOVERY_GITHUB_TOKEN")
    demand(type(token) is str and bool(token), "read-only Actions API credential is required")
    base = "https://api.github.com/repos/" + protocol["repository"]
    api_folder = evidence / "launch-api"
    current, current_hash = github_json(base + "/actions/runs/" + str(launch["run_id"]), token,
                                        api_folder, "current")
    demand(current.get("id") == launch["run_id"] and current.get("head_sha") == launch["head_sha"]
           and current.get("head_branch") == protocol["branch"]
           and current.get("event") == launch["event"]
           and str(current.get("path", "")).split("@", 1)[0] == protocol["execution"]["workflow"],
           "Actions run identity or workflow differs from the launch event")
    workflow = current.get("workflow_id")
    demand(type(workflow) is int, "workflow identity is unknown")
    runs, page_hashes, expected_count = [], [], None
    for page in range(1, 11):
        query = urllib.parse.urlencode({"branch": protocol["branch"], "per_page": 100, "page": page})
        batch, digest = github_json(base + "/actions/workflows/" + str(workflow) + "/runs?" + query, token,
                                   api_folder, "history-" + str(page).zfill(2))
        count = batch.get("total_count")
        demand(type(count) is int and 0 < count < 1000, "launch history is unavailable or reaches its complete-read bound")
        expected_count = max(expected_count or 0, count)
        page_hashes.append(digest)
        rows = batch.get("workflow_runs")
        demand(type(rows) is list, "workflow run list is missing")
        runs.extend(rows)
        if len(rows) < 100:
            break
    demand(len({run["id"] for run in runs}) == len(runs) and len(runs) >= expected_count,
           "launch history pagination is incomplete or inconsistent")
    decision = select_unique_launch(protocol, current, runs)
    record = {**launch, **decision, "workflow_id": workflow,
        "current_response_sha256": current_hash, "history_response_sha256": page_hashes,
        "history": [{"id": run.get("id"), "run_number": run.get("run_number"),
                     "head_sha": run.get("head_sha"), "head_branch": run.get("head_branch"),
                     "event": run.get("event"), "status": run.get("status"),
                     "conclusion": run.get("conclusion"),
                     "marker_occurrences": ((run.get("head_commit") or {}).get("message") or "").count(protocol["launch_marker"])}
                    for run in runs]}
    save(evidence / "LAUNCH_QUALIFICATION.json", record)
    return record


def run_command(evidence, name, argv, *, cwd=ROOT, timeout=None):
    started = time.monotonic_ns()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {"name": name, "argv": [str(value) for value in argv],
              "started_unix_ns": time.time_ns(), "timeout_seconds": timeout,
              "automatic_retry": False}
    error = None
    process = None
    anchor_owned = False
    try:
        demand(sys.platform == "linux" and hasattr(os, "WNOWAIT")
               and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
               "unreaped Linux child ownership is required")
        remaining = remaining_time()
        if remaining is not None:
            timeout = min(timeout, remaining) if timeout is not None else remaining
        record["effective_outer_timeout_seconds"] = timeout
        with (evidence / (name + ".stdout.txt")).open("x") as stdout, (evidence / (name + ".stderr.txt")).open("x") as stderr:
            process = subprocess.Popen(record["argv"], cwd=cwd, env=child_environment(),
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            anchor_owned = True
            record["owned_pid_and_process_group"] = process.pid
            save(evidence / (name + ".owner.json"),
                 {"pid_and_process_group": process.pid, "created_by_this_wrapper": True,
                  "started_unix_ns": record["started_unix_ns"], "argv": record["argv"]})
            deadline = time.monotonic() + timeout if timeout is not None else None
            while True:
                try:
                    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                except ChildProcessError:
                    # Somebody else reaped the PID. Its process-group identity
                    # is no longer anchored, so never signal that numeric ID.
                    anchor_owned = False
                    raise
                if status is not None:
                    record["unreaped_owner_status"] = {
                        "si_pid": status.si_pid, "si_code": status.si_code, "si_status": status.si_status}
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(record["argv"], timeout)
                time.sleep(min(.02, max(0, deadline-time.monotonic())) if deadline is not None else .02)
    except BaseException as failure:
        error = failure
        record["error"] = {"type": type(failure).__name__, "message": str(failure)}
    finally:
        if process is not None:
            cleanup_started = time.monotonic_ns()
            cleanup = {"group": process.pid, "signals_sent": [], "errors": [],
                "unreaped_owner_anchor": anchor_owned,
                "direct_owner_reaped": False, "all_engine_shutdown_receipts": None,
                "scope": "Signal only the newly created group before reaping its owner; this does not prove every descendant exited or synthesize engine.close receipts"}
            if anchor_owned:
                try:
                    # Even a successful owner may have left descendants. The
                    # unreaped child reserves its PID/PGID until this signal.
                    os.killpg(process.pid, signal.SIGKILL)
                    cleanup["signals_sent"].append(int(signal.SIGKILL))
                except ProcessLookupError:
                    cleanup["group_absent_at_signal"] = True
                except BaseException as failure:
                    cleanup["errors"].append({"operation": "kill_owned_group", "type": type(failure).__name__, "message": str(failure)})
            else:
                cleanup["errors"].append({"operation": "ownership", "type": "UnknownOwnership", "message": "owner PID was reaped elsewhere; numeric group was not signalled"})
            try:
                # This is the only wait/reap call. Never poll/wait beforehand.
                record["returncode"] = process.wait(timeout=5)
                cleanup["direct_owner_reaped"] = True
            except BaseException as failure:
                cleanup["errors"].append({"operation": "reap_owner", "type": type(failure).__name__, "message": str(failure)})
                record["returncode"] = None
            cleanup["wall_ns"] = time.monotonic_ns()-cleanup_started
            record["owned_group_cleanup"] = cleanup
            if error is None and (cleanup["errors"] or record["returncode"] != 0):
                error = RuntimeError("subprocess or owned-group cleanup failed: " + name)
                record["error"] = {"type": type(error).__name__, "message": str(error)}
        else:
            record["returncode"] = None
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update(wall_ns=time.monotonic_ns()-started,
            child_user_seconds=after.ru_utime-before.ru_utime,
            child_system_seconds=after.ru_stime-before.ru_stime,
            child_maxrss_kib=after.ru_maxrss,
            maxrss_scope="cumulative high-water mark of this wrapper's completed children; not a sum")
        save(evidence / (name + ".command.json"), record)
    if error is not None:
        raise error
    demand(record["returncode"] == 0, "subprocess failed: " + name)
    return record


def resource_admit(evidence, label):
    observed = resource_gate.observe()
    save(evidence / ("RESOURCE_" + label + ".json"), observed)
    demand(observed["eligible"] is True, "fixed resource admission failed: " + label)
    return observed


@contextmanager
def preparation_deadline(seconds):
    demand(threading.current_thread() is threading.main_thread()
           and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
           and signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, []),
           "preparation deadline is unavailable or already owned")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_number, _frame):
        raise TimeoutError("absolute preparation download deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        demand(urllib.parse.urlparse(url).scheme == "https", "download redirect left HTTPS")
        return super().redirect_request(request, fp, code, message, headers, url)


def download_fixed(evidence, cache, item):
    target = cache / item["filename"]
    temporary = target.with_name(target.name + ".partial")
    demand(not target.exists() and not temporary.exists(), "download destination already exists")
    started = time.monotonic_ns()
    record = {"item": item, "download_started_unix_ns": time.time_ns(),
              "automatic_retry": False, "passed": False}
    try:
        demand(urllib.parse.urlparse(item["url"]).scheme == "https", "download requires HTTPS")
        opener = urllib.request.build_opener(HTTPSOnlyRedirect())
        request = urllib.request.Request(item["url"], headers={"Accept-Encoding": "identity",
            "User-Agent": "hepta-agent-recovery-fixed-download"})
        digest = hashlib.sha256()
        total = 0
        remaining = remaining_time()
        with preparation_deadline(min(MAX_DOWNLOAD_SECONDS, remaining) if remaining is not None else MAX_DOWNLOAD_SECONDS):
            with opener.open(request, timeout=30) as response, temporary.open("xb") as target_stream:
                length = response.headers.get("Content-Length")
                if length is not None:
                    demand(length.isdigit() and int(length) == item["bytes"], "HTTP content length differs")
                while True:
                    chunk = response.read(min(1024**2, item["bytes"] - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    demand(total <= item["bytes"], "download exceeded its exact in-flight byte bound")
                    target_stream.write(chunk)
                    digest.update(chunk)
        record["streamed_bytes"] = total
        record["streamed_sha256"] = digest.hexdigest()
        actual = identity(temporary)
        record["downloaded_identity"] = actual
        demand((actual["bytes"], actual["sha256"]) == (item["bytes"], item["sha256"]),
               "download size or SHA-256 differs: " + item["id"])
        os.link(temporary, target)
        temporary.unlink()
        record["final_identity"] = identity(target)
        record["passed"] = True
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        if temporary.exists():
            record["partial_bytes"] = temporary.stat().st_size
        raise
    finally:
        record["download_and_identity_wall_ns"] = time.monotonic_ns()-started
        save(evidence / ("DOWNLOAD_" + item["id"] + ".json"), record)
    return target


def extract_runtime(archive, destination, evidence):
    started = time.monotonic_ns()
    record = {"archive_identity": identity(archive), "passed": False}
    destination.mkdir(exist_ok=False)
    try:
        with tarfile.open(archive, "r:gz") as stream:
            members = []
            names = set()
            total = 0
            for member in stream:
                demand(len(members) < MAX_RUNTIME_MEMBERS, "runtime member-count bound exceeded")
                members.append(member)
                path = PurePosixPath(member.name)
                demand(not path.is_absolute() and ".." not in path.parts and len(member.name) <= 1024,
                       "unsafe runtime member path")
                normalized = str(path)
                demand(normalized not in names, "duplicate runtime member path")
                names.add(normalized)
                demand(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                       "special runtime archive member is forbidden")
                if member.isfile():
                    total += member.size
                    demand(0 <= member.size <= 128 * 1024**2 and total <= MAX_RUNTIME_BYTES,
                           "runtime expansion bound exceeded")
                # Python's data filter also checks link destinations against
                # the extraction root. No archive content is executed here.
                tarfile.data_filter(member, str(destination))
            stream.extractall(destination, members=members, filter="data")
        files = {}
        for path in sorted(destination.rglob("*")):
            if path.is_dir():
                continue
            resolved = path.resolve(strict=True)
            demand(resolved.is_relative_to(destination.resolve()) and resolved.is_file(),
                   "runtime link escapes or does not resolve to a regular file")
            files[str(path.relative_to(destination))] = identity(resolved)
        binaries = [path for path in destination.rglob("llama-server") if path.is_file()]
        demand(len(binaries) == 1, "exactly one pinned llama-server is required")
        binary = binaries[0].resolve(strict=True)
        record.update(passed=True, files=files, uncompressed_regular_bytes=total,
                      member_count=len(members), binary=identity(binary))
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        record["extraction_and_identity_wall_ns"] = time.monotonic_ns()-started
        save(evidence / "RUNTIME_EXTRACTION.json", record)
    return binary


def verify_bindings(base, bindings):
    for name, expected in bindings.items():
        relative = PurePosixPath(name)
        demand(not relative.is_absolute() and ".." not in relative.parts, "invalid source binding path")
        path = base / name
        demand(path.is_file() and not path.is_symlink()
               and identity(path)["sha256"] == expected, "source identity differs: " + name)
    return True


def helper_bindings():
    paths = list(HERE.glob("*.py")) + [HERE / "PROTOCOL.json", HERE / "PARENT_RUNTIME_ENVIRONMENT.json",
        ROOT / ".github/workflows/hepta-agent-recovery.yml",
        ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/readout.py",
        ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/diagnose.py",
        ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/archive_evidence.py"]
    return {str(path.relative_to(ROOT)): identity(path)["sha256"] for path in sorted(paths)}


def prepare_snapshot(evidence, protocol, original, head_sha):
    started = time.monotonic_ns()
    archive = ROOT / protocol["original_source_archive"]["path"]
    expected = protocol["original_source_archive"]
    actual = identity(archive)
    demand((actual["bytes"], actual["sha256"]) == (expected["bytes"], expected["sha256"]),
           "the original source archive differs from its fixed identity")
    verify_bindings(ROOT, original["sources"])
    snapshot = evidence / "source-snapshot"
    snapshot.mkdir(exist_ok=False)
    copied = {}
    count = total = 0
    with tarfile.open(archive, "r:xz") as stream:
        for member in stream:
            count += 1
            total += member.size
            path = PurePosixPath(member.name)
            demand(count <= 1024 and total <= 32 * 1024**2 and 0 <= member.size <= 8 * 1024**2,
                   "original source extraction exceeded its fixed bounds")
            demand(member.isfile() and not path.is_absolute() and ".." not in path.parts,
                   "the original source archive must contain only relative regular files")
            # The historical control/result JSON is deliberately not reused as
            # fresh qualification. Exact Python and needed example sources are.
            selected = path.suffix == ".py" or str(path) == "pyproject.toml" or path.parts[0] in {"examples", "kernels"}
            if selected:
                demand(str(path) not in copied, "duplicate source member")
                stream.extract(member, snapshot, filter="data")
                copied[str(path)] = identity(snapshot / path)["sha256"]
    verify_bindings(snapshot, original["sources"])
    demand(len(original["sources"]) == 31, "the original evaluator closure must have 31 bindings")
    original_protocol = read(ROOT / STUDY / "PROTOCOL.json")
    demand(identity(ROOT / STUDY / "PROTOCOL.json")["sha256"] == original["protocol_sha256"],
           "the original protocol was modified")
    fresh = dict(original_protocol)
    fresh["schema"] = "hepta.agent.assembly-maintenance-upgrade.exploratory-replication.v1"
    fresh["task_origin"] = "The original four v4 tasks and their prior results are already seen; separate exploratory CI replication, not unseen-task evidence"
    fresh["replication_identity"] = {
        "study_id": protocol["study_id"], "replication_protocol_sha256": identity(HERE / "PROTOCOL.json")["sha256"],
        "original_registration_sha256": protocol["original_registration_sha256"],
        "original_cohort_sha256": protocol["original_cohort_sha256"],
        "source_commit": head_sha, "github_run_id": os.environ["GITHUB_RUN_ID"],
        "tasks_and_previous_results_already_seen": True, "old_results_replaced_or_pooled": False}
    fresh["resource_admission"] = protocol["resource_admission"]
    save(snapshot / STUDY / "PROTOCOL.json", fresh)
    record = {"original_archive": actual, "checked_current_source_commit": head_sha,
        "original_registered_sources": original["sources"], "copied_files": copied,
        "source_count": len(copied), "original_source_members_read": count,
        "snapshot_is_not_a_claim_about_the_complete_current_repository_tree": True,
        "wall_ns": time.monotonic_ns()-started}
    save(evidence / "SOURCE_PREPARATION.json", record)
    return snapshot


def install_toolchains(evidence):
    llvm = r'''
set -euo pipefail
hepta_recovery_key="$RUNNER_TEMP/hepta-agent-recovery-llvm.asc"
curl --fail --location --retry 0 --max-time 120 --output "$hepta_recovery_key" https://apt.llvm.org/llvm-snapshot.gpg.key
hepta_recovery_fingerprint=$(gpg --show-keys --with-colons "$hepta_recovery_key" | awk -F: '$1 == "fpr" { print $10; exit }')
test "$hepta_recovery_fingerprint" = 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
sudo install -m 0644 "$hepta_recovery_key" /usr/share/keyrings/hepta-agent-recovery-llvm.asc
printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/hepta-agent-recovery-llvm.asc] https://apt.llvm.org/noble/ llvm-toolchain-noble-20 main' | sudo tee /etc/apt/sources.list.d/hepta-agent-recovery-llvm20.list
sudo apt-get update
sudo apt-get install --yes clang-20 libclang-rt-20-dev llvm-20 lld-20
'''
    run_command(evidence, "install-llvm", ["/bin/bash", "-c", llvm], timeout=1200)
    run_command(evidence, "install-rust", ["rustup", "toolchain", "install", "1.95.0", "--profile", "minimal"], timeout=1200)
    run_command(evidence, "locate-rust", ["rustup", "which", "--toolchain", "1.95.0", "rustc"], timeout=30)
    rustc = (evidence / "locate-rust.stdout.txt").read_text().strip()
    demand(Path(rustc).is_absolute() and Path(rustc).is_file(), "actual Rust compiler is unavailable")
    clang = "/usr/bin/clang-20"
    run_command(evidence, "clang-version", [clang, "--version"], timeout=30)
    run_command(evidence, "rust-version", [rustc, "--version"], timeout=30)
    tools = {"clang": identity(clang), "rustc": identity(rustc), "python": identity(sys.executable)}
    save(evidence / "PREPARED_TOOLS.json", tools)
    return clang, rustc


def items_for_download(original_protocol):
    values = []
    for model in original_protocol["models"]:
        values.append({**model, "url": "https://huggingface.co/" + model["repository"]
            + "/resolve/" + model["revision"] + "/" + model["filename"]})
    runtime = original_protocol["runtime"]
    values.append({"id": "llama_runtime", "filename": runtime["archive"],
        "bytes": runtime["bytes"], "sha256": runtime["sha256"],
        "url": "https://github.com/" + runtime["repository"] + "/releases/download/"
               + runtime["release"] + "/" + runtime["archive"]})
    return values


def copy_new(source, destination):
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open("rb") as reader, Path(destination).open("xb") as writer:
        size = os.fstat(reader.fileno()).st_size
        demand(0 <= size <= 512 * 1024**2, "copied evidence exceeds its fixed file bound")
        total = 0
        while True:
            chunk = reader.read(min(1024**2, size-total+1))
            if not chunk:
                break
            total += len(chunk)
            demand(total <= size, "source grew during bounded evidence copy")
            writer.write(chunk)
        demand(total == size, "source shrank during bounded evidence copy")
    demand(identity(source)["sha256"] == identity(destination)["sha256"], "copied evidence bytes differ")


def retain_definitions(evidence, protocol):
    """Save actual governing bytes even when a later qualification refuses."""
    started = time.monotonic_ns()
    names = set(helper_bindings()) | {
        str(STUDY / "REGISTRATION.json"), str(STUDY / "PROTOCOL.json"),
        "experiments/hia_agent_assembly_v4_readout_20261030/FROZEN_COHORT_RESULT.json",
        protocol["original_source_archive"]["path"]}
    files = {}
    for name in sorted(names):
        source, target = ROOT / name, evidence / "definition-source" / name
        copy_new(source, target)
        files[name] = identity(target)
    save(evidence / "DEFINITION_RETENTION.json", {
        "files": files, "wall_ns": time.monotonic_ns()-started,
        "actual_bytes_retained_before_qualification": True,
        "retention_is_not_a_claim_that_a_mismatching_definition_is_eligible": True})


def run(output):
    global _RUN_DEADLINE
    started = time.monotonic_ns()
    protocol = read(HERE / "PROTOCOL.json")
    evidence = Path(output).absolute()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")).resolve()
    demand(evidence.is_relative_to(runner_temp) and evidence != runner_temp
           and not evidence.is_relative_to(ROOT), "evidence must be in this job's separate RUNNER_TEMP directory")
    evidence.mkdir(parents=True, exist_ok=True)
    demand(not (evidence / "RUN_START.json").exists(), "this evidence directory already consumed a run")
    _RUN_DEADLINE = time.monotonic() + protocol["execution"]["wrapper_deadline_seconds"]
    bootstrap = read(evidence / "BOOTSTRAP.json") if (evidence / "BOOTSTRAP.json").is_file() else None
    bootstrap_interval = None
    if bootstrap is not None:
        bootstrap_ns = bootstrap.get("started_monotonic_ns")
        demand(type(bootstrap_ns) is int and 0 < bootstrap_ns <= started,
               "bootstrap monotonic identity is unavailable")
        bootstrap_interval = started - bootstrap_ns
        _RUN_DEADLINE = min(_RUN_DEADLINE, bootstrap_ns / 1e9 + protocol["execution"]["wrapper_deadline_seconds"])
    state = {"schema": "hepta.agent.assembly-recovery.terminal.v1", "study_id": protocol["study_id"],
        "status": "preparing", "stage": "launch", "completed_models": [],
        "complete_valid_coverage": False, "cross_family_claims_eligible": False,
        "original_results_unchanged": True, "old_and_new_cells_pooled": False,
        "tasks_and_previous_results_already_seen": True, "model_completions_added_by_readout": 0}
    save(evidence / "RUN_START.json", {"study_id": protocol["study_id"],
        "started_unix_ns": time.time_ns(), "protocol_identity": identity(HERE / "PROTOCOL.json"),
        "bootstrap_to_executor_ns": bootstrap_interval,
        "deadline_from_first_bootstrap_when_available": True,
        "original_status": protocol["original_status"],
        "environment": {key: os.environ.get(key) for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "GITHUB_EVENT_NAME", "GITHUB_REF_NAME", "GITHUB_REPOSITORY", "RUNNER_OS", "RUNNER_ARCH",
            "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion")}})
    snapshot = suite = None
    previous_term = signal.getsignal(signal.SIGTERM)
    def cancelled(_number, _frame):
        raise KeyboardInterrupt("CI cancellation: stop the owned process group and retain incomplete evidence")
    signal.signal(signal.SIGTERM, cancelled)
    try:
        state["stage"] = "definition_retention"
        retain_definitions(evidence, protocol)
        run_command(evidence, "checkout-head", ["git", "rev-parse", "HEAD"], timeout=30)
        head = (evidence / "checkout-head.stdout.txt").read_text().strip()
        run_command(evidence, "checkout-status", ["git", "status", "--porcelain"], timeout=30)
        demand(not (evidence / "checkout-status.stdout.txt").read_text().strip(),
               "source checkout is not clean before preparation")
        state["stage"] = "original_definition_verification"
        original = read(ROOT / STUDY / "REGISTRATION.json")
        demand(identity(ROOT / STUDY / "REGISTRATION.json")["sha256"] == protocol["original_registration_sha256"],
               "original registration differs")
        demand(identity(ROOT / STUDY / "PROTOCOL.json")["sha256"] == original["protocol_sha256"],
               "the original protocol was modified before preparation")
        original_protocol = read(ROOT / STUDY / "PROTOCOL.json")
        demand(len(original["sources"]) == 31, "the original evaluator closure must have 31 bindings")
        verify_bindings(ROOT, original["sources"])
        demand(identity(ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/FROZEN_COHORT_RESULT.json")["sha256"]
               == protocol["original_cohort_sha256"], "original stopped cohort differs")
        state["stage"] = "launch_qualification"
        event = read(os.environ["GITHUB_EVENT_PATH"])
        save(evidence / "LAUNCH_EVENT.json", {"event": os.environ.get("GITHUB_EVENT_NAME"),
            "head_commit": event.get("head_commit"), "inputs": event.get("inputs")})
        launch = validate_launch(protocol, os.environ, event, head)
        verify_launch_history(protocol, launch, evidence)
        fixed_helpers = helper_bindings()
        state["stage"] = "resource_preparation"
        resource_admit(evidence, "before_preparation")
        state["stage"] = "tool_installation"
        clang, rustc = install_toolchains(evidence)
        state["stage"] = "downloads"
        cache = runner_temp / ("hepta-agent-recovery-cache-" + os.environ["GITHUB_RUN_ID"])
        cache.mkdir(exist_ok=False)
        paths = {item["id"]: download_fixed(evidence, cache, item)
                 for item in items_for_download(original_protocol)}
        binary = extract_runtime(paths["llama_runtime"], cache / "runtime", evidence)
        state["stage"] = "source_snapshot"
        snapshot = prepare_snapshot(evidence, protocol, original, head)
        study = snapshot / STUDY
        helper = str(HERE / "prepare_controls.py")
        state["stage"] = "fresh_orchestration_controls"
        run_command(evidence, "orchestration-controls", [sys.executable, "-B", helper,
            "--snapshot", str(snapshot), "--output", str(evidence / "unit-controls"), "--phase", "unit"], timeout=120)
        state["stage"] = "fresh_native_controls"
        run_command(evidence, "native-controls", [sys.executable, "-B", helper,
            "--snapshot", str(snapshot), "--output", str(evidence / "native-controls"), "--phase", "native",
            "--clang", clang, "--rustc", rustc], timeout=900)
        state["stage"] = "non_generative_capacity"
        resource_admit(evidence, "before_capacity")
        run_command(evidence, "capacity", [sys.executable, "-B", str(study / "tokenizer_check.py"),
            "--output", str(evidence / "capacity"), "--binary", str(binary),
            "--qwen", str(paths["qwen_coder1_5b"]), "--granite", str(paths["granite2b"])], cwd=snapshot, timeout=600)
        copy_new(evidence / "capacity/RESULT.json", study / "TOKENIZER_CAPACITY.json")
        state["stage"] = "new_registration"
        run_command(evidence, "register", [sys.executable, "-B", str(study / "run_study.py"), "register"],
                    cwd=snapshot, timeout=120)
        registration = read(study / "REGISTRATION.json")
        demand(registration["sources"] == original["sources"]
            and registration["prompts_and_schemas"] == original["prompts_and_schemas"]
            and registration["fixtures_canonical_sha256"] == original["fixtures_canonical_sha256"]
            and registration["fixtures_sha256"] == original["fixtures_sha256"],
            "replication source, prompt, schema or fixture content differs")
        verify_bindings(ROOT, fixed_helpers)
        copy_new(study / "REGISTRATION.json", evidence / "EVALUATOR_REGISTRATION.json")
        save(evidence / "RECOVERY_REGISTRATION.json", {"schema": "hepta.agent.assembly-recovery.registration.v1",
            "study_id": protocol["study_id"], "registered_unix_ns": time.time_ns(),
            "model_completions_before_registration": 0, "launch": launch,
            "protocol": protocol, "protocol_identity": identity(HERE / "PROTOCOL.json"),
            "original_registration_sha256": protocol["original_registration_sha256"],
            "original_cohort_sha256": protocol["original_cohort_sha256"],
            "evaluator_registration": identity(study / "REGISTRATION.json"),
            "exact_original_source_bindings": original["sources"],
            "same_prompt_schema_fixture_inventory": True, "helper_sources": fixed_helpers,
            "tools": {"clang": identity(clang), "rustc": identity(rustc), "binary": identity(binary),
                      "python": identity(sys.executable)},
            "seen_tasks_and_prior_results": True, "independent_cohort": True})
        suite = evidence / "raw-suite"
        for model in original_protocol["models"]:
            state["stage"] = "model_" + model["id"]
            verify_bindings(snapshot, original["sources"])
            verify_bindings(ROOT, fixed_helpers)
            resource_admit(evidence, "before_" + model["id"])
            argv = [sys.executable, "-B", str(study / "run_study.py"), "run", "--output", str(suite),
                "--model-id", model["id"], "--model-path", str(paths[model["id"]]), "--binary", str(binary),
                "--clang", clang, "--rustc", rustc]
            run_command(evidence, "model-" + model["id"], [sys.executable, "-B", str(HERE / "measure_child.py"),
                "--receipt", str(evidence / (model["id"] + ".OUTER.json")), "--", *argv], cwd=snapshot)
            terminal = read(suite / model["id"] / "MODEL_RESULT.json")
            demand(terminal["valid_observation"] is True and terminal["status"] == "all_cells_attempted"
                   and terminal["coverage_complete"] is True and len(terminal["cells"]) == 12,
                   "a model is incomplete or invalid; no next family or replacement")
            state["completed_models"].append(model["id"])
            save(evidence / ("RESOURCE_after_" + model["id"] + ".json"), resource_gate.observe())
        state["stage"] = "frozen_cohort_summary"
        run_command(evidence, "summarize", [sys.executable, "-B", str(study / "run_study.py"),
            "summarize", "--output", str(suite)], cwd=snapshot, timeout=120)
        result = read(suite / "RESULT.json")
        verify_bindings(ROOT, fixed_helpers)
        verify_bindings(snapshot, original["sources"])
        state.update(status="completed", complete_valid_coverage=result["complete_valid_coverage"],
                     cross_family_claims_eligible=result["complete_valid_coverage"],
                     descriptive_cross_family_gates=result["cross_family_gates"],
                     descriptive_assembly_vs_json_gates=result["cross_family_assembly_vs_json_gates"])
    except BaseException as error:
        state.update(status="incomplete", error={"type": type(error).__name__, "message": str(error)})
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        state.update(wrapper_wall_ns=time.monotonic_ns()-started,
                     model_deadline_policy_unchanged=True,
                     outer_deadline_is_infrastructure_only=True)
        if suite is not None and suite.exists():
            state["retained_raw_counts"] = {
                "cell_files": len(list(suite.glob("*/*/CELL.json"))),
                "transport_request_files": len(list(suite.glob("*/engine-*/transport-*.request.json"))),
                "transport_complete_response_files": len(list(suite.glob("*/engine-*/transport-*.response.raw")))}
        save(evidence / "TERMINAL.json", state)
        _RUN_DEADLINE = None
    print(json.dumps({"study_id": protocol["study_id"], "status": state["status"],
                      "complete_valid_coverage": state["complete_valid_coverage"],
                      "retained_raw_counts": state.get("retained_raw_counts")}), flush=True)
    return 0 if state["status"] == "completed" and state["complete_valid_coverage"] else 1


def permitted_artifact_file(path):
    lowered = path.name.lower()
    return not (".gguf" in lowered or lowered.endswith((".deb", ".rpm", ".deb.partial", ".rpm.partial"))
                or lowered.startswith("llama-b11669-bin-") or lowered == "llama-server")


def evidence_inventory(directory, *, excluded=()):
    """A bounded regular-file inventory, with no cache or secret payloads."""
    directory = Path(directory)
    files, total = {}, 0
    for path in sorted(directory.rglob("*")):
        remaining_time()
        demand(not path.is_symlink() and (path.is_dir() or path.is_file()),
               "nonregular evidence entry is forbidden")
        if path.is_dir():
            continue
        name = str(path.relative_to(directory))
        if name in excluded:
            continue
        # Model/runtime/tool material lives in a separate sibling cache. The
        # evidence contains source archives and actual native candidates only.
        demand(permitted_artifact_file(path),
               "downloaded model/runtime/tool material cannot enter the artifact")
        size = path.stat().st_size
        total += size
        demand(len(files) < 20000 and size <= 512 * 1024**2 and total <= 2 * 1024**3,
               "raw evidence inventory exceeds its fixed archive bound")
        files[name] = identity(path)
    return {"files": files, "member_count": len(files), "bytes": total,
            "exclusions": list(excluded), "all_regular": True,
            "weights_runtime_and_installation_packages_excluded": True}


def stage_artifact(evidence, destination, summary=None):
    """Copy only bounded regular evidence into the path used by upload-artifact.

    A failed inventory still permits retaining safe partial evidence. Rejected
    paths are recorded, never followed; their presence makes staging incomplete.
    No study, archive or model invocation is retried.
    """
    started = time.monotonic_ns()
    deadline = time.monotonic() + 300
    destination = Path(destination).absolute()
    demand(destination != evidence and not destination.is_relative_to(evidence)
           and not evidence.is_relative_to(destination), "upload staging must be a separate new directory")
    destination.mkdir(exist_ok=False)
    record = {"schema": "hepta.agent.assembly-recovery.upload-staging.v1", "files": {},
              "rejected": [], "errors": [], "complete": False, "upload_duration_ns": None,
              "model_or_native_executions": 0, "deadline_seconds": 300}
    total = 0
    try:
        for path in sorted(evidence.rglob("*")):
            demand(time.monotonic() < deadline, "upload staging deadline exceeded")
            name = str(path.relative_to(evidence))
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                record["rejected"].append({"path": name, "reason": "nonregular path"})
                continue
            if path.is_dir():
                continue
            if not permitted_artifact_file(path):
                record["rejected"].append({"path": name, "reason": "model/runtime/tool payload"})
                continue
            size = path.stat().st_size
            if size > 512 * 1024**2 or total+size > 2 * 1024**3 or len(record["files"]) >= 20000:
                record["rejected"].append({"path": name, "reason": "fixed evidence byte/count bound"})
                continue
            target = destination / name
            copy_new(path, target)
            actual = identity(target)
            demand(identity(path)["sha256"] == actual["sha256"], "source changed during artifact staging")
            record["files"][name] = {"bytes": actual["bytes"], "sha256": actual["sha256"]}
            total += size
        record["complete"] = not record["rejected"]
    except BaseException as failure:
        record["errors"].append({"type": type(failure).__name__, "message": str(failure)})
    finally:
        # A failed copy can leave useful partial bytes. Inventory the actual
        # upload directory, including those bytes, rather than only files for
        # which copying and the source comparison completed successfully.
        verified = record["files"]
        actual_files = {}
        for path in sorted(destination.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            name = str(path.relative_to(destination))
            if path.is_symlink() or not path.is_file():
                record["errors"].append({"type": "UnexpectedStagingEntry", "message": name})
                continue
            try:
                item = identity(path)
                actual_files[name] = {"bytes": item["bytes"], "sha256": item["sha256"],
                    "source_copy_verified": verified.get(name) == {"bytes": item["bytes"], "sha256": item["sha256"]}}
            except BaseException as failure:
                record["errors"].append({"type": type(failure).__name__, "message": str(failure), "path": name})
                actual_files[name] = {"bytes": path.stat().st_size, "sha256": None, "source_copy_verified": False}
        record["files"] = actual_files
        record["complete"] = not record["rejected"] and not record["errors"]
        record.update(bytes=sum(item["bytes"] for item in actual_files.values()), member_count=len(actual_files), wall_ns=time.monotonic_ns()-started,
            staging_receipt_self_hash_excluded=True)
        if summary is not None:
            qualified = bool(summary["complete_valid_coverage"] and not summary["errors"]
                             and record["complete"] and not record["errors"])
            result = {**summary, "schema": "hepta.agent.assembly-recovery.result.v1",
                "complete_valid_coverage": qualified,
                "artifact_staging_complete": record["complete"] and not record["errors"],
                "artifact_staging_wall_ns": record["wall_ns"],
                "publication_evidence_qualified": qualified,
                "qualified_descriptive_cross_family_gates": summary.get("descriptive_cross_family_gates") if qualified else {"maintenance": False, "upgrade": False},
                "qualified_descriptive_assembly_vs_json_gates": summary.get("descriptive_assembly_vs_json_gates") if qualified else {"maintenance": False, "upgrade": False},
                "general_agent_advantage_claim": False, "artifact_upload_duration_ns": None}
            save(destination / "RECOVERY_RESULT.json", result)
            saved = identity(destination / "RECOVERY_RESULT.json")
            record["files"]["RECOVERY_RESULT.json"] = {"bytes": saved["bytes"], "sha256": saved["sha256"]}
            record["bytes"] += saved["bytes"]
            record["member_count"] += 1
        save(destination / "ARTIFACT_STAGING.json", record)
    return record


def raw_model_inventory(suite, models):
    """Describe receipt presence without rescoring a missing or partial cell."""
    rows = []
    for model in models:
        folder = suite / model["id"]
        cell_files = sorted(folder.glob("*/CELL.json"))
        path = folder / "MODEL_RESULT.json"
        value = read(path) if path.is_file() else None
        engines = value.get("engines", []) if value is not None else []
        rows.append({"model_id": model["id"], "planned_cells": 12,
            "retained_cell_files": len(cell_files), "unattempted_or_no_terminal_cell_receipt": 12-len(cell_files),
            "terminal_present": value is not None,
            "reported_status": value.get("status") if value is not None else None,
            "reported_error": value.get("error") if value is not None else None,
            "reported_valid_observation": value.get("valid_observation") if value is not None else None,
            "reported_successes_not_independently_audited_here": sum(cell.get("correct") is True for cell in value.get("cells", [])) if value is not None else None,
            "recorded_engine_count": len(engines),
            "recorded_engine_shutdowns": sum(engine.get("process_exited") is True for engine in engines),
            "all_descendants_closed": None,
            "shutdown_scope": "Only existing frozen engine.close receipts; no inferred receipt for an outer-killed process or independent Clang session"})
    return rows


def finalize(output):
    """Read and archive available evidence once, without native/model work."""
    global _RUN_DEADLINE
    started = time.monotonic_ns()
    evidence = Path(output).absolute()
    evidence.mkdir(parents=True, exist_ok=True)
    demand(not (evidence / "FINALIZE_START.json").exists(), "evidence finalization cannot be retried")
    protocol = read(HERE / "PROTOCOL.json")
    # A fresh finalization budget, independent of a consumed inference budget.
    # Staging has a separate five-minute bound; upload retains the last reserve.
    _RUN_DEADLINE = time.monotonic() + 1200
    save(evidence / "FINALIZE_START.json", {"started_unix_ns": time.time_ns(),
        "readout_and_archive_only": True, "new_model_or_native_executions": 0,
        "independent_of_exhausted_run_deadline": True, "deadline_seconds": 1200,
        "automatic_retry": False})
    record = {"schema": "hepta.agent.assembly-recovery.finalization.v1",
        "study_id": protocol["study_id"], "errors": [], "steps": {},
        "model_or_native_executions": 0, "complete_valid_coverage": False,
        "general_agent_advantage_claim": False, "causal_memory_effect_claim": False,
        "unseen_task_claim": False, "original_cells_replaced_or_pooled": False}
    suite, snapshot = evidence / "raw-suite", evidence / "source-snapshot"
    script_directory = ROOT / "experiments/hia_agent_assembly_v4_readout_20261030"

    def perform(label, operation):
        stamp = time.monotonic_ns()
        try:
            value = operation()
            record["steps"][label] = {"passed": True, "wall_ns": time.monotonic_ns()-stamp}
            return value
        except BaseException as failure:
            error = {"stage": label, "type": type(failure).__name__, "message": str(failure)}
            record["errors"].append(error)
            record["steps"][label] = {"passed": False, "error": error, "wall_ns": time.monotonic_ns()-stamp}
            return None

    try:
        # All governed source and protocol bytes precede the potentially failed
        # launch. If setup never reached run(), retain them in this final step.
        if not (evidence / "DEFINITION_RETENTION.json").exists():
            perform("retain_definitions", lambda: retain_definitions(evidence, protocol))
        registration = read(evidence / "RECOVERY_REGISTRATION.json") if (evidence / "RECOVERY_REGISTRATION.json").is_file() else None
        bound = False
        if registration is not None:
            def verify_registered_sources():
                original_path = ROOT / STUDY / "REGISTRATION.json"
                demand(identity(original_path)["sha256"] == protocol["original_registration_sha256"],
                       "original registration differs at finalization")
                original_registration = read(original_path)
                demand(registration["protocol"] == protocol
                       and registration["exact_original_source_bindings"] == original_registration["sources"]
                       and registration["original_registration_sha256"] == protocol["original_registration_sha256"]
                       and registration["original_cohort_sha256"] == protocol["original_cohort_sha256"],
                       "replication registration differs from its governing identities")
                verify_bindings(ROOT, registration["helper_sources"])
                verify_bindings(snapshot, registration["exact_original_source_bindings"])
                demand(identity(snapshot / STUDY / "REGISTRATION.json") == registration["evaluator_registration"],
                       "evaluator registration differs at finalization")
                return True
            bound = perform("registered_sources", verify_registered_sources) is True
        if bound and (suite / "SUITE_PLAN.json").is_file() and not (suite / "RESULT.json").exists():
            if (evidence / "summarize.command.json").exists():
                record["steps"]["summarize"] = {"passed": False, "skipped": "previous summarize invocation retained; no automatic retry"}
            else:
                perform("summarize", lambda: run_command(evidence, "summarize",
                    [sys.executable, "-B", str(snapshot / STUDY / "run_study.py"), "summarize", "--output", str(suite)],
                    cwd=snapshot, timeout=120))
        models = [{"id": identifier} for identifier in protocol["frozen_execution"]["model_order"]]
        all_model_records = all((suite / model["id"] / "MODEL_RESULT.json").is_file()
                                and (suite / model["id"] / "PLAN.json").is_file() for model in models)
        audit = None
        if bound and all_model_records and (suite / "RESULT.json").is_file():
            def readout():
                run_command(evidence, "independent-readout", [sys.executable, "-B", str(script_directory / "readout.py"),
                    "--suite", str(suite), "--snapshot", str(snapshot), "--output", str(evidence / "independent-readout")], timeout=180)
                return read(evidence / "independent-readout/RESULT.json")
            audit = perform("independent_readout", readout)
            perform("response_diagnosis", lambda: run_command(evidence, "response-diagnosis", [sys.executable, "-B",
                str(script_directory / "diagnose.py"), "--suite", str(suite), "--snapshot", str(snapshot),
                "--output", str(evidence / "response-diagnosis")], timeout=120))
        else:
            record["steps"]["independent_readout"] = {"passed": False,
                "unavailable": "Both model terminal records, a bound registration and cohort summary are required; missing observations are not fabricated"}
        terminal = read(evidence / "TERMINAL.json") if (evidence / "TERMINAL.json").is_file() else None
        record.update(wrapper_terminal_status=terminal.get("status") if terminal else "unavailable",
            wrapper_terminal_error=terminal.get("error") if terminal else None,
            models=raw_model_inventory(suite, models),
            bootstrap_to_executor_ns=(read(evidence / "RUN_START.json").get("bootstrap_to_executor_ns")
                                      if (evidence / "RUN_START.json").is_file() else None),
            original_registration_sha256=protocol["original_registration_sha256"],
            original_cohort_sha256=protocol["original_cohort_sha256"],
            recovery_registration=identity(evidence / "RECOVERY_REGISTRATION.json") if registration else None,
            audited_totals=audit["totals"] if audit is not None else None,
            independent_readout_available=audit is not None,
            complete_valid_coverage=bool(terminal and terminal["status"] == "completed" and bound
                                        and audit is not None and audit["complete_valid_coverage"]),
            descriptive_cross_family_gates=audit["cross_family_gates"] if audit is not None else None,
            descriptive_assembly_vs_json_gates=audit["cross_family_assembly_vs_json_gates"] if audit is not None else None,
            interpretation=protocol["interpretation"],
            costs={"nested_intervals_must_not_be_added_twice": True,
                   "all_preparation_command_download_and_control_receipts_retained": True,
                   "unknown": protocol["costs"]["unknown"], "complete_economic_cost": None})
        # Preflight the complete raw tree before compression. No weight/tool
        # material is archived, even if a future change misplaces the cache.
        safe = perform("prearchive_inventory", lambda: evidence_inventory(evidence))
        if safe is not None:
            for name, source in (("raw-suite", suite), ("source-snapshot", snapshot)):
                if source.is_dir():
                    perform("archive_" + name, lambda name=name, source=source: run_command(evidence, "archive-" + name,
                        [sys.executable, "-B", str(script_directory / "archive_evidence.py"), str(source),
                         str(evidence / (name + ".tar.xz"))], timeout=420))
        if record["errors"]:
            record["complete_valid_coverage"] = False
    except BaseException as failure:
        record["errors"].append({"stage": "finalization", "type": type(failure).__name__, "message": str(failure)})
        record["complete_valid_coverage"] = False
    finally:
        record["finalization_wall_ns_before_final_inventory"] = time.monotonic_ns()-started
        record["new_model_or_native_executions"] = 0
        save(evidence / "FINALIZE.json", record)
        inventory_start = time.monotonic_ns()
        try:
            inventory = evidence_inventory(evidence, excluded=("ARTIFACT_MANIFEST.json", "ARTIFACT_INVENTORY_FAILURE.json"))
            inventory.update(schema="hepta.agent.assembly-recovery.artifact-manifest.v1",
                inventory_wall_ns=time.monotonic_ns()-inventory_start,
                upload_duration_ns=None, manifest_self_hash_excluded=True,
                finalization_and_inventory_total_wall_ns=time.monotonic_ns()-started)
            save(evidence / "ARTIFACT_MANIFEST.json", inventory)
        except BaseException as failure:
            save(evidence / "ARTIFACT_INVENTORY_FAILURE.json", {"type": type(failure).__name__, "message": str(failure),
                "wall_ns": time.monotonic_ns()-inventory_start, "upload_only_explicit_safe_paths": True})
            record["errors"].append({"stage": "artifact_inventory", "type": type(failure).__name__, "message": str(failure)})
        _RUN_DEADLINE = None
        staging = stage_artifact(evidence, evidence.parent / "hepta-agent-recovery-artifact", record)
        if not staging["complete"] or staging["errors"]:
            record["errors"].append({"stage": "artifact_staging", "type": "IncompleteStaging", "message": "see ARTIFACT_STAGING.json"})
    authoritative = read(evidence.parent / "hepta-agent-recovery-artifact/RECOVERY_RESULT.json")
    print(json.dumps({"study_id": protocol["study_id"],
        "complete_valid_coverage": authoritative["complete_valid_coverage"],
        "publication_evidence_qualified": authoritative["publication_evidence_qualified"],
        "independent_readout_available": authoritative.get("independent_readout_available"),
        "errors": record["errors"]}), flush=True)
    return 1 if record["errors"] else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "finalize"))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output) if args.action == "run" else finalize(args.output))
