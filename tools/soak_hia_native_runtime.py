#!/usr/bin/env python3
"""Registered, finite native-entry lifecycle load; never a service benchmark.

Every call uses the diagnostic sealed-image dispatcher. The hosted profile
requires elapsed time AND actual completed workload; a budget is not evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import resource
import re
import shutil
import subprocess
import stat
import sys
from threading import Event, Thread
from time import monotonic_ns, sleep

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_native_differential import HIADifferentialRejected
from hepta.hia_native_version_dispatch import NativeVersionDispatcher
from hepta.hia_ndu import make_plan, prepare_candidate
from hepta.hia_program import verify_program
from hepta.hia_program_tools import read_bounded
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_native_loans import _execution_counts
from tools.release_check import snapshot

SITE = ("swap_candidate", "entry", "loan")
FIXTURE = ROOT / "examples/hia_native_lifecycle/swap.json"
HOSTED = "hosted-native-lifecycle-30m.v1"
DEVELOPMENT = "development-native-lifecycle.v1"
_COMMON = {
    "schema": "hepta.hia.native-runtime-soak-profile.v1",
    "max_concurrent_calls": 2, "middle_pairs_per_epoch": 12,
    "calls_per_epoch": 33, "buffer_sizes": [5, 64, 4096, 65536],
    "minimum_pair_spacing_seconds": 0.2, "native_call_timeout_seconds": 8.0,
    "withheld_ack_timeout_seconds": 1.0, "build_wait_seconds": 60.0,
    "close_wait_seconds": 60.0, "max_evidence_bytes": 96 * 1024 * 1024,
    "report_reserve_bytes": 2 * 1024 * 1024, "minimum_free_disk_bytes": 128 * 1024 * 1024,
    "max_parent_rss_kib": 512 * 1024, "max_drained_parent_fd_growth": 4,
    "max_pacing_fraction": 0.6,
}
PROFILES = {
    HOSTED: dict(_COMMON, profile_id=HOSTED, max_wall_seconds=1800.0,
        new_epoch_deadline_seconds=1620.0, max_epochs=512, max_attempted_calls=16896,
        minimum_observation_seconds=1500.0, minimum_completed_epochs=128,
        minimum_completed_observations=5000, formal_qualification=True),
    DEVELOPMENT: dict(_COMMON, profile_id=DEVELOPMENT, max_wall_seconds=180.0,
        new_epoch_deadline_seconds=90.0, max_epochs=1, max_attempted_calls=33,
        minimum_observation_seconds=0.0, minimum_completed_epochs=1,
        minimum_completed_observations=33, formal_qualification=False),
}
CLAIMS = {
    "actual_native_children_required": True, "diagnostic_instrumentation": True,
    "selected_loan_and_endpoint_bytes_only": True, "shared_host": True,
    "production_p6_qualified": False, "production_long_term_qualified": False,
    "application_or_shared_task_runtime_qualified": False,
    "network_slo_qualified": False, "performance_gain_qualified": False,
    "all_bytes_or_full_resource_ledger_observed": False,
    "external_state_or_callback_migration_qualified": False,
    "whole_process_resources_bounded": False, "hard_wall_preemption_proved": False,
}
COUNT_KEYS = ("attempted_calls", "child_processes_started", "child_processes_reaped",
    "completed_observations", "native_entries_observed", "unavailable_child_start_outcomes",
    "unavailable_native_entry_outcomes", "unconfirmed_child_reaps")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(value).hexdigest()


def need(condition, message):
    if condition is not True:
        raise ValueError("E_NATIVE_RUNTIME_SOAK: " + message)


def profile(profile_id):
    need(type(profile_id) is str and profile_id in PROFILES, "unknown fixed profile")
    return json.loads(canonical(PROFILES[profile_id]))


def git(*args):
    result = subprocess.run(["git", "-C", str(ROOT), *args], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=10, check=False)
    need(result.returncode == 0, "source Git identity unavailable")
    return result.stdout.decode("utf-8", "strict").strip()


def tools_identity(clang):
    found = shutil.which(clang)
    need(found is not None, "Clang 20 executable unavailable")
    compiler = Path(found).resolve()
    version = run_bounded([str(compiler), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    target = run_bounded([str(compiler), "-dumpmachine"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    need(version.returncode == target.returncode == 0 and "clang version 20." in version.stdout,
         "this registered profile requires Clang 20")
    need(target.stdout.strip() in {"x86_64-unknown-linux-gnu", "x86_64-pc-linux-gnu"}, "unsupported native target")
    python = Path(sys.executable).resolve()
    return {"clang": {"path": str(compiler), "sha256": digest_executable(compiler),
                      "version": version.stdout.splitlines()[0], "target": target.stdout.strip()},
            "python": {"path": str(python), "sha256": digest_executable(python), "version": sys.version},
            "rustc_used": False}


def registration(profile_id, clang):
    selected = profile(profile_id)
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    need(not selected["formal_qualification"] or not status, "formal registration requires committed clean source")
    need(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
         "Linux x86-64 is required")
    return {"schema": "hepta.hia.native-runtime-soak-registration.v1",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "profile": selected, "profile_sha256": digest(canonical(selected)),
            "source": {"git_commit": git("rev-parse", "HEAD"), "git_status": status, "snapshot": snapshot()},
            "tools": tools_identity(clang), "fixture_sha256": digest(FIXTURE.read_bytes()),
            "host": {"system": platform.system(), "machine": platform.machine(),
                     "kernel": platform.release(), "cpu_count": os.cpu_count()},
            "claims": dict(CLAIMS)}


def validate_registration(value):
    from tools.hia_runtime_soak_evidence import validate_registration as replay_registration
    return replay_registration(value)


def process_resources(pid=None):
    """Best-effort Linux sample; no RSS maximum or whole-memory proof."""
    pid = os.getpid() if pid is None else pid
    base = Path("/proc") / str(pid)
    try:
        before = (base / "stat").read_text()
        identity = before.rsplit(")", 1)[1].split()[19]  # Linux stat field 22.
        status = (base / "status").read_text().splitlines()
        fields = {row.split(":", 1)[0]: row.split(":", 1)[1].strip() for row in status if ":" in row}
        descriptors = len(os.listdir(base / "fd"))
        after = (base / "stat").read_text().rsplit(")", 1)[1].split()[19]
        need(identity == after, "process identity changed during resource sample")
        return {"available": True, "pid": pid, "starttime_ticks": int(identity),
                "fd_count": descriptors, "rss_kib": int(fields["VmRSS"].split()[0]),
                "vm_hwm_kib": int(fields["VmHWM"].split()[0]), "threads": int(fields["Threads"])}
    except (OSError, KeyError, ValueError, IndexError) as error:
        return {"available": False, "pid": pid, "reason": type(error).__name__, "message": str(error)[:512]}


def latencies(values):
    if not values:
        return {"samples": 0, "p50_ns": None, "p95_ns": None, "p99_ns": None, "max_ns": None}
    ordered = sorted(values)
    return {"samples": len(values), "p50_ns": ordered[math.ceil(len(values) * .50) - 1],
            "p95_ns": ordered[math.ceil(len(values) * .95) - 1],
            "p99_ns": ordered[math.ceil(len(values) * .99) - 1], "max_ns": ordered[-1]}


def workload_complete(selected, counts, epochs, observation_ns, pacing_ns):
    """Declared time AND actual work are necessary, independently of caps."""
    return (epochs >= selected["minimum_completed_epochs"]
            and counts["completed_observations"] >= selected["minimum_completed_observations"]
            and observation_ns >= selected["minimum_observation_seconds"] * 1e9
            and pacing_ns <= observation_ns * selected["max_pacing_fraction"]
            and counts["unavailable_child_start_outcomes"] == counts["unconfirmed_child_reaps"] == 0
            and counts["child_processes_started"] == counts["child_processes_reaped"] == counts["attempted_calls"])


class EvidenceBudgetExceeded(RuntimeError):
    pass


class Journal:
    """Append all actions/samples; bound retained output before each write."""
    def __init__(self, output, selected):
        self.output, self.selected = Path(output).absolute(), selected
        need(self.output != ROOT and ROOT not in self.output.parents, "evidence must be outside the source checkout")
        need(not self.output.exists() and not self.output.is_symlink(), "evidence output must be new")
        self.output.mkdir(parents=True)
        (self.output / "objects").mkdir()
        self.used = 0
        self.sequence = 0
        self.chain = "0" * 64
        self.stream = (self.output / "events.jsonl").open("xb")

    def _reserve(self, size):
        if self.used + size > self.selected["max_evidence_bytes"] - self.selected["report_reserve_bytes"]:
            raise EvidenceBudgetExceeded("retained evidence budget exhausted; no more admission")
        self.used += size

    def event(self, kind, value):
        row = {"sequence": self.sequence, "previous_sha256": self.chain, "kind": kind, "value": value}
        raw = canonical(row) + b"\n"
        self._reserve(len(raw))
        self.stream.write(raw)
        self.stream.flush()
        self.chain = digest(raw)
        self.sequence += 1
        return {"sequence": row["sequence"], "sha256": self.chain}

    def retain(self, raw, suffix):
        identity = digest(raw)
        destination = self.output / "objects" / (identity + suffix)
        if not destination.exists():
            self._reserve(len(raw))
            with destination.open("xb") as stream:
                stream.write(raw)
        return {"path": str(destination.relative_to(self.output)), "sha256": identity, "bytes": len(raw)}

    def checkpoint(self, report):
        raw = canonical(report) + b"\n"
        need(len(raw) * 2 <= self.selected["report_reserve_bytes"], "report exceeded its reserved output budget")
        temporary = self.output / "report.json.tmp"
        temporary.write_bytes(raw)
        temporary.replace(self.output / "report.json")


class NativeRuntimeSoak:
    """Keep any unconfirmed dispatcher owner attached to this run object."""
    def __init__(self, registered, output):
        self.profile = validate_registration(registered)
        self.registered = registered
        self.journal = Journal(output, self.profile)
        self.host = None
        self.handles = []
        self.start_ns = monotonic_ns()
        self.pacing_ns = 0
        self.next_pair_ns = self.start_ns
        self.counts = Counter({key: 0 for key in COUNT_KEYS})
        self.cases = Counter()
        self.call_times = []
        self.build_times = []
        self.attempt_id = 0
        self.cancelled_builds = 0
        self.epoch = 0
        self.phase = "identity_setup"
        self.recovery_thread = None
        self.report = {"schema": "hepta.hia.native-runtime-soak.v2", "status": "running", "ok": False,
            "execution_passed": False, "claims": dict(CLAIMS), "profile": self.profile,
            "registration_sha256": digest(canonical(registered)), "started_utc": datetime.now(timezone.utc).isoformat(),
            "source_git_commit": registered["source"]["git_commit"],
            "source_was_committed": registered["source"]["git_status"] == "", "host": registered["host"],
            "completed_epochs": 0, "stop_reason": None, "failure": None, "drained": False,
            "counts": {}, "resources": {}, "timing": {}}

    def elapsed(self):
        return monotonic_ns() - self.start_ns

    def remaining(self):
        return max(0.0, self.profile["max_wall_seconds"] - self.elapsed() / 1e9)

    def record(self, kind, value):
        value = {"epoch": self.epoch, "elapsed_ns": self.elapsed(), **value}
        return {**self.journal.event(kind, value), "elapsed_ns": value["elapsed_ns"]}

    def cleanup_record(self, kind, value):
        # Cleanup and denominator accounting must continue even if the main
        # journal has exhausted its budget or its write failed. The separate
        # report reserve can retain the bounded current epoch's terminal rows.
        try:
            return self.record(kind, value)
        except (EvidenceBudgetExceeded, OSError) as error:
            self.report.setdefault("evidence_write_error", self.error(error))
            self.report.setdefault("emergency_events", []).append({"kind": kind, "value": value})

    def pace(self):
        before = monotonic_ns()
        if before < self.next_pair_ns:
            sleep(min((self.next_pair_ns - before) / 1e9, self.remaining()))
        waited = monotonic_ns() - before
        self.pacing_ns += waited
        self.next_pair_ns = monotonic_ns() + int(self.profile["minimum_pair_spacing_seconds"] * 1e9)
        self.record("pacing", {"wait_ns": waited, "kind": "offered_load_spacing_not_native_work"})

    def image(self, identity):
        version = self.host._versions[identity]
        raw = os.pread(version.descriptor, version.artifact_bytes + 1, 0)
        need(len(raw) == version.artifact_bytes and digest(raw) == version.artifact_sha256, "actual sealed image differs")
        return {"program_sha256": identity, "artifact": self.journal.retain(raw, ".so"),
                "build_receipt": self.journal.retain(canonical(version.receipt()), ".build.json")}

    def build_receipt(self, receipt):
        receipt = dict(receipt)
        native = receipt.pop("native_receipt", None)
        if native is not None:
            receipt["native_receipt_object"] = self.journal.retain(canonical(native), ".build.json")
        return receipt

    def begin(self, name, arguments, expected, *, hold=True, timeout=None):
        self.phase = "admission:" + name
        need(self.attempt_id < self.profile["max_attempted_calls"], "attempted-call budget exhausted")
        need(self.remaining() >= 20, "no native admission inside final cleanup reserve")
        self.attempt_id += 1
        row = {"attempt_id": self.attempt_id, "epoch": self.epoch, "case": name, "entry": "native_swap",
            "arguments": arguments, "expected": expected, "start_ns": self.elapsed(),
            "admission_version": self.host.snapshot()["active_sha256"], "dispatcher_admission_attempted": False}
        item = [row, None]
        self.handles.append(item)
        self.record("attempt", row)
        try:
            row["dispatcher_admission_attempted"] = True
            handle = self.host.start_loan_probe("native_swap", arguments,
                timeout=self.profile["native_call_timeout_seconds"] if timeout is None else timeout)
            item[1] = handle
            if hold:
                held = handle.wait_active(timeout=5 if timeout is None else timeout)
                need(held["held"] is True and len(held["events"]) == 1, "selected real loan not held")
                row["loan_observed_ns"] = self.elapsed()
                row["child_resource_sample"] = process_resources(held["child_process"]["pid"])
                row["held_program_sha256"] = held["program_sha256"]
                row["held_artifact_sha256"] = held["artifact_sha256"]
                self.record("loan_held", {"attempt_id": row["attempt_id"], "observation": self.compact(held)})
            return item
        except BaseException as error:
            row["error"] = self.error(error)
            row["observed_ns"] = self.elapsed()
            raise

    @staticmethod
    def error(error):
        value = {"type": type(error).__name__, "message": str(error)[:4096]}
        return dict(value, identity=digest(canonical(value)))

    @staticmethod
    def compact(observation):
        return {key: observation[key] for key in ("schema", "generation", "program_sha256", "artifact_sha256",
            "events", "ack_sent", "done", "held", "quarantined", "child_process", "error")}

    def finish(self, item, *, resume=True):
        row, handle = item
        self.phase = "observation:" + row["case"]
        try:
            if resume:
                handle.resume()
                row["resumed_ns"] = self.elapsed()
            try:
                result = handle.wait(timeout=min(12.0, max(.001, self.remaining())))
            except HIADifferentialRejected as error:
                if row["expected"] != "timeout" or "timed out" not in str(error):
                    raise
                row["expected_rejection"] = self.error(error)
                observation = handle.snapshot()
                need(observation["done"] and not observation["ack_sent"] and len(observation["events"]) == 1,
                     "timeout did not retain exactly the held loan")
            else:
                row["result"] = {key: result[key] for key in ("schema", "generation", "program_sha256",
                    "artifact_sha256", "status", "value", "native_observation")}
                observation = result["observation"]
                if row["expected"] == "return":
                    need(result["status"] == "returned" and result["value"] == 55, "native return differs")
                    events = observation["events"]
                    length = row["arguments"][0]
                    need(len(events) == 2 and events[0]["bytes"] == events[1]["bytes"] == length,
                         "normal loan event count/extent differs")
                    need((events[0]["first_byte"], events[0]["last_byte"]) == (0, 0)
                         and (events[1]["first_byte"], events[1]["last_byte"]) == (55, 11 if length == 5 else 0),
                         "actual loan endpoint bytes differ")
                elif row["expected"] in {"trap_in_loan", "trap_before_loan"}:
                    need(result["status"] == "trapped" and len(observation["events"]) ==
                         (1 if row["expected"] == "trap_in_loan" else 0), "trap observation differs")
                else:
                    raise ValueError("expected timeout returned")
            row["control_passed"] = True
        except BaseException as error:
            row["error"] = self.error(error)
            raise
        finally:
            row["observed_ns"] = self.elapsed()
            self.record("terminal_observation", {"attempt_id": row["attempt_id"],
                "control_passed": row.get("control_passed", False), "error": row.get("error")})

    def pair(self, prefix, length):
        self.pace()
        return [self.begin(prefix + "-" + str(i), [length, 0, 4, 0], "return") for i in range(2)]

    def run_epoch(self, baseline, candidate):
        self.handles = []
        self.phase = "baseline_build"
        self.record("build_attempt", {"operation": self.phase, "program_sha256": baseline.sha256})
        before = monotonic_ns()
        self.host = NativeVersionDispatcher(baseline.canonical_bytes,
            clang=self.registered["tools"]["clang"]["path"], max_in_flight=2, diagnostic_loan_site=SITE)
        self.build_times.append(monotonic_ns() - before)
        self.record("baseline_build", {"image": self.image(baseline.sha256), "build_wall_ns": self.build_times[-1]})
        self.phase = "candidate_cancellation"
        self.record("build_attempt", {"operation": self.phase, "program_sha256": candidate.sha256})
        before = monotonic_ns()
        queued = self.host.stage_candidate_async(candidate.canonical_bytes)
        cancelled = self.host.cancel_candidate(queued["job_id"])
        done = self.host.wait_candidate(queued["job_id"], timeout=min(60, self.remaining()))
        self.build_times.append(monotonic_ns() - before)
        self.record("cancel_attempt", {"submitted": queued, "cancel": cancelled, "finished": self.build_receipt(done),
            "dispatch": self.host.snapshot(), "build_control_wall_ns": self.build_times[-1]})
        need(done["status"] in {"cancelled", "staged"}, "candidate cancellation/build failed or unfinished")
        if done["status"] == "cancelled":
            self.cancelled_builds += 1
            need(not done["published"] and self.host.snapshot()["active_sha256"] == baseline.sha256,
                 "cancelled build changed active version")
        else:
            need(cancelled["changed"] is False, "accepted cancellation published a candidate")
        self.phase = "candidate_stage"
        self.record("build_attempt", {"operation": self.phase, "program_sha256": candidate.sha256})
        before = monotonic_ns()
        queued = self.host.stage_candidate_async(candidate.canonical_bytes)
        done = self.host.wait_candidate(queued["job_id"], timeout=min(60, self.remaining()))
        self.build_times.append(monotonic_ns() - before)
        self.record("candidate_build", {"finished": self.build_receipt(done), "build_wall_ns": self.build_times[-1]})
        need(done["status"] == "staged", "candidate build failed or unfinished")
        self.record("staged_image", {"image": self.image(candidate.sha256)})

        self.pace()
        old = self.begin("baseline-across-activation", [5, 0, 4, 0], "return")
        self.record("activation", self.host.activate(candidate.sha256, expected_generation=0))
        current = self.begin("candidate-after-activation", [5, 0, 4, 0], "return")
        need(old[0]["held_program_sha256"] == baseline.sha256
             and current[0]["held_program_sha256"] == candidate.sha256
             and self.host.snapshot()["in_flight"] == 2, "activation lost actual held-call identity")
        self.finish(current)
        self.finish(old)
        for number in range(self.profile["middle_pairs_per_epoch"]):
            length = self.profile["buffer_sizes"][(self.epoch + number) % len(self.profile["buffer_sizes"])]
            for item in self.pair("steady-" + str(number), length):
                self.finish(item)
        pending = self.pair("candidate-across-rollback", 5)
        descriptor = self.host._versions[candidate.sha256].descriptor
        self.record("rollback", self.host.rollback(expected_generation=1))
        need(os.fstat(descriptor).st_size > 0 and self.host.snapshot()["in_flight"] == 2,
             "rollback discarded an active native image")
        for item in pending:
            self.finish(item)
        need(candidate.sha256 not in {row["sha256"] for row in self.host.snapshot()["versions"]},
             "inactive candidate did not retire after actual calls drained")
        self.finish(self.begin("trap-in-loan", [5, 5, 0, 0], "trap_in_loan"))
        self.finish(self.begin("trap-before-loan", [2**32 - 1, 0, 4, 0], "trap_before_loan", hold=False), resume=False)
        self.finish(self.begin("withheld-ack", [5, 0, 4, 0], "timeout",
            timeout=self.profile["withheld_ack_timeout_seconds"]), resume=False)
        pending = self.pair("baseline-across-close", 5)
        closing = self.host.close(wait=False)
        self.record("close_while_held", closing)
        need(not closing["drained"] and self.host.snapshot()["in_flight"] == 2, "close abandoned held native loans")
        for item in pending:
            self.finish(item)

    def close_epoch(self):
        closed = None
        failure = None
        if self.host is not None:
            try:
                closed = self.host.close(wait=True, timeout=min(self.profile["close_wait_seconds"], self.remaining()))
                self.cleanup_record("epoch_cleanup", {"close": closed, "dispatch": self.host.snapshot()})
            except BaseException as error:
                failure = error
                self.report["epoch_close_error"] = self.error(error)
        for row, handle in self.handles:
            if handle is not None:
                row["final_observation"] = self.compact(handle.snapshot())
            elif not row["dispatcher_admission_attempted"]:
                row["final_observation"] = {"child_process": {"creation_attempted": False, "spawn_observed": False,
                    "child_start_count_complete": True, "native_entry_observed": False,
                    "native_entry_outcome_available": True, "cleanup": None}}
            row["finalized_ns"] = self.elapsed()
            observed = row.get("observed_ns", row["finalized_ns"])
            row["admission_to_observation_ns"] = observed - row["start_ns"]
            counts = _execution_counts([row])
            self.counts.update({key: counts[key] for key in COUNT_KEYS})
            self.cases.update([row["expected"]])
            self.call_times.append(row["admission_to_observation_ns"])
            sample = row.get("child_resource_sample")
            resources = self.report["resources"]
            if sample is not None and sample["available"]:
                resources["available_child_samples"] = resources.get("available_child_samples", 0) + 1
                resources["largest_observed_child_rss_kib"] = max(resources.get("largest_observed_child_rss_kib", 0), sample["rss_kib"])
                resources["largest_observed_child_fd_count"] = max(resources.get("largest_observed_child_fd_count", 0), sample["fd_count"])
            else:
                resources["unavailable_or_unrequested_child_samples"] = resources.get("unavailable_or_unrequested_child_samples", 0) + 1
            self.cleanup_record("sample", row)
        # Do not discard the actual owner when confirmation is unavailable.
        # A caller can retain this runner and retry runner.host.retry_cleanup.
        if closed is not None and closed["drained"]:
            self.host = None
        self.handles = []
        self.report["drained"] = self.host is None
        if failure is not None:
            raise failure
        need("evidence_write_error" not in self.report, "terminal evidence used emergency report reserve")
        need(self.report["drained"], "epoch cleanup unconfirmed; dispatcher owner retained on runner.host")

    def start_cleanup_retainer(self):
        """A failed report cannot let normal interpreter exit drop ownership."""
        if self.host is None or self.recovery_thread is not None:
            return
        self.report["initial_run_drained"] = False
        self.report["ok"] = self.report["execution_passed"] = False
        self.report["status"] = "failed_cleanup_retained"
        try:
            self.recovery_thread = Thread(target=self._recover_held_owner,
                name="hia-soak-cleanup-owner", daemon=False)
            self.recovery_thread.start()
        except BaseException as error:
            self.report["cleanup_retainer_start_error"] = self.error(error)
            if self.recovery_thread is not None and self.recovery_thread.is_alive():
                return
            # If a thread cannot be created, the current thread remains the
            # owner. A normal function/CLI return is unsafe until confirmed.
            self.recovery_thread = None
            self._recover_held_owner()

    def _recover_held_owner(self):
        host = self.host
        if host is None:
            return
        started = monotonic_ns()
        attempts = 0
        recovered = set()
        pause = Event()
        last_checkpoint = 0
        while True:
            attempts += 1
            closed = None
            try:
                outcome = host.retry_cleanup(timeout=.25)
                recovered.update(outcome["recovered_call_ids"])
                closed = host.close(wait=True, timeout=.25)
            except BaseException as error:
                self.report["recovery_last_error"] = self.error(error)
            confirmed = closed is not None and closed["drained"] is True
            self.report["cleanup_recovery"] = {"status": "confirmed" if confirmed else "retained",
                "attempts": attempts, "recovered_call_ids_observed": sorted(recovered),
                "elapsed_ns": monotonic_ns() - started, "normal_process_exit_blocked_until_confirmed": True,
                "outside_profile_measurement_budget": True,
                "qualification_promoted": False, "native_calls_reexecuted": False}
            if confirmed:
                self.report["drained"] = True
                self.report["status"] = "failed_cleanup_recovered"
                self.host = None
            now = monotonic_ns()
            if confirmed or now - last_checkpoint >= 10**9:
                try:
                    self.journal.checkpoint(self.report)
                except BaseException as error:
                    # Reporting failure must not abandon the child owner.
                    self.report["recovery_checkpoint_error"] = self.error(error)
                last_checkpoint = now
            if confirmed:
                return
            pause.wait(.1)

    def run(self):
        # This ownership boundary encloses *all* final statistics, identity
        # checks and evidence teardown. No earlier exception may skip it.
        try:
            return self._run_tracked()
        finally:
            try:
                self.journal.stream.close()
            finally:
                if self.host is not None:
                    self.start_cleanup_retainer()

    def _run_tracked(self):
        primary = None
        original_parent = process_resources()
        self.report["resources"]["parent_before"] = original_parent
        before_usage = resource.getrusage(resource.RUSAGE_SELF)
        try:
            self.record("run_start", {"parent": original_parent,
                "cpu_user_seconds": before_usage.ru_utime, "cpu_system_seconds": before_usage.ru_stime})
            need(self.registered["source"]["git_commit"] == git("rev-parse", "HEAD")
                 and self.registered["source"]["git_status"] == git("status", "--porcelain=v1", "--untracked-files=all")
                 and self.registered["source"]["snapshot"] == snapshot(), "registered source changed before load")
            need(self.registered["tools"] == tools_identity(self.registered["tools"]["clang"]["path"]),
                 "registered executable identity changed")
            fixture = read_bounded(FIXTURE)
            need(digest(fixture) == self.registered["fixture_sha256"], "fixture identity changed")
            self.report["registration_object"] = self.journal.retain(canonical(self.registered), ".registration.json")
            self.report["fixture_object"] = self.journal.retain(fixture, ".fixture.json")
            baseline = verify_program(fixture)
            candidate = prepare_candidate(baseline, make_plan(baseline, entry="native_swap")).candidate
            self.report["programs"] = {"baseline": self.journal.retain(baseline.canonical_bytes, ".core.json"),
                                       "candidate": self.journal.retain(candidate.canonical_bytes, ".core.json")}
            self.journal.checkpoint(self.report)
            for number in range(self.profile["max_epochs"]):
                if self.elapsed() >= self.profile["new_epoch_deadline_seconds"] * 1e9:
                    self.report["stop_reason"] = "new_epoch_deadline"
                    break
                if shutil.disk_usage(self.journal.output).free < self.profile["minimum_free_disk_bytes"]:
                    raise EvidenceBudgetExceeded("free disk reserve reached")
                self.epoch = number
                failure = None
                try:
                    self.run_epoch(baseline, candidate)
                except BaseException as error:
                    failure = error
                    self.report["failure_phase"] = self.phase
                try:
                    self.phase = "epoch_cleanup"
                    self.close_epoch()
                except BaseException as error:
                    if failure is None:
                        failure = error
                    else:
                        self.report["secondary_cleanup_error"] = self.error(error)
                if failure is not None:
                    raise failure
                sampled = process_resources()
                self.record("drained_resources", {"parent": sampled})
                need(sampled["available"] and original_parent["available"], "parent resource sample unavailable")
                need(sampled["rss_kib"] <= self.profile["max_parent_rss_kib"], "parent RSS stop limit exceeded")
                need(sampled["fd_count"] - original_parent["fd_count"] <= self.profile["max_drained_parent_fd_growth"],
                     "drained parent FD growth exceeded stop limit")
                self.report["completed_epochs"] += 1
                self.report["resources"]["last_drained_parent"] = sampled
                self.report["resources"]["largest_observed_drained_parent_rss_kib"] = max(
                    self.report["resources"].get("largest_observed_drained_parent_rss_kib", 0), sampled["rss_kib"])
                self.report["resources"]["largest_observed_drained_parent_fd_count"] = max(
                    self.report["resources"].get("largest_observed_drained_parent_fd_count", 0), sampled["fd_count"])
                self.report["counts"] = dict(self.counts)
                self.report["progress_wall_ns"] = self.elapsed()
                self.journal.checkpoint(self.report)
            else:
                self.report["stop_reason"] = "max_epochs"
            need(self.attempt_id == self.report["completed_epochs"] * self.profile["calls_per_epoch"],
                 "completed epoch denominator differs")
            need(self.cancelled_builds > 0, "no actual build-publication cancellation observed")
        except BaseException as error:
            primary = error
            self.report["failure"] = self.error(error)
            self.report.setdefault("failure_phase", self.phase)
            self.report["stop_reason"] = "evidence_budget" if isinstance(error, EvidenceBudgetExceeded) else "unexpected_failure"
        finally:
            elapsed = self.elapsed()
            self.report["counts"] = dict(self.counts)
            self.report["counts"].update(child_process_start_count_complete=self.counts["unavailable_child_start_outcomes"] == 0,
                native_entry_invocations=None if self.counts["unavailable_native_entry_outcomes"] else self.counts["native_entries_observed"])
            self.report["case_counts"] = dict(self.cases)
            self.report["cancelled_build_publications"] = self.cancelled_builds
            after_usage = resource.getrusage(resource.RUSAGE_SELF)
            self.report["resources"]["parent_after"] = process_resources()
            self.report["timing"] = {"observation_wall_ns": elapsed, "explicit_pacing_wait_ns": self.pacing_ns,
                "nonpacing_controller_wall_ns": elapsed - self.pacing_ns,
                "parent_cpu_seconds": (after_usage.ru_utime + after_usage.ru_stime) - (before_usage.ru_utime + before_usage.ru_stime),
                "actual_call_observation_wall_sum_ns": sum(self.call_times), "observed_build_control_wall_sum_ns": sum(self.build_times),
                "admission_to_host_observation": latencies(self.call_times),
                "completed_observations_per_wall_second": self.counts["completed_observations"] / (elapsed / 1e9) if elapsed else None,
                "call_intervals_overlap": True, "includes_process_startup_diagnostic_wait_and_cleanup": True,
                "network_or_service_latency": False}
            self.report["timing"]["outer_process_wall_including_recovery_requires_supervisor_record"] = True
            try:
                self.report["source_unchanged"] = (self.registered["source"]["snapshot"] == snapshot()
                    and self.registered["source"]["git_commit"] == git("rev-parse", "HEAD")
                    and self.registered["source"]["git_status"] == git("status", "--porcelain=v1", "--untracked-files=all"))
                self.report["tools_unchanged"] = self.registered["tools"] == tools_identity(self.registered["tools"]["clang"]["path"])
            except BaseException as error:
                self.report["identity_recheck_error"] = self.error(error)
                self.report["source_unchanged"] = self.report["tools_unchanged"] = False
            self.report["execution_passed"] = (primary is None and self.report["drained"]
                and self.report["source_unchanged"] and self.report["tools_unchanged"]
                and workload_complete(self.profile, self.counts, self.report["completed_epochs"], elapsed, self.pacing_ns)
                and self.elapsed() <= self.profile["max_wall_seconds"] * 1e9)
            end_record = self.cleanup_record("run_end", {"observation_wall_ns": elapsed,
                "parent": self.report["resources"]["parent_after"],
                "cpu_user_seconds": after_usage.ru_utime, "cpu_system_seconds": after_usage.ru_stime,
                "completed_epochs": self.report["completed_epochs"], "stop_reason": self.report["stop_reason"],
                "source_unchanged": self.report["source_unchanged"], "tools_unchanged": self.report["tools_unchanged"]})
            if end_record is None:
                self.report["execution_passed"] = False
            self.report["ok"] = self.report["execution_passed"] and self.profile["formal_qualification"]
            self.report["status"] = "passed" if self.report["ok"] else "development_complete" if self.report["execution_passed"] else "incomplete_or_failed"
            self.report["total_wall_ns"] = self.elapsed() if end_record is None else end_record["elapsed_ns"]
            self.report["journal"] = {"path": "events.jsonl", "records": self.journal.sequence,
                                      "last_sha256": self.journal.chain, "retained_bytes_excluding_report": self.journal.used}
            self.report["finished_utc"] = datetime.now(timezone.utc).isoformat()
            self.journal.checkpoint(self.report)
        return self.report


def validate_evidence(output, *, require_hosted=True):
    from tools.hia_runtime_soak_evidence import validate
    return validate(output, require_hosted=require_hosted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    register = commands.add_parser("register")
    register.add_argument("--profile", choices=sorted(PROFILES), required=True)
    register.add_argument("--clang", default="/usr/bin/clang-20")
    register.add_argument("--output-file", required=True)
    execute = commands.add_parser("run")
    execute.add_argument("--registration", required=True)
    execute.add_argument("--registration-sha256", required=True)
    execute.add_argument("--output-directory", required=True)
    check = commands.add_parser("validate")
    check.add_argument("--output-directory", required=True)
    check.add_argument("--allow-development", action="store_true")
    args = parser.parse_args()
    if args.command == "validate":
        print(json.dumps(validate_evidence(args.output_directory, require_hosted=not args.allow_development)))
        return 0
    if args.command == "register":
        path = Path(args.output_file).absolute()
        need(path != ROOT and ROOT not in path.parents, "registration must be outside source checkout")
        value = registration(args.profile, args.clang)
        raw = canonical(value)
        with path.open("xb") as stream:
            stream.write(raw)
        print(json.dumps({"registration": str(path), "sha256": digest(raw), "profile": args.profile}))
        return 0
    raw = read_bounded(args.registration, 8 * 1024 * 1024)
    need(digest(raw) == args.registration_sha256,
         "registration bytes differ from reviewed identity")
    from tools.hia_runtime_soak_evidence import strict_json
    registered = strict_json(raw)
    need(raw == canonical(registered), "registration is not canonical JSON")
    runner = NativeRuntimeSoak(registered, args.output_directory)
    result = runner.run()
    if runner.recovery_thread is not None:
        runner.recovery_thread.join()
    print(json.dumps({"ok": result["ok"], "execution_passed": result["execution_passed"],
                      "status": result["status"], "counts": result["counts"], "stop_reason": result["stop_reason"]}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
