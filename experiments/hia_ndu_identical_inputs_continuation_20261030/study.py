"""Prospective identical-input native planner study; never a safety authority.

Formal execution requires an immutable committed registration and a one-shot
claim. Development uses only the distinct development seed and existing native
artifacts. Every arm gets the same canonical request bytes, including candidates,
verification labels, resource ceilings and event costs.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from hashlib import sha256
import lzma
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from . import planning
from .build_controls import (ROOT, HERE, CRATE, CRATE_FILES, admit_blob,
                             build_control, file_sha, write_json, crate_identity, run_bounded)
from hepta.hia_ndu_session import NduSession, STREAM_SOURCE_PIN
from tools import build_hia_recursive_ndu_bridge as native_builder

PROTOCOL = HERE / "PROTOCOL.json"
FREEZE = HERE / "FREEZE.json"
CLAIM = HERE / "EXECUTION_CLAIM.json"
SCHEMA = "hepta.ndu.identical-inputs-continuation.result.v1"
SHARED = (
    "tools/build_hia_recursive_ndu_bridge.py",
    "tools/evidence_checks.py",
)
CLAIMS = {
    "same_canonical_request_bytes_for_every_arm": True,
    "same_candidate_feasibility_and_cost_information": True,
    "zero_cross_request_decision_caches": True,
    "native_exact_dp_is_a_separate_control_implementation": True,
    "original_ndu_source_unchanged": True,
    "original_ndu_and_control_evidence_algorithms_identical": False,
    "native_transport_time_is_pure_algorithm_time": False,
    "foreign_input_verification_labels_are_proofs": False,
    "real_application_net_gain_established": False,
    "global_optimality": False,
    "execution_authority": False,
    "unlimited_future_amortization": False,
}


def protocol():
    value = json.loads(PROTOCOL.read_bytes())
    required = {"native_source_pin": STREAM_SOURCE_PIN, "decisions_per_arm": 2048,
                "session_requests": 256, "decision_cache_entries": 0,
                "formal_seed": planning.SEEDS["formal"], "development_seed": planning.SEEDS["development"],
                "authority": "DENY_ALL", "safety_certificate": False}
    if any(type(value.get(k)) is not type(v) or value.get(k) != v for k, v in required.items()):
        raise ValueError("fixed identical-input protocol changed")
    return value


def source_files():
    # Bind all available production Python sources; new unrelated evidence and
    # documents are not compiler/runner inputs and do not invalidate this study.
    files = {str(p.relative_to(ROOT)) for p in (ROOT / "hepta").glob("*.py")}
    files.update(str(p.relative_to(ROOT)) for p in HERE.glob("*.py"))
    files.add(str(PROTOCOL.relative_to(ROOT)))
    files.update(str((CRATE / p).relative_to(ROOT)) for p in CRATE_FILES)
    files.update(SHARED)
    test = ROOT / "tests/test_hia_ndu_identical_inputs.py"
    if test.exists():
        files.add(str(test.relative_to(ROOT)))
    return {p: file_sha(ROOT / p) for p in sorted(files)}


def git_head():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def assert_sources(snapshot, *, commit=None):
    if source_files() != snapshot:
        raise ValueError("bound study source changed")
    if commit:
        for path, expected in snapshot.items():
            admit_blob(commit, path, expected)


class TransportTiming:
    def __init__(self, *args, **kwargs):
        self.transport_parse_ns = []
        self._expected_request = None
        self.sent_request_digests = []
        self.attempted_request_digests = []
        try:
            super().__init__(*args, **kwargs)
        except BaseException as error:
            error.native_session_start_failure = {
                "raw_received_frame_hex": getattr(self, "_last_received_frame", b"").hex(),
                "stderr_hex": bytes(getattr(self, "_stderr", b"")).hex(),
                "closed": getattr(self, "_closed", None)}
            raise

    def expect(self, payload):
        self._expected_request = payload

    def _invoke(self, arguments, payload):
        if payload != self._expected_request:
            raise ValueError("arm did not send the byte-identical shared request")
        self.attempted_request_digests.append(sha256(payload).hexdigest())
        begin = time.monotonic_ns()
        try:
            response = super()._invoke(arguments, payload)
            self.sent_request_digests.append(sha256(payload).hexdigest())
            return response
        finally:
            self.transport_parse_ns.append(time.monotonic_ns() - begin)

    def snapshot(self):
        result = super().snapshot()
        result["transport_parse_envelope_costs_ns"] = list(self.transport_parse_ns)
        result["sent_request_sha256"] = list(self.sent_request_digests)
        result["attempted_request_sha256"] = list(self.attempted_request_digests)
        result["pure_algorithm_time_available"] = False
        return result


class NativeSession(TransportTiming, NduSession):
    pass


class ControlSession(TransportTiming, planning.ControlSession):
    pass


class WireArchive:
    """Lossless interleaved wire bytes, one independent XZ member per decision.

    Every record is flushed to an uncompressed pending file before the next
    native call. Completed decision chunks are compressed together, preserving
    original strings/hex bytes, and the pending file is cleared only after the
    compressed member is flushed. This is assay storage, never a decision cache.
    """
    def __init__(self, path):
        self.path = Path(path)
        self.raw = self.path.open("xb")
        self.pending_path = self.path.with_suffix(self.path.suffix + ".pending")
        self.pending = self.pending_path.open("x+b")
        self.chunks = []
        self.closed = False
        self.close_cost_ns = 0

    def put(self, channel, value):
        begin = time.monotonic_ns()
        self.pending.write(planning.canonical({"channel": channel, **value}) + b"\n")
        self.pending.flush()
        return time.monotonic_ns()-begin

    def checkpoint(self, index):
        begin = time.monotonic_ns()
        self.pending.seek(0)
        raw = self.pending.read()
        if not raw:
            return 0
        compressed = lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=3)
        offset = self.raw.tell()
        self.raw.write(compressed)
        self.raw.flush()
        self.chunks.append({"decision": index, "offset": offset, "raw_bytes": len(raw),
            "compressed_bytes": len(compressed), "raw_sha256": sha256(raw).hexdigest(),
            "compressed_sha256": sha256(compressed).hexdigest()})
        self.pending.seek(0)
        self.pending.truncate()
        self.pending.flush()
        elapsed = time.monotonic_ns()-begin
        self.chunks[-1]["wall_ns"] = elapsed
        return elapsed

    def close(self):
        if self.closed:
            return
        begin = time.monotonic_ns()
        self.checkpoint("stopped-or-final")
        self.pending.close()
        self.raw.close()
        self.closed = True
        self.close_cost_ns = time.monotonic_ns()-begin

    def snapshot(self):
        return {"path": self.path.name, "bytes": self.path.stat().st_size,
                "sha256": file_sha(self.path), "chunks": self.chunks,
                "close_cost_ns": self.close_cost_ns, "pending_bytes": self.pending_path.stat().st_size,
                "codec": "concatenated-XZ-SHA256-preset3-one-member-per-decision",
                "lossless_raw_wire_records": True}


class Journal:
    """A logical channel in the shared evidence archive."""
    def __init__(self, path, *, archive=None, channel="standalone"):
        self.archive = WireArchive(path) if archive is None else archive
        self.owns_archive = archive is None
        self.channel = channel
        self.rows = 0
        self.write_cost_ns = 0

    def put(self, value):
        elapsed = self.archive.put(self.channel, value)
        self.rows += 1
        self.write_cost_ns += elapsed
        return elapsed

    def close(self):
        if self.owns_archive:
            self.archive.close()

    def snapshot(self):
        return {"path": self.archive.path.name, "logical_channel": self.channel,
                "rows": self.rows, "write_cost_ns": self.write_cost_ns,
                "close_cost_ns": 0, "lossless_raw_wire_records": True}


def audit_archive(archive, *, expected_completed=None):
    """Decode actual retained byte strings, not a reserialization of parsed JSON."""
    requests, started, completed, accounting = {}, set(), set(), set()
    received = 0
    with archive.path.open("rb") as source:
        for chunk in archive.chunks:
            source.seek(chunk["offset"])
            raw = source.read(chunk["compressed_bytes"])
            if len(raw) != chunk["compressed_bytes"] or sha256(raw).hexdigest() != chunk["compressed_sha256"]:
                raise ValueError("retained compressed member differs")
            decoded = lzma.decompress(raw)
            if len(decoded) != chunk["raw_bytes"] or sha256(decoded).hexdigest() != chunk["raw_sha256"]:
                raise ValueError("retained uncompressed member differs")
            for line in decoded.splitlines():
                row = json.loads(line)
                index, channel = row["index"], row["channel"]
                if channel == "requests":
                    wire = row["canonical_request"].encode("utf-8")
                    if index in requests or len(wire) != row["request_bytes"] or sha256(wire).hexdigest() != row["request_sha256"]:
                        raise ValueError("retained original request bytes differ")
                    requests[index] = row["request_sha256"]
                    continue
                if channel == "accounting":
                    if (index not in requests or index in accounting or row["row"]["index"] != index
                            or row["row"]["request_sha256"] != requests[index]):
                        raise ValueError("accounting row identity differs")
                    accounting.add(index)
                    continue
                if channel not in planning.ARMS or index not in requests:
                    raise ValueError("response channel has no preceding shared request")
                key = (channel, index)
                if row["state"] == "started":
                    if key in started or row["request_sha256"] != requests[index]:
                        raise ValueError("started request identity differs")
                    started.add(key)
                    continue
                if key not in started:
                    raise ValueError("native result lacks its retained start")
                if "raw_response_frame" in row:
                    wire = row["raw_response_frame"].encode("utf-8")
                    if len(wire) != row["response_frame_bytes"] or sha256(wire).hexdigest() != row["response_frame_sha256"]:
                        raise ValueError("retained original response bytes differ")
                    envelope = json.loads(wire)
                    if (envelope.get("sequence") != index % 256 + 1
                            or envelope.get("response", {}).get("request_digest") != requests[index]):
                        raise ValueError("retained native frame sequence/request differs")
                    received += 1
                if "raw_received_frame_hex" in row:
                    wire = bytes.fromhex(row["raw_received_frame_hex"])
                    if len(wire) != row["received_frame_bytes"] or sha256(wire).hexdigest() != row["received_frame_sha256"]:
                        raise ValueError("retained partial response bytes differ")
                    received += 1
                if row["state"] == "completed":
                    if key in completed:
                        raise ValueError("duplicate completed native response")
                    completed.add(key)
    if expected_completed is not None:
        expected = {(arm, index) for arm in planning.ARMS for index in range(expected_completed)}
        if (started != expected or completed != expected or set(requests) != set(range(expected_completed))
                or accounting != set(range(expected_completed))):
            raise ValueError("decoded completed native denominator differs")
    return {"ok": True, "original_requests_checked": len(requests), "original_received_frames_checked": received,
            "started_requests": len(started), "completed_requests": len(completed),
            "accounting_records_checked": len(accounting),
            "original_byte_lengths_and_sha256_rechecked": True, "not_parsed_json_reserialization": True}


def tiny_requests():
    """Fixed development-only controls for ties, abstention and exact boundaries."""
    packet = planning.packet(0, seed=planning.SEEDS["development"], phase="development")
    request = deepcopy(packet["bundle"]["request"])
    abstain = next(c for c in request["candidates"] if c["id"] == "abstain")
    candidate = deepcopy(next(c for c in request["candidates"] if c["id"] != "abstain"))
    candidate.update(id="tiny-a", verified=True, terminal_q32=4 * planning.Q32,
                     resource_cost_q32=2 * planning.Q32)
    candidate["events"] = candidate["events"][:2]
    candidate["events"][0]["instant_q32"] = -1
    candidate["events"][1]["instant_q32"] = -planning.Q32
    request["resource_budget_q32"] = 2 * planning.Q32
    request["candidates"] = [candidate, deepcopy(abstain)]
    yield "q32-fraction-and-inclusive-budget", deepcopy(request)
    twin = deepcopy(candidate)
    twin["id"] = "tiny-b"
    request["candidates"].insert(1, twin)
    yield "complete-value-tie", deepcopy(request)
    for c in request["candidates"]:
        if c["id"] != "abstain":
            c["verified"] = False
    yield "only-explicit-abstain-feasible", deepcopy(request)
    request["candidates"][0]["verified"] = True
    request["candidates"][0]["resource_cost_q32"] = request["resource_budget_q32"] + 1
    yield "one-q32-unit-over-budget", deepcopy(request)


def open_session(arm, manifest, timeout):
    manifest = Path(manifest).resolve(strict=True)
    binary = Path(json.loads(manifest.read_bytes())["binary"]).resolve(strict=True)
    if arm == "native-ndu":
        return NativeSession.for_stream_profile(binary, manifest, timeout=timeout)
    return ControlSession(binary, manifest, arm=arm, timeout=timeout)


def session_cap_control(arm, manifest, output):
    """Real development requests exercise the complete 256-reply lifecycle."""
    request = next(tiny_requests())[1]
    payload = planning.canonical(request)
    session = open_session(arm, manifest, protocol()["request_timeout_seconds"])
    archive = WireArchive(Path(output) / (arm + "-session-cap.xz"))
    accepted, refused = 0, False
    try:
        for index in range(protocol()["session_requests"]):
            session.expect(payload)
            response = session.evaluate(request)
            planning.compare_receipt(response, request, arm=arm)
            frame = session._last_received_frame
            archive.put(arm, {"index": index, "request_bytes": len(payload),
                "canonical_request": payload.decode(), "request_sha256": sha256(payload).hexdigest(),
                "raw_response_frame": frame.decode(), "response_frame_bytes": len(frame),
                "response_frame_sha256": sha256(frame).hexdigest()})
            accepted += 1
        archive.checkpoint("all-256-replies")
        session.expect(payload)
        try:
            session.evaluate(request)
        except Exception as error:
            if "request budget exhausted" not in str(error):
                raise
            refused = True
        if not refused or not session.snapshot()["closed"]:
            raise ValueError("request257 must be refused and the session closed")
    finally:
        session.close()
        archive.close()
    if len(session.sent_request_digests) != 256 or len(session.attempted_request_digests) != 257:
        raise ValueError("attempted/completed native request counts differ")
    return {"arm": arm, "accepted_requests": accepted, "request257_rejected": refused,
            "closed": session.snapshot()["closed"], "archive": archive.snapshot(),
            "session": session.snapshot(), "phase": "development"}


def development_controls(manifests, output):
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    sources = source_files()
    for arm in planning.ARMS:
        session = open_session(arm, manifests[arm], protocol()["request_timeout_seconds"])
        try:
            for name, request in tiny_requests():
                payload = planning.canonical(request)
                session.expect(payload)
                response = session.evaluate(request)
                quality = planning.compare_receipt(response, request, arm=arm)
                frame = session._last_received_frame
                (output / (arm + "-" + name + ".frame")).write_bytes(frame)
                rows.append({"arm": arm, "name": name, "request_sha256": sha256(payload).hexdigest(),
                             "response_frame_sha256": sha256(frame).hexdigest(), "quality": quality})
        finally:
            session.close()
            write_json(output / (arm + ".session.json"), session.snapshot())
    cap_controls = [session_cap_control(arm, manifests[arm], output) for arm in planning.ARMS]
    # Same request metadata for all arms is already checked inside the transport.
    assert_sources(sources)
    report = {"ok": True, "phase": "development", "source_identity": sources, "source_unchanged": True,
              "cases": rows, "case_count": len(rows), "session_cap_controls": cap_controls,
              "formal_inputs_generated": 0, "authority": "DENY_ALL", "safety_certificate": False}
    write_json(output / "RESULT.json", report)
    return report


def cold_build_all(output, *, ndu_source, cargo, rustc, cargo_home, code_commit, outer_started):
    output = Path(output)
    output.mkdir()
    manifests, costs = {}, {}
    for arm in planning.ARMS:
        begin = time.monotonic_ns()
        if arm == "native-ndu":
            target = output / "native-ndu-empty-target"
            if target.exists():
                raise ValueError("NDU cold target must not preexist")
            build_output = output / arm
            previous_jobs = os.environ.get("CARGO_BUILD_JOBS")
            os.environ["CARGO_BUILD_JOBS"] = "1"
            try:
                command = [sys.executable, "-B", str(ROOT / "tools/build_hia_recursive_ndu_bridge.py"),
                    "--ndu-source", str(ndu_source), "--output", str(build_output), "--target-dir", str(target),
                    "--cargo", str(cargo), "--rustc", str(rustc), "--cargo-home", str(cargo_home),
                    "--expected-source", STREAM_SOURCE_PIN, "--offline"]
                remaining = protocol()["max_study_wall_seconds"] - (time.monotonic_ns()-outer_started)/1e9
                if remaining <= 0:
                    raise TimeoutError("overall deadline before NDU build")
                completed, timed_out = run_bounded(command, cwd=ROOT, env=dict(os.environ),
                    timeout=remaining, receipt_prefix=output / "native-builder")
                if completed.returncode or timed_out:
                    raise RuntimeError("original pinned NDU empty-target build failed")
                manifest = build_output / "identity.json"
            finally:
                clean_start = time.monotonic_ns()
                process_receipt_path = output / "native-builder.process.json"
                process_receipt = json.loads(process_receipt_path.read_bytes()) if process_receipt_path.exists() else {}
                cleanup_allowed = process_receipt.get("safe_target_cleanup") is True
                if target.exists() and cleanup_allowed:
                    shutil.rmtree(target)
                cleanup = time.monotonic_ns() - clean_start
                if previous_jobs is None:
                    os.environ.pop("CARGO_BUILD_JOBS", None)
                else:
                    os.environ["CARGO_BUILD_JOBS"] = previous_jobs
                build_output.mkdir(exist_ok=True)
                if build_output.exists():
                    write_json(build_output / "OUTER_BUILD.json", {
                        "process_cleanup_confirmed": cleanup_allowed,
                        "target_retained_due_to_unconfirmed_process_cleanup": target.exists(),
                        "total_build_and_cleanup_ns": time.monotonic_ns() - begin,
                        "target_cleanup_ns": cleanup, "target_cache": "empty", "build_jobs": 1,
                        "dependency_cache": "preinstalled; no acquisition charge inferred",
                        "acquisition_cost_ns": None, "human_cost_ns": None,
                        "authority": "DENY_ALL", "safety_certificate": False})
            costs[arm] = json.loads((build_output / "OUTER_BUILD.json").read_bytes())
        else:
            manifest = build_control(arm, output / arm, cargo=cargo, rustc=rustc,
                                     cargo_home=cargo_home, source_commit=code_commit,
                timeout=max(0.001, protocol()["max_study_wall_seconds"]-(time.monotonic_ns()-outer_started)/1e9))
            costs[arm] = json.loads((output / arm / "BUILD.json").read_bytes())
            costs[arm]["outer_total_build_and_cleanup_ns"] = time.monotonic_ns() - begin
        manifests[arm] = str(manifest)
        if costs[arm]["target_cache"] != "empty":
            raise ValueError("cold comparison cannot reuse compiled targets")
    return manifests, costs


def prefix_accounting(rows, sessions, builds, journals, horizons, common_preparation_ns=0, common_finalize_ns=0):
    result = {}
    for horizon in horizons:
        if horizon > len(rows):
            continue
        prefix = rows[:horizon]
        arms = {}
        common = sum(r["common_construction_ns"] + r["common_request_write_ns"] + r.get("common_archive_checkpoint_ns", 0) + r.get("common_accounting_write_ns", 0)
            + sum(a["arm_record_write_ns"] for a in r["arms"].values()) for r in prefix)
        common += common_preparation_ns + common_finalize_ns
        for arm in planning.ARMS:
            used = [s for s in sessions[arm] if s["start_index"] < horizon]
            build = builds.get(arm)
            cold = None if build is None else build.get(
                "outer_total_build_and_cleanup_ns", build["total_build_and_cleanup_ns"])
            startup = sum(s["startup_outer_ns"] for s in used)
            cleanup = sum(s["cleanup_outer_ns"] for s in used)
            recurrent = sum(r["arms"][arm]["evaluate_outer_ns"] + r["arms"][arm]["quality_check_ns"]
                            for r in prefix)
            finish = journals[arm]["close_cost_ns"]
            subtotal = common + startup + cleanup + recurrent + finish
            selected = [r["arms"][arm]["quality"] for r in prefix]
            arms[arm] = {"common_cost_ns": common, "session_startup_ns": startup,
                "session_cleanup_ns": cleanup, "request_validation_and_evidence_ns": recurrent,
                "evidence_stream_finalization_ns": finish, "cold_build_ns": cold,
                "observed_recurrent_transport_ns": sum(r["arms"][arm]["transport_parse_envelope_ns"] for r in prefix),
                "subtotal_excluding_unknown_acquisition_and_human_ns": subtotal if cold is None else subtotal+cold,
                "total_has_fresh_empty_target_cost": cold is not None,
                "unresolved_frontiers": sum(q["unresolved_frontier"] for q in selected),
                "unique_recommendation_regret_q32": sum(q["full_path_regret_q32"] or 0 for q in selected),
                "regret_sum_excludes_unresolved_frontiers": True,
                "frontier_worst_regret_sum_q32": sum(q["frontier_regret_max_q32"] for q in selected),
                "session_count_touched": len(used)}
        a, d = arms["native-ndu"], arms["native-exact-dp"]
        result[str(horizon)] = {"arms": arms, "prefix_accounting_not_separate_trial": True,
            "ndu_minus_exact_dp_accounted_ns": a["subtotal_excluding_unknown_acquisition_and_human_ns"]
                                               - d["subtotal_excluding_unknown_acquisition_and_human_ns"],
            "ndu_all_frontiers_equal_exact_dp": all(
                r["arms"]["native-ndu"]["quality"]["frontier"] == r["arms"]["native-exact-dp"]["quality"]["frontier"]
                for r in prefix),
            "native_algorithm_only_contribution_identified": False}
    return result


def retained_bytes(directory):
    return sum(p.stat().st_size for p in Path(directory).rglob("*") if p.is_file())


def known_execution_cost(rows, sessions, common_finalization_ns):
    common = sum(r["common_construction_ns"] + r["common_request_write_ns"]
        + r.get("common_archive_checkpoint_ns", 0) + r.get("common_accounting_write_ns", 0)
        + sum(a["arm_record_write_ns"] for a in r["arms"].values()) for r in rows)
    arm_specific = sum(s["startup_outer_ns"] + (s["cleanup_outer_ns"] or 0)
        for values in sessions.values() for s in values)
    arm_specific += sum(a["evaluate_outer_ns"] + a["quality_check_ns"]
        for r in rows for a in r["arms"].values())
    return {"shared_component_ns": common + common_finalization_ns,
            "all_arm_components_ns": arm_specific,
            "sum_disjoint_components_ns": common + common_finalization_ns + arm_specific}


def add_common_to_prefixes(prefixes, residual):
    value = deepcopy(prefixes)
    for row in value.values():
        row["full_run_unallocated_assay_common_charge_ns"] = row.get("full_run_unallocated_assay_common_charge_ns", 0)+residual
        row["full_run_common_charge_is_not_an_observed_short_trial"] = True
        for arm in row["arms"].values():
            arm["common_cost_ns"] += residual
            arm["subtotal_excluding_unknown_acquisition_and_human_ns"] += residual
            arm["common_unallocated_coordination_and_reporting_ns"] = arm.get("common_unallocated_coordination_and_reporting_ns", 0)+residual
    return value


def finalize_result(output, report, *, started, deadline_start, cfg,
                    known_components_ns=0, retention_root=None):
    """Close ordinary output, then fail closed on the actual terminal budget.

    FINAL_GATE is authoritative only together with absence of a failure marker
    and a successful post-write check. Its own tail cannot recursively contain
    its own measurement; that boundary remains explicit, never priced at zero.
    """
    output = Path(output)
    root = output if retention_root is None else Path(retention_root)
    result_path = output / "RESULT.json"
    gate_path = output / "FINAL_GATE.json"
    failure_path = output / "FINAL_GATE_FAILURE.json"
    completion_path = output / "FINAL_COMPLETE.json"
    completion_bytes = 2048
    report["result_is_provisional_until_final_gate"] = True
    report["required_final_gate"] = gate_path.name
    report["run_wall_through_result_preparation_ns"] = time.monotonic_ns()-started
    write_begin = time.monotonic_ns()
    write_json(result_path, report)
    write_cost = time.monotonic_ns()-write_begin
    result_sha = file_sha(result_path)
    result_bytes = result_path.stat().st_size
    size_before_gate = retained_bytes(root)
    # All normal report encoding/writing, prefix analysis, source checks and
    # directory/hash scans above are inside this observed interval.
    boundary = time.monotonic_ns()
    observed = boundary-started
    residual = observed-known_components_ns
    gate = {"schema": "hepta.ndu.terminal-budget-gate.v1", "ok": report.get("ok") is True,
        "result_sha256": result_sha, "result_bytes": result_bytes,
        "normal_result_serialization_and_write_ns": write_cost,
        "observed_wall_ns": observed, "deadline_wall_ns": boundary-deadline_start,
        "known_disjoint_components_ns": known_components_ns,
        "common_unallocated_coordination_and_reporting_ns": residual,
        "wall_reconciles_to_disjoint_components_plus_common": residual >= 0,
        "prefix_accounting": add_common_to_prefixes(report.get("prefix_accounting", {}), residual),
        "retained_bytes_before_gate": size_before_gate, "retained_bytes_including_gate": 0,
        "retained_bytes_including_completion": 0, "completion_record_reserved_bytes": completion_bytes,
        "gate_encoded_bytes": 0, "retention_root": str(root),
        "limits": {"wall_seconds": cfg["max_study_wall_seconds"], "retained_bytes": cfg["max_retained_bytes"]},
        "terminal_record_tail_is_measured_as_zero": False,
        "gate_tail_accounting": "FINAL_COMPLETE records the additional observed common time through the post-gate check; add it equally to every prefix arm.",
        "unmeasured_terminal_tail": ["FINAL_COMPLETE own preparation/encoding/write, its later check and process exit"],
        "post_write_success_requires": "Actual stat and monotonic checks must pass before FINAL_COMPLETE is created; admission requires that positive bound receipt and no FINAL_GATE_FAILURE.",
        "authority": "DENY_ALL", "safety_certificate": False}
    if residual < 0 or gate["deadline_wall_ns"] > cfg["max_study_wall_seconds"]*1_000_000_000:
        gate.update(ok=False, error="terminal accounting or wall limit failed")
    # Include this exact final record's retained bytes without pretending to
    # measure its own write. Iteration resolves decimal length changes only.
    for _ in range(16):
        raw = (json.dumps(gate, sort_keys=True, indent=2)+"\n").encode()
        gate_total = size_before_gate+len(raw)
        total = gate_total+completion_bytes
        changed = (gate["gate_encoded_bytes"] != len(raw)
                   or gate["retained_bytes_including_gate"] != gate_total
                   or gate["retained_bytes_including_completion"] != total)
        gate["gate_encoded_bytes"] = len(raw)
        gate["retained_bytes_including_gate"] = gate_total
        gate["retained_bytes_including_completion"] = total
        if total > cfg["max_retained_bytes"] and gate.get("error") != "terminal retained-byte limit failed":
            gate.update(ok=False, error="terminal retained-byte limit failed")
            changed = True
        if not changed:
            break
    else:
        raise RuntimeError("terminal gate byte count did not stabilize")
    try:
        with gate_path.open("xb") as stream:
            stream.write(raw)
        actual_bytes = retained_bytes(root)
        actual_wall = time.monotonic_ns()-deadline_start
        if (actual_bytes != gate["retained_bytes_including_gate"]
                or actual_bytes+completion_bytes > cfg["max_retained_bytes"]
                or actual_wall > cfg["max_study_wall_seconds"]*1_000_000_000):
            raise ValueError("post-write wall/retention gate failed")
        completion = {"schema": "hepta.ndu.post-write-complete.v1", "ok": gate["ok"],
            "post_gate_check_passed": True, "gate_sha256": file_sha(gate_path),
            "result_sha256": result_sha, "observed_retained_bytes_after_gate": actual_bytes,
            "observed_deadline_wall_ns_after_gate": actual_wall,
            "additional_observed_common_ns_after_gate_boundary": actual_wall-gate["deadline_wall_ns"],
            "prefix_accounting_requires_equal_additional_common_charge": True,
            "completion_reserved_bytes": completion_bytes,
            "retained_bytes_with_reserved_completion": actual_bytes+completion_bytes,
            "completion_own_encoding_write_and_process_exit_unmeasured": True,
            "terminal_tail_cost_is_zero": False}
        completion_raw = json.dumps(completion, sort_keys=True, indent=2).encode()
        if len(completion_raw)+1 > completion_bytes:
            raise ValueError("fixed terminal completion receipt capacity exceeded")
        with completion_path.open("xb") as stream:
            stream.write(completion_raw+b" "*(completion_bytes-len(completion_raw)-1)+b"\n")
        actual_bytes = retained_bytes(root)
        actual_wall = time.monotonic_ns()-deadline_start
        if (actual_bytes != gate["retained_bytes_including_completion"]
                or actual_bytes > cfg["max_retained_bytes"]
                or actual_wall > cfg["max_study_wall_seconds"]*1_000_000_000):
            raise ValueError("post-completion wall/retention gate failed")
    except BaseException as error:
        failed = {"schema": "hepta.ndu.terminal-budget-failure.v1", "ok": False,
            "error": type(error).__name__ + ": " + str(error), "gate_sha256": file_sha(gate_path) if gate_path.exists() else None,
            "observed_wall_ns": time.monotonic_ns()-deadline_start,
            "retained_bytes_before_failure_record": retained_bytes(root),
            "failure_record_own_write_excluded": True, "no_retry_authorized": True}
        write_json(failure_path, failed)
        gate.update(ok=False, post_write_failure=failed)
        if not isinstance(error, Exception):
            raise
    else:
        # This actual later observation is returned to the CLI/outer caller;
        # it is not falsely claimed to be inside the already-written gate.
        gate["post_write_observation"] = {"ok": True, "actual_retained_bytes": actual_bytes,
            "actual_deadline_wall_ns": actual_wall, "gate_sha256": file_sha(gate_path),
            "completion_sha256": file_sha(completion_path)}
        gate["prefix_accounting_with_completed_gate_tail"] = add_common_to_prefixes(
            gate["prefix_accounting"], completion["additional_observed_common_ns_after_gate_boundary"])
    return gate


def admit_final_gate(result_path, cfg):
    result_path = Path(result_path)
    gate_path = result_path.with_name("FINAL_GATE.json")
    completion_path = result_path.with_name("FINAL_COMPLETE.json")
    if (result_path.with_name("FINAL_GATE_FAILURE.json").exists()
            or not gate_path.exists() or not completion_path.exists()):
        raise ValueError("a successful final post-write budget gate is required")
    result = json.loads(result_path.read_bytes())
    gate = json.loads(gate_path.read_bytes())
    completion = json.loads(completion_path.read_bytes())
    if (result.get("result_is_provisional_until_final_gate") is not True or gate.get("ok") is not True
            or completion.get("ok") is not True or completion.get("post_gate_check_passed") is not True
            or completion.get("gate_sha256") != file_sha(gate_path)
            or completion.get("result_sha256") != file_sha(result_path)
            or completion_path.stat().st_size != gate.get("completion_record_reserved_bytes")
            or completion.get("retained_bytes_with_reserved_completion") != retained_bytes(result_path.parent)
            or completion.get("observed_deadline_wall_ns_after_gate", float("inf")) > cfg["max_study_wall_seconds"]*1_000_000_000
            or gate.get("result_sha256") != file_sha(result_path)
            or gate.get("result_bytes") != result_path.stat().st_size
            or gate.get("gate_encoded_bytes") != gate_path.stat().st_size
            or gate.get("retained_bytes_including_completion") != retained_bytes(result_path.parent)
            or gate["retained_bytes_including_completion"] > cfg["max_retained_bytes"]
            or gate.get("deadline_wall_ns", float("inf")) > cfg["max_study_wall_seconds"]*1_000_000_000):
        raise ValueError("final post-write budget gate or result binding differs")
    gate["prefix_accounting_with_completed_gate_tail"] = add_common_to_prefixes(
        gate["prefix_accounting"], completion["additional_observed_common_ns_after_gate_boundary"])
    return gate


def execute(manifests, output, *, phase, count, builds=None, registration=None,
            outer_started=None, common_preparation_ns=0, retention_root=None):
    started = time.monotonic_ns()
    cfg = protocol()
    if phase not in planning.SEEDS or type(count) is not int or not 1 <= count <= cfg["decisions_per_arm"]:
        raise ValueError("invalid study phase/count")
    if phase == "formal" and (count != cfg["decisions_per_arm"] or not registration):
        raise ValueError("formal run needs the full registered denominator")
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    sources = source_files()
    deadline_start = started if outer_started is None else outer_started
    report = {"schema": SCHEMA, "ok": False, "phase": phase, "started_decisions": 0,
        "completed_decisions": 0, "requested_decisions_per_arm": count,
        "source_commit": git_head(), "source_identity": sources, "registration": registration,
        "host_cpu_affinity": sorted(os.sched_getaffinity(0)),
        "protocol": cfg, "claims": dict(CLAIMS), "authority": "DENY_ALL", "safety_certificate": False,
        "common_preparation_ns": common_preparation_ns,
        "unmeasured_costs": ["Python interpreter bootstrap before instrumented entry", "toolchain/dependency acquisition", "human engineering/review"],
        "builds": builds or {}, "manifest_sha256": {a: file_sha(p) for a,p in manifests.items()},
        "model_requests": 0, "source_unchanged": False, "rows": []}
    archive = WireArchive(output / "wire.jsonl.xz")
    journals = {a: Journal(archive.path, archive=archive, channel=a) for a in ("requests", *planning.ARMS)}
    sessions = {}
    records = {a: [] for a in planning.ARMS}
    write_json(output / "STARTED.json", {"schema": SCHEMA, "phase": phase, "count": count,
        "source_identity": sources, "registration": registration, "monotonic_start_ns": started,
        "no_formal_retry_authorized": phase == "formal"})
    def check_budget():
        if time.monotonic_ns()-deadline_start > cfg["max_study_wall_seconds"]*1_000_000_000:
            raise TimeoutError("registered study wall budget exceeded")
        size = sum(p.stat().st_size for p in output.rglob("*") if p.is_file())
        if size > cfg["max_retained_bytes"]:
            raise ValueError("registered retained-byte budget exceeded")
    def close_sessions():
        errors = []
        for arm, session in list(sessions.items()):
            begin = time.monotonic_ns()
            try:
                session.close()
            except BaseException as error:
                errors.append(type(error).__name__ + ": " + str(error))
            records[arm][-1]["cleanup_outer_ns"] = time.monotonic_ns() - begin
            records[arm][-1]["observation"] = session.snapshot()
            del sessions[arm]
        if errors:
            raise RuntimeError("session cleanup failed: " + repr(errors))
    try:
        for index in range(count):
            check_budget()
            if index % cfg["session_requests"] == 0:
                close_sessions()
                for slot in range(3):
                    arm = planning.ARMS[(index + slot) % 3]
                    begin = time.monotonic_ns()
                    try:
                        session = open_session(arm, manifests[arm], cfg["request_timeout_seconds"])
                    except BaseException as error:
                        report["session_start_failure"] = {"arm": arm, "index": index,
                            "elapsed_ns": time.monotonic_ns()-begin,
                            "error": type(error).__name__ + ": " + str(error),
                            "native_failure_record": getattr(error, "native_session_start_failure", None)}
                        raise
                    sessions[arm] = session
                    records[arm].append({"start_index": index, "startup_outer_ns": time.monotonic_ns()-begin,
                                         "cleanup_outer_ns": None})
            common_begin = time.monotonic_ns()
            packet = planning.packet(index, seed=planning.SEEDS[phase], phase=phase,
                                     permit_formal=phase == "formal")
            payload = packet["canonical_request"].encode()
            common_ns = time.monotonic_ns()-common_begin
            common_write = journals["requests"].put({
                "index": index, "request_sha256": packet["request_sha256"], "request_bytes": len(payload),
                "canonical_request": packet["canonical_request"], "fields": packet["fields"],
                "graph_sha256": packet["bundle"]["graph_sha256"],
                "enumeration_complete": packet["bundle"]["enumeration_complete"],
                "common_construction_ns": common_ns})
            row = {"index": index, "regime": cfg["regimes"][index % 3],
                "candidates": len(packet["bundle"]["request"]["candidates"]),
                "request_sha256": packet["request_sha256"],
                "common_construction_ns": common_ns, "common_request_write_ns": common_write,
                "order": [], "arms": {}}
            report["rows"].append(row)
            report["started_decisions"] = index+1
            for slot in range(3):
                arm = planning.ARMS[(index + slot) % 3]
                row["order"].append(arm)
                session = sessions[arm]
                journal = journals[arm]
                started_write = journal.put({"index": index, "state": "started",
                                             "request_sha256": packet["request_sha256"]})
                session.expect(payload)
                begin = time.monotonic_ns()
                try:
                    response = session.evaluate(packet["bundle"]["request"])
                except BaseException as error:
                    journal.put({"index": index, "state": "failed", "error": type(error).__name__+": "+str(error),
                        "elapsed_ns": time.monotonic_ns()-begin,
                        "raw_received_frame": session._last_received_frame.decode("utf-8", "replace"),
                        "raw_received_frame_hex": session._last_received_frame.hex(),
                        "received_frame_bytes": len(session._last_received_frame),
                        "received_frame_sha256": sha256(session._last_received_frame).hexdigest(),
                        "observation": session.snapshot()})
                    raise
                elapsed = time.monotonic_ns()-begin
                quality_begin = time.monotonic_ns()
                try:
                    quality = planning.compare_receipt(response, packet["bundle"]["request"], arm=arm)
                except BaseException as error:
                    journal.put({"index": index, "state": "quality_failed",
                        "error": type(error).__name__ + ": " + str(error),
                        "raw_response_frame": session._last_received_frame.decode("utf-8"),
                        "response_frame_sha256": sha256(session._last_received_frame).hexdigest(),
                        "response_frame_bytes": len(session._last_received_frame),
                        "evaluate_outer_ns": elapsed, "quality_check_ns": time.monotonic_ns()-quality_begin})
                    raise
                quality_ns = time.monotonic_ns()-quality_begin
                frame = session._last_received_frame
                completed = {"index": index, "state": "completed", "request_sha256": packet["request_sha256"],
                    "raw_response_frame": frame.decode("utf-8"), "response_frame_sha256": sha256(frame).hexdigest(),
                    "response_frame_bytes": len(frame),
                    "evaluate_outer_ns": elapsed, "transport_parse_envelope_ns": session.transport_parse_ns[-1],
                    "session_request_ns": session._request_costs_ns[-1],
                    "quality_check_ns": quality_ns, "quality": quality}
                written = journal.put(completed) + started_write
                row["arms"][arm] = {k:v for k,v in completed.items()
                    if k not in {"raw_response_frame", "state", "request_sha256", "index"}}
                row["arms"][arm]["arm_record_write_ns"] = written
                if arm in planning.CONTROL_SCOPES:
                    row["arms"][arm]["control_host_normalization_validation_ns"] = session.host_control_admission_costs_ns[-1]
                if session.sent_request_digests[-1] != packet["request_sha256"]:
                    raise ValueError("native send hash differs between arms")
            if row["arms"]["native-ndu"]["quality"]["frontier"] != row["arms"]["native-exact-dp"]["quality"]["frontier"]:
                raise ValueError("native NDU and exact DP disagree on the complete frontier")
            row["common_accounting_write_ns"] = archive.put("accounting", {"index": index, "row": row})
            row["common_archive_checkpoint_ns"] = archive.checkpoint(index)
            archive.chunks[-1]["accounting_write_ns"] = row["common_accounting_write_ns"]
            report["completed_decisions"] = index+1
        close_sessions()
        recheck_begin = time.monotonic_ns()
        assert_sources(sources)
        report["source_recheck_ns"] = time.monotonic_ns()-recheck_begin
        report.update(ok=True, status="completed_defined_matrix_scope", source_unchanged=True)
    except BaseException as error:
        report.update(ok=False, status="failed_no_rerun", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        try:
            close_sessions()
        except BaseException as error:
            report.update(ok=False, status="failed_no_rerun", cleanup_error=type(error).__name__ + ": " + str(error))
        finalize_begin = time.monotonic_ns()
        for journal in journals.values():
            journal.close()
        archive.close()
        try:
            report["archive_audit"] = audit_archive(archive, expected_completed=count if report["ok"] else None)
        except BaseException as error:
            report.update(ok=False, status="failed_no_rerun", archive_error=type(error).__name__+": "+str(error))
        report["wire_archive"] = archive.snapshot()
        report["common_archive_finalize_and_byte_audit_ns"] = time.monotonic_ns()-finalize_begin
        report["sessions"] = records
        report["journals"] = {name:j.snapshot() for name,j in journals.items()}
        report["known_execution_components"] = known_execution_cost(report["rows"], records,
            report["common_archive_finalize_and_byte_audit_ns"] + report.get("source_recheck_ns", 0))
        report["prefix_accounting"] = prefix_accounting(
            [r for r in report["rows"] if len(r["arms"]) == 3], records, builds or {},
            report["journals"], cfg["horizons_to_report"], common_preparation_ns,
            report["common_archive_finalize_and_byte_audit_ns"] + report.get("source_recheck_ns", 0))
        if report["ok"] and report["completed_decisions"] != count:
            report.update(ok=False, status="failed_no_rerun", error="incomplete denominator")
        retained_rows = report.pop("rows")
        report["accounting_rows_retained_losslessly_in_wire_archive"] = True
        report["accounting_rows_completed"] = report["completed_decisions"]
        if retained_rows and retained_rows[-1]["index"] >= report["completed_decisions"]:
            report["stopped_partial_accounting_row"] = retained_rows[-1]
        if not report["ok"]:
            report["claims"] = {name: False for name in CLAIMS}
        gate = finalize_result(output, report, started=started, deadline_start=deadline_start,
            cfg=cfg, known_components_ns=report["known_execution_components"]["sum_disjoint_components_ns"],
            retention_root=retention_root)
        report["final_gate"] = gate
        if gate.get("ok") is not True:
            report.update(ok=False, status="failed_no_rerun", error="terminal budget gate failed")

    return report


def freeze(output, controls_result, development_result):
    cfg = protocol()
    controls_result, development_result = Path(controls_result), Path(development_result)
    controls = json.loads(controls_result.read_bytes())
    development = json.loads(development_result.read_bytes())
    if (controls.get("ok") is not True or controls.get("phase") != "development" or controls.get("case_count") != 12
            or development.get("ok") is not True or development.get("phase") != "development"
            or development.get("completed_decisions", 0) < 32):
        raise ValueError("real native development controls and complete development matrix run are required")
    cap = controls.get("session_cap_controls")
    if (type(cap) is not list or len(cap) != 3 or {r.get("arm") for r in cap} != set(planning.ARMS)
            or any(type(r.get("accepted_requests")) is not int or r["accepted_requests"] != 256
                   or r.get("request257_rejected") is not True or r.get("closed") is not True for r in cap)):
        raise ValueError("actual 256-request lifecycle controls are required")
    source_commit = git_head()
    sources = source_files()
    if (controls.get("source_identity") != sources or controls.get("source_unchanged") is not True
            or development.get("source_identity") != sources or development.get("source_unchanged") is not True):
        raise ValueError("development controls must bind the current exact study sources")
    admit_final_gate(development_result, cfg)
    assert_sources(sources, commit=source_commit)
    data = {"schema": "hepta.ndu.identical-inputs-continuation.freeze.v1",
        "code_commit": source_commit, "source_identity": sources,
        "protocol_sha256": file_sha(PROTOCOL), "native_source_pin": STREAM_SOURCE_PIN,
        "controls_sha256": file_sha(controls_result), "development_sha256": file_sha(development_result),
        "development_final_gate_sha256": file_sha(development_result.with_name("FINAL_GATE.json")),
        "development_final_completion_sha256": file_sha(development_result.with_name("FINAL_COMPLETE.json")),
        "formal_inputs_generated": 0, "formal_requests": 0, "model_requests": 0,
        "authority": "DENY_ALL", "safety_certificate": False}
    write_json(output, data)
    return data


def registered(freeze_path, registration_commit):
    if not re.fullmatch("[0-9a-f]{40}", registration_commit):
        raise ValueError("complete published registration commit is required")
    freeze_path = Path(freeze_path).resolve(strict=True)
    if freeze_path != FREEZE.resolve():
        raise ValueError("formal run uses the reviewed repository FREEZE path")
    data = json.loads(freeze_path.read_bytes())
    if data.get("schema") != "hepta.ndu.identical-inputs-continuation.freeze.v1":
        raise ValueError("unknown registration schema")
    if (data.get("protocol_sha256") != file_sha(PROTOCOL) or data.get("native_source_pin") != STREAM_SOURCE_PIN
            or type(data.get("formal_requests")) is not int or data["formal_requests"] != 0
            or type(data.get("formal_inputs_generated")) is not int or data["formal_inputs_generated"] != 0):
        raise ValueError("registration protocol or pre-execution state differs")
    assert_sources(data["source_identity"], commit=data["code_commit"])
    admit_blob(registration_commit, str(FREEZE.relative_to(ROOT)), file_sha(freeze_path))
    subprocess.run(["git", "merge-base", "--is-ancestor", data["code_commit"], registration_commit],
                   cwd=ROOT, check=True)
    return {**data, "published_registration_commit": registration_commit,
            "freeze_sha256": file_sha(freeze_path),
            "remote_publication_verification": "operator/root verifies before invoking formal CLI"}


def formal(args):
    began = time.monotonic_ns()
    registration = registered(args.freeze, args.registration_commit)
    common_preparation_ns = time.monotonic_ns()-began
    write_json(CLAIM, {"schema": "hepta.ndu.identical-inputs.execution-claim.v1",
        "registration": registration["published_registration_commit"], "freeze_sha256": registration["freeze_sha256"],
        "source_commit": registration["code_commit"], "output": str(Path(args.output).absolute()),
        "formal_started": True, "allow_rerun": False})
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    costs, report = {}, None
    status = {"schema": SCHEMA, "ok": False, "phase": "formal",
              "registration": registration, "formal_inputs_generated_before_cold_build": 0}
    try:
        manifests, costs = cold_build_all(output / "cold", ndu_source=args.ndu_source,
            cargo=args.cargo, rustc=args.rustc, cargo_home=args.cargo_home, code_commit=registration["code_commit"], outer_started=began)
        report = execute(manifests, output / "study", phase="formal", count=protocol()["decisions_per_arm"],
                         builds=costs, registration=registration, outer_started=began,
                         common_preparation_ns=common_preparation_ns, retention_root=output)
        status.update(ok=report["ok"], status=report["status"], completed_decisions=report["completed_decisions"],
                      study_result_sha256=file_sha(output / "study/RESULT.json"))
    except BaseException as error:
        status.update(ok=False, status="failed_no_rerun", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        status["source_unchanged"] = source_files() == registration["source_identity"]
        if not status["source_unchanged"]:
            status.update(ok=False, status="failed_no_rerun", error="overall source gate failed")
        if report is not None:
            status["prefix_accounting"] = report["prefix_accounting"]
        build_ns = sum(value.get("outer_total_build_and_cleanup_ns", value["total_build_and_cleanup_ns"])
                       for value in costs.values())
        execution_ns = 0 if report is None else report["known_execution_components"]["sum_disjoint_components_ns"]
        status["known_outer_components"] = {"build_ns": build_ns,
            "common_registration_ns": common_preparation_ns, "execution_components_ns": execution_ns}
        gate = finalize_result(output, status, started=began, deadline_start=began, cfg=protocol(),
            known_components_ns=build_ns+execution_ns+common_preparation_ns)
        status["final_gate"] = gate
        if gate.get("ok") is not True:
            status.update(ok=False, status="failed_no_rerun", error="overall terminal budget gate failed")

    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    dev = modes.add_parser("development")
    dev.add_argument("--ndu-manifest", required=True)
    dev.add_argument("--control-directory", required=True)
    dev.add_argument("--output", required=True)
    dev.add_argument("--count", type=int, default=32)
    fr = modes.add_parser("freeze")
    fr.add_argument("--output", default=str(FREEZE))
    fr.add_argument("--controls-result", required=True)
    fr.add_argument("--development-result", required=True)
    run = modes.add_parser("formal")
    run.add_argument("--freeze", default=str(FREEZE))
    run.add_argument("--registration-commit", required=True)
    run.add_argument("--output", required=True)
    for name in ("ndu-source", "cargo", "rustc", "cargo-home"):
        run.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if args.mode == "development":
        base = Path(args.output)
        manifests = {"native-ndu": args.ndu_manifest,
            **{a:str(Path(args.control_directory)/a/"identity.json") for a in planning.CONTROL_SCOPES}}
        controls = development_controls(manifests, base / "controls")
        result = execute(manifests, base / "matrix", phase="development", count=args.count)
        print(json.dumps({"ok": result["ok"], "controls": controls["case_count"],
                          "decisions_per_arm": result["completed_decisions"],
                          "final_post_write_observation": result["final_gate"].get("post_write_observation"),
                          "final_gate_ok": result["final_gate"]["ok"]}))
        return 0 if result["ok"] else 2
    elif args.mode == "freeze":
        data = freeze(args.output, args.controls_result, args.development_result)
        print(json.dumps({"ok": True, "code_commit": data["code_commit"], "formal_inputs_generated": 0}))
        return 0
    else:
        result = formal(args)
        print(json.dumps({"ok": result["ok"], "completed_decisions": result.get("completed_decisions"),
            "final_post_write_observation": result["final_gate"].get("post_write_observation"),
            "final_gate_ok": result["final_gate"]["ok"]}))
        return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
