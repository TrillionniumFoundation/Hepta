"""Fixed soak protocol negatives and small actual native lifecycle controls.

No test performs the hosted-duration profile or qualifies service performance.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import tempfile
from time import monotonic, sleep
from threading import Event
import unittest
from unittest import mock

from hepta import hia_native_loan_probe as probe
from hepta.hia_native_differential import NativeChildCleanupPending
from hepta.hia_native_version_dispatch import NativeVersionDispatcher
from tools import soak_hia_native_runtime as soak

CLANG = shutil.which("clang-20")


def retain_development_evidence(output, name):
    """Opt-in development retention; never changes any execution outcome."""
    root = os.environ.get("HEPTA_SOAK_TEST_EVIDENCE_ROOT")
    if root:
        destination = Path(root).absolute() / name
        if destination == soak.ROOT or soak.ROOT in destination.parents:
            raise ValueError("development evidence must remain outside source")
        shutil.copytree(output, destination)


def protocol_only_registration(profile_id=soak.HOSTED):
    selected = soak.profile(profile_id)
    files = {"examples/hia_native_lifecycle/swap.json": "0" * 64}
    return {"schema": "hepta.hia.native-runtime-soak-registration.v1", "created_utc": "2026-10-28T00:00:00+00:00",
            "profile": selected, "profile_sha256": soak.digest(soak.canonical(selected)),
            "source": {"git_commit": "0" * 40, "git_status": "",
                       "snapshot": {"files": files, "sha256": soak.digest(soak.canonical(files))}},
            "tools": {"clang": {"path": "/protocol-only/clang", "sha256": "0" * 64,
                       "version": "protocol-only clang version 20.0", "target": "x86_64-unknown-linux-gnu"},
                      "python": {"path": "/protocol-only/python", "sha256": "0" * 64, "version": "protocol-only"},
                      "rustc_used": False}, "fixture_sha256": "0" * 64,
            "host": {"system": "Linux", "machine": "x86_64", "kernel": "protocol-only", "cpu_count": 1},
            "claims": dict(soak.CLAIMS)}


def assert_replay_relation_controls(testcase, original):
    """Replay separate copies of actual samples; never manufacture an execution.

    This helper also permits bounded offline regression against an already
    retained real epoch, without rerunning the native workload.
    """
    results = []
    controls = (
        ("build_duration_outside_event_window", "build interval"),
        ("pacing_duration_outside_event_window", "pacing measurement"),
        ("observation_ends_before_last_drained_sample", "clock anchor"),
        ("simultaneously_held_children_share_pid", "distinct child PIDs"),
        ("child_cannot_reuse_live_parent_pid", "distinct child PIDs"),
        ("sequential_child_pid_reuse_is_permitted", None),
    )
    for name, rejection in controls:
        with testcase.subTest(relation=name), tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "copy"
            shutil.copytree(original, output)
            report = json.loads((output / "report.json").read_bytes())
            rows = [json.loads(raw) for raw in (output / "events.jsonl").read_bytes().splitlines()]
            if name == "build_duration_outside_event_window":
                index = next(i for i, row in enumerate(rows) if row["kind"] == "candidate_build")
                value, previous = rows[index]["value"], rows[index - 1]["value"]
                testcase.assertEqual(rows[index - 1]["kind"], "build_attempt")
                changed = value["elapsed_ns"] - previous["elapsed_ns"] + 1
                report["timing"]["observed_build_control_wall_sum_ns"] += changed - value["build_wall_ns"]
                value["build_wall_ns"] = changed
            elif name == "pacing_duration_outside_event_window":
                index = next(i for i, row in enumerate(rows) if row["kind"] == "pacing")
                value, previous = rows[index]["value"], rows[index - 1]["value"]
                changed = value["elapsed_ns"] - previous["elapsed_ns"] + 1
                delta = changed - value["wait_ns"]
                value["wait_ns"] = changed
                report["timing"]["explicit_pacing_wait_ns"] += delta
                report["timing"]["nonpacing_controller_wall_ns"] -= delta
            elif name == "observation_ends_before_last_drained_sample":
                drained = [row["value"] for row in rows if row["kind"] == "drained_resources"][-1]
                changed = drained["elapsed_ns"] - 1
                rows[-1]["value"]["observation_wall_ns"] = changed
                report["progress_wall_ns"] = changed
                report["timing"]["observation_wall_ns"] = changed
                report["timing"]["nonpacing_controller_wall_ns"] = changed - report["timing"]["explicit_pacing_wait_ns"]
                report["timing"]["completed_observations_per_wall_second"] = report["counts"]["completed_observations"] / (changed / 1e9)
            else:
                held = [(i, row["value"]) for i, row in enumerate(rows) if row["kind"] == "loan_held"]
                first_pid = held[0][1]["observation"]["child_process"]["pid"]
                if name == "simultaneously_held_children_share_pid":
                    _, target = held[1]
                    changed = first_pid
                    terminal = next(i for i, row in enumerate(rows) if row["kind"] == "terminal_observation"
                                    and row["value"]["attempt_id"] == held[0][1]["attempt_id"])
                    testcase.assertLess(held[1][0], terminal)
                elif name == "child_cannot_reuse_live_parent_pid":
                    _, target = held[0]
                    changed = rows[0]["value"]["parent"]["pid"]
                else:
                    target_index, target = held[2]
                    changed = first_pid
                    terminal = next(i for i, row in enumerate(rows) if row["kind"] == "terminal_observation"
                                    and row["value"]["attempt_id"] == held[0][1]["attempt_id"])
                    testcase.assertLess(terminal, target_index)
                sample = next(row["value"] for row in rows if row["kind"] == "sample"
                              and row["value"]["attempt_id"] == target["attempt_id"])
                for observed in (target["observation"], sample["final_observation"]):
                    observed["child_process"]["pid"] = changed
                    observed["child_process"]["cleanup"]["pid"] = changed
                sample["child_resource_sample"]["pid"] = changed
            chain, serialized = "0" * 64, []
            for row in rows:
                row["previous_sha256"] = chain
                raw = soak.canonical(row) + b"\n"
                chain = soak.digest(raw)
                serialized.append(raw)
            (output / "events.jsonl").write_bytes(b"".join(serialized))
            report["journal"].update(last_sha256=chain, retained_bytes_excluding_report=sum(
                path.stat().st_size for path in output.rglob("*") if path.is_file() and path.name != "report.json"))
            (output / "report.json").write_bytes(soak.canonical(report))
            if rejection is None:
                testcase.assertTrue(soak.validate_evidence(output, require_hosted=False)["validated"])
                results.append({"name": name, "accepted": True, "expected_accept": True})
            else:
                with testcase.assertRaisesRegex(ValueError, rejection) as caught:
                    soak.validate_evidence(output, require_hosted=False)
                results.append({"name": name, "accepted": False, "expected_accept": False,
                                "error": str(caught.exception)})
    return results


class NativeRuntimeSoakProtocolTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_json_cannot_enter_replay(self):
        from tools.hia_runtime_soak_evidence import strict_json
        for raw in (b'{"ok":false,"ok":true}', b'{"cpu":NaN}', b'{"cpu":Infinity}', b'{"cpu":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_changed_budget_and_boolean_budget_cannot_reuse_profile_identity(self):
        self.assertEqual(soak.profile(soak.HOSTED)["max_evidence_bytes"], 96 * 1024 * 1024)
        self.assertEqual(soak.profile(soak.HOSTED)["report_reserve_bytes"], 2 * 1024 * 1024)
        for field, value in (("max_wall_seconds", 1801), ("minimum_completed_epochs", True),
                             ("minimum_observation_seconds", 0), ("max_attempted_calls", 1),
                             ("max_evidence_bytes", 64 * 1024 * 1024)):
            with self.subTest(field=field):
                registered = protocol_only_registration()
                registered["profile"][field] = value
                registered["profile_sha256"] = soak.digest(soak.canonical(registered["profile"]))
                with self.assertRaises(ValueError):
                    soak.validate_registration(registered)

    def test_elapsed_time_and_actual_work_are_separate_required_denominators(self):
        selected = soak.profile(soak.HOSTED)
        counts = {key: 0 for key in soak.COUNT_KEYS}
        for key in ("attempted_calls", "child_processes_started", "child_processes_reaped", "completed_observations"):
            counts[key] = 5016
        self.assertFalse(soak.workload_complete(selected, counts, 152, 10 * 10**9, 0))
        self.assertFalse(soak.workload_complete(selected, {key: 0 for key in soak.COUNT_KEYS}, 0, 1700 * 10**9, 0))
        self.assertFalse(soak.workload_complete(selected, counts, 152, 1600 * 10**9, 1200 * 10**9))
        self.assertTrue(soak.workload_complete(selected, counts, 152, 1600 * 10**9, 500 * 10**9))
        counts["unavailable_child_start_outcomes"] = 1
        self.assertFalse(soak.workload_complete(selected, counts, 152, 1600 * 10**9, 0))

    def test_output_budget_stops_journal_without_discarding_reserved_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = soak.NativeRuntimeSoak(protocol_only_registration(soak.DEVELOPMENT), Path(directory) / "evidence")
            try:
                runner.journal.event("protocol-negative", {"native_executed": False})
                count = runner.journal.sequence
                runner.journal.used = runner.profile["max_evidence_bytes"] - runner.profile["report_reserve_bytes"]
                with self.assertRaises(soak.EvidenceBudgetExceeded):
                    runner.journal.event("refused", {})
                self.assertEqual(runner.journal.sequence, count)
                runner.cleanup_record("sample", {"attempt_id": 1, "control_passed": False, "synthetic_protocol_negative": True})
                self.assertEqual(len(runner.report["emergency_events"]), 1)
                self.assertIn("evidence_write_error", runner.report)
                self.assertFalse(runner.report["ok"])
                runner.journal.checkpoint(runner.report)
            finally:
                runner.journal.stream.close()


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "requires Linux x86-64 and actual Clang 20")
class NativeRuntimeSoakExecutionTests(unittest.TestCase):
    def test_one_real_epoch_has_v2_counts_artifacts_and_replayable_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            registered = soak.registration(soak.DEVELOPMENT, CLANG)
            runner = soak.NativeRuntimeSoak(registered, Path(directory) / "evidence")
            result = runner.run()
            retain_development_evidence(runner.journal.output, "single-epoch")
            self.assertTrue(result["execution_passed"], result.get("failure"))
            self.assertFalse(result["ok"])
            self.assertEqual(result["completed_epochs"], 1)
            counts = result["counts"]
            self.assertEqual([counts[key] for key in ("attempted_calls", "child_processes_started",
                             "child_processes_reaped", "completed_observations")], [33] * 4)
            self.assertEqual(counts["native_entries_observed"], 32)
            self.assertEqual(counts["unavailable_native_entry_outcomes"], 1)
            self.assertIsNone(counts["native_entry_invocations"])
            self.assertEqual(result["case_counts"], {"return": 30, "trap_in_loan": 1, "trap_before_loan": 1, "timeout": 1})
            self.assertEqual(soak.validate_evidence(runner.journal.output, require_hosted=False)["samples"], 33)
            assert_replay_relation_controls(self, runner.journal.output)
            with self.assertRaisesRegex(ValueError, "development"):
                soak.validate_evidence(runner.journal.output)
            path = runner.journal.output / "report.json"
            originals = path.read_bytes()
            mutations = [
                lambda r: r["counts"].update(native_entry_invocations=33),
                lambda r: r["counts"].update(child_process_start_count_complete=False),
                lambda r: r.update(case_counts={}),
                lambda r: r.update(cancelled_build_publications=0),
                lambda r: r["timing"].update(observation_wall_ns=1, explicit_pacing_wait_ns=0),
                lambda r: r["timing"].update(actual_call_observation_wall_sum_ns=0),
                lambda r: r["timing"].update(completed_observations_per_wall_second=0),
                lambda r: r["resources"].update(largest_observed_child_rss_kib=0),
                lambda r: r["journal"].update(retained_bytes_excluding_report=1),
                lambda r: r["programs"].update(candidate=r["programs"]["baseline"]),
            ]
            for mutation in mutations:
                changed = copy.deepcopy(result)
                mutation(changed)
                path.write_bytes(soak.canonical(changed))
                with self.assertRaises(ValueError):
                    soak.validate_evidence(runner.journal.output, require_hosted=False)
            path.write_bytes(b'{"execution_passed":false,' + originals.lstrip()[1:])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                soak.validate_evidence(runner.journal.output, require_hosted=False)
            changed = copy.deepcopy(result)
            changed["timing"]["parent_cpu_seconds"] = float("nan")
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                soak.validate_evidence(runner.journal.output, require_hosted=False)
            changed = copy.deepcopy(result)
            changed["counts"]["child_processes_started"] = 32
            path.write_bytes(soak.canonical(changed))
            with self.assertRaisesRegex(ValueError, "counters"):
                soak.validate_evidence(runner.journal.output, require_hosted=False)
            path.write_bytes(soak.canonical(result))
            events = runner.journal.output / "events.jsonl"
            original_events = events.read_bytes()
            for mutation in ("cleanup_pid", "returned_value"):
                decoded = [json.loads(line) for line in original_events.splitlines()]
                sample = next(row["value"] for row in decoded if row["kind"] == "sample")
                if mutation == "cleanup_pid":
                    sample["final_observation"]["child_process"]["cleanup"]["pid"] += 1
                else:
                    sample["result"]["value"] = 99
                chain, serialized = "0" * 64, []
                for row in decoded:
                    row["previous_sha256"] = chain
                    raw = soak.canonical(row) + b"\n"
                    chain = soak.digest(raw)
                    serialized.append(raw)
                events.write_bytes(b"".join(serialized))
                changed = copy.deepcopy(result)
                changed["journal"]["last_sha256"] = chain
                path.write_bytes(soak.canonical(changed))
                with self.assertRaises(ValueError):
                    soak.validate_evidence(runner.journal.output, require_hosted=False)
            path.write_bytes(originals)
            events.write_bytes(original_events)
            rows = events.read_bytes().splitlines(keepends=True)
            events.write_bytes(b"".join(rows[:-1]))
            with self.assertRaisesRegex(ValueError, "extent"):
                soak.validate_evidence(runner.journal.output, require_hosted=False)

    def test_failed_spawn_keeps_attempt_unknown_outcomes_and_failed_evidence(self):
        original = subprocess.Popen
        observed = []
        def failed(arguments, *args, **kwargs):
            if type(arguments) in (list, tuple) and len(arguments) > 4 and arguments[4] == probe._WORKER:
                observed.append(True)
                raise OSError("injected native creation refusal")
            return original(arguments, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            registered = soak.registration(soak.DEVELOPMENT, CLANG)
            runner = soak.NativeRuntimeSoak(registered, Path(directory) / "evidence")
            with mock.patch.object(subprocess, "Popen", side_effect=failed):
                result = runner.run()
            retain_development_evidence(runner.journal.output, "failed-spawn")
            self.assertEqual(len(observed), 1)
            self.assertFalse(result["execution_passed"])
            self.assertTrue(result["drained"])
            self.assertEqual(result["counts"]["attempted_calls"], 1)
            self.assertEqual(result["counts"]["child_processes_started"], 0)
            self.assertEqual(result["counts"]["unavailable_child_start_outcomes"], 1)
            self.assertEqual(result["counts"]["completed_observations"], 0)
            self.assertIsNone(result["counts"]["native_entry_invocations"])
            samples = [json.loads(line)["value"] for line in (runner.journal.output / "events.jsonl").read_text().splitlines()
                       if json.loads(line)["kind"] == "sample"]
            self.assertEqual(len(samples), 1)
            self.assertIn("injected native creation refusal", samples[0]["error"]["message"])

    def test_deadline_cleanup_retains_actual_unconfirmed_dispatcher_owner(self):
        original_wait = subprocess.Popen.wait
        exited = []
        def withheld(process, *args, **kwargs):
            if type(process.args) not in (list, tuple) or len(process.args) < 5 or process.args[4] != probe._WORKER:
                return original_wait(process, *args, **kwargs)
            deadline = monotonic() + 2
            status = None
            while status is None and monotonic() < deadline:
                status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if status is None:
                    sleep(.001)
            self.assertIsNotNone(status, "real native child did not exit")
            exited.append(process)
            raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))
        with tempfile.TemporaryDirectory() as directory:
            runner = soak.NativeRuntimeSoak(soak.registration(soak.DEVELOPMENT, CLANG), Path(directory) / "evidence")
            runner.host = NativeVersionDispatcher(soak.FIXTURE.read_bytes(), clang=CLANG, diagnostic_loan_site=soak.SITE)
            host = runner.host
            descriptor = next(iter(host._versions.values())).descriptor
            try:
                with mock.patch.object(subprocess.Popen, "wait", withheld):
                    item = runner.begin("actual-cleanup-negative", [5, 0, 4, 0], "return")
                    with self.assertRaises(NativeChildCleanupPending):
                        runner.finish(item)
                    # An explicit elapsed-deadline control, not a shortened
                    # successful profile or a simulated child completion.
                    with mock.patch.object(runner, "remaining", return_value=0.0):
                        with self.assertRaisesRegex(ValueError, "owner retained"):
                            runner.close_epoch()
                    self.assertIs(runner.host, host)
                    self.assertFalse(runner.report["drained"])
                    self.assertEqual(runner.counts["child_processes_started"], 1)
                    self.assertEqual(runner.counts["child_processes_reaped"], 0)
                    self.assertEqual(runner.counts["unconfirmed_child_reaps"], 1)
                    self.assertGreater(os.fstat(descriptor).st_size, 0)
                    runner.start_cleanup_retainer()
                    self.assertIsNotNone(runner.recovery_thread)
                    self.assertFalse(runner.recovery_thread.daemon)
                    self.assertTrue(runner.recovery_thread.is_alive())
                    self.assertIs(runner.host, host)
                runner.recovery_thread.join(3)
                self.assertFalse(runner.recovery_thread.is_alive())
                self.assertIsNone(runner.host)
                self.assertTrue(runner.report["drained"])
                self.assertFalse(runner.report["ok"])
                self.assertEqual(runner.report["cleanup_recovery"]["status"], "confirmed")
                self.assertEqual(runner.counts["child_processes_reaped"], 0,
                                 "later recovery must not rewrite the earlier failed sample")
                self.assertTrue(exited)
            finally:
                host.retry_cleanup(timeout=2)
                host.close(wait=True, timeout=2)
                for process in exited:
                    if process.returncode is None:
                        original_wait(process, timeout=2)
                if runner.recovery_thread is not None:
                    runner.recovery_thread.join(3)
                runner.journal.stream.close()
                retain_development_evidence(runner.journal.output, "cleanup-owner-negative")


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "requires Linux x86-64 and actual Clang 20")
class NativeRuntimeSoakFinalizationTests(unittest.TestCase):
    def finalizer_control(self, kind):
        """One real exited child; injected epoch can never pass a full profile."""
        with tempfile.TemporaryDirectory() as directory:
            runner = soak.NativeRuntimeSoak(soak.registration(soak.DEVELOPMENT, CLANG), Path(directory) / "evidence")
            original_stream = runner.journal.stream
            original_wait, original_usage = subprocess.Popen.wait, resource.getrusage
            enabled, pending = Event(), Event()
            enabled.set()
            processes, hosts = {}, []
            close_epoch = runner.close_epoch

            def withheld(process, *args, **kwargs):
                if (not enabled.is_set() or type(process.args) not in (tuple, list)
                        or len(process.args) < 5 or process.args[4] != probe._WORKER):
                    return original_wait(process, *args, **kwargs)
                deadline, status = monotonic() + 2, None
                while status is None and monotonic() < deadline:
                    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    if status is None:
                        sleep(.001)
                self.assertIsNotNone(status, "actual child did not exit before withheld reap")
                processes[process.pid] = process
                raise subprocess.TimeoutExpired(process.args, kwargs.get("timeout", 0))

            def one_call(baseline, candidate):
                runner.host = NativeVersionDispatcher(baseline.canonical_bytes, clang=CLANG, diagnostic_loan_site=soak.SITE)
                hosts.append(runner.host)
                item = runner.begin("finalization-negative-" + kind, [5, 0, 4, 0], "return")
                try:
                    runner.finish(item)
                except NativeChildCleanupPending:
                    pending.set()
                    raise
                self.fail("actual unconfirmed reap was not observed")

            def deadline_close():
                with mock.patch.object(runner, "remaining", return_value=0.0):
                    return close_epoch()

            def usage(who):
                if kind == "statistics" and pending.is_set():
                    raise OSError("injected final resource statistics failure")
                return original_usage(who)

            def constructor(*args, **kwargs):
                enabled.clear()  # Let the original actual wait confirm synchronous fallback.
                raise RuntimeError("injected recovery Thread construction failure")

            class CloseFailure:
                def __getattr__(self, name):
                    return getattr(original_stream, name)
                def close(self):
                    original_stream.close()
                    raise OSError("injected journal close failure after actual close")

            if kind == "close":
                runner.journal.stream = CloseFailure()
            try:
                with mock.patch.object(subprocess.Popen, "wait", withheld), \
                     mock.patch.object(runner, "run_epoch", side_effect=one_call), \
                     mock.patch.object(runner, "close_epoch", side_effect=deadline_close), \
                     mock.patch.object(resource, "getrusage", side_effect=usage):
                    if kind == "constructor":
                        with mock.patch.object(soak, "Thread", side_effect=constructor):
                            runner.run()
                        self.assertIsNone(runner.host)
                        self.assertTrue(hosts[0].snapshot()["drained"])
                        self.assertEqual(hosts[0].snapshot()["in_flight"], 0)
                        self.assertEqual(hosts[0].snapshot()["versions"], [])
                    else:
                        with self.assertRaises(OSError):
                            runner.run()
                        self.assertIs(runner.host, hosts[0])
                        self.assertIsNotNone(runner.recovery_thread)
                        self.assertFalse(runner.recovery_thread.daemon)
                        self.assertTrue(runner.recovery_thread.is_alive())
                        state = hosts[0].snapshot()
                        self.assertFalse(state["drained"])
                        self.assertEqual(state["in_flight"], 1)
                        self.assertEqual(state["unconfirmed_child_reaps"], 1)
                    self.assertTrue(pending.is_set())
                    self.assertEqual(len(processes), 1)
                    self.assertFalse(runner.report["ok"])
            finally:
                enabled.clear()
                if runner.recovery_thread is not None:
                    runner.recovery_thread.join(5)
                for host in hosts:
                    host.retry_cleanup(timeout=2)
                    self.assertTrue(host.close(wait=True, timeout=2)["drained"])
                for process in processes.values():
                    if process.returncode is None:
                        original_wait(process, timeout=2)
                original_stream.close()
                retain_development_evidence(runner.journal.output, "finalizer-" + kind)

    def test_final_statistics_failure_still_transfers_actual_cleanup_owner(self):
        self.finalizer_control("statistics")

    def test_journal_close_failure_still_transfers_actual_cleanup_owner(self):
        self.finalizer_control("close")

    def test_thread_constructor_failure_synchronously_confirms_actual_cleanup(self):
        self.finalizer_control("constructor")
