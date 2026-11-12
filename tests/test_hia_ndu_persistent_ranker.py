"""Real Linux framed transport controls and separately pinned native checks."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hepta.hia_ndu_optimizer import ROOT, OptimizationRejected, _bytes
from hepta.hia_ndu_persistent_ranker import (
    PersistentNduRanker, MAX_SESSION_BYTES, MAX_WIRE_BYTES, TAG_BYTES, PROFILE)
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker
from hepta.hia_rust_crosscheck import _run_bounded_shadow


_FIXTURE = r'''
import hashlib,json,os,sys,time
from pathlib import Path
session=sys.argv[2]
maximum=int(sys.argv[3])
marker=Path(MARKER)
def encode(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def packet(sequence,body,token=session):
    data=sequence.to_bytes(4,"big")+token.encode()+body
    return len(data).to_bytes(4,"big")+data
def send(raw):
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
def exact(length):
    data=b""
    while len(data)<length:
        piece=sys.stdin.buffer.read(length-len(data))
        if not piece: raise SystemExit(9)
        data+=piece
    return data
hello=HELLO
hello["max_requests"]=maximum
BEFORE_HELLO
send(packet(0,encode(hello)))
counter=0
for sequence in range(1,maximum+1):
    header=sys.stdin.buffer.read(4)
    if not header: break
    if len(header)!=4: raise SystemExit(8)
    frame=exact(int.from_bytes(header,"big"))
    if int.from_bytes(frame[:4],"big")!=sequence or frame[4:68]!=session.encode():
        raise SystemExit(7)
    raw=frame[68:]
    request=json.loads(raw)
    counter+=1
    marker.write_text(str(counter))
    response={
      "schema":"hepta.hia.ndu-response.v1","upstream_commit":UPSTREAM,
      "entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy",
      "objective_sha256":request["objective_sha256"],"generation":request["generation"],
      "request_sha256":hashlib.sha256(raw).hexdigest(),"authority":"ADVISORY_ONLY",
      "proves_program_safety":False,"global_optimality_established":False,
      "evaluation_digest_v2":hashlib.sha256(raw+b"evaluated").hexdigest(),
      "evaluation_policy_digest":"3"*64,"utility_profile_digest":"4"*64,
      "advisory_recommendation":"abstain","fixture_evaluation":counter}
    BEFORE_RESPONSE
    output=packet(sequence,encode(response))
    BEFORE_WRITE
    send(output)
    AFTER_RESPONSE
AFTER_LOOP
'''


@unittest.skipUnless(sys.platform == "linux", "Linux sealed process ownership required; NOT qualified")
class PersistentRankerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-persistent-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "bridge"
        self.receipt_file = self.root / "build-receipt.json"
        self.marker = self.root / "calls"
        self.locked = json.loads((ROOT / "rust/hia-ndu-bridge/upstream.json").read_bytes())
        self.request = {
            "schema": "hepta.hia.ndu-request.v1", "objective_sha256": "1" * 64, "generation": 1,
            "resource_cap_q32": 1, "candidates": [
                {"id": "abstain", "cost_q32": 0, "resource_q32": 0,
                 "uncertainty_q32": 0, "hard_violation": False, "support_sha256": "2" * 64}]}
        self.bridge = {"binary": str(self.binary), "build_receipt": str(self.receipt_file)}
        self.write_fixture()

    def write_fixture(self, *, before_hello="pass", before_response="pass",
                      before_write="pass", after_response="pass", after_loop="pass"):
        hello = {"schema": "hepta.hia.ndu-stream-hello.v1", "transport_profile": PROFILE,
                 "upstream_commit": self.locked["commit"],
                 "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
                 "max_requests": 1, "max_frame_json_bytes": 1048576,
                 "max_session_bytes": 8388608, "authority": "ADVISORY_ONLY",
                 "result_cache": False, "evaluates_each_request": True}
        source = _FIXTURE.replace("MARKER", repr(str(self.marker))).replace("hello=HELLO", "hello=" + repr(hello))
        source = source.replace("UPSTREAM", repr(self.locked["commit"]))
        for key, value in (("BEFORE_HELLO", before_hello),
                           ("BEFORE_RESPONSE", before_response), ("BEFORE_WRITE", before_write),
                           ("AFTER_RESPONSE", after_response), ("AFTER_LOOP", after_loop)):
            source = source.replace(key, value)
        raw = ("#!" + sys.executable + "\n" + source).encode()
        self.binary.write_bytes(raw)
        self.binary.chmod(0o700)
        adapter = ROOT / "rust/hia-ndu-bridge"
        inputs = {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
                  for p in sorted(adapter.rglob("*")) if p.is_file()}
        receipt = {"schema": "hepta.hia.ndu-build.v1", "upstream": self.locked,
                   "original_rust_sources_unchanged": True, "all_original_non_manifest_inputs_unchanged": True,
                   "build_inputs_unchanged": True, "locked_dependencies": True,
                   "isolated_production_manifests": True, "production_activation": False,
                   "adapter_files": inputs, "cargo_lock_sha256": inputs["Cargo.lock"],
                   "builder_sha256": sha256((ROOT / "tools/build_hia_ndu_bridge.py").read_bytes()).hexdigest(),
                   "binary_sha256": sha256(raw).hexdigest(), "build_inputs": {"fixture": True}}
        self.receipt_file.write_bytes(_bytes(receipt))

    def owner(self, **kwargs):
        owner = PersistentNduRanker(self.bridge, **kwargs)
        self.addCleanup(owner.close)
        return owner

    def assert_reaped(self, child):
        self.assertIsNotNone(child.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)

    def test_one_process_evaluates_each_identical_request_and_costs_close(self):
        events = []
        owner = self.owner(max_requests=3, observer=events.append)
        self.assertFalse(owner.receipt()["complete"])
        with owner:
            responses = [owner.rank(self.request)[0] for _ in range(3)]
        self.assertEqual([r["fixture_evaluation"] for r in responses], [1, 2, 3])
        self.assertEqual(self.marker.read_text(), "3")
        receipt = owner.receipt()
        self.assertTrue(receipt["complete"] and receipt["session_accepted"])
        self.assertEqual(receipt["native_processes_started"], 1)
        self.assertEqual(receipt["original_native_requests_completed"], 3)
        self.assertEqual(len({e["observation"]["worker_pid"] for e in events if e["phase"] != "close"}), 1)
        self.assertEqual(receipt["observed_disjoint_wall_ns"],
                         receipt["preparation_wall_ns"] + receipt["close_wall_ns"]
                         + sum(a["wall_ns"] for a in receipt["attempts"]))
        receipt["attempts"][0]["status"] = "tampered"
        self.assertEqual(owner.receipt()["attempts"][0]["status"], "completed")
        self.assertFalse(receipt["whole_lifecycle_cost_complete"])
        self.assert_reaped(owner._worker.proc)

    def test_request_copy_binds_actual_written_bytes_despite_caller_mutation(self):
        owner = self.owner(max_requests=1)
        request = deepcopy(self.request)
        real_write = os.write
        def mutate_after_write(fd, data):
            result = real_write(fd, data)
            if fd == owner._worker.proc.stdin.fileno():
                request["generation"] = 999
            return result
        with owner, patch("os.write", side_effect=mutate_after_write):
            response, _ = owner.rank(request)
        self.assertEqual(response["generation"], 1)
        self.assertEqual(response["request_sha256"], sha256(_bytes(self.request)).hexdigest())

    def test_changed_origin_path_cannot_replace_the_sealed_running_image(self):
        owner = self.owner(max_requests=2)
        fd = owner._image._fd
        self.binary.write_bytes(b"unadmitted replacement")
        with owner:
            for _ in range(2):
                self.assertEqual(owner.rank(self.request)[0]["advisory_recommendation"], "abstain")
        self.assertEqual(self.marker.read_text(), "2")
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_response_sequence_session_and_request_replays_refuse_and_retire(self):
        for action in ("output=packet(sequence+1,encode(response))",
                       "output=packet(sequence,encode(response),'0'*64)",
                       "response['request_sha256']='0'*64; output=packet(sequence,encode(response))"):
            with self.subTest(action=action):
                self.write_fixture(before_write=action)
                events = []
                owner = self.owner(max_requests=2, observer=events.append)
                with self.assertRaises(OptimizationRejected):
                    owner.rank(self.request)
                self.assertTrue(owner.receipt()["closed"])
                self.assertFalse(owner.receipt()["session_accepted"])
                self.assert_reaped(owner._worker.proc)
                with self.assertRaisesRegex(OptimizationRejected, "closed"):
                    owner.rank(self.request)
                self.assertEqual(self.marker.read_text(), "1")
                self.assertTrue(any(e["phase"] == "round" for e in events))

    def test_greeting_mismatch_and_startup_timeout_close_real_child_and_descriptor(self):
        for action in ("hello['result_cache']=True", "time.sleep(30)"):
            with self.subTest(action=action):
                self.write_fixture(before_hello=action)
                children, descriptors, events = [], [], []
                real_popen = subprocess.Popen
                def spawn(command, **kwargs):
                    descriptors.append(kwargs["pass_fds"][0])
                    child = real_popen(command, **kwargs); children.append(child); return child
                with patch("subprocess.Popen", side_effect=spawn), self.assertRaises(OptimizationRejected):
                    PersistentNduRanker(self.bridge, startup_timeout_s=0.2, observer=events.append)
                self.assert_reaped(children[0])
                with self.assertRaises(OSError):
                    os.fstat(descriptors[0])
                self.assertTrue(any(e["phase"] == "close" for e in events))

    def test_real_round_timeout_kills_and_reaps_without_retry(self):
        self.write_fixture(before_response="time.sleep(30)")
        owner = self.owner(max_requests=2)
        with self.assertRaisesRegex(OptimizationRejected, "deadline"):
            owner.rank(self.request, timeout_s=0.1)
        self.assertEqual(owner._worker.proc.returncode, -signal.SIGKILL)
        self.assert_reaped(owner._worker.proc)
        self.assertTrue(owner.receipt()["complete"])
        self.assertFalse(owner.receipt()["session_accepted"])
        self.assertEqual(self.marker.read_text(), "1")

    def test_idle_lifetime_watchdog_reaps_even_without_another_round(self):
        owner = self.owner(max_requests=2, lifetime_s=0.2)
        owner._worker.timer.join(timeout=1)
        self.assert_reaped(owner._worker.proc)
        self.assertEqual(owner._worker.cleanup["reason"], "session_lifetime_expired")
        with self.assertRaises(OptimizationRejected):
            owner.close()
        self.assertTrue(owner.receipt()["complete"])
        self.assertFalse(owner.receipt()["session_accepted"])

    def test_frame_length_overflow_partial_frame_and_error_output_refuse(self):
        actions = (
            "os.write(1,bytes([255])*4+b'x'*4096); time.sleep(30)",
            "os.write(1,bytes([0,0])); time.sleep(30)",
            "os.write(2,b'failure'*1024); raise SystemExit(7)",
        )
        for action in actions:
            with self.subTest(action=action):
                self.write_fixture(before_write=action)
                owner = self.owner(max_requests=2)
                with self.assertRaises(OptimizationRejected):
                    owner.rank(self.request, timeout_s=0.1)
                self.assert_reaped(owner._worker.proc)
                transport = owner.receipt()["attempts"][0]["transport"]
                self.assertLessEqual(transport["stdout_frame"]["bytes"], 8192)
                self.assertLessEqual(transport["stderr"]["bytes"], 8192)
                self.assertFalse(owner.receipt()["session_accepted"])

    def test_trailing_response_and_close_suffix_cannot_be_hidden(self):
        for hooks in ({"before_write": "output += packet(sequence,encode(response))"},
                      {"after_loop": "os.write(1,b'late unadmitted output')"}):
            with self.subTest(hooks=hooks):
                self.write_fixture(**hooks)
                owner = self.owner(max_requests=2)
                try:
                    owner.rank(self.request)
                except OptimizationRejected:
                    pass
                else:
                    with self.assertRaises(OptimizationRejected):
                        owner.close()
                self.assertTrue(owner.receipt()["complete"])
                self.assertFalse(owner.receipt()["session_accepted"])
                self.assert_reaped(owner._worker.proc)

    def test_owner_limit_and_total_wire_budget_are_bounded(self):
        owner = self.owner(max_requests=1)
        owner.rank(self.request)
        with self.assertRaisesRegex(OptimizationRejected, "allowance"):
            owner.rank(self.request)
        self.assertTrue(owner.receipt()["session_accepted"])
        # Large real writes into the fixture exercise the aggregate wire cap.
        large = self.owner(max_requests=12)
        request = {**self.request, "fixture_padding": "x" * 1_000_000}
        with self.assertRaisesRegex(OptimizationRejected, "byte allowance"):
            for _ in range(12):
                large.rank(request)
        total = sum(large.receipt()["wire_bytes"].values())
        self.assertLessEqual(total, MAX_SESSION_BYTES)
        self.assertLess(large.receipt()["original_native_requests_completed"], 12)
        self.assert_reaped(large._worker.proc)

    def test_external_reaping_refuses_before_any_numeric_group_signal(self):
        owner = self.owner(max_requests=1)
        owner.rank(self.request)
        _, status = os.waitpid(owner._worker.proc.pid, 0)  # Test-only ownership theft.
        with patch("os.killpg") as kill, self.assertRaises(OptimizationRejected):
            owner.close()
        kill.assert_not_called()
        self.assertFalse(owner.receipt()["complete"])
        self.assertFalse(owner.receipt()["session_accepted"])
        # The child really was reaped above; settle only test bookkeeping after
        # asserting that the owner refused its now-unowned numeric PID.
        owner._worker.proc.returncode = os.waitstatus_to_exitcode(status)

    def test_observer_reentrancy_refuses_and_observer_failure_is_costed(self):
        holder = {}
        observed = []
        def observer(event):
            if event["phase"] == "round":
                owner = holder["owner"]
                with self.assertRaisesRegex(OptimizationRejected, "reentrant"):
                    owner.rank(self.request)
                with self.assertRaisesRegex(OptimizationRejected, "active"):
                    owner.close()
                observed.append("checked")
                raise ValueError("observer control failure")
        owner = self.owner(max_requests=2, observer=observer)
        holder["owner"] = owner
        with self.assertRaisesRegex(ValueError, "observer control failure"):
            owner.rank(self.request)
        self.assertEqual(observed, ["checked"])
        self.assertEqual(owner.receipt()["attempts"][0]["status"], "rejected")
        self.assertGreater(owner.receipt()["attempts"][0]["wall_ns"], 0)
        self.assertTrue(owner.receipt()["complete"])

    def test_parallel_call_waits_are_separate_from_disjoint_service_cost(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        def observer(event):
            if event["phase"] == "round" and event["observation"]["sequence"] == 1:
                entered.set()
                release.wait(1)
        owner = self.owner(max_requests=2, observer=observer)
        def invoke():
            try: owner.rank(self.request)
            except BaseException as error: errors.append(error)
        one, two = threading.Thread(target=invoke), threading.Thread(target=invoke)
        one.start(); self.assertTrue(entered.wait(1)); two.start()
        time.sleep(0.03); release.set()
        one.join(2); two.join(2); owner.close()
        self.assertEqual(errors, [])
        receipt = owner.receipt()
        self.assertGreater(receipt["attempts"][1]["queue_wait_ns"], 10_000_000)
        self.assertEqual(receipt["observed_disjoint_wall_ns"],
                         receipt["preparation_wall_ns"] + receipt["close_wall_ns"]
                         + sum(a["wall_ns"] for a in receipt["attempts"]))

    def test_failed_context_entry_closes_image_and_process(self):
        import fcntl
        owner = self.owner(max_requests=2)
        fd = owner._image._fd
        real_fcntl = fcntl.fcntl
        def changed(fd, operation, *args):
            if operation == getattr(fcntl, "F_GET_SEALS", 1034): return 7
            return real_fcntl(fd, operation, *args)
        with patch("fcntl.fcntl", side_effect=changed), self.assertRaises(OptimizationRejected):
            with owner: self.fail("bad owner entered")
        with self.assertRaises(OSError): os.fstat(fd)
        self.assert_reaped(owner._worker.proc)

    def test_invalid_limits_and_changed_image_cannot_launch(self):
        for kwargs in ({"max_requests": 0}, {"max_requests": 257}, {"max_requests": True},
                       {"lifetime_s": float("nan")}, {"startup_timeout_s": 0}):
            with patch("subprocess.Popen") as spawn, self.assertRaises(OptimizationRejected):
                PersistentNduRanker(self.bridge, **kwargs)
            spawn.assert_not_called()
        self.binary.write_bytes(b"changed")
        with patch("subprocess.Popen") as spawn, self.assertRaises(OptimizationRejected):
            PersistentNduRanker(self.bridge)
        spawn.assert_not_called()

    def test_startup_budget_cannot_launch_after_admission_exhausts_it(self):
        with patch("hepta.hia_ndu_persistent_ranker.time.monotonic", side_effect=[0, 0, 2]), \
                patch("subprocess.Popen") as spawn, self.assertRaisesRegex(OptimizationRejected, "before process start"):
            PersistentNduRanker(self.bridge, startup_timeout_s=1)
        spawn.assert_not_called()

    def test_watchdog_start_failure_still_reaps_the_started_child(self):
        children = []
        real_popen = subprocess.Popen
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs); children.append(child); return child
        with patch("threading.Timer.start", side_effect=RuntimeError("thread unavailable")), \
                patch("subprocess.Popen", side_effect=spawn), self.assertRaisesRegex(RuntimeError, "thread unavailable"):
            PersistentNduRanker(self.bridge)
        self.assert_reaped(children[0])

    def test_observer_cannot_rewrite_startup_receipt_and_close_error_blocks_acceptance(self):
        def observer(event):
            if event["phase"] == "startup":
                event["observation"]["worker_pid"] = -1
            if event["phase"] == "close":
                raise ValueError("final observation unavailable")
        owner = self.owner(max_requests=1, observer=observer)
        owner.rank(self.request)
        with self.assertRaisesRegex(ValueError, "final observation unavailable"):
            owner.close()
        receipt = owner.receipt()
        self.assertEqual(receipt["startup"]["worker_pid"], owner._worker.proc.pid)
        self.assertTrue(receipt["complete"])
        self.assertFalse(receipt["session_accepted"])
        self.assertEqual(receipt["close"]["observer_error"]["type"], "ValueError")

    def test_startup_observer_failure_closes_and_costs_its_failure_observation(self):
        events = []
        def observer(event):
            events.append(event)
            if event["phase"] == "startup":
                raise ValueError("startup observer unavailable")
            if event["phase"] == "startup_failure":
                time.sleep(0.01)
        # Retain the object only for inspecting a failed constructor in this
        # control; normal callers receive no owner and must time their attempt.
        owner = PersistentNduRanker.__new__(PersistentNduRanker)
        with self.assertRaisesRegex(ValueError, "startup observer unavailable"):
            owner.__init__(self.bridge, observer=observer)
        self.addCleanup(owner.close)
        receipt = owner.receipt()
        self.assertTrue(receipt["closed"] and receipt["complete"])
        self.assertFalse(receipt["session_accepted"])
        self.assertGreater(receipt["preparation_wall_ns"], 10_000_000)
        self.assertEqual([e["phase"] for e in events], ["startup", "startup_failure", "close"])
        self.assert_reaped(owner._worker.proc)


@unittest.skipUnless(os.environ.get("HEPTA_NDU_BRIDGE") and os.environ.get("HEPTA_NDU_BUILD"),
                     "original native stream build not supplied; NOT qualified")
class NativePersistentRankerTests(unittest.TestCase):
    def setUp(self):
        self.bridge = {"binary": os.environ["HEPTA_NDU_BRIDGE"],
                       "build_receipt": str(Path(os.environ["HEPTA_NDU_BUILD"]) / "build-receipt.json")}

    def invoke_stream(self, payload, session, maximum):
        with PreparedNduRanker(self.bridge) as image:
            return _run_bounded_shadow(
                ["/proc/self/fd/" + str(image._fd), "--stream-v1", session, str(maximum)],
                payload, 1, pass_fds=(image._fd,))

    def test_original_native_responses_equal_prepared_for_four_fresh_evaluations(self):
        from tools.qualify_hia_ndu_prepared_ranker import requests
        rows = requests()[:4]
        events = []
        owner = PersistentNduRanker(self.bridge, max_requests=4, observer=events.append)
        with owner:
            actual = [owner.rank(request)[0] for request in rows]
        with PreparedNduRanker(self.bridge, max_requests=4) as prepared:
            expected = [prepared.rank(request)[0] for request in rows]
        self.assertEqual(actual, expected)
        self.assertTrue(owner.receipt()["session_accepted"])
        self.assertEqual(owner.receipt()["native_processes_started"], 1)
        self.assertEqual(owner.receipt()["original_native_requests_completed"], 4)

    def test_original_native_rejects_bad_session_sequence_length_and_partial_header(self):
        from tools.qualify_hia_ndu_prepared_ranker import requests
        raw = _bytes(requests()[0])
        session = "1" * 64
        def frame(sequence, token):
            data = sequence.to_bytes(4, "big") + token.encode() + raw
            return len(data).to_bytes(4, "big") + data
        for payload in (frame(0, session), frame(2, session), frame(1, "2" * 64),
                        bytes([255]) * 4, bytes([0])):
            with self.subTest(payload=payload[:4]):
                stdout, stderr, code = self.invoke_stream(payload, session, 2)
                self.assertEqual(code, 2)
                self.assertIn(b"hepta.hia.ndu-stream-error.v1", stderr)
                self.assertIn(b"hepta.hia.ndu-stream-hello.v1", stdout)

    def test_original_native_stops_at_the_startup_round_allowance(self):
        from tools.qualify_hia_ndu_prepared_ranker import requests
        raw = _bytes(requests()[0]); session = "1" * 64
        payload = (1).to_bytes(4, "big") + session.encode() + raw
        framed = len(payload).to_bytes(4, "big") + payload
        stdout, stderr, code = self.invoke_stream(framed + framed, session, 1)
        self.assertEqual(code, 0); self.assertEqual(stderr, b"")
        sequences = []
        while stdout:
            length = int.from_bytes(stdout[:4], "big")
            self.assertGreaterEqual(len(stdout), length + 4)
            sequences.append(int.from_bytes(stdout[4:8], "big"))
            stdout = stdout[4 + length:]
        self.assertEqual(sequences, [0, 1])


if __name__ == "__main__":
    unittest.main()
