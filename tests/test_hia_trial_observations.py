"""Evidence survives real subprocess exit and failed generation stages."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
import threading
from types import SimpleNamespace
import unittest

from tests.test_hia_agent_gguf import offline_engine, response
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine
from tools.qualify_hia_release_parity import assess, specification
from tools.qualify_hia_native_ndu import run_command


class TrialObservationTests(unittest.TestCase):
    def test_raw_completion_survives_exit_but_truncated_body_is_not_complete(self):
        for complete in (False, True):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory() as folder:
                path = str(Path(folder)/"test.sock")
                body = b'{"content":"retained"}'
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(path)
                    listener.listen(1)

                    def serve():
                        connection, _ = listener.accept()
                        with connection:
                            request = b""
                            while b"\r\n\r\n" not in request:
                                request += connection.recv(4096)
                            headers, received = request.split(b"\r\n\r\n", 1)
                            content_length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                                                  if line.lower().startswith(b"content-length:"))
                            while len(received) < content_length:
                                received += connection.recv(4096)
                            length = len(body) + (0 if complete else 5)
                            connection.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode()+body)

                    worker = threading.Thread(target=serve, daemon=True)
                    worker.start()
                    polls = []

                    def terminal_poll():
                        polls.append(True)
                        return None if len(polls) == 1 else 7

                    engine = object.__new__(LlamaCppEngine)
                    engine.output, engine.generation_count = Path(folder), 1
                    engine.socket_path = path
                    engine.process = SimpleNamespace(pid=os.getpid(), poll=terminal_poll)
                    try:
                        with self.assertRaises((RuntimeError, ValueError)):
                            engine.request("/completion", {"prompt": [1]}, timeout=1)
                    finally:
                        worker.join(timeout=2)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual((Path(folder)/"transport-001.response.raw").read_bytes(), body)
                    self.assertEqual(engine.last_completion_observation["body_complete"], complete)
                    self.assertEqual(engine.last_completion_observation["owned_process_returncode"], 7)

    def test_dripped_http_body_cannot_reset_the_wall_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder)/"test.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(path)
            except BaseException:
                listener.close()
                raise
            listener.listen(1)

            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.recv(4096)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
                    for _ in range(20):
                        try:
                            connection.sendall(b" ")
                        except OSError:
                            break
                        time.sleep(.02)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            engine = object.__new__(LlamaCppEngine)
            engine.socket_path = path
            engine.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(TimeoutError, "wall deadline"):
                    engine.request("/props", timeout=.06)
                self.assertLess(time.monotonic()-started, .35)
            finally:
                listener.close()
                worker.join(timeout=1)
            self.assertFalse(worker.is_alive())

    def test_timed_out_native_command_preserves_printed_failure_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = []
            with self.assertRaises(subprocess.TimeoutExpired):
                run_command([sys.executable, "-u", "-c", "import time; print('before timeout', flush=True); time.sleep(10)"],
                            Path(folder), ledger, timeout=.15)
            self.assertEqual(ledger[0]["status"], "timeout")
            self.assertIn(b"before timeout", Path(ledger[0]["stdout"]["path"]).read_bytes())
            self.assertGreater(ledger[0]["wall_ns"], 0)

    def test_template_and_tokenize_consume_one_generation_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = offline_engine(Path(folder), json_object=False, raw=response())
            request = engine.request.side_effect

            def slow_template(endpoint, payload=None, **kwargs):
                if endpoint == "/apply-template":
                    time.sleep(.02)
                return request(endpoint, payload, **kwargs)

            engine.request.side_effect = slow_template
            with self.assertRaisesRegex(TimeoutError, "entire generate"):
                engine.generate([{"role": "user", "content": "probe"}], limit=4, wall_seconds=.005)
            retained = json.loads((Path(folder)/"attempt-001.json").read_text())
            self.assertEqual(retained["status"], "failed")
            self.assertFalse(retained["completion_requested"])
            self.assertEqual(engine.generation_count, 0)
            self.assertIsNone(retained["usage"])
            self.assertGreaterEqual(retained["wall_nanoseconds"], 5_000_000)

    def test_transport_failure_keeps_known_input_and_unknown_output(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = offline_engine(Path(folder), json_object=False, raw=response())
            request = engine.request.side_effect

            def fail_completion(endpoint, payload=None, **kwargs):
                if endpoint == "/completion":
                    raise ConnectionResetError("owned test server disconnected")
                return request(endpoint, payload, **kwargs)

            engine.request.side_effect = fail_completion
            with self.assertRaises(ConnectionResetError):
                engine.generate([{"role": "user", "content": "probe"}], limit=4)
            retained = json.loads((Path(folder)/"attempt-001.json").read_text())
            self.assertTrue(retained["completion_requested"])
            self.assertFalse(retained["response_received"])
            self.assertEqual(retained["input_tokens"], 3)
            self.assertIsNone(retained["usage"])
            self.assertEqual((engine.generation_count, engine.response_count), (1, 0))

    def test_real_already_exited_child_preserves_exit_code_without_signalling(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = object.__new__(LlamaCppEngine)
            engine.output = Path(folder)
            engine.generation_count, engine.response_count = 1, 0
            engine.lifecycle_started_ns = time.monotonic_ns()
            engine.process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
            self.assertEqual(engine.process.wait(timeout=5), 7)
            engine.close()
            first = (Path(folder)/"lifecycle.json").read_bytes()
            retained = json.loads(first)
            self.assertEqual(retained["returncode_before_close"], 7)
            self.assertEqual(retained["returncode"], 7)
            self.assertTrue(retained["reaped"])
            self.assertFalse(retained["termination_requested"])
            self.assertFalse(retained["oom_cause_established"])
            engine.close()
            self.assertEqual(first, (Path(folder)/"lifecycle.json").read_bytes())

    def test_invalid_budgets_never_start_a_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = offline_engine(Path(folder), json_object=False, raw=response())
            for value in (0, -1, float("inf"), float("nan"), True):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    engine.generate([], wall_seconds=value)
            engine.request.assert_not_called()

    def test_release_assessment_rejects_missing_duplicate_or_padded_samples(self):
        spec = specification()
        rows = [{"phase": phase, "backend": backend, "n": n, "seed": seed,
                 "times_ns": [100]*spec["samples"]}
                for phase in ("training", "holdout") for backend in spec["backends"]
                for n in spec[phase+"_sizes"] for seed in spec[phase+"_seeds"]]
        self.assertTrue(assess(rows, spec)["performance_gate_passed"])
        padded = deepcopy(rows)
        padded[0]["times_ns"].append(1)
        for invalid in (rows[1:], rows+[rows[0]], padded):
            with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
                assess(invalid, spec)
        # A real slowdown cannot disappear behind complete positive controls.
        slower = deepcopy(rows)
        for row in slower:
            if row["backend"] == "hia" and row["phase"] == "holdout":
                row["times_ns"] = [1000]*spec["samples"]
        actual = assess(slower, spec)
        self.assertFalse(actual["performance_gate_passed"])
        self.assertFalse(actual["holdout_gate_passed"])
        self.assertFalse(actual["broad_rust_performance_parity_established"])


if __name__ == "__main__":
    unittest.main()
