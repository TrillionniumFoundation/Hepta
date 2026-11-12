"""Explicit bounded persistence of one sealed original native NDU process.

The native streaming profile evaluates every framed request afresh. Only the
process and admitted executable are retained; no response cache is present.
The Linux child leader remains unreaped until one owned process-group cleanup.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import os
import secrets
import selectors
import signal
import subprocess
import threading
import time

from .hia_ndu_optimizer import OptimizationRejected, _bytes, _json, _validate_native_rank_response
from .hia_ndu_prepared_ranker import PreparedNduRanker, MAX_REQUESTS, MAX_WIRE_BYTES
from .hia_rust_crosscheck import _require_shadow_process_ownership

PROFILE = "hepta.hia.ndu-ranking-persistent-framed.v1"
MAX_SESSION_BYTES = 8 * 1024 * 1024
TAG_BYTES = 4 + 64


def _reject(message):
    raise OptimizationRejected("E_HIA_NDU_PERSISTENT: " + message)


def _bounded_seconds(value, name):
    if type(value) not in (int, float) or not 0 < value <= 60:
        _reject(name + " must be in (0, 60] seconds")
    return float(value)


def _frame(sequence, session, body):
    payload = sequence.to_bytes(4, "big") + session.encode("ascii") + body
    return len(payload).to_bytes(4, "big") + payload


def _hello(maximum, upstream):
    return {"schema": "hepta.hia.ndu-stream-hello.v1",
            "transport_profile": PROFILE, "upstream_commit": upstream,
            "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
            "max_requests": maximum, "max_frame_json_bytes": MAX_WIRE_BYTES,
            "max_session_bytes": MAX_SESSION_BYTES, "authority": "ADVISORY_ONLY",
            "result_cache": False, "evaluates_each_request": True}


class _FramedWorker:
    """Private child owner. Never poll/reap the PID before group cleanup."""

    def __init__(self):
        self.proc = None
        self.timer = None
        self.guard = threading.Lock()
        self.cleanup_attempted = False
        self.cleanup = None
        self.deadline = None
        self.input_bytes = 0
        self.output_bytes = 0
        self.stderr_bytes = 0
        self.eof = {"stdout": False, "stderr": False}
        self.last_exchange = None

    def start(self, descriptor, session, maximum, deadline):
        _require_shadow_process_ownership()
        self.deadline = deadline
        if time.monotonic() >= deadline:
            _reject("session lifetime exhausted before process start")
        self.proc = subprocess.Popen(
            ["/proc/self/fd/" + str(descriptor), "--stream-v1", session, str(maximum)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, pass_fds=(descriptor,),
            env={"LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": "utf-8"})
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            os.set_blocking(stream.fileno(), False)
        # The watchdog acts even while the owner is idle. It owns the same
        # one-time WNOWAIT -> killpg -> wait transition as explicit close.
        self.timer = threading.Timer(max(0, deadline - time.monotonic()),
                                     self.stop, args=("session_lifetime_expired",))
        self.timer.daemon = True
        self.timer.start()

    def status(self):
        with self.guard:
            if self.cleanup_attempted:
                return None if self.cleanup is None else self.cleanup.get("returncode")
            value = os.waitid(os.P_PID, self.proc.pid,
                              os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if value is None:
                return None
            return value.si_status if value.si_code == os.CLD_EXITED else -value.si_status

    def stop(self, reason):
        with self.guard:
            if self.cleanup_attempted:
                return deepcopy(self.cleanup)
            self.cleanup_attempted = True
            started = time.perf_counter_ns()
            record = {"reason": reason, "pid": self.proc.pid if self.proc else None,
                      "signal_sent": False, "cleanup_confirmed": self.proc is None,
                      "returncode": None, "error": None, "wall_ns": None}
            self.cleanup = record
            try:
                if self.proc is not None:
                    # WNOWAIT retains the original PID even if the leader has
                    # exited; external reaping refuses rather than guessing.
                    os.waitid(os.P_PID, self.proc.pid,
                              os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    try:
                        os.killpg(self.proc.pid, signal.SIGKILL)
                        record["signal_sent"] = True
                    finally:
                        self.proc.wait(timeout=2)
                    record.update(cleanup_confirmed=True, returncode=self.proc.returncode)
            except BaseException as error:
                record.update(error={"type": type(error).__name__, "message": str(error)[:2048]},
                              returncode=self.proc.returncode if self.proc else None)
            finally:
                record["wall_ns"] = time.perf_counter_ns() - started
            return deepcopy(record)

    def _charge(self, kind, amount):
        if kind == "stdin":
            self.input_bytes += amount
        elif kind == "stdout":
            self.output_bytes += amount
        else:
            self.stderr_bytes += amount
        if self.input_bytes + self.output_bytes + self.stderr_bytes > MAX_SESSION_BYTES:
            _reject("session byte allowance exhausted")

    def _check_live_budget(self, deadline):
        if time.monotonic() >= min(deadline, self.deadline):
            _reject("execution deadline or session lifetime exhausted")
        if self.cleanup_attempted:
            _reject("worker has already been retired")

    def exchange(self, sequence, session, body, deadline, *, last_request=False):
        """One frame with bounded simultaneous input and output, no read-ahead."""
        started = time.perf_counter_ns()
        wire = b"" if body is None else _frame(sequence, session, body)
        stdout, stderr = bytearray(), bytearray()
        offset = 0
        complete = False
        error_record = None
        try:
            self._check_live_budget(deadline)
            if self.input_bytes + self.output_bytes + self.stderr_bytes + len(wire) > MAX_SESSION_BYTES:
                _reject("request would exceed session byte allowance")
            if self.eof["stdout"]:
                _reject("worker stdout already ended")
            with selectors.DefaultSelector() as selector:
                selector.register(self.proc.stdout, selectors.EVENT_READ, "stdout")
                if not self.eof["stderr"]:
                    selector.register(self.proc.stderr, selectors.EVENT_READ, "stderr")
                if wire:
                    # A response queued before its request is not admitted.
                    for key, _ in selector.select(0):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if chunk:
                            (stdout if key.data == "stdout" else stderr).extend(chunk)
                            self._charge(key.data, len(chunk))
                            _reject("unsolicited worker output before request")
                        self.eof[key.data] = True
                        selector.unregister(key.fileobj)
                    if self.eof["stdout"]:
                        _reject("worker exited before request")
                    selector.register(self.proc.stdin, selectors.EVENT_WRITE, "stdin")
                expected = None
                while True:
                    self._check_live_budget(deadline)
                    for key, _ in selector.select(max(0, min(deadline, self.deadline) - time.monotonic())):
                        kind, stream = key.data, key.fileobj
                        if kind == "stdin":
                            try:
                                count = os.write(stream.fileno(), memoryview(wire)[offset:offset + 65536])
                            except BlockingIOError:
                                continue
                            if count <= 0:
                                _reject("worker refused request input")
                            offset += count
                            self._charge(kind, count)
                            if offset == len(wire):
                                selector.unregister(stream)
                        else:
                            try:
                                chunk = os.read(stream.fileno(), 4096)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                self.eof[kind] = True
                                selector.unregister(stream)
                                if kind == "stdout" and not complete:
                                    _reject("worker output ended before a complete frame")
                                continue
                            target = stdout if kind == "stdout" else stderr
                            target.extend(chunk)
                            self._charge(kind, len(chunk))
                            if kind == "stderr":
                                _reject("worker emitted error output")
                            if expected is None and len(stdout) >= 4:
                                length = int.from_bytes(stdout[:4], "big")
                                if not TAG_BYTES + 1 <= length <= TAG_BYTES + MAX_WIRE_BYTES:
                                    _reject("response frame exceeds byte bounds")
                                expected = length + 4
                            if expected is not None:
                                if len(stdout) > expected:
                                    _reject("worker emitted trailing response bytes")
                                complete = len(stdout) == expected
                    if complete:
                        if offset != len(wire):
                            _reject("response arrived before request was fully written")
                        # Read any bytes already visible after the complete
                        # frame. Later unexpected bytes are caught on next
                        # request or final close; close is part of admission.
                        for key, _ in selector.select(0):
                            if key.data == "stdin":
                                continue
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if chunk:
                                (stdout if key.data == "stdout" else stderr).extend(chunk)
                                self._charge(key.data, len(chunk))
                                _reject("worker emitted trailing response bytes")
                            self.eof[key.data] = True
                            selector.unregister(key.fileobj)
                        break
                self._check_live_budget(deadline)
                actual_sequence = int.from_bytes(stdout[4:8], "big")
                if actual_sequence != sequence or bytes(stdout[8:8 + 64]) != session.encode("ascii"):
                    _reject("response session or sequence mismatch")
                code = self.status()
                if code is not None and (code != 0 or not last_request):
                    _reject("worker exited before the admitted session boundary")
                return bytes(stdout[4 + TAG_BYTES:])
        except BaseException as error:
            error_record = {"type": type(error).__name__, "message": str(error)[:2048]}
            raise
        finally:
            self.last_exchange = {
                "schema": "hepta.hia.ndu-stream-observation.v1",
                "sequence": sequence, "worker_pid": self.proc.pid if self.proc else None,
                "session": session, "stdin_frame": wire, "stdin_bytes_written": offset,
                "stdout_frame": bytes(stdout), "stderr": bytes(stderr),
                "frame_complete": complete, "eof": dict(self.eof),
                "error": error_record, "wall_ns": time.perf_counter_ns() - started,
                "output_scope": "actual bounded reads; unread bytes are never asserted complete"}

    def finish(self, *, abort, all_requests_used):
        """Retain final suffix/EOF and perform exactly one group cleanup."""
        started = time.perf_counter_ns()
        suffix = {"stdout": bytearray(), "stderr": bytearray()}
        error_record = None
        pipe_errors = []
        try:
            if self.cleanup_attempted and not abort:
                _reject("worker was retired before explicit close")
            if self.proc is not None and not self.cleanup_attempted and not abort:
                code = self.status()
                if code is not None and (code != 0 or not all_requests_used):
                    _reject("worker exited before explicit close")
                self.proc.stdin.close()
                deadline = min(time.monotonic() + 1.0, self.deadline)
                with selectors.DefaultSelector() as selector:
                    for name in ("stdout", "stderr"):
                        if not self.eof[name]:
                            selector.register(getattr(self.proc, name), selectors.EVENT_READ, name)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            _reject("worker close exceeded deadline")
                        for key, _ in selector.select(remaining):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if chunk:
                                suffix[key.data].extend(chunk)
                                self._charge(key.data, len(chunk))
                                _reject("worker emitted output after final admitted response")
                            self.eof[key.data] = True
                            selector.unregister(key.fileobj)
                while self.status() is None:
                    if time.monotonic() >= deadline:
                        _reject("worker did not exit after clean input EOF")
                    time.sleep(min(0.005, max(0, deadline - time.monotonic())))
                if self.status() != 0:
                    _reject("worker failed at close")
        except BaseException as error:
            error_record = {"type": type(error).__name__, "message": str(error)[:2048]}
        finally:
            cleanup = self.stop("failure_retirement" if abort or error_record else "explicit_close")
            if self.timer is not None:
                self.timer.cancel()
                if self.timer.ident is not None:
                    self.timer.join(timeout=2)
                    if self.timer.is_alive():
                        pipe_errors.append("watchdog thread join unconfirmed")
            if self.proc is not None:
                for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                    try:
                        if stream is not None and not stream.closed:
                            stream.close()
                    except BaseException as error:
                        pipe_errors.append(type(error).__name__ + ": " + str(error)[:2048])
        return {"schema": "hepta.hia.ndu-stream-close.v1", "cleanup": cleanup,
                "stdout_suffix": bytes(suffix["stdout"]), "stderr_suffix": bytes(suffix["stderr"]),
                "eof": dict(self.eof), "protocol_error": error_record, "pipe_errors": pipe_errors,
                "wall_ns": time.perf_counter_ns() - started,
                "cleanup_wall_is_nested": True}


class PersistentNduRanker:
    """Bounded owner for a sealed, framed native evaluator with mandatory close.

    Partial per-round observations are advisory until final session close.
    The lifetime watchdog closes the process even while the owner is idle;
    the caller still owns descriptor/pipe closure and complete outer costing.
    """

    def __init__(self, bridge, *, max_requests=MAX_REQUESTS, lifetime_s=60.0,
                 startup_timeout_s=1.0, observer=None):
        started = time.perf_counter_ns()
        lifetime = _bounded_seconds(lifetime_s, "lifetime")
        startup = _bounded_seconds(startup_timeout_s, "startup timeout")
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_REQUESTS:
            _reject("max_requests must be an integer in 1..256")
        self._lock = threading.RLock()
        self._image = None
        self._worker = _FramedWorker()
        self._max_requests = max_requests
        self._session = secrets.token_hex(32)
        self._observer = observer
        self._attempts = []
        self._active = False
        self._closed = False
        self._failed = False
        self._preparation_wall_ns = None
        self._close_wall_ns = None
        self._close_record = None
        self._startup_summary = None
        self._identity = None
        self._lifetime_deadline = time.monotonic() + lifetime
        startup_deadline = min(self._lifetime_deadline, time.monotonic() + startup)
        try:
            self._image = PreparedNduRanker(bridge, max_requests=max_requests)
            self._identity = _json(self._image._identity_wire)
            if time.monotonic() >= startup_deadline:
                _reject("startup deadline exhausted before process start")
            self._worker.start(self._image._fd, self._session, max_requests, self._lifetime_deadline)
            raw = self._worker.exchange(0, self._session, None, startup_deadline)
            if _json(raw) != _hello(max_requests, self._identity["upstream_commit"]):
                _reject("native streaming greeting differs from the explicit profile")
            self._image._check_snapshot()
            self._emit("startup", self._worker.last_exchange)
            self._startup_summary = self._summarize(self._worker.last_exchange)
        except BaseException:
            self._failed = True
            try:
                if self._worker.last_exchange is not None:
                    self._emit("startup_failure", self._worker.last_exchange)
            finally:
                self._preparation_wall_ns = time.perf_counter_ns() - started
                self.close()
            raise
        self._preparation_wall_ns = time.perf_counter_ns() - started

    @staticmethod
    def _summarize(value):
        return {key: ({"bytes": len(item), "sha256": sha256(item).hexdigest()}
                      if type(item) is bytes else deepcopy(item)) for key, item in value.items()}

    def _emit(self, phase, observation):
        if self._observer is not None:
            # Treat observer reentrancy exactly like an active round.
            old = self._active
            self._active = True
            try:
                self._observer({"schema": "hepta.hia.ndu-persistent-event.v1",
                                "phase": phase, "observation": deepcopy(observation)})
            finally:
                self._active = old

    def rank(self, request, *, timeout_s=1.0):
        started = time.perf_counter_ns()
        deadline = time.monotonic() + _bounded_seconds(timeout_s, "round timeout")
        with self._lock:
            if self._closed:
                _reject("persistent owner is closed")
            if self._active:
                _reject("reentrant persistent invocation is not allowed")
            if len(self._attempts) >= self._max_requests:
                self.close()
                _reject("persistent request allowance exhausted")
            service_started = time.perf_counter_ns()
            self._active = True
            attempt = {"sequence": len(self._attempts) + 1, "status": "started",
                       "request_sha256": None, "response_sha256": None,
                       "wall_ns": None, "queue_wait_ns": service_started - started,
                       "caller_wall_ns": None, "error": None, "transport": None}
            self._attempts.append(attempt)
            self._worker.last_exchange = None
            try:
                if type(request) is not dict:
                    _reject("request must be a scalar wire object")
                raw = _bytes(request)
                if len(raw) > MAX_WIRE_BYTES:
                    _reject("native request exceeds byte limit")
                frozen = _json(raw)
                attempt["request_sha256"] = sha256(raw).hexdigest()
                self._image._check_snapshot()
                output = self._worker.exchange(attempt["sequence"], self._session, raw, deadline,
                                               last_request=attempt["sequence"] == self._max_requests)
                self._image._check_snapshot()
                identity = {**self._identity, "transport_profile": PROFILE,
                            "worker_session": self._session, "worker_pid": self._worker.proc.pid}
                response = _validate_native_rank_response(frozen, raw, output, identity)
                attempt.update(status="completed", response_sha256=sha256(output).hexdigest())
                return response, identity
            except BaseException as error:
                self._failed = True
                attempt.update(status="rejected", error={
                    "type": type(error).__name__, "message": str(error)[:2048]})
                raise
            finally:
                try:
                    if self._worker.last_exchange is not None:
                        attempt["transport"] = self._summarize(self._worker.last_exchange)
                        self._emit("round", self._worker.last_exchange)
                except BaseException as error:
                    self._failed = True
                    attempt.update(status="rejected", error={
                        "type": type(error).__name__, "message": str(error)[:2048]})
                    raise
                finally:
                    finished = time.perf_counter_ns()
                    attempt["wall_ns"] = finished - service_started
                    attempt["caller_wall_ns"] = finished - started
                    self._active = False
                    if self._failed:
                        self.close()

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._active:
                _reject("cannot close during active persistent invocation")
            started = time.perf_counter_ns()
            self._closed = True
            record = None
            image_error = None
            try:
                record = self._worker.finish(abort=self._failed,
                                             all_requests_used=len(self._attempts) == self._max_requests)
            finally:
                try:
                    if self._image is not None:
                        self._image.close()
                except BaseException as error:
                    image_error = {"type": type(error).__name__, "message": str(error)[:2048]}
                try:
                    self._close_record = self._summarize(record) if record is not None else None
                    if self._close_record is not None:
                        self._close_record["image_close_error"] = image_error
                    if record is not None:
                        try:
                            self._emit("close", record)
                        except BaseException as error:
                            self._failed = True
                            self._close_record["observer_error"] = {
                                "type": type(error).__name__, "message": str(error)[:2048]}
                            raise
                finally:
                    self._close_wall_ns = time.perf_counter_ns() - started
            if (record is None or image_error or record["protocol_error"] or record["pipe_errors"]
                    or not record["cleanup"]["cleanup_confirmed"]):
                self._failed = True
                _reject("persistent close or protocol completion unconfirmed")

    def receipt(self):
        with self._lock:
            attempts = deepcopy(self._attempts)
            cleanup = (self._close_record or {}).get("cleanup") or {}
            closed_cost = (self._closed and self._close_wall_ns is not None
                           and cleanup.get("cleanup_confirmed") is True
                           and not (self._close_record or {}).get("pipe_errors")
                           and not (self._close_record or {}).get("image_close_error")
                           and all(row["wall_ns"] is not None for row in attempts))
            total = ((self._preparation_wall_ns or 0) + (self._close_wall_ns or 0)
                     + sum(row["wall_ns"] or 0 for row in attempts))
            return {"schema": "hepta.hia.ndu-ranking-persistent-cost.v1",
                    "profile": PROFILE, "native_identity": deepcopy(self._identity),
                    "session": self._session, "max_requests": self._max_requests,
                    "worker_pid": self._worker.proc.pid if self._worker.proc else None,
                    "native_processes_started": int(self._worker.proc is not None),
                    "original_native_requests_completed": sum(row["status"] == "completed" for row in attempts),
                    "preparation_wall_ns": self._preparation_wall_ns,
                    "startup": deepcopy(self._startup_summary),
                    "attempts": attempts, "close_wall_ns": self._close_wall_ns,
                    "close": deepcopy(self._close_record), "closed": self._closed,
                    "observed_disjoint_wall_ns": total, "complete": bool(closed_cost),
                    "session_accepted": bool(closed_cost and not self._failed
                        and not (self._close_record or {}).get("protocol_error")),
                    "wire_bytes": {"stdin": self._worker.input_bytes,
                                   "stdout": self._worker.output_bytes,
                                   "stderr": self._worker.stderr_bytes},
                    "native_process_reuse": True, "result_cache_hits": 0,
                    "cost_scope": "preparation plus serialized admitted rounds including observer work plus explicit close; inner sealed-image costs and cleanup are nested, not added again; overlapping queue waits, caller setup, source acquisition, build, idle work and final receipt serialization are excluded",
                    "whole_lifecycle_cost_complete": False,
                    "economic_benefit_established": False, "authority": "ADVISORY_ONLY",
                    "safety_certificate": False}

    def __enter__(self):
        try:
            if self._closed:
                _reject("persistent owner is closed")
            self._image._check_snapshot()
            self._worker._check_live_budget(self._lifetime_deadline)
        except BaseException:
            self._failed = True
            self.close()
            raise
        return self

    def __exit__(self, *_exc):
        self.close()
