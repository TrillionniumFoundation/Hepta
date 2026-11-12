"""Explicit, bounded reuse of one admitted sealed native ranking image.

Every call starts and reaps a new original NDU process. Only source/receipt
admission and executable sealing are reused; responses and ranking work are
never cached. This is a different transport profile from the one-shot caller:
its owner deliberately retains immutable bytes, not a live pathname binding.
The caller must charge preparation, every attempt, and close to its lifecycle.
Nothing here changes the existing macro policy, its ledgers or old campaigns.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import os
import stat
import threading
import time

from .hia_ndu_optimizer import (
    OptimizationRejected, _bridge_identity, _bytes, _json,
    _seal_bridge_image, _validate_native_rank_response,
)
from .hia_rust_crosscheck import HIARustCrosscheckRejected, _run_bounded_shadow

PROFILE = "hepta.hia.ndu-ranking-prepared-sealed.v1"
MAX_REQUESTS = 256
MAX_WIRE_BYTES = 1024 * 1024
_SEALS = 0x0008 | 0x0004 | 0x0002 | 0x0001


def _reject(message):
    raise OptimizationRejected("E_HIA_NDU_PREPARED: " + message)


class PreparedNduRanker:
    """Caller-owned snapshot, serialized calls, no process or result reuse.

    Kernel seal readback and descriptor identity are required before and after
    each invocation. Origin path changes do not select another image. The
    trusted kernel, loader/interpreter, shared libraries, process environment
    and local build receipt remain assumptions; this is not host attestation.
    A failed admitted attempt retires the handle. Construct a new one only as
    an explicit separately charged caller decision, never an automatic retry.
    """

    def __init__(self, bridge, *, max_requests=MAX_REQUESTS):
        started = time.perf_counter_ns()
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_REQUESTS:
            _reject("max_requests must be an integer in 1..256")
        self._lock = threading.RLock()
        self._max_requests = max_requests
        self._fd = None
        self._pinned_identity = None
        self._closed = False
        self._active = False
        self._attempts = []
        self._close_wall_ns = None
        self._close_confirmed = False
        self._close_error = None
        self._preparation_wall_ns = None
        self._identity_wire = None
        try:
            image, identity = _bridge_identity(bridge)
            self._identity_wire = _bytes(identity)
            self._fd = _seal_bridge_image(image.data)
            info = os.fstat(self._fd)
            self._pinned_identity = self._file_identity(info)
            self._check_snapshot()
            self._preparation_wall_ns = time.perf_counter_ns() - started
        except BaseException:
            # A constructor failure has no returned owner. Its caller's outer
            # measured attempt must retain that failure and the complete cost.
            self._preparation_wall_ns = time.perf_counter_ns() - started
            self.close()
            raise

    @staticmethod
    def _file_identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mode)

    def _check_snapshot(self):
        if self._closed or self._fd is None:
            _reject("prepared handle is closed")
        try:
            import fcntl
            current = os.fstat(self._fd)
            seals = fcntl.fcntl(self._fd, getattr(fcntl, "F_GET_SEALS", 1034))
        except (OSError, ImportError) as error:
            raise OptimizationRejected(
                "E_HIA_NDU_PREPARED: sealed descriptor unavailable") from error
        if (not stat.S_ISREG(current.st_mode)
                or self._file_identity(current) != self._pinned_identity
                or seals & _SEALS != _SEALS):
            _reject("sealed descriptor identity or mandatory seals changed")

    def rank(self, request, *, timeout_s=10.0, observer=None):
        """Execute one exact request and retain all admitted attempt costs.

        The original native response remains unchanged. The returned identity
        separately names this snapshot transport and its preparation receipt.
        Timeout includes serialization and waiting for another owner call;
        process launch and cleanup are not hard real-time reservations.
        """
        started = time.perf_counter_ns()
        if type(timeout_s) not in (int, float) or not 0 < timeout_s <= 60:
            _reject("timeout must be in (0, 60] seconds")
        deadline = started + int(timeout_s * 1_000_000_000)
        with self._lock:
            if self._closed:
                _reject("prepared handle is closed")
            if self._active:
                _reject("reentrant prepared invocation is not allowed")
            if len(self._attempts) >= self._max_requests:
                self.close()
                _reject("prepared request allowance exhausted")
            service_started = time.perf_counter_ns()
            self._active = True
            attempt = {"sequence": len(self._attempts) + 1,
                       "status": "started", "request_sha256": None,
                       "native_started": False, "response_admitted": False,
                       "cleanup_confirmed": False, "wall_ns": None,
                       "queue_wait_ns": service_started - started,
                       "caller_wall_ns": None, "error": None}
            self._attempts.append(attempt)
            observation = {"schema": "hepta.hia.ndu-native-observation.v1",
                           "transport_profile": PROFILE, "stdin": None,
                           "native_identity": None, "pump": None,
                           "response_admitted": False, "error": None}

            def remaining_seconds():
                remaining = deadline - time.perf_counter_ns()
                if remaining <= 0:
                    _reject("native budget exhausted before process start")
                return remaining / 1_000_000_000

            def observe_pump(value):
                observation["pump"] = value
                attempt.update(native_started=value["started"],
                               cleanup_confirmed=value["cleanup_confirmed"])
                for stream in ("stdout", "stderr"):
                    raw = value[stream]
                    attempt[stream + "_bytes"] = len(raw)
                    attempt[stream + "_sha256"] = sha256(raw).hexdigest()

            failed = False
            try:
                if type(request) is not dict:
                    _reject("request must be a scalar wire object")
                data = _bytes(request)
                if len(data) > MAX_WIRE_BYTES:
                    _reject("native request exceeds byte limit")
                # Bind response checks to these actual submitted bytes even if
                # a caller mutates its original object during native execution.
                frozen_request = _json(data)
                attempt["request_sha256"] = sha256(data).hexdigest()
                identity = _json(self._identity_wire)
                identity.update(transport_profile=PROFILE,
                                preparation_receipt_sha256=self.preparation_receipt_sha256)
                observation.update(stdin=data, native_identity=identity)
                self._check_snapshot()
                try:
                    stdout, stderr, returncode = _run_bounded_shadow(
                        ["/proc/self/fd/" + str(self._fd)], data,
                        remaining_seconds(), maximum_output=MAX_WIRE_BYTES + 1,
                        pass_fds=(self._fd,), observer=observe_pump)
                except (OSError, HIARustCrosscheckRejected) as error:
                    raise OptimizationRejected(
                        "E_HIA_NDU_PREPARED: native evaluator could not complete: " + str(error)) from error
                self._check_snapshot()
                if returncode or len(stdout) > MAX_WIRE_BYTES or len(stderr) > MAX_WIRE_BYTES:
                    _reject("native evaluator failed or exceeded output bounds")
                response = _validate_native_rank_response(frozen_request, data, stdout, identity)
                observation["response_admitted"] = True
                attempt.update(status="completed", response_admitted=True)
                return response, identity
            except BaseException as error:
                failed = True
                detail = {"type": type(error).__name__, "message": str(error)[:2048]}
                attempt.update(status="rejected", error=detail)
                observation["error"] = detail
                raise
            finally:
                try:
                    if observer is not None:
                        observer(observation)
                except BaseException as error:
                    failed = True
                    attempt.update(status="rejected", error={
                        "type": type(error).__name__, "message": str(error)[:2048]})
                    raise
                finally:
                    # Closing is a separate, disjoint interval in the receipt.
                    # External observers are included in this attempt exactly once.
                    finished = time.perf_counter_ns()
                    attempt["wall_ns"] = finished - service_started
                    attempt["caller_wall_ns"] = finished - started
                    self._active = False
                    if failed:
                        self.close()

    @property
    def preparation_receipt_sha256(self):
        return sha256(_bytes(self._preparation_receipt())).hexdigest()

    def _preparation_receipt(self):
        return {"schema": PROFILE, "native_identity": _json(self._identity_wire),
                "max_requests": self._max_requests,
                "executable_bytes_sealed": True,
                "origin_path_reopened_for_calls": False,
                "preparation_wall_ns": self._preparation_wall_ns,
                "authority": "ADVISORY_ONLY", "safety_certificate": False}

    def close(self):
        """Retire exactly this descriptor once; never retry an uncertain close."""
        with self._lock:
            if self._closed:
                return
            if self._active:
                _reject("cannot close during an active prepared invocation")
            started = time.perf_counter_ns()
            self._closed = True
            fd, self._fd = self._fd, None
            try:
                if fd is not None:
                    # Do not close a reused descriptor if outside code consumed
                    # ours. Such in-process tampering is not an admitted host.
                    if (self._pinned_identity is not None
                            and self._file_identity(os.fstat(fd)) != self._pinned_identity):
                        _reject("descriptor ownership changed before close")
                    os.close(fd)
                self._close_confirmed = True
            except BaseException as error:
                self._close_error = {"type": type(error).__name__, "message": str(error)[:2048]}
                raise
            finally:
                self._close_wall_ns = time.perf_counter_ns() - started

    def receipt(self):
        """Bounded copied costs; a live owner never reports a complete total."""
        with self._lock:
            attempts = deepcopy(self._attempts)
            cleanup_confirmed = all(not row["native_started"] or row["cleanup_confirmed"]
                                    for row in attempts)
            total = (self._preparation_wall_ns + sum(row["wall_ns"] or 0 for row in attempts)
                     + (self._close_wall_ns or 0))
            return {"schema": "hepta.hia.ndu-ranking-prepared-cost.v1",
                    "profile": PROFILE,
                    "preparation": self._preparation_receipt(),
                    "preparation_receipt_sha256": self.preparation_receipt_sha256,
                    "attempts": attempts, "closed": self._closed,
                    "close_confirmed": self._close_confirmed,
                    "close_wall_ns": self._close_wall_ns, "close_error": self._close_error,
                    "observed_disjoint_wall_ns": total,
                    "all_native_cleanup_confirmed": cleanup_confirmed,
                    "complete": self._closed and self._close_confirmed and cleanup_confirmed
                    and all(row["wall_ns"] is not None for row in attempts),
                    "cost_scope": "preparation plus serialized admitted calls including observer work plus close; caller setup, queue waiting, source acquisition, build, between-call work and final receipt serialization excluded; per-caller queue waits are separate overlapping observations and never added to the disjoint total",
                    "original_native_calls": sum(row["native_started"] for row in attempts),
                    "result_cache_hits": 0, "native_process_reuse": False,
                    "whole_lifecycle_cost_complete": False,
                    "economic_benefit_established": False,
                    "authority": "ADVISORY_ONLY", "safety_certificate": False}

    def __enter__(self):
        try:
            self._check_snapshot()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *_exc):
        self.close()
