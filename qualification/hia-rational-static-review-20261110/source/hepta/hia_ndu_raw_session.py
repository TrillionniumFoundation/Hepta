"""Process-owned transport reuse for the native raw-model planner.

Both modes execute the same Rust search on every request. Only explicit `ndu`
invokes NDU. No model, plan, result or Python DP cache is reused. This service
is advisory; it neither activates programs nor isolates an untrusted host.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from .hia_native_differential import _pin_native_artifact
from .hia_ndu import NduBridgeError, _read_json
from .hia_ndu_raw_model import UPSTREAM, request_bytes, validate_response
from .hia_ndu_session import (
    IMAGE_CHECK_PROFILES, MAX_SESSION_REQUESTS, NduSession,
    _manifest_bytes, _manifest_wire, fcntl,
)


def _adapter_files():
    root = Path(__file__).resolve().parents[1] / "rust/hia-ndu-raw-model"
    return {str(p.relative_to(root)): sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


class RawModelSession(NduSession):
    """One sealed image and at most 256 fresh sequential model decisions.

The existing NDU transport supplies bounded nonblocking I/O, sealed image
checks and owned-process cleanup. Raw-model framing and witness admission are
separate. A failed request closes this session and is never replayed.
"""

    @classmethod
    def for_stream_profile(cls, *args, **kwargs):
        raise NduBridgeError("raw-model stream uses its constructor, not the legacy NDU profile factory")

    def __init__(self, executable, identity_manifest, *, timeout=10.0,
                 image_check="sealed"):
        if fcntl is None or not hasattr(os, "memfd_create") or not Path("/proc/self/exe").exists():
            raise NduBridgeError("raw-model stream requires qualified Linux sealed images")
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise NduBridgeError("timeout must be in (0, 120] seconds")
        if image_check not in IMAGE_CHECK_PROFILES:
            raise NduBridgeError("unknown sealed-image checking profile")
        started = time.monotonic_ns()
        self._owner_pid = os.getpid()
        self._lock = threading.RLock()
        self._process = None
        self._fd = None
        self._closed = False
        self._sequence = 0
        self._stderr = bytearray()
        self._request_costs_ns = []
        self._image_check = image_check
        self._image_identity_checks = 0
        self._cleanup_errors = []
        self.timeout = timeout
        self.executable = Path(executable).resolve(strict=True)
        self.identity_manifest = Path(identity_manifest).resolve(strict=True)
        self._manifest_path = self.identity_manifest
        self._manifest_raw = _manifest_bytes(self.identity_manifest)
        self.manifest = _read_json(self._manifest_raw)
        if (self.manifest.get("schema") != "hepta.hia.ndu-build.v1"
                or self.manifest.get("upstream", {}).get("commit") != UPSTREAM
                or self.manifest.get("original_rust_sources_unchanged") is not True
                or self.manifest.get("all_original_non_manifest_inputs_unchanged") is not True):
            raise NduBridgeError("raw-model build source binding differs")
        self._adapter_files = _adapter_files()
        if self.manifest.get("adapter_files") != self._adapter_files:
            raise NduBridgeError("raw-model adapter source binding differs")
        self._manifest_canonical = _manifest_wire(self.manifest)
        self._admitted_binary_sha256 = self.manifest.get("binary_sha256")
        self._binary_sha256 = self._admitted_binary_sha256
        self._identity_bytes = json.dumps({"upstream_commit": UPSTREAM,
            "profile": "raw-model-stream-v1"}, sort_keys=True).encode()
        try:
            raw, _, self._fd = _pin_native_artifact(self.executable)
            if sha256(raw).hexdigest() != self._admitted_binary_sha256:
                raise NduBridgeError("raw-model executable digest mismatch")
            self._pinned_stat = os.fstat(self._fd)
            self._process = subprocess.Popen(
                ["/proc/self/fd/" + str(self._fd), "--stream"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(self._fd,), bufsize=0)
            for pipe in (self._process.stdin, self._process.stdout, self._process.stderr):
                os.set_blocking(pipe.fileno(), False)
            hello = self._exchange(None)
            expected = {"schema": "hepta.hia.ndu.raw-model.stream.v1",
                "upstream_commit": UPSTREAM, "max_requests": MAX_SESSION_REQUESTS,
                "modes": ["exact_dp", "ndu"], "authority": "DENY_ALL", "safety_certificate": False}
            if _manifest_wire(hello) != _manifest_wire(expected):
                raise NduBridgeError("raw-model stream handshake differs")
            self._verify_binary()
            self.startup_cost_ns = time.monotonic_ns() - started
        except BaseException:
            self._close_after_failure()
            raise

    def _check_owner(self):
        # Refuse before any inherited mutex or child-process operation.
        if os.getpid() != self._owner_pid:
            raise NduBridgeError("raw-model session belongs to its creating process")

    def _verify_binary(self):
        self._check_owner()
        super()._verify_binary()
        if _adapter_files() != self._adapter_files:
            raise NduBridgeError("raw-model adapter source changed during the session")

    def evaluate(self, raw, *, mode="exact_dp"):
        self._check_owner()
        with self._lock:
            started = time.monotonic_ns()
            try:
                if self._closed or self._sequence >= MAX_SESSION_REQUESTS:
                    raise NduBridgeError("raw-model session is closed or exhausted")
                model, payload = request_bytes(raw, mode)
                self._verify_binary()
                envelope = self._exchange(payload)
                self._sequence += 1
                if (type(envelope) is not dict
                        or set(envelope) != {"schema", "sequence", "response", "authority", "safety_certificate"}
                        or envelope.get("schema") != "hepta.hia.ndu.raw-model.stream-response.v1"
                        or type(envelope.get("sequence")) is not int
                        or envelope["sequence"] != self._sequence
                        or envelope.get("authority") != "DENY_ALL"
                        or envelope.get("safety_certificate") is not False):
                    raise NduBridgeError("raw-model response sequence or authority differs")
                response = validate_response(model, mode, payload, envelope["response"])
                self._verify_binary()
                receipt = {"schema": "hepta.hia.ndu.raw-model.session-call.v1",
                    "mode": mode, "sequence": self._sequence,
                    "outer_wall_ns": time.monotonic_ns() - started,
                    "request_sha256": sha256(payload).hexdigest(),
                    "request_bytes": payload.decode(), "stdout": self._last_received_frame.decode(),
                    "binary_sha256": self._binary_sha256, "python_search_performed": False,
                    "includes": "input/source/image validation, stream I/O, Rust planning/evaluation, witness replay",
                    "excludes": "build, startup, close, imports, caller reporting, program execution"}
                return response, receipt
            except BaseException:
                self._close_after_failure()
                raise
            finally:
                self._request_costs_ns.append(time.monotonic_ns() - started)

    def snapshot(self):
        self._check_owner()
        report = super().snapshot()
        report["schema"] = "hepta.hia.ndu.raw-model.session-observation.v1"
        report["process_owner_pid"] = self._owner_pid
        report["python_search_performed"] = False
        report["cached_model_results"] = False
        return report

    def close(self):
        self._check_owner()
        return super().close()

    def __exit__(self, exc_type, exc_value, traceback):
        self._check_owner()
        if exc_type is not None:
            self._close_after_failure()
        else:
            self.close()
