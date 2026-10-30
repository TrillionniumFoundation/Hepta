"""One bounded native NDU process with sealed executable and sequential replies.

Transport reuse does not reuse evaluation results or grant deployment authority.
Every request is decoded and evaluated by the unchanged original NDU algorithms.
Linux process identity, native dependencies, host and build manifest are trusted;
this is not a sandbox or attestation against a compromised host.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import selectors
import subprocess
import threading
import time

from .hia_native_differential import _pin_native_artifact
from .hia_ndu import MAX_REQUEST_BYTES, NduBridge, NduBridgeError, _read_json

MAX_SESSION_REQUESTS = 256
_MAX_STDERR = 16384
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


class NduSession(NduBridge):
    """A caller-owned, finite session; every protocol or timeout failure closes it.

    Instances are serialized internally. Output never crosses request boundaries:
    exact sequence, request hash, native identity, objective and generation are
    checked before the result is returned. A failed session cannot be resumed.
    """

    def __init__(self, executable, identity_manifest, *, timeout=10.0):
        started = time.monotonic_ns()
        self._lock = threading.RLock()
        self._process = None
        self._fd = None
        self._closed = False
        self._sequence = 0
        self._stderr = bytearray()
        self._request_costs_ns = []
        self._image_identity_checks = 0
        self._cleanup_errors = []
        self.executable = Path(executable).resolve(strict=True)
        self.identity_manifest = Path(identity_manifest).resolve(strict=True)
        self.timeout = timeout
        if type(timeout) not in {int, float} or not 0 < timeout <= 120:
            raise NduBridgeError("timeout must be in (0, 120] seconds")
        with self.identity_manifest.open("rb") as stream:
            raw_manifest = stream.read(MAX_REQUEST_BYTES + 1)
        if len(raw_manifest) > MAX_REQUEST_BYTES:
            raise NduBridgeError("build identity exceeds 1 MiB")
        self.manifest = _read_json(raw_manifest)
        if self.manifest.get("schema") != "hepta.hia.ndu.build.v1":
            raise NduBridgeError("unsupported build identity schema")
        # The public manifest is observational input, not mutable authority.
        # Freeze only the executable/identity bindings used by NduBridge so a
        # later manifest edit cannot rebind an already running native process.
        self._binary_sha256 = self.manifest.get("binary_sha256")
        self._identity_bytes = self._encode_identity(self.manifest.get("identity"))
        try:
            raw, _, self._fd = _pin_native_artifact(self.executable)
            if sha256(raw).hexdigest() != self._binary_sha256:
                raise NduBridgeError("native executable digest mismatch")
            self._pinned_stat = os.fstat(self._fd)
            self._process = subprocess.Popen(
                ["/proc/self/fd/" + str(self._fd), "--stream"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(self._fd,), bufsize=0)
            for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                os.set_blocking(stream.fileno(), False)
            hello = self._exchange(None)
            if (set(hello) != {"schema", "identity", "max_requests", "authority", "safety_certificate"}
                    or hello.get("schema") != "hepta.hia.ndu.stream.v1"
                    or hello.get("identity") != self.manifest.get("identity")
                    or type(hello.get("max_requests")) is not int
                    or hello["max_requests"] != MAX_SESSION_REQUESTS
                    or hello.get("authority") != "DENY_ALL"
                    or hello.get("safety_certificate") is not False):
                raise NduBridgeError("native stream handshake does not match the build identity")
            self._verify_binary()
            self.startup_cost_ns = time.monotonic_ns() - started
        except BaseException:
            self._close_after_failure()
            raise

    @staticmethod
    def _encode_identity(identity):
        try:
            if type(identity) is not dict:
                raise NduBridgeError("native identity must be an object")
            return json.dumps(identity, sort_keys=True, separators=(",", ":"),
                              allow_nan=False).encode()
        except (TypeError, ValueError, UnicodeError) as error:
            raise NduBridgeError("native manifest identity is invalid") from error

    def _verify_binary(self):
        if self._closed or self._fd is None or self._process is None or self._process.poll() is not None:
            raise NduBridgeError("native session is closed")
        if (self.manifest.get("binary_sha256") != self._binary_sha256
                or self._encode_identity(self.manifest.get("identity")) != self._identity_bytes):
            raise NduBridgeError("native manifest bindings changed after admission")
        try:
            current = os.fstat(self._fd)
            seals = fcntl.fcntl(self._fd, fcntl.F_GET_SEALS)
        except OSError as error:
            raise NduBridgeError("sealed executable descriptor is unavailable") from error
        if (current.st_dev, current.st_ino, current.st_size) != (
                self._pinned_stat.st_dev, self._pinned_stat.st_ino, self._pinned_stat.st_size):
            raise NduBridgeError("sealed executable descriptor changed")
        # _pin_native_artifact compares the actual sealed descriptor bytes with
        # raw before returning it; raw is hashed above against the manifest.
        # F_SEAL_WRITE/GROW/SHRINK plus F_SEAL_SEAL make those bytes immutable.
        # While that same inode remains held and sealed, re-reading and hashing
        # the entire image twice per request adds no new byte-identity evidence.
        # Descriptor reuse, missing seals and an exec into another inode still
        # fail both before dispatch and after the actual native reply.
        if seals & _SEALS != _SEALS:
            raise NduBridgeError("sealed executable seals changed")
        try:
            loaded = os.stat("/proc/" + str(self._process.pid) + "/exe")
        except OSError as error:
            raise NduBridgeError("actual native process executable identity is unavailable") from error
        if (loaded.st_dev, loaded.st_ino) != (current.st_dev, current.st_ino):
            raise NduBridgeError("actual native process executes a different image")
        self._image_identity_checks += 1

    def _exchange(self, payload):
        deadline = time.monotonic() + self.timeout
        pending = memoryview(payload + b"\n") if payload is not None else memoryview(b"")
        received = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(self._process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(self._process.stderr, selectors.EVENT_READ, "stderr")
            if pending:
                selector.register(self._process.stdin, selectors.EVENT_WRITE, "stdin")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NduBridgeError("native stream request timed out")
                ready = selector.select(remaining)
                if not ready:
                    raise NduBridgeError("native stream request timed out")
                for key, _ in ready:
                    if key.data == "stdin":
                        count = os.write(key.fd, pending[:65536])
                        if count <= 0:
                            raise NduBridgeError("native stream write made no progress")
                        pending = pending[count:]
                        if not pending:
                            selector.unregister(key.fileobj)
                        continue
                    part = os.read(key.fd, 65536)
                    if key.data == "stderr":
                        self._stderr.extend(part)
                        if len(self._stderr) > _MAX_STDERR:
                            raise NduBridgeError("native stderr exceeds its session bound")
                        if not part:
                            selector.unregister(key.fileobj)
                        continue
                    if not part:
                        raise NduBridgeError("native stream ended before a complete response: " +
                                             self._stderr.decode("utf-8", "replace")[:2000])
                    received.extend(part)
                    if len(received) > 4 * MAX_REQUEST_BYTES:
                        raise NduBridgeError("native stream response exceeds its byte bound")
                    if b"\n" in received:
                        line, extra = bytes(received).split(b"\n", 1)
                        if extra or pending:
                            raise NduBridgeError("native stream returned an unsolicited response")
                        return _read_json(line)

    def _invoke(self, arguments, payload):
        if arguments:
            raise NduBridgeError("stream accepts only ordinary evaluation requests")
        if self._sequence >= MAX_SESSION_REQUESTS:
            raise NduBridgeError("native session request budget exhausted")
        envelope = self._exchange(payload)
        self._sequence += 1
        if (set(envelope) != {"schema", "sequence", "response", "authority", "safety_certificate"}
                or envelope.get("schema") != "hepta.hia.ndu.stream-response.v1"
                or type(envelope.get("sequence")) is not int
                or envelope["sequence"] != self._sequence
                or envelope.get("authority") != "DENY_ALL"
                or envelope.get("safety_certificate") is not False):
            raise NduBridgeError("native response sequence or authority mismatch")
        response = envelope["response"]
        if (type(response) is not dict or response.get("authority") != "DENY_ALL"
                or response.get("safety_certificate") is not False):
            raise NduBridgeError("native response attempted to confer authority")
        return response

    def evaluate(self, request):
        with self._lock:
            if self._closed:
                raise NduBridgeError("native session is closed")
            started = time.monotonic_ns()
            try:
                result = super().evaluate(request)
                self._verify_binary()
                return result
            except BaseException:
                self._close_after_failure()
                raise
            finally:
                self._request_costs_ns.append(time.monotonic_ns() - started)

    def snapshot(self):
        with self._lock:
            return {"schema": "hepta.hia.ndu.session-observation.v1", "closed": self._closed,
                    "pid": self._process.pid if self._process else None, "requests": self._sequence,
                    "startup_cost_ns": getattr(self, "startup_cost_ns", None),
                    "request_costs_ns": list(self._request_costs_ns),
                    "binary_sha256": self._binary_sha256,
                    "identity": json.loads(self._identity_bytes),
                    "image_identity_checks": self._image_identity_checks,
                    "content_binding": "sealed-bytes-verified-once; inode-seals-process-checked-per-request",
                    "cleanup_errors": list(self._cleanup_errors),
                    "stderr": self._stderr.decode("utf-8", "replace"),
                    "authority": "DENY_ALL", "safety_certificate": False}

    def _close_after_failure(self):
        # A cleanup diagnostic must not replace the rejection or cancellation
        # that caused it. close() still releases the parent's fd in its finally.
        try:
            self.close()
        except BaseException as error:
            self._cleanup_errors.append(type(error).__name__ + ": " + str(error))

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._process is not None:
                    try:
                        if self._process.stdin:
                            self._process.stdin.close()
                    finally:
                        try:
                            self._process.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            self._process.terminate()
                            try:
                                self._process.wait(timeout=2.0)
                            except subprocess.TimeoutExpired:
                                self._process.kill()
                                self._process.wait()
            finally:
                try:
                    if self._process is not None:
                        try:
                            if self._process.stdout:
                                self._process.stdout.close()
                        finally:
                            if self._process.stderr:
                                self._process.stderr.close()
                finally:
                    if self._fd is not None:
                        fd, self._fd = self._fd, None
                        os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()
