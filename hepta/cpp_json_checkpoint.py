"""Finite caller-owned checkpoints around the existing scoped JSON C ABI.

This is explicit foreign-process isolation, not C++ translation or a memory
safety proof. Only bounded integer arrays are reconstructed between calls.
No foreign address, handle, external side effect or arbitrary object state is
transferred. The existing run_bounded owner remains the only process supervisor.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
import platform
import secrets
import struct
import sys
import threading
import time

from .clang_capture import CaptureRejected, run_bounded

PROFILE = "hepta.cpp-json-checkpoint.v1"
WORKER_SCHEMA = "hepta.cpp-json-checkpoint-worker.v1"
VERSIONS = ("3.11.3", "3.12.0")
MAX_ITEMS = 64
MAX_MAGNITUDE = 1_000_000
MAX_REQUESTS = 128
MAX_FAULT_SITE = 127
MAX_IMAGE_BYTES = 2_000_000
MAX_LAUNCH_BYTES = 3_000_000
MAX_STREAM_BYTES = 4096
TIMEOUT_SECONDS = 3
ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
SENTINEL = (1 << 63) - 1
_IMAGE_KEY = object()
_REQUEST_KEY = object()


class CheckpointRejected(ValueError):
    pass


def _require(value, message):
    if not value:
        raise CheckpointRejected("E_CPP_JSON_CHECKPOINT: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate worker field")
        result[key] = value
    return result


def _json(data):
    def bad(value):
        raise CheckpointRejected("E_CPP_JSON_CHECKPOINT: nonfinite worker value")
    return json.loads(data, object_pairs_hook=_unique, parse_constant=bad)


def _state(values):
    _require(type(values) in (list, tuple) and 1 <= len(values) <= MAX_ITEMS,
             "checkpoint requires 1..64 ordinary integer values")
    result = tuple(values)
    _require(all(type(v) is int and -MAX_MAGNITUDE <= v <= MAX_MAGNITUDE for v in result),
             "checkpoint value is outside the exact integer domain")
    return result


# This small bootstrap is executed by the existing bounded process owner. It
# receives a private immutable ELF snapshot, seals that exact byte sequence,
# and execs its descriptor. Mutable build paths are never execution authority.
# It adds no independent process watcher, retry, shell, or descendant protocol.
_BOOTSTRAP = r'''
import base64,fcntl,hashlib,json,os,resource,sys
def need(ok):
    if not ok: raise ValueError("finite JSON worker launch refused")
def pairs(items):
    result={}
    for k,v in items:
        need(k not in result); result[k]=v
    return result
wire=lambda x:json.dumps(x,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
raw=sys.stdin.buffer.read(3000001)
need(len(raw)<=3000000 and sys.platform=="linux" and os.execve in os.supports_fd)
launch=json.loads(raw,object_pairs_hook=pairs)
need(type(launch) is dict and set(launch)=={"image","image_sha256","request","request_sha256"})
request=launch["request"]
need(type(request) is dict and set(request)=={"schema","owner","nonce","sequence","revision","version","values","index","value","fault_site"})
need(request["schema"]=="hepta.cpp-json-checkpoint.v1" and request["version"] in ("3.11.3","3.12.0"))
for field in ("owner","nonce"):
    v=request[field];need(type(v) is str and len(v)==32 and all(c in "0123456789abcdef" for c in v))
for field,lo,hi in (("sequence",1,128),("revision",0,127),("index",0,63),("value",-1000000,1000000),("fault_site",0,127)):
    v=request[field];need(type(v) is int and lo<=v<=hi)
values=request["values"]
need(type(values) is list and 1<=len(values)<=64 and request["index"]<len(values))
need(all(type(v) is int and -1000000<=v<=1000000 for v in values))
digest=hashlib.sha256(wire(request)).hexdigest()
need(digest==launch["request_sha256"])
image=base64.b64decode(launch["image"],validate=True)
need(64<=len(image)<=2000000 and image[:6]==b"\x7fELF\x02\x01" and hashlib.sha256(image).hexdigest()==launch["image_sha256"])
def sealed(name,data,mode):
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    offset=0
    while offset<len(data):
        wrote=os.write(fd,data[offset:]);need(wrote>0);offset+=wrote
    os.fchmod(fd,mode)
    seals=0x0001|0x0002|0x0004|0x0008
    fcntl.fcntl(fd,getattr(fcntl,"F_ADD_SEALS",1033),seals)
    need(fcntl.fcntl(fd,getattr(fcntl,"F_GET_SEALS",1034))&seals==seals)
    need(os.pread(fd,len(data)+1,0)==data)
    os.lseek(fd,0,os.SEEK_SET)
    return fd
image_fd=sealed("hepta-cpp-json",image,0o500)
numbers=[request[k] for k in ("revision","sequence","fault_site")]+[len(values),request["index"],request["value"],*values]
input_fd=sealed("hepta-cpp-json-request",(" ".join(map(str,numbers))+"\n").encode(),0o400)
os.dup2(input_fd,0);os.close(input_fd)
for kind,requested in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,65536),(resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,2)):
    soft,hard=resource.getrlimit(kind)
    bound=min([requested]+[v for v in (soft,hard) if v!=resource.RLIM_INFINITY])
    resource.setrlimit(kind,(bound,bound))
    after=resource.getrlimit(kind);need(after==(bound,bound))
os.execve(image_fd,["hepta-cpp-json",request["nonce"],digest],dict(os.environ))
'''


@dataclass(frozen=True, slots=True, init=False)
class JsonWorkerImage:
    """Opaque image issued only by the existing-bridge build path.

    Python host code and the native compiler remain trusted. This is not a
    capability boundary against hostile code with access to Python internals.
    """
    _bytes: bytes
    version: str
    sha256: str
    build_sha256: str

    def __init__(self, data, version, build_sha256, *, _key=None):
        _require(_key is _IMAGE_KEY, "use the actual scoped bridge build factory")
        _require(type(data) is bytes and 64 <= len(data) <= MAX_IMAGE_BYTES
                 and data[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<H", data, 16)[0] in (2, 3)
                 and struct.unpack_from("<H", data, 18)[0] == 62,
                 "finite Linux x86-64 ELF worker required")
        _require(version in VERSIONS and type(build_sha256) is str and len(build_sha256) == 64
                 and all(c in "0123456789abcdef" for c in build_sha256), "worker build binding differs")
        for name, value in (("_bytes", data), ("version", version),
                            ("sha256", _sha(data)), ("build_sha256", build_sha256)):
            object.__setattr__(self, name, value)

    def __reduce_ex__(self, protocol):
        raise TypeError("native worker images cannot be deserialized as build authority")


def _issue_worker_image(data, version, build_sha256):
    """Private end of the real C++/Hepta ABI generation and build factory."""
    return JsonWorkerImage(data, version, build_sha256, _key=_IMAGE_KEY)


@dataclass(frozen=True, slots=True, init=False)
class CheckpointRequest:
    _owner: object
    _body: bytes

    def __init__(self, owner, body, *, _key=None):
        _require(_key is _REQUEST_KEY, "requests must be prepared by their live owner")
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_body", body)

    def __copy__(self):
        raise TypeError("one-use checkpoint requests cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()

    def __reduce_ex__(self, protocol):
        raise TypeError("one-use checkpoint requests cannot be serialized")


class JsonCheckpoint:
    """An explicit, bounded parent checkpoint; no C++ object survives a call."""
    def __init__(self, image, values):
        _require(type(image) is JsonWorkerImage, "actual built worker image required")
        _require(sys.platform == "linux" and platform.machine() == "x86_64",
                 "this finite isolation profile requires Linux x86-64")
        self._image = image
        self._values = _state(values)
        self._revision = 0
        self._issued = 0
        self._owner = object()
        self._namespace = secrets.token_hex(16)
        self._pending = None
        self._busy = False
        self._poisoned = False
        self._closed = False
        self._history = []
        self._lock = threading.RLock()

    def __copy__(self):
        raise TypeError("checkpoint owners cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()

    def __reduce_ex__(self, protocol):
        raise TypeError("checkpoint owners cannot be serialized")

    def _mutable(self):
        _require(not self._busy, "reentrant checkpoint mutation is forbidden")
        _require(not self._closed and not self._poisoned, "checkpoint is closed or poisoned")

    def _snapshot(self):
        data = {"revision": self._revision, "values": list(self._values)}
        return {**data, "sha256": _sha(_wire(data))}

    def snapshot(self):
        with self._lock:
            return {"schema": PROFILE, **self._snapshot(), "closed": self._closed,
                    "poisoned": self._poisoned, "issued_requests": self._issued,
                    "pending": self._pending is not None}

    def history(self):
        with self._lock:
            return json.loads(_wire(self._history))

    def prepare(self, index, value, *, revision, fault_site=0):
        with self._lock:
            self._mutable()
            _require(self._pending is None, "only one outstanding replacement is permitted")
            _require(type(revision) is int and revision == self._revision, "stale checkpoint revision")
            _require(type(index) is int and 0 <= index < len(self._values)
                     and type(value) is int and -MAX_MAGNITUDE <= value <= MAX_MAGNITUDE,
                     "replacement is outside the bounded scalar state")
            _require(type(fault_site) is int and 0 <= fault_site <= MAX_FAULT_SITE,
                     "allocation fault site is outside the finite test profile")
            _require(self._issued < MAX_REQUESTS, "checkpoint request lifetime budget exhausted")
            self._issued += 1
            body = _wire({"schema": PROFILE, "owner": self._namespace,
                          "nonce": secrets.token_hex(16), "sequence": self._issued,
                          "revision": self._revision, "version": self._image.version,
                          "values": list(self._values), "index": index, "value": value,
                          "fault_site": fault_site})
            request = CheckpointRequest(self._owner, body, _key=_REQUEST_KEY)
            self._pending = (request, body)
            return request

    def _take(self, request):
        _require(type(request) is CheckpointRequest and self._pending is not None
                 and request is self._pending[0] and request._owner is self._owner
                 and request._body == self._pending[1], "foreign, changed, cancelled or consumed request")
        body = self._pending[1]
        self._pending = None
        return body

    def cancel(self, request):
        with self._lock:
            self._mutable()
            self._take(request)

    def execute(self, request):
        with self._lock:
            self._mutable()
            body = self._take(request)
            invocation = json.loads(body)
            _require(invocation["revision"] == self._revision
                     and invocation["values"] == list(self._values), "prepared state no longer matches owner")
            started = time.monotonic_ns()
            self._busy = True
            before = self._snapshot()
            row = {"request": invocation, "request_sha256": _sha(body),
                   "worker_sha256": self._image.sha256, "build_sha256": self._image.build_sha256,
                   "before": before, "status": "started", "committed": False,
                   "returncode": None, "direct_child_reaped": False,
                   "all_descendants_completion_proved": False,
                   "foreign_memory_safety_proved": False, "foreign_failure_recovered_in_process": False}
            self._history.append(row)
            try:
                launch = _wire({"image": base64.b64encode(self._image._bytes).decode(),
                                "image_sha256": self._image.sha256, "request": invocation,
                                "request_sha256": row["request_sha256"]})
                _require(len(launch) <= MAX_LAUNCH_BYTES, "worker launch exceeds fixed byte budget")
                result = run_bounded([sys.executable, "-I", "-c", _BOOTSTRAP],
                                     input_text=launch.decode(), timeout=TIMEOUT_SECONDS,
                                     stdin_limit=MAX_LAUNCH_BYTES, stdout_limit=MAX_STREAM_BYTES,
                                     stderr_limit=MAX_STREAM_BYTES)
                _require(type(result.returncode) is int, "exact process wait status required")
                row.update(returncode=result.returncode, direct_child_reaped=True)
                self._streams(row, result.raw_stdout, result.raw_stderr)
                if result.returncode != 0:
                    row["status"] = ("foreign_noexcept_termination" if result.returncode == -6
                                     and b"std::bad_alloc" in result.raw_stderr else "process_failed")
                    if row["status"] == "process_failed":
                        self._poisoned = True
                else:
                    _require(result.raw_stderr == b"", "normal worker emitted unexpected diagnostics")
                    observation = _json(result.raw_stdout)
                    self._accept(observation, invocation, row)
            except CaptureRejected as error:
                row.update(status="capture_refused", capture_code=error.code,
                           capture_error=error.capture_error)
                captured = error.capture
                if captured is not None:
                    row.update(returncode=captured.returncode,
                               stdout_total_bytes=captured.stdout_total_bytes,
                               stderr_total_bytes=captured.stderr_total_bytes)
                    self._streams(row, captured.stdout, captured.stderr)
                confirmed = (captured is not None and type(captured.returncode) is int
                             and error.capture_error is None
                             and error.code in {"E_CAPTURE_TIMEOUT", "E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_ENCODING"})
                row["direct_child_reaped"] = confirmed
                if not confirmed:
                    self._poisoned = True
            except (CheckpointRejected, ValueError, KeyError, TypeError, UnicodeError) as error:
                row.update(status="protocol_refused", error=str(error))
                self._poisoned = True
            except BaseException as error:
                row.update(status="interrupted", error=type(error).__name__)
                self._poisoned = True
                raise
            finally:
                try:
                    after = self._snapshot()
                    row.update(after=after, poisoned=self._poisoned, state_preserved=after == before,
                               wall_ns=time.monotonic_ns() - started)
                except BaseException:
                    self._poisoned = True
                    raise
                finally:
                    self._busy = False
            try:
                return json.loads(_wire(row))
            except BaseException as error:
                # A publication failure after a valid commit must not invite
                # blind retry. Preserve the actual commit and annotate this
                # same history row; publication failure is not rollback.
                self._poisoned = True
                row.update(poisoned=True,
                           publication_failure={"type": type(error).__name__,
                                                "checkpoint_committed": row["committed"]},
                           wall_ns=time.monotonic_ns() - started)
                raise

    @staticmethod
    def _streams(row, stdout, stderr):
        _require(type(stdout) is bytes and type(stderr) is bytes
                 and len(stdout) <= MAX_STREAM_BYTES and len(stderr) <= MAX_STREAM_BYTES,
                 "exact bounded raw worker streams required")
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            row[name] = {"base64": base64.b64encode(data).decode(), "bytes": len(data), "sha256": _sha(data)}

    def _accept(self, observation, invocation, row):
        fixed = {"schema": WORKER_SCHEMA, "version": self._image.version,
                 "nonce": invocation["nonce"], "request_sha256": row["request_sha256"],
                 "revision": invocation["revision"], "sequence": invocation["sequence"]}
        _require(type(observation) is dict and set(observation) == set(fixed) | {
                    "status", "result", "allocation_attempts", "failure_injected", "live_delta"}
                 and _wire({k: observation[k] for k in fixed}) == _wire(fixed),
                 "worker response is not bound to this exact request")
        _require(type(observation["status"]) is int and observation["status"] in (0, 3)
                 and type(observation["result"]) is int and type(observation["allocation_attempts"]) is int
                 and 0 < observation["allocation_attempts"] < 128
                 and type(observation["failure_injected"]) is bool
                 and type(observation["live_delta"]) is int and observation["live_delta"] == 0,
                 "worker status, allocation or ordinary lifetime ledger differs")
        row["observation"] = observation
        if observation["status"] == 3:
            _require(observation["result"] == SENTINEL and invocation["fault_site"] > 0
                     and observation["failure_injected"]
                     and observation["allocation_attempts"] >= invocation["fault_site"],
                     "uncounted foreign refusal or published error value")
            row["status"] = "foreign_exception"
            return
        _require(not observation["failure_injected"], "injected allocation failure was reported as success")
        values = list(self._values)
        values[invocation["index"]] = invocation["value"]
        _require(observation["result"] == sum(values), "native scalar result differs from bounded state transition")
        if invocation["fault_site"]:
            row["status"] = "fault_site_not_reached"
            return
        # This reconstructed state follows the registered replace operation.
        # It is not a serialized C++ object or a copy of foreign ownership.
        self._values = tuple(values)
        self._revision += 1
        row.update(status="committed", committed=True)

    def close(self):
        with self._lock:
            _require(not self._busy, "reentrant checkpoint close is forbidden")
            self._closed = True
            self._pending = None

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()
