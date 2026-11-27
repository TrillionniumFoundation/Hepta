"""Pinned native HIA Cell continuation transport; no Cell or effect authority.

Only the .so chooses actions. The adapter frames byte observations, verifies
their hashes and copies returned state. The durable runtime must commit pending
state before dispatch and supply results of the original authorized operation.
"""
from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass
import fcntl
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import threading
import time
import types

COMPILER_COMMIT = "f33d8da316de8fdf27b504371f1a5310997ff548"
SOURCE_PATH = "examples/hia_cell_bridge/continuation.hepta"
HEADER = STATE_BYTES = 256
MAX_PAYLOAD = 65536
MAX_EXTENT = HEADER + MAX_PAYLOAD
REQUEST_MAGIC = b"HCLREQ01"
RESPONSE_MAGIC = b"HCLRES01"
STATE_MAGIC = b"HCLSTA01"
ACTIONS = {1: "INVOKE_CELL", 2: "COMPLETE", 3: "FAILED", 4: "CANCELLED", 5: "UNKNOWN", 6: "CANCEL_REQUEST"}
OUTCOMES = {"success": 1, "succeeded": 1, "failed": 2, "cancelled": 3, "unknown": 4}
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_RETAINED_IMAGES = 16
MAX_RETAINED_IMAGE_BYTES = 64 * 1024 * 1024
# Linux UAPI values are stable even when Python was built without these names.
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
REQUIRED_IMAGE_SEALS = 0x0008 | 0x0004 | 0x0002 | 0x0001

# The worker may import this file under a fresh module name. Keep one process
# registry across those imports, not one cache per wrapper/module instance.
# A retained fd name must never be reused while its dlopen image stays loaded.
_REGISTRY_KEY = "_hepta_cell_sealed_image_registry_v1"
_proposed_registry = types.ModuleType(_REGISTRY_KEY)
_proposed_registry.schema = "hepta.cell.sealed-image-registry.v1"
_proposed_registry.lock = threading.RLock()
_proposed_registry.entries = {}
_proposed_registry.total_bytes = 0
_proposed_registry.max_images = MAX_RETAINED_IMAGES
_proposed_registry.max_bytes = MAX_RETAINED_IMAGE_BYTES
_IMAGE_REGISTRY = sys.modules.setdefault(_REGISTRY_KEY, _proposed_registry)
if (getattr(_IMAGE_REGISTRY, "schema", None) != _proposed_registry.schema
        or getattr(_IMAGE_REGISTRY, "max_images", None) != MAX_RETAINED_IMAGES
        or getattr(_IMAGE_REGISTRY, "max_bytes", None) != MAX_RETAINED_IMAGE_BYTES):
    raise RuntimeError("incompatible process-native image registry")
del _proposed_registry


class BridgeRejected(ValueError):
    def __init__(self, code, message="native HIA continuation rejected"):
        self.native_return = code
        super().__init__(f"{message}: {code}")


class BridgeIntegrityError(RuntimeError):
    pass


class BridgeCapacityError(BridgeIntegrityError):
    pass


def _verified_image_bytes(path, expected):
    """Capture exactly the admitted file bytes; a later path write is harmless."""
    descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_IMAGE_BYTES:
            raise BridgeIntegrityError("invalid native image extent")
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - len(data)), len(data))
            if not chunk:
                raise BridgeIntegrityError("native image became shorter during capture")
            data.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise BridgeIntegrityError("native image changed during capture")
        if sha256(data).hexdigest() != expected:
            raise BridgeIntegrityError("native image digest mismatch")
        return data
    finally:
        os.close(descriptor)


def _check_retained_image(record, expected):
    descriptor = record["fd"]
    observed = os.fstat(descriptor)
    if (record["sha256"] != expected
            or (observed.st_dev, observed.st_ino, observed.st_size) != record["identity"]
            or fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_IMAGE_SEALS != REQUIRED_IMAGE_SEALS):
        raise BridgeIntegrityError("retained sealed image identity changed")
    if record["entry"] is None:
        raise BridgeIntegrityError("retained native image lacks the required entry")
    return record


def _retained_image(path, expected):
    """Admit one sealed Linux memfd and retain it for the entire process.

    Admission, hashing, copying and loading are serialized: quotas cannot race,
    and at most one bounded source buffer is captured by this registry at once.
    Cached bytes never bypass validation of a caller's supplied source file.
    """
    with _IMAGE_REGISTRY.lock:
        data = _verified_image_bytes(path, expected)
        existing = _IMAGE_REGISTRY.entries.get(expected)
        if existing is not None:
            return _check_retained_image(existing, expected)
        if (len(_IMAGE_REGISTRY.entries) >= MAX_RETAINED_IMAGES
                or _IMAGE_REGISTRY.total_bytes + len(data) > MAX_RETAINED_IMAGE_BYTES):
            raise BridgeCapacityError("bounded process-native image registry is full")
        descriptor = os.memfd_create("hepta-cell-" + expected[:24], os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        library = None
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, memoryview(data)[offset:])
                if written <= 0:
                    raise BridgeIntegrityError("sealed image staging did not progress")
                offset += written
            fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_IMAGE_SEALS)
            observed = os.fstat(descriptor)
            if (observed.st_size != len(data)
                    or fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_IMAGE_SEALS != REQUIRED_IMAGE_SEALS):
                raise BridgeIntegrityError("native image could not be completely sealed")
            retained_hash = sha256()
            offset = 0
            while offset < len(data):
                chunk = os.pread(descriptor, min(1024 * 1024, len(data) - offset), offset)
                if not chunk:
                    raise BridgeIntegrityError("sealed image readback is incomplete")
                retained_hash.update(chunk)
                offset += len(chunk)
            if retained_hash.hexdigest() != expected:
                raise BridgeIntegrityError("sealed image readback digest differs")
            owner = os.readlink("/proc/self")
            if not owner.isdecimal():
                raise BridgeIntegrityError("cannot bind sealed image descriptor")
            library = ctypes.CDLL(f"/proc/{owner}/fd/{descriptor}")
            # A successful dlopen is retained even if symbol admission fails.
            # Its name must not be recycled while that image may remain loaded.
            record = {"sha256": expected, "fd": descriptor, "library": library,
                      "entry": None, "identity": (observed.st_dev, observed.st_ino, observed.st_size)}
            _IMAGE_REGISTRY.entries[expected] = record
            _IMAGE_REGISTRY.total_bytes += len(data)
            descriptor = None  # registry now owns this fd, including failures
            try:
                entry = library.cell_bridge_step
                entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
                entry.restype = ctypes.c_uint64
                record["entry"] = entry
            except (AttributeError, TypeError) as error:
                raise BridgeIntegrityError("native image lacks the required entry") from error
            return _check_retained_image(record, expected)
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _digest(value: str) -> bytes:
    if type(value) is not str or len(value) != 64 or value != value.lower():
        raise ValueError("expected canonical lowercase SHA256")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("expected canonical lowercase SHA256") from error
    if len(raw) != 32 or raw == bytes(32):
        raise ValueError("zero or malformed SHA256")
    return raw


def _q(raw, at):
    return struct.unpack_from("<Q", raw, at)[0]


@dataclass(frozen=True)
class BridgeBinding:
    candidate_sha256: str
    cell_sha256: str
    request_sha256: str
    input_sha256: str
    sequence: int
    result_limit: int = MAX_PAYLOAD

    def __post_init__(self):
        for value in (self.candidate_sha256, self.cell_sha256, self.request_sha256, self.input_sha256):
            _digest(value)
        if type(self.sequence) is not int or not 1 <= self.sequence < 1 << 64:
            raise ValueError("sequence must be a nonzero u64")
        if type(self.result_limit) is not int or not 1 <= self.result_limit <= MAX_PAYLOAD:
            raise ValueError("result_limit exceeds the bound")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid continuation binding fields")
        return cls(**value)


@dataclass(frozen=True)
class NativeStep:
    state: bytes
    response: bytes
    action: str
    payload: bytes
    native_return: int
    native_wall_ns: int
    binding: BridgeBinding


def _compiler_modules(root):
    root = root.resolve(strict=True)
    for name, module in tuple(sys.modules.items()):
        if name == "hepta" or name.startswith("hepta."):
            filename = getattr(module, "__file__", None)
            if filename and not Path(filename).resolve().is_relative_to(root):
                raise ValueError("another Hepta compiler is already imported")
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    return root


def build_native_bridge(hepta_root: Path, output_dir: Path) -> dict:
    """Build a fresh native image with the unchanged pinned hosted compiler.

    Existing output directories are refused. No native-selfhost or whole-stack
    qualification is implied. Build records retain every native artifact hash.
    """
    root = Path(hepta_root).resolve(strict=True)
    active = sorted(name for name in os.environ if name.startswith("HEPTA_HIA_") and os.environ[name])
    if active:
        raise ValueError("build needs an explicit unselected compiler environment: " + ", ".join(active))
    subprocess.run(["git", "-C", str(root), "cat-file", "-e", COMPILER_COMMIT + "^{commit}"], check=True, capture_output=True)
    pinned = ["hepta", "docs/HIA_CORE_LOWERING_ABI.json", "docs/HIA_CORE_EMITTER_ABI.json",
              "docs/HIA_BYTE_WRAPPER_ABI.json", "docs/HIA_MACHINE_OBJECT_ABI.json"]
    subprocess.run(["git", "-C", str(root), "diff", "--quiet", COMPILER_COMMIT, "--", *pinned], check=True)
    source_path = root / SOURCE_PATH
    source = source_path.read_bytes()
    _compiler_modules(root)
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_native import build_program_machine
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    start = time.perf_counter_ns()
    program = assemble_program(source)
    image_path = destination / "cell_bridge.so"
    receipt = build_program_machine(program.as_dict(), image_path, kind="shared",
                                    foreign_buffer_exports=(("cell_bridge_step", MAX_EXTENT),))
    elapsed = time.perf_counter_ns() - start
    if source_path.read_bytes() != source:
        raise BridgeIntegrityError("HIA source changed during build")
    record = {
        "schema": "hepta.cell-hia-continuation-build.v1",
        "compiler_commit": COMPILER_COMMIT,
        "compiler_implementation_sha256": receipt["implementation_sha256"],
        "compiler_profile": "pinned hosted compiler; direct native emitter; no selfhost claim",
        "hepta_root": str(root), "source_path": SOURCE_PATH,
        "source_sha256": sha256(source).hexdigest(), "source_bytes": len(source),
        "image_path": str(image_path), "image_sha256": receipt["artifact_sha256"],
        "image_bytes": receipt["artifact_bytes"], "compile_wall_ns": elapsed,
        "receipt": receipt,
        "claims": {"native_execution_qualified": False, "cell_called": False,
                   "whole_stack_qualified": False, "production_activated": False},
    }
    (destination / "build.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def encode_request(event: int, binding: BridgeBinding, payload: bytes = b"", status: int = 0) -> bytes:
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD:
        raise ValueError("payload exceeds the bound or is not bytes")
    if event not in (1, 2, 3, 4):
        raise ValueError("invalid continuation event")
    no_observation = event in (3, 4) or event == 2 and status == 4
    if no_observation and payload:
        raise ValueError("unknown/cancellation observations cannot invent payload")
    if event == 1 and sha256(payload).hexdigest() != binding.input_sha256:
        raise ValueError("input digest mismatch")
    if event == 2 and len(payload) > binding.result_limit:
        raise ValueError("result exceeds its admitted bound")
    raw = bytearray(HEADER)
    raw[:8] = REQUEST_MAGIC
    struct.pack_into("<3Q", raw, 8, 1, event, binding.sequence)
    for at, value in zip((32, 64, 96, 128),
                         (binding.candidate_sha256, binding.cell_sha256, binding.request_sha256, binding.input_sha256)):
        raw[at:at + 32] = _digest(value)
    struct.pack_into("<3Q", raw, 160, len(payload), status, binding.result_limit)
    raw[192:224] = bytes(32) if no_observation else sha256(payload).digest()
    return bytes(raw) + payload


class NativeCellBridge:
    """Call one hash-pinned native image with live, disjoint owned allocations."""
    binding_from_dict = staticmethod(BridgeBinding.from_dict)

    def __init__(self, hepta_root: Path, image_path: Path, expected_image_sha256: str,
                 *, expected_source_sha256: str | None = None):
        self._instance_lock = threading.RLock()
        self._fd = self._library = self._entry = None
        self.hepta_root = Path(hepta_root).resolve(strict=True)
        self.source_sha256 = sha256((self.hepta_root / SOURCE_PATH).read_bytes()).hexdigest()
        if expected_source_sha256 is not None and self.source_sha256 != expected_source_sha256:
            raise BridgeIntegrityError("HIA source digest mismatch")
        _digest(expected_image_sha256)
        self.image_sha256 = expected_image_sha256
        image = _retained_image(image_path, expected_image_sha256)
        self._fd, self._library, self._entry = image["fd"], image["library"], image["entry"]

    def close(self):
        """Revoke this instance after any admitted call; retain process custody."""
        with self._instance_lock:
            self._fd = self._library = self._entry = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def begin(self, state: bytes, *, candidate_sha256: str, cell_sha256: str,
              request_sha256: str, input_bytes: bytes, sequence: int,
              result_limit: int = MAX_PAYLOAD) -> NativeStep:
        binding = BridgeBinding(candidate_sha256, cell_sha256, request_sha256,
                                sha256(input_bytes).hexdigest(), sequence, result_limit)
        return self.step(encode_request(1, binding, input_bytes), state, binding=binding)

    def resume(self, state: bytes, *, binding: BridgeBinding, outcome: str,
               result_bytes: bytes = b"") -> NativeStep:
        if outcome not in OUTCOMES:
            raise ValueError("unknown outcome label")
        return self.step(encode_request(2, binding, result_bytes, OUTCOMES[outcome]), state, binding=binding)

    def recover(self, state: bytes, *, binding: BridgeBinding) -> NativeStep:
        return self.step(encode_request(3, binding), state, binding=binding)

    def cancel(self, state: bytes, *, binding: BridgeBinding) -> NativeStep:
        return self.step(encode_request(4, binding), state, binding=binding)

    def step(self, request: bytes, state: bytes, *, binding: BridgeBinding) -> NativeStep:
        with self._instance_lock:
            return self._step(request, state, binding=binding)

    def _step(self, request: bytes, state: bytes, *, binding: BridgeBinding) -> NativeStep:
        if self._fd is None:
            raise ValueError("native image is closed")
        if type(request) is not bytes or not HEADER <= len(request) <= MAX_EXTENT:
            raise ValueError("invalid request extent")
        if type(state) is not bytes or len(state) != STATE_BYTES:
            raise ValueError("invalid state extent")
        if request[:8] != REQUEST_MAGIC or _q(request, 8) != 1:
            raise ValueError("invalid request header")
        event, status, payload = _q(request, 16), _q(request, 168), request[HEADER:]
        expected = encode_request(event, binding, payload, status)
        if request != expected:
            raise ValueError("request header/payload digest or binding mismatch")
        sentinel = b"\xa7" * 16
        initial_output = b"\xa5" * len(request)
        source = ctypes.create_string_buffer(sentinel + request + sentinel)
        output = ctypes.create_string_buffer(sentinel + initial_output + sentinel)
        workspace = ctypes.create_string_buffer(sentinel + state + sentinel)
        start = time.perf_counter_ns()
        code = int(self._entry(ctypes.byref(source, 16), len(request),
                               ctypes.byref(output, 16), len(request),
                               ctypes.byref(workspace, 16), len(state)))
        elapsed = time.perf_counter_ns() - start
        for array, extent in ((source, len(request)), (output, len(request)), (workspace, len(state))):
            if array.raw[:16] != sentinel or array.raw[extent + 16:extent + 32] != sentinel:
                raise BridgeIntegrityError("native range guard changed")
        if source.raw[16:16 + len(request)] != request:
            raise BridgeIntegrityError("native read-only input changed")
        new_state = workspace.raw[16:16 + len(state)]
        response = output.raw[16:16 + len(request)]
        if code:
            if new_state != state or response != initial_output:
                raise BridgeIntegrityError("rejected native call changed state/output")
            raise BridgeRejected(code)
        action = _q(response, 16)
        if action not in ACTIONS or response[:8] != RESPONSE_MAGIC or _q(response, 8) != 1:
            raise BridgeIntegrityError("invalid native response header")
        expected_response = bytearray(request)
        expected_response[:8] = RESPONSE_MAGIC
        struct.pack_into("<Q", expected_response, 16, action)
        struct.pack_into("<Q", expected_response, 168, action)
        if response != bytes(expected_response):
            raise BridgeIntegrityError("native response lost request/payload identity")
        if event == 1 and action != 1 or event != 1 and action == 1:
            raise BridgeIntegrityError("invalid native invocation phase")
        if new_state[:8] != STATE_MAGIC or _q(new_state, 8) != 1 or _q(new_state, 16) != action:
            raise BridgeIntegrityError("invalid native state header")
        if new_state[24:160] != request[24:160] or _q(new_state, 168) != binding.result_limit:
            raise BridgeIntegrityError("native state identity mismatch")
        if new_state[224:] != bytes(32):
            raise BridgeIntegrityError("native reserved state changed")
        if action in (2, 3, 4):
            if _q(new_state, 176) != len(payload) or new_state[192:224] != sha256(payload).digest():
                raise BridgeIntegrityError("native terminal digest mismatch")
        elif _q(new_state, 176) != 0 or new_state[192:224] != bytes(32):
            raise BridgeIntegrityError("native pending state invented a terminal")
        expected_input_size = len(payload) if event == 1 else _q(state, 160)
        if _q(new_state, 160) != expected_input_size:
            raise BridgeIntegrityError("native input length changed")
        expected_cancel = 1 if action == 6 else (0 if event == 1 else _q(state, 184))
        if _q(new_state, 184) != expected_cancel:
            raise BridgeIntegrityError("native cancellation custody changed")
        return NativeStep(new_state, response, ACTIONS[action], payload, code, elapsed, binding)
