"""Mechanical Python ABI for the complete source-owned HIA NDU rank policy.

Ranking, proof admission, budgets, sorting, identity, native child ownership and
result lifetime are implemented by the fixed HIA images. This module translates
Python values and exceptions and retains physical buffers while those images run.
"""
from __future__ import annotations

import builtins
import ctypes as C
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time

CONTRACT = "docs/HIA_NATIVE_NDU_RANK_BUILD.json"
CONTRACT_RESOURCE = "_hia_ndu_rank_build.json"
CONTRACT_SHA256 = "d0a4b5d83dd0f6802728adf19cd4b2e2349af72416c894420e612cb1fdd232fd"
SELF = Path(__file__)
SELF_BYTES = SELF.read_bytes()
PROFILE = "hepta.hia.ndu-rank-native-construction-records.v4"
NAMES = {
    "engine": "_hia_ndu_rank_engine.bin",
    "context": "_hia_ndu_rank_context.bin",
    "normalizer": "_hia_ndu_normalizer.elf",
    "proof": "_hia_ndu_public_proof.elf",
    "threshold": "_hia_ndu_threshold.hiadat",
}
_FUNCTION = C.CFUNCTYPE(C.c_uint32, *([C.c_void_p, C.c_uint64] * 3))
_LIB = C.CDLL(None, use_errno=True)
_LIB.mmap.argtypes = (C.c_void_p, C.c_size_t, C.c_int, C.c_int, C.c_int, C.c_long)
_LIB.mmap.restype = C.c_void_p
_LIB.munmap.argtypes = (C.c_void_p, C.c_size_t)
_LIB.munmap.restype = C.c_int


def _word(raw, offset):
    return struct.unpack_from("<Q", raw, offset)[0]


def _request(operation, token=(), *, result=False, entered_ns=0):
    raw = bytearray(struct.pack("<8s15Q", b"HIANRO01" if result else b"HIANKC02",
                                operation, *token, *([0] * (14 - len(token)))))
    if not result and operation == 3:
        struct.pack_into("<Q", raw, 40, entered_ns)
    return raw


class _Buffer:
    def __init__(self, size, guard):
        self.size = size
        self.guard = guard * 16
        self.storage = C.create_string_buffer(self.guard + bytes(size) + self.guard, size + 32)
        self.address = C.addressof(self.storage) + 16
        self.view = (C.c_char * size).from_address(self.address)

    def check(self):
        if self.storage.raw[:16] != self.guard or self.storage.raw[-16:] != self.guard:
            raise RuntimeError("native NDU buffer guard changed")

    def raw(self):
        self.check()
        return self.storage.raw[16:-16]


class _Image:
    def __init__(self, raw):
        from .hia_ndu_optimizer import _seal_bridge_image
        self.size = len(raw)
        self.address = None
        descriptor = _seal_bridge_image(raw)
        try:
            address = _LIB.mmap(None, self.size, 5, 2, descriptor, 0)
            if address in (None, C.c_void_p(-1).value):
                raise OSError(C.get_errno(), "native NDU executable mapping failed")
            self.address = address
            self.entry = _FUNCTION(address)
        finally:
            os.close(descriptor)

    def close(self):
        if self.address is not None:
            address = self.address
            self.address = None
            if _LIB.munmap(address, self.size):
                raise OSError(C.get_errno(), "native NDU executable unmap failed")


class _Context:
    """Retain ABI buffers; native code owns descriptor, lease and result policy."""

    def __init__(self, products, source_root):
        from .hia_ndu_optimizer import _seal_bridge_image
        self.context = None
        self.engine = None
        self.work = _Buffer(131072, b"W")
        self.token = None
        self.closed = False
        fds = []
        init_reply = _Buffer(65536, b"O")
        try:
            self.context = _Image(products["context"])
            self.engine = _Image(products["engine"])
            for role in ("normalizer", "proof"):
                fds.append(_seal_bridge_image(products[role]))
                if role == "normalizer":
                    os.fchmod(fds[-1], 0o500)
            fds.append(os.open(source_root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
            fds.append(_seal_bridge_image(products["threshold"]))
            request = _request(0)
            struct.pack_into("<5Q", request, 48, *fds, sys.get_int_max_str_digits())
            result = self._call(request, init_reply)
            self._status(result)
            self.token = struct.unpack_from("<3Q", result, 16)
        except BaseException:
            # The native owner may have completed before Python delivered an
            # exception at the FFI return. Recover only its actual published
            # input token, then use the unchanged native release protocol.
            try:
                reply = init_reply.raw()
                if reply[:8] == b"HIANKS02" and _word(reply, 8) == 0:
                    token = struct.unpack_from("<3Q", reply, 16)
                    if token[0]:
                        self._status(self._call(_request(2, token)))
                        self._status(self._call(_request(6)))
            finally:
                try:
                    if self.engine is not None:
                        self.engine.close()
                finally:
                    if self.context is not None:
                        self.context.close()
            raise
        finally:
            for descriptor in fds:
                os.close(descriptor)

    def _call(self, request, output=None):
        output = _Buffer(65536, b"O") if output is None else output
        source = request.view if isinstance(request, _Buffer) else C.create_string_buffer(bytes(request))
        size = request.size if isinstance(request, _Buffer) else len(request)
        result = self.context.entry(source, size, output.address, output.size,
                                    self.work.address, self.work.size)
        self.work.check()
        output.check()
        if isinstance(request, _Buffer):
            request.check()
        if result != 0:
            raise RuntimeError("native NDU context ABI refusal: " + str(result))
        return output.raw()

    @staticmethod
    def _status(raw, result=False):
        if raw[:8] != (b"HIANRR01" if result else b"HIANKS02") or _word(raw, 8) != 0:
            raise RuntimeError("native NDU context refused operation: " + str(_word(raw, 8)))

    def execute(self, baseline, arguments, entered_ns):
        if self.closed:
            raise RuntimeError("native NDU context is closed")
        packet = (struct.pack("<8s15Q", b"HIANRK01", 1, len(baseline), len(arguments),
                              *([0] * 12)) + baseline + arguments)
        control = _Buffer(65536, b"O")
        finish_reply = _Buffer(65536, b"O")
        source = C.create_string_buffer(packet)
        result_token = None
        try:
            acquired = self._call(_request(3, self.token, entered_ns=entered_ns), control)
            self._status(acquired)
            # Consume only the reply header. The native token, entry clock and
            # descriptors remain at their original bound control offsets.
            struct.pack_into("<Q", control.view, 0, 0)
            returned = self.engine.entry(source, len(packet), control.address, control.size, None, 0)
            control.check()
            work_address, work_size = _word(control.view, 40), _word(control.view, 16)
            if returned != 0:
                raise RuntimeError("native NDU rank ABI refusal: " + str(returned))
            struct.pack_into("<8sQ", control.view, 0, b"HIANKC02", 4)
            result = self._call(control, finish_reply)
            if result[:8] != b"HIANKR02":
                raise RuntimeError("native NDU result owner reply differs")
            status, count = _word(result, 8), _word(result, 32)
            result_token = struct.unpack_from("<3Q", result, 40)
            if not result_token[0]:
                if count:
                    raise RuntimeError("native NDU result has no owner")
                return status, b""
            body = bytearray()
            for offset in range(0, count, 65024):
                request = _request(1, result_token, result=True)
                amount = min(65024, count - offset)
                struct.pack_into("<2Q", request, 40, offset, amount)
                reply = self._call(request)
                self._status(reply, result=True)
                if _word(reply, 16) != count or _word(reply, 24) != amount:
                    raise RuntimeError("native NDU result extent differs")
                body.extend(reply[512:512 + amount])
            return status, bytes(body)
        finally:
            try:
                # Read the retained native publication even if an exception
                # arrived between _call returning and a Python assignment.
                finished = finish_reply.raw()
                if finished[:8] == b"HIANKR02":
                    result_token = struct.unpack_from("<3Q", finished, 40)
                    if result_token[0]:
                        self._status(self._call(_request(2, result_token, result=True)), result=True)
                elif _word(control.raw(), 3504):
                    # Acquisition publishes this token only after binding the
                    # exact control address. Never invent or replay a lease.
                    struct.pack_into("<8sQ", control.view, 0, b"HIANKC02", 5)
                    self._status(self._call(control))
            finally:
                control.check()
                work_address, work_size = _word(control.view, 40), _word(control.view, 16)
                if work_address and _LIB.munmap(work_address, work_size):
                    raise OSError(C.get_errno(), "native NDU rank workspace unmap failed")

    def close(self):
        if self.closed:
            return
        if self.token is not None:
            self._status(self._call(_request(2, self.token)))
            self.token = None
        self._status(self._call(_request(6)))
        self.closed = True
        try:
            self.engine.close()
        finally:
            self.context.close()


def _admit(*, roles=None):
    from .hia_json_preflight_native import _source_resource_path
    from .hia_ndu_optimizer import _read_file
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("complete native NDU ranking requires Linux x86_64")
    if SELF.read_bytes() != SELF_BYTES:
        raise RuntimeError("executed native NDU adapter changed")
    source_receipt_path = _source_resource_path(CONTRACT)
    receipt_path = SELF.resolve(strict=True).parent / CONTRACT_RESOURCE
    receipt_raw = _read_file(receipt_path, 1 << 20)
    if _read_file(source_receipt_path, 1 << 20) != receipt_raw:
        raise RuntimeError("installed native NDU contract differs from its captured source")
    if sha256(receipt_raw).hexdigest() != CONTRACT_SHA256:
        raise RuntimeError("native NDU current build contract differs")
    receipt = json.loads(receipt_raw)
    if receipt["schema"] != PROFILE or set(receipt["products"]) != set(NAMES):
        raise RuntimeError("native NDU current product inventory differs")
    products = {}
    physical = {}
    parent = SELF.resolve(strict=True).parent
    wanted = tuple(NAMES) if roles is None else tuple(roles)
    if len(set(wanted)) != len(wanted) or any(role not in NAMES for role in wanted):
        raise RuntimeError("native NDU requested product inventory differs")
    for role in wanted:
        name = NAMES[role]
        row = receipt["products"][role]
        if row["resource"] != name:
            raise RuntimeError("native NDU role path differs")
        path = parent / name
        raw = _read_file(path, 16 << 20)
        if len(raw) != row["bytes"] or sha256(raw).hexdigest() != row["sha256"]:
            raise RuntimeError("native NDU product differs: " + role)
        products[role] = raw
        physical[path] = raw
    for name, pin in receipt["source_files"].items():
        path = _source_resource_path(name)
        raw = _read_file(path, 1 << 20)
        if sha256(raw).hexdigest() != pin:
            raise RuntimeError("native NDU source differs: " + name)
        physical[path] = raw
    # The native owner captures the eleven original evaluator sources relative
    # to this package-owned source root. There is no cwd/HOME/environment path.
    root = source_receipt_path
    for _ in Path(CONTRACT).parts:
        root = root.parent

    def unchanged():
        if (SELF.read_bytes() != SELF_BYTES or _read_file(receipt_path, 1 << 20) != receipt_raw
                or _read_file(source_receipt_path, 1 << 20) != receipt_raw
                or any(_read_file(path, 16 << 20) != raw for path, raw in physical.items())):
            raise RuntimeError("native NDU source or product changed during invocation")

    unchanged()
    return products, root, unchanged


def _baseline_bytes(value):
    from .hia_program import VerifiedProgram, verify_program
    if isinstance(value, VerifiedProgram):
        checked = verify_program(value)
        return checked.structured_bytes if checked.structured_bytes is not None else checked.canonical_bytes
    if type(value) is bytes:
        return value
    if type(value) is str:
        return value.encode("utf-8", "surrogatepass")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=True).encode("utf-8", "surrogatepass")


def _raise_error(status, raw, original_values):
    from .hia_ndu_optimizer import OptimizationRejected
    from .hia_program import HIAProgramRejected
    from .hia_ndu_scalar_selection import ScalarSelectionRejected
    if status == 2:
        raise KeyboardInterrupt()
    if status == 3:
        raise MemoryError()
    if status != 1 or not raw:
        raise RuntimeError("native NDU rank operation failed")
    error = json.loads(raw)
    if type(error) is not dict or set(error) != {"type", "message"}:
        raise RuntimeError("native NDU exception envelope differs")
    name, message = error["type"], error["message"]
    if type(name) is not str or type(message) is not str:
        raise RuntimeError("native NDU exception text differs")
    if name == "HIAProgramRejected":
        code, separator, detail = message.partition(": ")
        if not separator:
            raise RuntimeError("native program exception code is absent")
        raise HIAProgramRejected(detail, code)
    if name == "OptimizationRejected":
        raise OptimizationRejected(message)
    if name == "ScalarSelectionRejected":
        raise ScalarSelectionRejected(message)
    if name == "UnicodeEncodeError":
        # Recreate a language exception object only after HIA selected that
        # exception. The native decision, message and ordering are authoritative.
        pending = list(original_values)
        seen = set()
        while pending:
            value = pending.pop()
            if type(value) is str:
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    if str(exc) == message:
                        raise
            elif type(value) in (dict, list, tuple) and id(value) not in seen:
                seen.add(id(value))
                pending.extend(value.keys() if type(value) is dict else ())
                pending.extend(value.values() if type(value) is dict else value)
        raise RuntimeError("native Unicode exception cannot be represented")
    kinds = {key: getattr(builtins, key) for key in (
        "ValueError", "TypeError", "RuntimeError", "MemoryError", "RecursionError",
        "OSError", "FileNotFoundError", "PermissionError", "NotADirectoryError",
        "IsADirectoryError", "FileExistsError", "BlockingIOError", "BrokenPipeError",
        "ChildProcessError", "ProcessLookupError", "InterruptedError",
    )}
    if name not in kinds:
        raise RuntimeError("unknown native NDU exception type: " + name)
    raise kinds[name](message)


def _rank_candidates(baseline, candidates, observations, *, function, bridge=None,
                     objective, generation=1, timeout_ms=2000, bridge_timeout_s=10.0,
                     _entered_ns):
    entered_ns = _entered_ns
    from .hia_ndu_evaluator_native import default_ndu_bridge
    if type(bridge) is dict:
        bridge = {key: os.fspath(value) if key in ("binary", "build_receipt") and isinstance(value, os.PathLike) else value
                  for key, value in bridge.items()}
    arguments = {
        "candidates": candidates, "observations": observations, "function": function,
        "bridge": default_ndu_bridge() if bridge is None else bridge,
        "objective": objective, "generation": generation,
        "timeout_ms": timeout_ms, "bridge_timeout_s": bridge_timeout_s,
    }
    source = _baseline_bytes(baseline)
    wire = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=True).encode("utf-8", "surrogatepass")
    products, root, unchanged = _admit()
    context = _Context(products, root)
    try:
        status, result = context.execute(source, wire, entered_ns)
    finally:
        context.close()
        unchanged()
    if status:
        _raise_error(status, result, (baseline, arguments))
    return json.loads(result)
