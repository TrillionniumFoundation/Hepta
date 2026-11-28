"""Mechanical access to the packaged HIA cost, JSON and response-binding roles.

The actual role bytes are extracted from the fully admitted rank engine and
sealed before mapping. HIA owns arithmetic, JSON admission and all response
policy. Python only retains buffers, projects exact input types and materializes
already-admitted values or the original exception objects.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from hashlib import sha256
from pathlib import Path
import ctypes as C
import json
import struct

SELF = Path(__file__)
SELF_BYTES = SELF.read_bytes()
ROLE_HOLES = {"r1": 699, "r9": 755, "r12": 776}
ROLE_NAMES = ("main", "tasks", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
              "r16", "r17", "r19", "r20")


def _unchanged():
    if SELF.read_bytes() != SELF_BYTES:
        raise RuntimeError("executed native NDU policy adapter changed")


@contextmanager
def _roles(names):
    from . import hia_ndu_rank_native as rank
    from .hia_json_preflight_native import _source_resource_path
    from .hia_ndu_optimizer import _read_file
    _unchanged()
    if _source_resource_path("hepta/hia_ndu_native_policy.py").read_bytes() != SELF_BYTES:
        raise RuntimeError("selected native NDU policy adapter is not the executed source")
    products, root, unchanged = rank._admit(roles=("engine",))
    contract_raw = _read_file(_source_resource_path(rank.CONTRACT), 1 << 20)
    if sha256(contract_raw).hexdigest() != rank.CONTRACT_SHA256:
        raise RuntimeError("native NDU policy contract changed")
    rows = json.loads(contract_raw)["rank_roles"]
    if type(rows) is not list or tuple(row.get("role") for row in rows) != ROLE_NAMES:
        raise RuntimeError("native NDU policy role inventory differs")
    row_by_role = {row["role"]: row for row in rows}
    images = {}
    closing = ExitStack()
    engine = products["engine"]
    try:
        for name in names:
            hole = ROLE_HOLES[name]
            row = row_by_role[name]
            size = row["bytes"]
            if type(size) is not int or not 0 < size <= 4 << 20:
                raise RuntimeError("native NDU policy role extent differs")
            if engine[hole - 1] != 0xE8:
                raise RuntimeError("native NDU policy call site differs")
            offset = hole + 4 + struct.unpack_from("<i", engine, hole)[0]
            if not 0 < offset <= len(engine) or size > len(engine) - offset:
                raise RuntimeError("native NDU policy role is out of bounds")
            raw = engine[offset:offset + size]
            if sha256(raw).hexdigest() != row["sha256"]:
                raise RuntimeError("native NDU policy role bytes differ")
            image = rank._Image(raw)
            closing.callback(image.close)
            images[name] = image
        unchanged()
        _unchanged()
        yield images
    finally:
        try:
            closing.close()
        finally:
            unchanged()
            _unchanged()


def _call(image, raw, output_bytes, work_bytes, *, work_values=()):
    from .hia_ndu_rank_native import _Buffer
    source = C.create_string_buffer(raw)
    output = _Buffer(output_bytes, b"O")
    work = _Buffer(work_bytes, b"W")
    for offset, value in work_values:
        struct.pack_into("<Q", work.view, offset, value)
    code = image.entry(source, len(raw), output.address, output.size,
                       work.address, work.size)
    output.check()
    work.check()
    if source.raw[:len(raw)] != raw:
        raise RuntimeError("native NDU policy modified readonly input")
    return code, output.raw()


def ns_to_ms_q32(value):
    from .hia_ndu_optimizer import _reject
    # The two-word input is a tagged exact integer. Unrepresentable Python
    # values use the role's existing nonzero high-word rejection channel.
    valid_type = type(value) is int and 0 <= value <= (1 << 63) - 1
    request = struct.pack("<8s15Q", b"HIANRC01", 0,
                          value if valid_type else 0,
                          0 if valid_type else 1, *([0] * 12))
    with _roles(("r9",)) as roles:
        code, reply = _call(roles["r9"], request, 256, 256)
        if code or reply[:8] != b"HIANRR01" or struct.unpack_from("<Q", reply, 8)[0] != 0:
            raise RuntimeError("native NDU exact-cost ABI refusal")
        status = struct.unpack_from("<Q", reply, 16)[0]
        if status == 1:
            _reject("nanoseconds must be a bounded exact integer")
        if status == 2:
            _reject("cost exceeds the Q32.32 millisecond range")
        if status:
            raise RuntimeError("native NDU exact-cost status differs")
        return struct.unpack_from("<Q", reply, 40)[0]


def _wire(raw):
    # Match the original JSON byte encoding domain. This is decoding only;
    # syntax, duplicate names and all policy remain native decisions.
    if type(raw) is str:
        return raw.encode("utf-8", "surrogatepass")
    if type(raw) in (bytes, bytearray):
        return bytes(raw).decode(json.detect_encoding(raw), "surrogatepass").encode("utf-8", "surrogatepass")
    raise TypeError("the JSON object must be str, bytes or bytearray, not " + type(raw).__name__)


def _arena(image, raw, original):
    from .hia_ndu_optimizer import _json
    try:
        wire = _wire(raw)
    except (TypeError, UnicodeError):
        _json(original)  # Recreate only the original rejected exception.
        raise RuntimeError("native NDU JSON encoding disagrees with the original domain")
    code, plan = _call(image, wire, 64, 128)
    if code or plan[:8] != b"HIANJS01":
        _json(original)
        raise RuntimeError("native NDU JSON extent planning failed")
    nodes, keys, depth, arena_size, scratch, input_size = struct.unpack_from("<6Q", plan, 8)
    if input_size != len(wire):
        raise RuntimeError("native NDU JSON plan input differs")
    code, arena = _call(image, wire, arena_size, scratch,
                        work_values=((48, nodes), (56, depth), (96, keys), (104, 1)))
    if code:
        _json(original)
        raise RuntimeError("native NDU JSON rejected an otherwise accepted value")
    used = struct.unpack_from("<Q", arena, 24)[0]
    if not 64 <= used <= len(arena):
        raise RuntimeError("native NDU JSON arena extent differs")
    return wire, arena[:used]


def validate_native_rank_response(request, data, stdout, identity):
    from .hia_ndu_optimizer import _bytes, _json, _reject, OptimizationRejected
    request_raw = _bytes(request)
    # Admitted transport requests already have this exact generation domain.
    # The HIA binding role owns comparisons against the response's numeric kind.
    generation = request["generation"]
    if type(generation) is not int or not 1 <= generation <= (1 << 64) - 1:
        _reject("native response binding requires an admitted request generation")
    if identity["upstream_commit"] != "d3c2d760eca5065fc966820379c35c6e8d56e855":
        _reject("native evaluator response does not bind the exact request")
    with _roles(("r1", "r12")) as roles:
        response_wire, response_arena = _arena(roles["r1"], stdout, stdout)
        request_wire, request_arena = _arena(roles["r1"], request_raw, request_raw)
        header = bytearray(256)
        struct.pack_into("<8s7Q", header, 0, b"HIANBD01", 1,
                         len(request_wire), len(request_arena),
                         len(response_wire), len(response_arena), generation, 0)
        header[64:96] = sha256(data).digest()
        frame = bytes(header) + request_wire + request_arena + response_wire + response_arena
        # The fixed role keeps one visited byte per arena node after its
        # 128 KiB state prefix. Its final 8 KiB belongs to binary64 decoding.
        counts = [struct.unpack_from("<Q", arena, 8)[0]
                  for arena in (request_arena, response_arena)]
        if any(count < 1 or count > (len(arena) - 64) // 72
               for count, arena in zip(counts, (request_arena, response_arena))):
            raise RuntimeError("native NDU response arena node extent differs")
        work_size = 131072 + max(counts) + 8192
        code, reply = _call(roles["r12"], frame, 1152, work_size)
        if code or reply[:8] != b"HIANBDR1":
            raise RuntimeError("native NDU response-binding ABI refusal")
        status, proved, error, size = struct.unpack_from("<4Q", reply, 8)
        if status:
            if not 0 < size <= len(reply) - 128:
                raise RuntimeError("native NDU response-binding error extent differs")
            failure = json.loads(reply[128:128 + size])
            if type(failure) is not dict or set(failure) != {"type", "message"}:
                raise RuntimeError("native NDU response-binding error envelope differs")
            kinds = {"OptimizationRejected": OptimizationRejected, "TypeError": TypeError}
            if failure["type"] not in kinds or type(failure["message"]) is not str:
                raise RuntimeError("native NDU response-binding error type differs")
            raise kinds[failure["type"]](failure["message"])
        if proved != 1 or error or size:
            raise RuntimeError("native NDU response-binding success envelope differs")
        # Complete syntax and policy have already passed in the actual HIA
        # roles. Python now materializes the identical original JSON value.
        return _json(stdout)
