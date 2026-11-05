#!/usr/bin/env python3
"""Supplementary indexed-text oracle using the compiler-private native C ABI.

Run from a checkout's tools directory or pass --root REPOSITORY. Executes both
O0 and O3 with UBSan and no recovery. This is not a public FFI contract, native
Rust execution, or whole-language qualification. Python's strict UTF-8 decoder,
canonical Base64 roundtrip, sorting, and bisect provide independent expectations.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import ctypes
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile


class ByteSlice(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class ScalarSlice(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint64)), ("len", ctypes.c_size_t)]


class IndexResult(ctypes.Structure):
    _fields_ = [("stage", ctypes.c_uint32), ("scalars", ctypes.c_size_t),
                ("lower", ctypes.c_size_t), ("upper", ctypes.c_size_t)]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exercise(function) -> dict[str, int]:
    rng = random.Random(0x35489)
    counts: dict[str, int] = {}

    def case(group, data, start, end, scratch_capacity, scalar_capacity, query):
        counts[group] = counts.get(group, 0) + 1
        # Physical guard cells surround every logical slice, including empty
        # slices. No pointer or output aliases another input or output buffer.
        input_array = (ctypes.c_uint8 * (len(data) + 2))(91, *data, 92)
        scratch_array = (ctypes.c_uint8 * (scratch_capacity + 2))(
            93, *([165] * scratch_capacity), 94)
        scalar_array = (ctypes.c_uint64 * (scalar_capacity + 2))(
            0xDEADBEEF, *([999] * scalar_capacity), 0xFACECAFE)
        input_pointer = ctypes.cast(ctypes.byref(input_array, 1), ctypes.POINTER(ctypes.c_uint8))
        scratch_pointer = ctypes.cast(ctypes.byref(scratch_array, 1), ctypes.POINTER(ctypes.c_uint8))
        scalar_pointer = ctypes.cast(ctypes.byref(scalar_array, 8), ctypes.POINTER(ctypes.c_uint64))
        want_scratch = bytes(scratch_array)
        want_scalars = list(scalar_array)
        stage, values, raw = 1, [], None
        if 0 <= start <= end <= len(data):
            part = data[start:end]
            try:
                decoded = base64.b64decode(part, validate=True)
                if (base64.b64encode(decoded) == part and scratch_capacity >= 1
                        and len(decoded) <= scratch_capacity - 1):
                    raw = decoded
            except binascii.Error:
                pass
        if raw is not None:
            # Physical guard + caller-owned prefix account for two cells.
            want_scratch = want_scratch[:2] + raw + want_scratch[2 + len(raw):]
            if len(raw) < 2:
                stage = 2
            elif int.from_bytes(raw[:2], "big") != len(raw) - 2:
                stage = 3
            else:
                try:
                    values = sorted(map(ord, raw[2:].decode("utf8", "strict")))
                    stage = 0 if scalar_capacity >= len(values) + 1 else 5
                except UnicodeDecodeError:
                    stage = 4
        expected = (stage, 0, 0, 0)
        if stage == 0:
            expected = (0, len(values), 1 + bisect.bisect_left(values, query),
                        1 + bisect.bisect_right(values, query))
            want_scalars[2:2 + len(values)] = values
        result = function(ByteSlice(input_pointer, len(data)), start, end,
                          ByteSlice(scratch_pointer, scratch_capacity),
                          ScalarSlice(scalar_pointer, scalar_capacity), query)
        got = (result.stage, result.scalars, result.lower, result.upper)
        context = (group, data.hex(), start, end, scratch_capacity, scalar_capacity, query)
        assert got == expected, (context, got, expected)
        assert bytes(scratch_array) == want_scratch, (context, "scratch or guard changed")
        assert list(scalar_array) == want_scalars, (context, "scalars or guard changed")
        assert bytes(input_array) == b"[" + data + b"\\", (context, "input or guard changed")

    boundary_values = [[], [0],
                       [127, 128, 2047, 2048, 0xD7FF, 0xE000, 65535, 65536, 0x10FFFF],
                       [233] * 5, [0, 122, 233, 233, 128512]]
    for values in boundary_values:
        raw = "".join(map(chr, values)).encode()
        wire = base64.b64encode(len(raw).to_bytes(2, "big") + raw)
        for scratch_capacity in [0, 1, 2, len(raw) + 2, len(raw) + 3, len(raw) + 7]:
            for scalar_capacity in [0, 1, len(values), len(values) + 1, len(values) + 3]:
                for query in [0, 1, 127, 233, 128512, 2**64 - 1]:
                    case("boundary", b"!" + wire + b"!", 1, len(wire) + 1,
                         scratch_capacity, scalar_capacity, query)
    for number in range(12000):
        values = [rng.choice([0, 233, 0x10FFFF, rng.randrange(0xD800),
                              rng.randrange(0xE000, 0x110000)])
                  for _ in range(rng.randrange(16))]
        raw = "".join(map(chr, values)).encode()
        if number % 4 == 0:
            raw = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
        packet = (len(raw) + (number % 13 == 0)).to_bytes(2, "big") + raw
        wire = base64.b64encode(packet)
        if number % 5 == 0:
            position = rng.randrange(len(wire))
            wire = wire[:position] + bytes([rng.randrange(256)]) + wire[position + 1:]
        wire = b"!" + wire + b"!"
        start, end = 1, len(wire) - 1
        if number % 7 == 0:
            start, end = rng.randrange(len(wire) + 3), rng.randrange(len(wire) + 3)
        case("seeded", wire, start, end,
             rng.choice([0, 1, len(packet), len(packet) + 1, len(packet) + 8]),
             rng.choice([0, 1, len(values), len(values) + 1, len(values) + 4]),
             rng.choice([0, 233, 2**64 - 1, rng.randrange(0x110000)]))
    for raw in [b"", b"\x00", b"\0\0", b"\0\1", b"\0\1\xff", b"\0\2\xc0\x80"]:
        wire = base64.b64encode(raw)
        for start, end in [(0, len(wire)), (2**64 - 1, 2**64 - 1),
                           (0, 2**64 - 1), (2**64 - 1, 0)]:
            case("short_and_max_range", wire, start, end, 32, 32, 0)
    for wire in [b"AA==", b"AB==", b"AAA=", b"AAB=", b"AAAA", b"AA==AAAA",
                 b"AAA=\n", b"====", b""]:
        case("canonical", wire, 0, len(wire), 32, 32, 0)
    return counts


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without Python -O: assertions are required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    if ctypes.sizeof(ctypes.c_size_t) != 8 or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Oracle requires the qualified 64-bit size_t/pointer host")
    sys.path.insert(0, str(root))
    from hepta.modules import load_project
    from hepta.checker import check
    from hepta.c_backend import emit_c, compile_c
    from hepta.pipeline import compiler_hash

    app = root / "examples/packages/indexed_text"
    program = load_project(app, locked=True).program
    checked = check(program)
    if not checked.ok:
        raise RuntimeError(checked.diagnostics)
    source = emit_c(program, checked, crate_type="cdylib")
    names = [function.name for function in program.functions if function.name.endswith("index_packet")]
    if len(names) != 1:
        raise RuntimeError(f"Expected one consumer symbol: {names}")
    source_paths = [app / "src/main.hepta", app / "src/packet.hepta", app / "hepta.toml",
                    app / "Hepta.lock"]
    for component in ("base64", "bytes", "ordering", "utf8"):
        source_paths += [root / "stdlib" / component / "src/lib.hepta",
                         root / "stdlib" / component / "hepta.toml"]
    identities = {str(path.relative_to(root)): sha256(path) for path in source_paths}
    with tempfile.TemporaryDirectory(prefix="hepta-integration-oracle-") as temporary:
        for optimize in (False, True):
            lane = "O3" if optimize else "O0"
            report = compile_c(source, crate_type="cdylib", optimize=optimize,
                               sanitize=True, output=Path(temporary) / f"{lane}.so")
            if not report["ok"]:
                raise RuntimeError(report)
            flags = report["flags"]
            if ("-fsanitize=undefined" not in flags or "-fno-sanitize-recover=all" not in flags
                    or f"-{lane}" not in flags or report["rustc_used"]):
                raise RuntimeError(f"Unexpected native configuration: {report}")
            library = ctypes.CDLL(report["artifact"])
            function = getattr(library, "__hepta_cb_fn_" + names[0])
            function.argtypes = [ByteSlice, ctypes.c_size_t, ctypes.c_size_t,
                                 ByteSlice, ScalarSlice, ctypes.c_uint64]
            function.restype = IndexResult
            counts = exercise(function)
            if sum(counts.values()) != 12933:
                raise RuntimeError(f"Unexpected corpus size: {counts}")
            print(json.dumps({"lane": lane, "result": "PASS", "case_groups": counts,
                              "native_calls": sum(counts.values()), "flags": flags,
                              "source_sha256": identities, "compiler_sha256": compiler_hash(),
                              "script_sha256": sha256(Path(__file__)),
                              "python_version": sys.version, "toolchain": report["toolchain"],
                              "target": report["target"],
                              "emitted_c_sha256": report["source_sha256"],
                              "artifact_sha256": report["artifact_sha256"],
                              "qualification": "supplementary compiler-private ABI native C only; not native Rust"},
                             sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
