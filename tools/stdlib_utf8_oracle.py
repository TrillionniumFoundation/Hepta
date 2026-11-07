#!/usr/bin/env python3
"""Exhaustive runtime UTF-8 oracle against Python's strict decoder.

This supplemental test loads emitted C through the compiler-private ctypes ABI.
It is not a public FFI contract, a Rust execution test, or native Rust
qualification. Public package-consumer tests belong in test_stdlib_utf8.py.
Requires the qualified 64-bit host, a native GCC-compatible compiler, and UBSan.
Run from any directory with --root REPOSITORY, or place this script in tools/.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys
import tempfile


class Slice(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class Decoded(ctypes.Structure):
    _fields_ = [("scalar", ctypes.c_uint32), ("next", ctypes.c_size_t),
                ("ok", ctypes.c_bool)]


class Validation(ctypes.Structure):
    _fields_ = [("scalars", ctypes.c_size_t), ("error", ctypes.c_size_t),
                ("ok", ctypes.c_bool)]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected(data: bytes, start: int, end: int) -> tuple:
    """Use prefix decoding rather than duplicating UTF-8 transition rules."""
    first = (0, start, False)
    whole = (0, start, False)
    if not 0 <= start <= end <= len(data):
        return first, whole
    part = data[start:end]
    try:
        decoded = part.decode("utf-8", "strict")
        whole = (len(decoded), end, True)
    except UnicodeDecodeError as exc:
        prefix = part[:exc.start].decode("utf-8", "strict")
        whole = (len(prefix), start + exc.start, False)
    for width in range(1, min(4, len(part)) + 1):
        try:
            decoded = part[:width].decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if len(decoded) == 1:
            first = (ord(decoded), start + width, True)
            break
    return first, whole


def exercise(library: ctypes.CDLL, program) -> dict[str, int]:
    """Exercise both functions and check all backing bytes after each call."""
    functions = {}
    for suffix, result_type in (("decode_next", Decoded), ("validate", Validation)):
        names = [fn.name for fn in program.functions if fn.name.endswith(suffix)]
        if len(names) != 1:
            raise RuntimeError(f"Expected one {suffix} symbol, found {names}")
        native = getattr(library, "__hepta_cb_fn_" + names[0])
        native.argtypes = [Slice, ctypes.c_size_t, ctypes.c_size_t]
        native.restype = result_type
        functions[suffix] = native
    counts: dict[str, int] = {}

    def case(group: str, data: bytes, start: int = 0, end: int | None = None):
        end = len(data) if end is None else end
        want_first, want_whole = expected(data, start, end)
        # A sentinel makes empty input's backing allocation nonempty while the
        # logical slice length remains exactly zero.
        backing = data or b"\xa5"
        array = (ctypes.c_uint8 * len(backing))(*backing)
        view = Slice(array, len(data))
        decoded = functions["decode_next"](view, start, end)
        if bytes(array) != backing:
            raise AssertionError(("decode_next mutated backing bytes", data.hex(), start, end))
        checked = functions["validate"](view, start, end)
        if bytes(array) != backing:
            raise AssertionError(("validate mutated backing bytes", data.hex(), start, end))
        got_first = (decoded.scalar, decoded.next, decoded.ok)
        got_whole = (checked.scalars, checked.error, checked.ok)
        if got_first != want_first or got_whole != want_whole:
            raise AssertionError({"data": data.hex(), "start": start, "end": end,
                                  "first": (got_first, want_first),
                                  "whole": (got_whole, want_whole)})
        counts[group] = counts.get(group, 0) + 1

    # All scalar values, including NUL, BOM, and Unicode noncharacters.
    for scalar in range(0x110000):
        if not 0xD800 <= scalar <= 0xDFFF:
            case("all_unicode_scalars", chr(scalar).encode("utf-8"))
    case("empty", b"")
    for width in (1, 2):
        for values in itertools.product(range(256), repeat=width):
            case("all_one_two_byte_strings", bytes(values))
    tails = (b"\x80", b"\xbf", b"\x7f", b"\xc0", b"\x80\x80", b"\xbf\xbf",
             b"\x80\x7f", b"\xc0\x80")
    for lead in range(0xE0, 0x100):
        for second in range(256):
            for tail in tails:
                case("three_four_byte_classes", bytes((lead, second)) + tail)
    rng = random.Random(0xFEED20261105)
    for _ in range(50000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(18)))
        start = rng.randrange(len(data) + 3)
        end = rng.randrange(len(data) + 3)
        case("seeded_arbitrary_ranges", data, start, end)
    for _ in range(1000):
        scalars = [rng.randrange(0x110000) for _ in range(4)]
        text = "".join(chr(value) for value in scalars if not 0xD800 <= value <= 0xDFFF)
        data = b"\xff" + text.encode("utf-8") + b"\xff"
        for start in range(len(data) + 1):
            for end in range(start, len(data) + 1):
                case("mixed_buffer_all_subranges", data, start, end)
    maximum = (1 << 64) - 1
    for data in (b"", b"a", b"\xf0\x90\x80\x80"):
        for start, end in ((maximum, maximum), (0, maximum), (maximum, 0),
                           (maximum - 1, maximum)):
            case("usize_maximum_bounds", data, start, end)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    host = {"pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
            "size_t_bits": ctypes.sizeof(ctypes.c_size_t) * 8,
            "ssize_t_bits": ctypes.sizeof(ctypes.c_ssize_t) * 8,
            "byte_bits": ctypes.sizeof(ctypes.c_uint8) * 8}
    if host != {"pointer_bits": 64, "size_t_bits": 64, "ssize_t_bits": 64, "byte_bits": 8}:
        raise RuntimeError(f"Oracle requires the qualified 64-bit host: {host}")
    sys.path.insert(0, str(root))
    from hepta.c_backend import compile_c, emit_c
    from hepta.checker import check
    from hepta.modules import load_project

    program = load_project(root / "stdlib/utf8").program
    checked = check(program)
    if not checked.ok:
        raise RuntimeError(checked.diagnostics)
    source = emit_c(program, checked, crate_type="cdylib")
    with tempfile.TemporaryDirectory(prefix="hepta-utf8-oracle-") as temporary:
        for optimize in (False, True):
            lane = "optimized" if optimize else "unoptimized"
            report = compile_c(source, crate_type="cdylib", optimize=optimize,
                               sanitize=True, output=Path(temporary) / f"{lane}.so")
            if not report["ok"]:
                raise RuntimeError(report)
            if "-fsanitize=undefined" not in report["flags"] or report["rustc_used"]:
                raise RuntimeError(f"Unexpected compiler configuration: {report}")
            counts = exercise(ctypes.CDLL(report["artifact"]), program)
            print(json.dumps({"lane": lane, "result": "PASS", "host": host,
                              "cases": sum(counts.values()), "case_groups": counts,
                              "native_calls": 2 * sum(counts.values()),
                              "immutability_checks": 2 * sum(counts.values()),
                              "library_sha256": sha256(root / "stdlib/utf8/src/lib.hepta"),
                              "script_sha256": sha256(Path(__file__)),
                              "python_executable_sha256": sha256(Path(sys.executable)),
                              "python_version": sys.version, "toolchain": report["toolchain"],
                              "target": report["target"], "flags": report["flags"],
                              "emitted_c_sha256": report["source_sha256"],
                              "artifact_sha256": report["artifact_sha256"],
                              "qualification": "compiler-private C ABI only; not native Rust"},
                             sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
