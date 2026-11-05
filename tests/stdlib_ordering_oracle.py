#!/usr/bin/env python3
"""Independent Python sorted/bisect oracle for the source-only ordering library.

Run from any directory with:
    python /path/to/repo/tests/stdlib_ordering_oracle.py --output report.json

Compiles the actual library through Hepta's existing C backend with real GCC
and UBSan at both -O0 and -O3. The ctypes adapter uses compiler-private generated
C names/layouts; this is not a public Hepta consumer or a stable ABI test. The
separate test_stdlib_ordering.py suite covers public package consumers. This
script never runs or claims native Rust validation. Missing tools fail.
"""
from __future__ import annotations

import argparse
import bisect
import ctypes as ct
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

SEED = 0x20261105
LIMITS = {"i32": (-(1 << 31), (1 << 31) - 1), "u64": (0, (1 << 64) - 1)}
SIZE_MAX = (1 << (ct.sizeof(ct.c_size_t) * 8)) - 1


class SearchIndex(ct.Structure):
    _fields_ = [("index", ct.c_size_t), ("ok", ct.c_bool)]


def exercise(library):
    """Expected results come only from Python sorted/bisect, not heapsort code."""
    counts = {"valid_sort_cases": 0, "invalid_sort_cases": 0, "search_calls": 0,
              "idempotence_checks": 0, "verified_array_elements": 0,
              "empty_slice_cases": 0, "invalid_search_calls": 0}
    rng = random.Random(SEED)
    for name, ctype in (("i32", ct.c_int32), ("u64", ct.c_uint64)):
        class Slice(ct.Structure):
            _fields_ = [("data", ct.POINTER(ctype)), ("len", ct.c_size_t)]

        sort = getattr(library, "__hepta_cb_fn_sort_" + name)
        sort.argtypes, sort.restype = [Slice, ct.c_size_t, ct.c_size_t], ct.c_bool
        lower = getattr(library, "__hepta_cb_fn_lower_bound_" + name)
        upper = getattr(library, "__hepta_cb_fn_upper_bound_" + name)
        for function in (lower, upper):
            function.argtypes = [Slice, ct.c_size_t, ct.c_size_t, ctype]
            function.restype = SearchIndex
        minimum, maximum = LIMITS[name]
        alphabet = (-1, 0, 1) if name == "i32" else (0, 1, maximum)
        probes = ((minimum, -1, 0, 1, maximum) if name == "i32"
                  else (0, 1, (1 << 63) - 1, 1 << 63, maximum))

        def run_case(values, start, end, extra_probes=()):
            # The advertised length always equals the actual allocation length,
            # including genuine zero-length native slices. No oversized views.
            data = (ctype * len(values))(*values)
            view = Slice(data, len(values))
            valid = 0 <= start <= end <= len(values)
            expected = values[:]
            if valid:
                expected[start:end] = sorted(values[start:end])
            actual_ok = sort(view, start, end)
            if actual_ok != valid:
                raise AssertionError((name, values, start, end, "sort validity", actual_ok))
            actual = list(data)
            if actual != expected:
                raise AssertionError((name, values, start, end, "sort result", actual, expected))
            counts["verified_array_elements"] += len(values)
            counts["valid_sort_cases" if valid else "invalid_sort_cases"] += 1
            counts["empty_slice_cases"] += not values
            for needle in (*probes, *extra_probes):
                for function, oracle in ((lower, bisect.bisect_left), (upper, bisect.bisect_right)):
                    found = function(view, start, end, needle)
                    index = oracle(expected, needle, start, end) if valid else 0
                    if (found.index, found.ok) != (index, valid):
                        raise AssertionError((name, values, start, end, needle,
                                              function.__name__, found.index, found.ok, index, valid))
                    counts["search_calls"] += 1
                    counts["invalid_search_calls"] += not valid
            if list(data) != expected:
                raise AssertionError(("read-only search mutated values", name, values, start, end))
            if valid:
                if not sort(view, start, end) or list(data) != expected:
                    raise AssertionError(("sort not idempotent", name, values, start, end))
                counts["idempotence_checks"] += 1

        # All arrays of length 0..5 over three values; every valid half-open range.
        for length in range(6):
            for values in itertools.product(alphabet, repeat=length):
                values = list(values)
                for start in range(length + 1):
                    for end in range(start, length + 1):
                        run_case(values, start, end)

        # Larger/adversarial shapes and deterministic full-width random values.
        shapes = [[], [minimum], [maximum], [minimum, maximum], [maximum, minimum],
                  [minimum, maximum] * 128, [maximum, minimum, 0] * 85,
                  [maximum] * 257, [minimum] * 257,
                  list(range(257)), list(reversed(range(257)))]
        for length in (7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                       127, 128, 129, 255, 256, 257):
            shapes.append([rng.randint(minimum, maximum) for _ in range(length)])
        for _ in range(1500):
            length = rng.randrange(0, 258)
            shapes.append([rng.choice(probes) if rng.randrange(3) == 0
                           else rng.randint(minimum, maximum) for _ in range(length)])
        for values in shapes:
            length = len(values)
            selected = {(0, length), (0, 0), (length, length)}
            if length:
                selected.add((length // 3, 2 * length // 3))
                a, b = sorted((rng.randrange(length + 1), rng.randrange(length + 1)))
                selected.add((a, b))
            for start, end in sorted(selected):
                run_case(values, start, end, (rng.randint(minimum, maximum),))
            # Validation must precede unsigned subtraction/addition/indexing.
            for start, end in {(length + 1, length), (0, length + 1),
                               (SIZE_MAX, 0), (0, SIZE_MAX),
                               (SIZE_MAX, SIZE_MAX), (1, 0)}:
                run_case(values, start, end)
    return counts


def run_oracle():
    source_path = ROOT / "stdlib/ordering/src/lib.hepta"
    source = source_path.read_text(encoding="utf-8")
    program = parse(source, str(source_path))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    generated = emit_c(program, checked, crate_type="cdylib")
    runs = []
    with tempfile.TemporaryDirectory(prefix="hepta-ordering-oracle-") as directory:
        for optimize in (False, True):
            level = "O3" if optimize else "O0"
            native = compile_c(generated, crate_type="cdylib", optimize=optimize,
                               output=Path(directory) / ("ordering-" + level + ".so"),
                               sanitize=True)
            if not native["ok"]:
                raise AssertionError(native)
            counts = exercise(ct.CDLL(native["artifact"]))
            # Artifacts are temporary by design; retain identities, not a link
            # that would misleadingly imply a surviving output file.
            native.pop("artifact", None)
            native["artifact_retained"] = False
            runs.append({"optimization": level, "status": "passed",
                         "counts": counts, "native_c_build": native})
    if runs[0]["counts"] != runs[1]["counts"]:
        raise AssertionError("Optimization levels did not run the same corpus")
    return {
        "schema": "hepta.stdlib-ordering-independent-oracle.v1",
        "status": "passed",
        "oracle": "Python built-in sorted and bisect_left/bisect_right",
        "adapter": "Compiler-private C names/layouts via ctypes; not public ABI qualification",
        "seed": SEED,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "declared_resource_contracts": {fn.name: fn.resources for fn in program.functions},
        "inferred_effects": {name: sorted(effects) for name, effects in checked.effects.items()},
        "runs": runs,
        "native_rust": "not run by this oracle; use the public consumer suite with its Rust backend",
        "limits": "64-bit native C host, i32/u64 only; huge valid slices are not execution-tested",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    arguments = parser.parse_args()
    report = run_oracle()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
