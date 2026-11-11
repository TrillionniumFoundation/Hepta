"""Record exact runtime character classes; this is not product qualification."""
from __future__ import annotations
from hashlib import sha256
import argparse
import json
from pathlib import Path
import sys
import time
import unicodedata

def main():
    start = time.monotonic_ns()
    executable = Path(sys.executable).resolve(strict=True)
    binary_before = sha256(executable.read_bytes()).hexdigest()
    ranges = {"decimal": [], "printable": []}
    counts = {"decimal": 0, "printable": 0}
    lower = {"decimal": None, "printable": None}
    for point in range(0x110000):
        character = chr(point)
        states = {"decimal": character.isdecimal(), "printable": character.isprintable()}
        for name, present in states.items():
            if present:
                counts[name] += 1
                if lower[name] is None:
                    lower[name] = point
            elif lower[name] is not None:
                ranges[name].append([lower[name], point - 1])
                lower[name] = None
    for name in ranges:
        if lower[name] is not None:
            ranges[name].append([lower[name], 0x10ffff])
    parser_path = Path(argparse.__file__)
    parser_raw = parser_path.read_bytes()
    binary_after = sha256(executable.read_bytes()).hexdigest()
    result = {
        "schema": "hia.cpython-unicode-observation.v1",
        "scope": "READ_ONLY_RUNTIME_FACTS_NOT_PRODUCT_QUALIFICATION",
        "python": sys.version,
        "requested_executable": sys.executable,
        "executable": str(executable),
        "executable_sha256": binary_before,
        "binary_preserved": binary_before == binary_after,
        "source_program_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "unicode_database_version": unicodedata.unidata_version,
        "points_examined": 0x110000,
        "range_convention": "inclusive endpoints",
        "predicate_true_counts": counts,
        "true_intervals": ranges,
        "argparse_source": {"path": str(parser_path), "bytes": len(parser_raw),
                            "sha256": sha256(parser_raw).hexdigest()},
        "elapsed_ns": time.monotonic_ns() - start,
        "whole_native_delivery_qualified": False,
    }
    if not result["binary_preserved"]:
        raise RuntimeError("runtime executable changed during read-only observation")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    main()
