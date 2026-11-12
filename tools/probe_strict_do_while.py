"""Finite independent C11/C++20 do-while normalization oracle.

This probes native language semantics only, not Hepta source translation,
type checking, ABI qualification or compiler refinement.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile

ORIGINAL = """int original_do(int n) { int total=0; int i=0; do {total=total+i; i=i+1;} while(i<n); return total; }\n"""
NORMALIZED = """int normalized_do(int n) { int total=0; int i=0; total=total+i; i=i+1; while(i<n){total=total+i; i=i+1;} return total; }\n"""
WRONG = """int wrong_do(int n) { int total=0; int i=0; total=total+i; i=i+1; while(i<n){total=total+i; i=i+1;} return total+1; }\n"""


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("Native oracle command failed: " + result.stderr[-2000:])
    return result


def _probe(compiler: str, extension: str, standard: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="hepta-do-while-oracle-") as directory:
        root = Path(directory)
        original = ORIGINAL + NORMALIZED + WRONG
        if extension == "cc":
            for name in ("original_do", "normalized_do", "wrong_do"):
                original = original.replace("int " + name + "(", 'extern "C" int ' + name + "(")
        source = root / ("source." + extension)
        source.write_text(original, encoding="utf-8")
        library = root / "native.so"
        _run([compiler, "-std=" + standard, "-O2", "-fPIC", "-shared",
              str(source), "-o", str(library)])
        loaded = ctypes.CDLL(str(library))
        ref, new, wrong = (getattr(loaded, name)
                           for name in ("original_do", "normalized_do", "wrong_do"))
        for function in (ref, new, wrong):
            function.argtypes = [ctypes.c_int32]
            function.restype = ctypes.c_int32

        rng = random.Random(20261025)
        values = [-101, -1, 0, 1, 2, 3, 6, 11, 99, 500, 1000, 3000]
        values += [rng.randint(-150, 3000) for _ in range(1000)]
        rejections = 0
        for n in values:
            expected = sum(range(n)) if n > 1 else 0
            if not ref(n) == new(n) == expected:
                raise RuntimeError("Original/normalized result mismatch")
            if wrong(n) != expected:
                rejections += 1
        driver = root / ("driver." + extension)
        abi = 'extern "C" ' if extension == "cc" else ""
        driver.write_text(
            abi + "int original_do(int);" + abi + "int normalized_do(int);"
            + "int main(){for(int n=-128;n<=1000;++n)"
            + "if(original_do(n)!=normalized_do(n))return 7;return 0;}",
            encoding="utf-8")
        sanitizer = root / "ubsan"
        _run([compiler, "-std=" + standard, "-O1", "-fsanitize=undefined",
              "-fno-sanitize-recover=undefined", str(source), str(driver),
              "-o", str(sanitizer)])
        _run([str(sanitizer)])
        return {
            "language": standard,
            "compiler": _run([compiler, "--version"]).stdout.splitlines()[0],
            "comparisons": len(values),
            "incorrect_impl_rejected": rejections,
            "ubsan_pairs": 1129,
            "ubsan_exit": 0,
            "original_sha256": hashlib.sha256(ORIGINAL.encode()).hexdigest(),
            "normalized_sha256": hashlib.sha256(NORMALIZED.encode()).hexdigest(),
            "sample_inputs_sha256": hashlib.sha256(json.dumps(values).encode()).hexdigest(),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "schema": "hepta.do-while-independent-oracle.v1",
        "scope": "independent_C11_Cpp20_native_defined_scalar_domain_not_Hepta_pipeline",
        "results": [_probe("clang", "c", "c11"), _probe("clang++", "cc", "c++20")],
        "claims": {
            "semantic_smoke_scoped_passed": True,
            "hepta_compiler_invoked": False,
            "full_source_equivalence_proved": False,
            "ffi_abi_qualified": False,
            "whole_language_soundness_proved": False,
        },
    }
    path = args.output.absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise SystemExit("E_ORACLE_OUTPUT: fresh destination in an existing directory is required")
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "compared": sum(x["comparisons"] for x in report["results"]),
                      "wrong_impl_rejected": sum(x["incorrect_impl_rejected"] for x in report["results"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
