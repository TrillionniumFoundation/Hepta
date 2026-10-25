"""Independent Clang C11/C++20 ternary-to-if control-flow oracle.

Finite, original-defined scalar inputs only. This does not call Hepta.
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

ORIGINAL = ("int original_choose(int x,int y){return x>y ? x : y;}\n"
            "int original_clamp(int x){int y=0;y=x>0 ? x : 0;return y;}\n")
NORMAL = ("int normalized_choose(int x,int y){if(x>y){return x;}else{return y;}}\n"
          "int normalized_clamp(int x){int y=0;if(x>0){y=x;}else{y=0;}return y;}\n")
BAD = "int wrong_choose(int x,int y){if(x>y){return x;}else{return x;}}\n"


def execute(argv: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
    if result.returncode:
        raise RuntimeError("C/C++ oracle command rejected: " + result.stderr[-1500:])
    return result


def probe(compiler: str, extension: str, standard: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="hepta-ternary-oracle-") as td:
        root = Path(td)
        source = root / ("source." + extension)
        material = ORIGINAL + NORMAL + BAD
        if standard == "c++20":
            for name in ("original_choose", "original_clamp", "normalized_choose",
                         "normalized_clamp", "wrong_choose"):
                material = material.replace("int " + name + "(", 'extern "C" int ' + name + "(")
        source.write_text(material, encoding="utf-8")
        lib_path = root / "native.so"
        execute([compiler, "-std=" + standard, "-O2", "-shared", "-fPIC",
                 str(source), "-o", str(lib_path)])
        library = ctypes.CDLL(str(lib_path))
        functions = {name: getattr(library, name)
                     for name in ("original_choose", "original_clamp",
                                  "normalized_choose", "normalized_clamp", "wrong_choose")}
        for name, function in functions.items():
            function.argtypes = [ctypes.c_int32] * (2 if "choose" in name else 1)
            function.restype = ctypes.c_int32
        rng = random.Random(20261025)
        values = [-2**31, -2000, -11, -1, 0, 1, 17, 90, 2000, 2**31 - 1]
        pairs = [(x, y) for x in values for y in values]
        pairs.extend((rng.randint(-2**31, 2**31 - 1), rng.randint(-2**31, 2**31 - 1))
                     for _ in range(1400))
        errors_caught = 0
        for x, y in pairs:
            expected = functions["original_choose"](x, y)
            if functions["normalized_choose"](x, y) != expected:
                raise RuntimeError("Choose result differs from original")
            if functions["wrong_choose"](x, y) != expected:
                errors_caught += 1
        for x in values + [rng.randint(-2**31, 2**31 - 1) for _ in range(1400)]:
            if functions["original_clamp"](x) != functions["normalized_clamp"](x):
                raise RuntimeError("Clamp result differs from original")
        driver = root / ("driver." + extension)
        abi = 'extern "C" ' if standard == "c++20" else ""
        driver.write_text(
            abi + "int original_choose(int,int);" + abi + "int normalized_choose(int,int);"
            + abi + "int original_clamp(int);" + abi + "int normalized_clamp(int);"
            + "int main(){for(int x=-200;x<=200;++x){"
            + "for(int y=-200;y<=200;++y)"
            + "if(original_choose(x,y)!=normalized_choose(x,y))return 1;"
            + "if(original_clamp(x)!=normalized_clamp(x))return 2;}return 0;}",
            encoding="utf-8")
        sanitizer = root / "ubsan"
        execute([compiler, "-std=" + standard, "-O1", "-fsanitize=undefined",
                 "-fno-sanitize-recover=undefined", str(source), str(driver),
                 "-o", str(sanitizer)])
        execute([str(sanitizer)])
        return {
            "compiler": execute([compiler, "--version"]).stdout.splitlines()[0],
            "language": standard,
            "choose_pairs": len(pairs),
            "clamp_cases": len(values) + 1400,
            "wrong_implementation_detected": errors_caught,
            "ubsan_choose_pairs": 401 * 401,
            "ubsan_clamp_cases": 401,
            "original_sha256": hashlib.sha256(ORIGINAL.encode()).hexdigest(),
            "normalized_sha256": hashlib.sha256(NORMAL.encode()).hexdigest(),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "schema": "hepta.strict-ternary-control-flow-oracle.v1",
        "scope": "independent_clang_C11_Cpp20_scalar_defined_domain_not_hepta_compilation",
        "results": [probe("clang", "c", "c11"), probe("clang++", "cc", "c++20")],
        "claims": {
            "hepta_compiler_invoked": False,
            "full_function_equivalence_proved": False,
            "whole_language_soundness_proved": False,
            "native_scalar_oracle_passed": True,
        },
    }
    path = args.output.absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise SystemExit("E_ORACLE_OUTPUT: require a fresh destination in existing directory")
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed",
                      "scalar_cases": sum(x["choose_pairs"] + x["clamp_cases"] for x in report["results"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
