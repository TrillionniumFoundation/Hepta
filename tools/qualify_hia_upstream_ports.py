"""Native upstream C/UBSan and HIA/Rust port controls before model inference."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.hia_upstream_factorial import tasks, evaluator
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity


def run(output, clang, rustc, cc):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    report = {"schema": "hepta.hia.upstream-native-port-controls.v1", "ok": False,
              "model_requests": 0, "rows": [], "commands": [], "human_labor_ns": None,
              "scope": "two selected real upstream fixes; finite native controls, not C-source refinement proof"}
    tool = file_identity(shutil.which(cc))

    def command(argv, *, stdin=None):
        then = time.monotonic_ns()
        result = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True, text=True, timeout=45)
        row = {"argv": list(map(str, argv)), "returncode": result.returncode, "stdout": result.stdout,
               "stderr": result.stderr, "wall_ns": time.monotonic_ns()-then}
        report["commands"].append(row)
        return row

    try:
        for task in tasks.make_fixtures():
            for label, profile in (("before", "stb_divide_v0_93"), ("after", "stb_divide")):
                folder = output / (task["id"] + "-c-" + label); folder.mkdir()
                header = ROOT / "tests/fixtures/c_migration" / profile / "stb_divide.h"
                shutil.copyfile(header, folder / "stb_divide.h")
                function = task["function"].removeprefix("c_")
                source = ('#define STB_DIVIDE_IMPLEMENTATION\n#include "stb_divide.h"\n' +
                    '#include <stdio.h>\n#include <stdint.h>\n#include <inttypes.h>\n' +
                    '_Static_assert(sizeof(int)==4,"32-bit C int required");\n' +
                    'int main(void) { int32_t a,b; while(scanf("%" SCNd32 " %" SCNd32,&a,&b)==2) { printf("%" PRId32 "\\n",' +
                    function + '(a,b)); fflush(stdout); } return 0; }\n')
                (folder / "driver.c").write_text(source)
                binary = folder / "reference"
                built = command([cc, "-std=c11", "-O2", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                                 folder / "driver.c", "-o", binary])
                if built["returncode"]:
                    raise RuntimeError("independent C/UBSan build failed")
                values = task["public_cases"] + task["hidden_cases"]
                expected = task["public_expected"] + task["hidden_expected"]
                observed = command([binary], stdin="".join(f"{a} {b}\n" for a,b in values))
                actual = [int(line) for line in observed["stdout"].splitlines()]
                passed = ((observed["returncode"] != 0 and "runtime error:" in observed["stderr"])
                          if label == "before" else observed["returncode"] == 0 and actual == expected)
                report["rows"].append({"task": task["id"], "language": "upstream_c", "version": label,
                    "passed": passed, "expected": "UBSan catches the historical defect" if label == "before" else "all defined-domain outputs match the mathematical oracle",
                    "cases_supplied": len(values), "values_observed_before_exit": len(actual),
                    "source_header_sha256": sha256(header.read_bytes()).hexdigest(), "binary": file_identity(binary),
                    "execution": observed})
                if not passed:
                    raise ValueError("original C control disagrees with declared historical change")
            for language in ("assembly", "rust"):
                for label in ("original", "correct"):
                    folder = output / (task["id"] + "-" + language + "-" + label)
                    built = evaluator.build(task, language, canonical({"files": task[label + "_" + language]}).decode(),
                                            folder, clang, rustc)
                    values = task["public_cases"] + task["hidden_cases"]
                    expected = task["public_expected"] + task["hidden_expected"]
                    observed = evaluator.execute(built, task, values, expected) if built["native_built"] else None
                    passed = (observed is not None and observed["artifact_unchanged"]
                              and observed["status"] == ("correct" if label == "correct" else "observable_wrong"))
                    report["rows"].append({"task": task["id"], "language": language, "version": label,
                                           "passed": passed, "build": built, "execution": observed})
                    if not passed:
                        raise ValueError("native port control failed")
        report["tool_unchanged"] = file_identity(tool["path"]) == tool
        report["ok"] = report["tool_unchanged"]
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    report["compiler"] = tool
    report["wall_ns"] = time.monotonic_ns()-start
    (output / "CONTROLS.json").write_bytes(canonical(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "clang", "rustc"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--cc", default="gcc"); args = parser.parse_args()
    result = run(args.output, args.clang, args.rustc, args.cc)
    print(json.dumps({"ok": result["ok"], "error": result.get("error"), "rows": len(result["rows"]),
                      "passed": sum(row["passed"] for row in result["rows"]), "wall_ns": result["wall_ns"]}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
