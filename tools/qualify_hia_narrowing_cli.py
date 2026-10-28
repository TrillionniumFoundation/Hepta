"""Exercise all narrowing CLI stages against their actual sealed native images.

These are correctness and refusal observations, never benchmark samples.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.native_mapping_identity import verify_loaded_symbols


def scalar_program():
    arguments = [{"name": "a", "type": "u32"}, {"name": "b", "type": "u32"}]
    return {"schema": "hepta.hia.program.v1", "module": "narrowing_cli",
        "functions": [{"name": "calculate", "params": arguments, "returns": ["u8"],
            "effects": ["trap"], "entry": "entry", "blocks": [{"id": "entry",
                "params": arguments, "ops": [
                    {"op": "int.add.wrap", "args": ["a", "b"],
                     "out": [{"name": "sum", "type": "u32"}], "attrs": {}},
                    {"op": "int.cast", "args": ["sum"],
                     "out": [{"name": "byte", "type": "u8"}], "attrs": {"mode": "wrap"}}],
                "term": {"op": "ret", "values": ["byte"]}}]}]}


def qualify(output, *, clang):
    work = Path(output).resolve()
    work.mkdir(parents=True, exist_ok=False)
    bindings = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest()
                for p in sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__)]}
    report = {"schema": "hepta.hia.narrowing-cli-qualification.v1", "passed": False,
              "commands": [], "native_observations": [], "source_bindings": bindings,
              "performance_claim": False}

    def command(arguments, expected=0):
        argv = [sys.executable, "-m", "hepta", "hia", *map(str, arguments)]
        completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=90)
        row = {"argv": argv, "returncode": completed.returncode,
               "stdout": completed.stdout, "stderr": completed.stderr}
        report["commands"].append(row)
        if completed.returncode != expected:
            raise ValueError("Unexpected CLI status: " + repr(row))
        return json.loads(completed.stdout)

    try:
        for label, guarded in (("scalar", False), ("guarded", True)):
            core, proposal, binary = (work / (label + suffix) for suffix in (".json", ".proposal.json", ".so"))
            if guarded:
                command(["lower", ROOT / "experiments/hia_optimizer_eval/kernels.hepta", "-o", core])
            else:
                core.write_text(json.dumps(scalar_program(), sort_keys=True) + "\n")
            suffix = "guarded-narrowed" if guarded else "narrowed"
            options = ["--maximum", "16"] if guarded else []
            proposed = command(["optimize-" + suffix, core, *options, "-o", proposal])
            checked = command(["verify-" + suffix, core, "--candidate", proposal])
            built = command(["build-" + suffix, core, "--candidate", proposal,
                             "--clang", clang, "-o", binary])
            if (proposed["verification"]["status"] != "verified" or checked["status"] != "verified"
                    or checked["candidate_sha256"] != built["native"]["core_sha256"]):
                raise ValueError("CLI stages do not bind the same proved candidate")
            base = verify_program(core.read_bytes())
            _, _, descriptor = _pin_native_artifact(binary)
            library = None
            try:
                actual_sha = sha256(os.pread(descriptor, os.fstat(descriptor).st_size, 0)).hexdigest()
                if actual_sha != built["native"]["artifact_sha256"]:
                    raise ValueError("Sealed CLI native image differs from final proof/build receipt")
                library = ctypes.CDLL(f"/proc/self/fd/{descriptor}")
                names = ("full_lifecycle", "packet_xor") if guarded else ("calculate",)
                mapping = verify_loaded_symbols(descriptor, {name: getattr(library, name) for name in names})
                report[label] = {"verification": checked, "build": built, "mapping": mapping}
                for name in names:
                    function = getattr(library, name)
                    if guarded:
                        function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint32], ctypes.c_uint64
                        cases = [(n, seed) for n in (0, 1, 15, 16, 17, 33)
                                 for seed in (0, 7, 2**32 - 1)]
                    else:
                        function.argtypes, function.restype = [ctypes.c_uint32, ctypes.c_uint32], ctypes.c_uint8
                        cases = [(a, b) for a in (0, 1, 255, 256, 2**32 - 1)
                                 for b in (0, 1, 257, 2**32 - 1)]
                    for arguments in cases:
                        expected = execute_program(base, name, list(arguments))["result"]
                        actual = function(*arguments)
                        report["native_observations"].append({"profile": label, "function": name,
                            "arguments": list(arguments), "actual": actual, "expected": expected})
                        if actual != expected:
                            raise ValueError("CLI native result disagrees with original Core")
            finally:
                if library is not None:
                    import _ctypes
                    _ctypes.dlclose(library._handle)
                os.close(descriptor)
            for failed, policy_change in (("timeout", {"timeout_ms": 0}),
                                          ("unknown", {"max_obligations": 0})):
                policy = work / (label + "." + failed + ".policy.json")
                policy.write_text(json.dumps({**DEFAULT_POLICY, **policy_change}))
                forbidden = work / (label + "." + failed + ".forbidden.json")
                refused = command(["optimize-" + suffix, core, *options,
                                   "--policy", policy, "-o", forbidden], expected=1)
                if refused["verification"]["status"] != failed or forbidden.exists():
                    raise ValueError("Unproved CLI candidate was published")
        report["source_unchanged"] = all(sha256((ROOT / p).read_bytes()).hexdigest() == h
                                         for p, h in bindings.items())
        if not report["source_unchanged"]:
            raise ValueError("CLI source changed during qualification")
        report.update(passed=True, timeout_and_unknown_never_published=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    (work / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args()
    result = qualify(args.output, clang=args.clang)
    print(json.dumps({k: result.get(k) for k in ("passed", "source_unchanged", "error")}))
    raise SystemExit(0 if result["passed"] else 1)
