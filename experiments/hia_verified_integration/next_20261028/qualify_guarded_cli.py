"""Execute the new CLI, then check its actual sealed native fast/slow paths."""
from hashlib import sha256
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.native_mapping_identity import verify_loaded_symbols


def run(directory, clang):
    work = Path(directory).absolute()
    work.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.guarded-cli-qualification.v1", "passed": False,
              "commands": [], "native_observations": [],
              "qualifier_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}

    def command(arguments, expected=0):
        argv = [sys.executable, "-m", "hepta", "hia", *map(str, arguments)]
        completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=60)
        row = {"argv": argv, "returncode": completed.returncode,
               "stdout": completed.stdout, "stderr": completed.stderr}
        report["commands"].append(row)
        if completed.returncode != expected:
            raise ValueError("CLI returned an unexpected status: " + repr(row))
        return json.loads(completed.stdout)

    try:
        core, proposal, binary = work / "base.json", work / "proposal.json", work / "candidate.so"
        command(["lower", ROOT / "experiments/hia_optimizer_eval/kernels.hepta", "-o", core])
        proposed = command(["optimize-guarded", core, "--maximum", "16", "-o", proposal])
        if proposed["verification"]["status"] != "verified":
            raise ValueError("CLI did not prove its actual proposal")
        checked = command(["verify-guarded", core, "--candidate", proposal])
        built = command(["build-guarded", core, "--candidate", proposal, "--clang", clang, "-o", binary])
        if (checked["status"] != "verified" or
                checked["candidate_sha256"] != built["native"]["core_sha256"]):
            raise ValueError("CLI verification/build Core binding differs")
        program = verify_program(core.read_bytes())
        _, _, descriptor = _pin_native_artifact(binary)
        library = None
        try:
            loaded = os.pread(descriptor, os.fstat(descriptor).st_size, 0)
            if sha256(loaded).hexdigest() != built["native"]["artifact_sha256"]:
                raise ValueError("Loaded CLI artifact differs from native receipt")
            library = ctypes.CDLL(f"/proc/self/fd/{descriptor}")
            report["loaded_mapping"] = verify_loaded_symbols(descriptor, {
                name: getattr(library, name) for name in ("full_lifecycle", "packet_xor")})
            for name in ("full_lifecycle", "packet_xor"):
                function = getattr(library, name)
                function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint32], ctypes.c_uint64
                for size in (0, 1, 15, 16, 17, 33):
                    for seed in (0, 7, 255):
                        expected = execute_program(program, name, [size, seed])["result"]
                        actual = function(size, seed)
                        report["native_observations"].append({"function": name, "arguments": [size, seed],
                            "path": "fast" if size <= 16 else "fallback", "actual": actual, "expected": expected})
                        if actual != expected:
                            raise ValueError("CLI native result differs from actual base Core")
        finally:
            if library is not None:
                import _ctypes
                _ctypes.dlclose(library._handle)
            os.close(descriptor)
        policy, forbidden = work / "timeout-policy.json", work / "forbidden-proposal.json"
        policy.write_text(json.dumps({**DEFAULT_POLICY, "timeout_ms": 0}))
        refused = command(["optimize-guarded", core, "--policy", policy, "-o", forbidden], expected=1)
        if refused["verification"]["status"] != "timeout" or forbidden.exists():
            raise ValueError("Timed-out CLI proposal was published")
        report.update(passed=True, timeout_never_published=True, native_artifact_sha256=sha256(binary.read_bytes()).hexdigest(),
                      candidate_core_sha256=built["native"]["core_sha256"], native_receipt=built)
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    (work / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    result = run(sys.argv[1], os.environ["CLANG"])
    print(json.dumps({"passed": result["passed"], "native_observations": len(result["native_observations"]),
                      "error": result.get("error")}))
    raise SystemExit(0 if result["passed"] else 1)
