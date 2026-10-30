"""Pre-freeze focused integration regression with raw streams and actual cost."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "hepta-integration"
OUT = Path(__file__).resolve().parent
MODULES = [
    "tests.test_hia_safety_protocol", "tests.test_hia_routes",
    "tests.test_hia_integrated_inputs", "tests.test_hia_integrated_workflow",
    "tests.test_hia_finite_context_timed_fold",
]
ENV = {
    "PATH": ":".join([str(ROOT / "hepta-native-venv/bin"), str(ROOT / "toolchains/llvm20/usr/lib/llvm-20/bin"),
                      str(ROOT / "toolchains/rust-1.90.0/bin"), "/usr/bin", "/bin"]),
    "LD_LIBRARY_PATH": str(ROOT / "toolchains/llvm20/usr/lib/x86_64-linux-gnu"),
    "RUSTC": str(ROOT / "toolchains/rust-1.90.0/bin/rustc"),
    "CLANG": str(ROOT / "toolchains/llvm20/usr/lib/llvm-20/bin/clang"),
    "HEPTA_CLANG": str(ROOT / "toolchains/llvm20/usr/lib/llvm-20/bin/clang"),
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "PYTHONPATH": str(REPO),
}


def main():
    argv = [sys.executable, "-B", "-m", "unittest", "-v", *MODULES]
    environment = dict(os.environ)
    environment.update(ENV)
    for key in ("CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "LIBRARY_PATH"):
        environment.pop(key, None)
    source = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=REPO)
    (OUT / "integration-timed-focus.patch").write_bytes(source)
    before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip()
    started = time.monotonic_ns()
    row = {"schema": "hepta.next2.pre-freeze-regression.v1", "base_head": before,
           "uncommitted_patch_sha256": hashlib.sha256(source).hexdigest(),
           "development_only": True, "argv": argv, "environment": ENV, "timeout_seconds": 240}
    try:
        with (OUT / "integration-timed-focus.stdout").open("xb") as stdout, (OUT / "integration-timed-focus.stderr").open("xb") as stderr:
            run = subprocess.run(argv, cwd=REPO, env=environment, stdout=stdout, stderr=stderr, timeout=240)
        row["returncode"] = run.returncode
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        row["wall_ns"] = time.monotonic_ns() - started
        row["source_patch_unchanged"] = source == subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=REPO)
        row["source_head_unchanged"] = before == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip()
        row["streams"] = {name: {"bytes": (OUT / name).stat().st_size,
                                  "sha256": hashlib.sha256((OUT / name).read_bytes()).hexdigest()}
                          for name in ("integration-timed-focus.stdout", "integration-timed-focus.stderr") if (OUT / name).exists()}
        (OUT / "INTEGRATION_TIMED_FOCUS.json").write_text(json.dumps(row, indent=2) + "\n")
        print(json.dumps(row, sort_keys=True))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
