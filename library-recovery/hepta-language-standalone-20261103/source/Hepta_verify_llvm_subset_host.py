"""Host-only LLVM scalar subset validation with explicit skipped-test claims.

This script binds test results and local compiler identities to source hashes;
it is not a soundness proof or a substitute for pinned Rust validation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("hepta/llvm_scalar_backend.py", "tests/test_llvm_scalar_backend.py",
           "tests/test_llvm_scalar_phi.py", "tests/test_llvm_scalar_targets.py",
           "tools/verify_llvm_subset_host.py")
TESTS = ("tests.test_llvm_scalar_backend", "tests.test_llvm_scalar_phi",
         "tests.test_llvm_scalar_targets")


def _sha(path: Path) -> str:
    h = sha256()
    with path.open('rb') as fp:
        for data in iter(lambda: fp.read(1_048_576), b''):
            h.update(data)
    return h.hexdigest()


def _tool(name: str) -> dict:
    raw = shutil.which(name)
    if raw is None:
        return {"status": "unavailable"}
    path = Path(raw).resolve()
    try:
        result = subprocess.run([str(path), "--version"], capture_output=True,
                                text=True, timeout=10, check=False)
        if result.returncode or not result.stdout:
            return {"status": "error", "path": str(path)}
        return {"status": "identified", "path": str(path),
                "version": result.stdout.splitlines()[0], "sha256": _sha(path)}
    except (OSError, subprocess.SubprocessError):
        return {"status": "error", "path": str(path)}


def qualify():
    command = [sys.executable, '-m', 'unittest', *TESTS, '-v']
    try:
        p = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=90,
                           check=False)
        log = p.stdout + p.stderr
        total_match = re.search(r'Ran (\d+) tests', log)
        skipped_match = re.search(r'\bskipped=(\d+)\b', log)
        total = int(total_match.group(1)) if total_match else 0
        skipped = int(skipped_match.group(1)) if skipped_match else 0
        passed = p.returncode == 0 and total > 0 and ('\nOK' in log or log.startswith('OK'))
        result = {"status": "passed_with_skips" if passed and skipped else "passed" if passed else "failed",
                  "tests_run": total, "skipped": skipped,
                  "executed_without_skip": total-skipped,
                  "exit_code": p.returncode, "command": command,
                  "log_sha256": sha256(log.encode()).hexdigest(), "log": log}
    except subprocess.TimeoutExpired as exc:
        result = {"status": "unknown_timeout", "command": command,
                  "reason": str(exc)}
    output = result.get('log', '')
    required = {
        'host_llvm_differential': 'test_host_llvm_abi_matches_independent_c_for_defined_inputs',
        'phi_gcc_differential': 'test_phi_executes_identically_to_independent_c_on_defined_inputs',
        'three_target_objects': 'test_three_target_objects_compile_with_real_llvm',
    }
    checks = {key: bool(re.search(r'(?m)^' + re.escape(name) + r' \(.*\) \.\.\. ok$', output))
              for key, name in required.items()}
    ran = result.get('status', '').startswith('passed')
    evidence = {
        "schema": "hepta.llvm-subset-host-validation.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "qualification_scope": "partial_checkout_host_llvm_object_and_executable_only",
        "source_sha256": {relative: _sha(ROOT/relative) for relative in SOURCES},
        "toolchains": {name: _tool(name) for name in ('clang', 'gcc')},
        "test_result": result,
        "explicit_test_observations": checks,
        "whole_project_blockers_closed": False,
        "claims": {"host_llvm_differential_tested": ran and checks['host_llvm_differential'] and checks['phi_gcc_differential'],
                   "x86_aarch64_windows_target_objects_tested": ran and checks['three_target_objects'],
                   "rust_reference_revalidated_current_head": False,
                   "hepta_frontend_integration_fully_qualified": False,
                   "cross_target_execution_verified": False,
                   "backend_semantics_proved": False,
                   "whole_p6_gate_closed": False},
    }
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    opts = parser.parse_args(argv)
    report = qualify()
    target = Path(opts.output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    # The output is a receipt, not a code artifact; atomic output avoids
    # misleading half-written JSON under an interrupted validation.
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile('w', dir=target.parent, delete=False,
                            prefix='.hepta-llvm-receipt-', encoding='utf-8') as fd:
        tmp = Path(fd.name)
        json.dump(report, fd, indent=2, sort_keys=True, ensure_ascii=False)
        fd.write('\n')
        fd.flush()
    tmp.replace(target)
    print(json.dumps({"status": report['test_result']['status'],
                      "tests_run": report['test_result'].get('tests_run'),
                      "skipped": report['test_result'].get('skipped'),
                      "output": str(target)}))
    return 0 if report['test_result']['status'].startswith('passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
