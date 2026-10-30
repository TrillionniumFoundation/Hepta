"""Correct only the root auditor's relative-path invocation; preserve first failure."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / 'hepta-integration'
PACKAGE = REPO / 'evidence/hia_next_ci_20261030'
OUT = HERE / 'root-readback'


def main():
    target = OUT / 'ci-followup-verification.json'
    if target.exists():
        raise ValueError('refuse to overwrite followup')
    verifier = PACKAGE / 'verify_ci.py'
    argv = [sys.executable, '-B', str(verifier), '--root', str(PACKAGE),
        '--pins', str(PACKAGE / 'CI_PINS.json'),
        '--pins-sha256', '1095dc2596424c76bab4fc99cda4bcee50c70f0c415a7e54bf23327cf28b1a5e',
        '--manifest', str(PACKAGE / 'MANIFEST.json'),
        '--manifest-sha256', '1ee9fea8cffc424cfcd3e12a3a4416682ddbfb5ad1d6ac246eb007113dfe3069',
        '--output', str(target)]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start = time.monotonic_ns()
    proc = subprocess.run(argv, cwd=REPO, capture_output=True, timeout=60)
    elapsed = time.monotonic_ns() - start
    for name, data in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
        with (OUT / ('ci-followup.' + name)).open('xb') as output:
            output.write(data)
    receipt = {'schema': 'hepta.next.root-ci-followup.v1', 'argv': argv, 'cwd': str(REPO),
        'started_utc': started, 'returncode': proc.returncode, 'wall_ns': elapsed,
        'verifier_sha256': hashlib.sha256(verifier.read_bytes()).hexdigest(),
        'stdout_bytes': len(proc.stdout), 'stdout_sha256': hashlib.sha256(proc.stdout).hexdigest(),
        'stderr_bytes': len(proc.stderr), 'stderr_sha256': hashlib.sha256(proc.stderr).hexdigest(),
        'initial_failure_reason': 'Relative CI_PINS.json was resolved against repository root, not package directory.',
        'only_invocation_paths_corrected': True, 'verifier_or_evidence_modified': False,
        'archive_payload_executed': False, 'new_native_or_model_execution': False}
    with (OUT / 'ci-followup-execution.json').open('x') as output:
        json.dump(receipt, output, indent=2, sort_keys=True); output.write('\n')
    first = json.loads((OUT / 'RESULT.json').read_text())
    verify = json.loads(target.read_text()) if target.exists() else {}
    passed = (proc.returncode == 0 and not proc.stderr and verify.get('passed') is True
        and verify.get('latest_required_source_verified') is True
        and all(row['returncode'] == 0 and row['stderr_bytes'] == 0 for row in first['executions'] if row['package'] != 'ci'))
    final = {'schema': 'hepta.next.root-readback-final.v1', 'passed': passed,
        'source_commit': first['source_commit'], 'packages_passed': 5 if passed else None,
        'initial_result': 'RESULT.json', 'initial_result_preserved': True,
        'ci_followup': 'ci-followup-execution.json', 'ci_latest_source_verified': verify.get('latest_required_source_verified'),
        'wall_ns_total_all_six_readbacks': first['wall_ns_total_sequential_children'] + elapsed,
        'actual_new_model_generations': 0, 'actual_new_native_test_cases': 0,
        'cost_scope': 'pure offline subprocess readbacks; includes initial path error, excludes unmeasured development/review'}
    with (OUT / 'FINAL_RESULT.json').open('x') as output:
        json.dump(final, output, indent=2, sort_keys=True); output.write('\n')
    print(json.dumps(final, sort_keys=True))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
