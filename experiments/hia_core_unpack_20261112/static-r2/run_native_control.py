"""Frozen independent development compile + six finite UNPACK controls.

No seed generation, cold replay, ordinary selector, installed claim, or 116
caller substitution. A read-only historical compiler is explicitly pinned.
The original compile_stage retains 20 wall seconds, 10 CPU seconds and 1 MiB.
The caller must wrap this whole worker with the original 180+3 process owner.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

COMPILER_SHA256 = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
SOURCE_SHA256 = 'f16b072ba6a3daa7dd162b8653eef7abb47d5da770197c2ebdc717bd2eaf81b0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'compiler', 'source', 'bridge', 'shim-source', 'tests', 'evidence-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    paths = [Path(__file__).resolve(), args.compiler, args.source, args.bridge,
             args.shim_source, args.tests, root / 'tools/qualify_hia_selfhost.py',
             root / 'tools/hia_selfhost_child.py', root / 'tools/hia_selfhost_process_owner.py',
             root / 'hepta/hia_json_preflight_native.py']
    before = {str(path.resolve()): sha256(path.read_bytes()).hexdigest() for path in paths}
    if before[str(args.compiler.resolve())] != COMPILER_SHA256 or before[str(args.source.resolve())] != SOURCE_SHA256:
        raise ValueError('frozen compiler/source identity differs')
    args.evidence_dir.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.core-unpack-finite-native.v1', 'status': 'HOLD',
              'source_before': before, 'python': sys.version, 'compiler_sha256': COMPILER_SHA256,
              'cold_qualified': False, 'ordinary_116_executed': False,
              'whole_python_object_runtime_in_hia': False}
    started = time.monotonic()
    try:
        sys.path.insert(0, str(root))
        from tools.qualify_hia_selfhost import compile_stage
        build = args.evidence_dir / 'build'
        build.mkdir(mode=0o700)
        image, receipt = compile_stage(build, 'core-unpack', args.compiler, args.source.read_bytes())
        report['compile'] = receipt
        command = [sys.executable, '-B', str(args.tests), '--phase', 'native',
                   '--bridge', str(args.bridge), '--shim-source', str(args.shim_source),
                   '--image', str(image), '--evidence-dir', str(args.evidence_dir / 'controls')]
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0', 'PYTHONPATH': str(root)}
        report['command'] = command
        with (args.evidence_dir / 'controls.stdout.log').open('xb') as stdout, (args.evidence_dir / 'controls.stderr.log').open('xb') as stderr:
            result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=180)
        report['control_returncode'] = result.returncode
        control = json.loads((args.evidence_dir / 'controls/report.json').read_bytes())
        report['controls'] = control
        expected = [
            '__main__.NativeControls.test_bad_ack_closes_and_hia_releases',
            '__main__.NativeControls.test_builtin_cardinality_and_version_messages',
            '__main__.NativeControls.test_duplicate_observe_and_terminal_result',
            '__main__.NativeControls.test_foreign_failure_cleanup_and_ambient_context',
            '__main__.NativeControls.test_generic_next_count_and_release_order',
            '__main__.NativeControls.test_noniterable_and_iter_errors']
        if (result.returncode != 0 or control['status'] != 'EXPERIMENTAL_CONTROL_PASS'
                or control['loaded_test_ids'] != expected or control['executed_test_ids'] != expected
                or control['tests_run'] != 6 or any(control[key] != 0 for key in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))):
            raise ValueError('the complete six finite native controls did not pass')
        if sha256(image.read_bytes()).hexdigest() != receipt['produced_sha256']:
            raise ValueError('compiled image changed during controls')
        report['status'] = 'FINITE_NATIVE_DEVELOPMENT_PASS'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        (args.evidence_dir / 'traceback.txt').write_text(traceback.format_exc())
    finally:
        try:
            after = {str(path.resolve()): sha256(path.read_bytes()).hexdigest() for path in paths}
            report['source_after'], report['source_stable'] = after, before == after
            if before != after:
                report['status'] = 'HOLD'
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = repr(error)
        report['seconds'] = time.monotonic() - started
        (args.evidence_dir / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'seconds': report['seconds'], 'report': str(args.evidence_dir / 'report.json')}))
    return 0 if report['status'] == 'FINITE_NATIVE_DEVELOPMENT_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
