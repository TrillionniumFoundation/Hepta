"""One new original R3 observation; preserve the earlier argv failure.

This driver changes only the caller's argument form. It imports the exact old
driver and supervisor from their separate authentic Git checkout. The original
120-case probe, policy, source overlays, compiler and deadlines are unchanged.
An observed original mismatch is recorded as a mismatch, never qualification.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import sys
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    original_root = args.original.resolve()
    inputs = original_root / 'inputs'
    sys.path.insert(0, str(inputs))
    spec = importlib.util.spec_from_file_location('frozen_r4_driver', inputs / 'run_development.py')
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    source, out = args.source.resolve(), args.out.resolve()
    result = {'schema': 'hia.shared-r3-baseline120-supplement.v1',
              'scope': 'ONE_NEW_ACTUAL_CPYTHON3144_ORIGINAL_OBSERVATION',
              'original_failed_run': 43244880819, 'original_argv_error_preserved': True,
              'original_R4_60_124_44_not_repeated': True,
              'current_cold': False, 'whole_native': False, 'status': 'HOLD'}
    try:
        if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 4)
                or sys.platform != 'linux' or platform.machine() != 'x86_64'):
            raise AssertionError('actual CPython 3.14.4 Linux x86-64 required')
        if (old.original.git(original_root, 'rev-parse', 'HEAD').decode().strip()
                != '0cade56c88497b1baa90f541c16c1ce3ff6c85cd'
                or old.original.git(original_root, 'rev-parse', 'HEAD^{tree}').decode().strip()
                != 'f783162fd223450cbd4a5676bdf95e3249dc974d'
                or old.original.git(original_root, 'status', '--porcelain=v1', '--untracked-files=all')):
            raise AssertionError('original independent harness checkout differs')
        if json.loads((out / 'BASELINE-PREPARE.json').read_bytes())['status'] != 'BASELINE_READY_NOT_QUALIFICATION':
            raise AssertionError('original baseline preparation incomplete')
        before = json.loads((out / 'BASELINE-SOURCE.json').read_bytes())
        if len(before) != 3181 or old.original.tree_id(before) != old.BASELINE_TREE:
            raise AssertionError('original 3181-file baseline identity differs')
        if not old.original.source_matches(source, before):
            raise AssertionError('original source changed before observation')
        harness_before = old.check_frozen_inputs()
        tools_before = old.original.tool_inputs()
        compiler = out / 'retained-development-compiler.bin'
        compiler_before = old.describe(compiler)
        if compiler_before['sha256'] != old.COMPILER_SHA:
            raise AssertionError('original development compiler differs')
        own_before = old.describe(Path(__file__))
        output = out / 'baseline120-positionals-r2'
        env, removed = old.original.clean_environment()
        # The unchanged original probe declares three positional arguments.
        command = [sys.executable, '-B', str(inputs / 'probe_shared_mechanism.py'),
                   str(source), str(compiler), str(output)]
        old.write(out / 'SUPPLEMENT-INTENT.json', {'command': command, 'seconds': 1800,
                  'removed_environment': removed, 'source_count': len(before),
                  'original_probe': old.describe(inputs / 'probe_shared_mechanism.py'),
                  'original_policy': old.describe(inputs / 'mechanism_policy.py')})
        process = old.run_workflow_step(command, cwd=source, env=env,
                    stdout_path=out / 'supplement.stdout.log', stderr_path=out / 'supplement.stderr.log',
                    receipt_path=out / 'SUPPLEMENT-PROCESS.json', seconds=1800)
        path = output / 'REPORT.json'
        actual = json.loads(path.read_bytes()) if path.exists() else {}
        after = old.original.snapshot(source, before)
        old.write(out / 'SUPPLEMENT-SOURCE-AFTER.json', after)
        checks = {
            'process_completed': process['status'] == 'WORKFLOW_STEP_COMPLETED'
                and process['returncode'] == 0 and process['timed_out'] is False,
            'all_original_cases_executed': type(actual.get('total')) is int and actual['total'] == 120,
            'actual_native_entries': type(actual.get('entries')) is int and actual['entries'] > 0,
            'original_outcome_retained': actual.get('status') in ('PASS', 'ORIGINAL_EQUIVALENCE_FAIL'),
            'probe_inputs_unchanged': actual.get('inputs_unchanged') is True,
            'all_3181_source_records_unchanged': before == after,
            'harness_unchanged': old.check_frozen_inputs() == harness_before,
            'tools_unchanged': old.original.tool_inputs() == tools_before,
            'compiler_unchanged': old.describe(compiler) == compiler_before,
            'new_driver_unchanged': old.describe(Path(__file__)) == own_before,
        }
        result.update(python=sys.version, actual_report=old.describe(path) if path.exists() else None,
                      original_status=actual.get('status'), original_matched=actual.get('matched'),
                      original_count=actual.get('total'), actual_native_entries=actual.get('entries'),
                      process=process, checks=checks, baseline_content_tree=old.BASELINE_TREE)
        if not all(value is True for value in checks.values()):
            raise AssertionError('one new original observation did not complete faithfully')
        result['status'] = 'ORIGINAL_OBSERVATION_COMPLETE_NOT_EQUIVALENCE_QUALIFICATION'
    except BaseException:
        result['exception'] = traceback.format_exc()
    finally:
        old.write(out / 'SUPPLEMENT-RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'ORIGINAL_OBSERVATION_COMPLETE_NOT_EQUIVALENCE_QUALIFICATION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
