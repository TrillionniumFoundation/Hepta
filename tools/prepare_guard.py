"""Materialize and observe one narrow guard successor; no Native qualification."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import traceback
from diagnose_source_scan import identity, snapshot, write_json


def run(command, cwd, output, name, seconds=1800):
    started = time.monotonic_ns()
    record = {'argv': command, 'cwd': str(cwd), 'limit_seconds': seconds, 'timed_out': False}
    with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL, start_new_session=True,
                                   env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            record['returncode'] = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            os.killpg(process.pid, signal.SIGKILL)
            record['returncode'] = process.wait(timeout=3)
    record['elapsed_ns'] = time.monotonic_ns() - started
    write_json(output / (name + '.json'), record)
    if record['returncode'] != 0 or record['timed_out']:
        raise RuntimeError('diagnostic stage failed: ' + name)


def source_map(source):
    return {path.relative_to(source).as_posix(): {
        'mode': oct(path.stat().st_mode & 0o777), **identity(path.read_bytes())}
        for path in sorted(source.rglob('*')) if path.is_file()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--harness', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    source, harness, evidence = args.source.resolve(), args.harness.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    work = source.parent / 'guard-candidate'
    candidate = work / 'source'
    expected = json.loads((harness / 'inputs/INPUTS.json').read_text())
    patch = json.loads((harness / 'inputs/GUARD-PATCH.json').read_text())
    result = {'schema': 'hepta.source-guard-actual-runtime-controls.v1', 'status': 'INCOMPLETE',
              'python': sys.version, 'qualification': False, 'whole_native': False,
              'original_business_tests_run': 0, 'native_compilations': 0,
              'scope': '91 guard cases, 2 foreign type-key cases, original 9 source freshness methods, warm fixed-CPU scan comparison'}
    original = prepared = None
    try:
        assert tuple(sys.version_info[:3]) == tuple(expected['python_version'])
        original = snapshot(source, expected)
        write_json(evidence / 'ORIGINAL-SOURCE-BEFORE.json', original)
        work.mkdir()
        shutil.copytree(source, candidate, copy_function=os.link, symlinks=True,
                        ignore=shutil.ignore_patterns('.git', '__pycache__'))
        before = (candidate / patch['path']).read_bytes()
        assert identity(before) == patch['before']
        after = patch['after_text'].encode()
        assert identity(after) == patch['after']
        old_ast, new_ast = ast.parse(before), ast.parse(after)
        changed = []
        for old, new in zip(old_ast.body, new_ast.body, strict=True):
            if ast.dump(old) != ast.dump(new):
                changed.append(old.name)
        assert changed == patch['expected_changed_definitions']
        selected = candidate / patch['path']
        selected.unlink()
        selected.write_bytes(after)
        contract = candidate / 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
        raw = contract.read_bytes()
        contract.unlink()
        contract.write_bytes(raw)
        for name in ('run_guard_controls.py', 'test_type_dictionary_keys.py', 'compare_abba.py'):
            shutil.copyfile(harness / 'tools' / name, work / name)
        run([sys.executable, '-B', 'tools/generate_hia_selfhost_contract.py'], candidate, evidence, 'prepare-support')
        prepared = source_map(candidate)
        expected_paths = set(original['files'])
        assert set(prepared) == expected_paths
        differences = [name for name in sorted(prepared)
                       if prepared[name]['git_blob'] != original['files'][name]['git_blob']]
        assert differences == ['docs/HIA_SELFHOST_CORE_SUPPORT.json', 'tools/hia_selfhost_contract.py']
        write_json(evidence / 'CANDIDATE-PREPARED.json', prepared)
        result['changed_paths'] = differences
        result['changed_definitions'] = changed
        run([sys.executable, '-B', str(work / 'run_guard_controls.py')], candidate, evidence, 'guard-and-original-nine')
        run([sys.executable, '-B', str(work / 'test_type_dictionary_keys.py')], candidate, evidence, 'foreign-type-keys')
        run([sys.executable, '-B', str(work / 'compare_abba.py')], candidate, evidence, 'warm-abba')
        controls = json.loads((work / 'controls-r3/REPORT.json').read_text())
        foreign = json.loads((work / 'TYPE-KEY-CONTROLS.json').read_text())
        comparison = json.loads((work / 'comparison-r1/REPORT.json').read_text())
        assert controls['status'] == 'PASS' and controls['mechanism_count'] == 91 and controls['original_source_tests_run'] == 9
        assert foreign['status'] == 'PASS' and len(foreign['cases']) == 2
        assert comparison['status'] == 'OBSERVATIONS_COMPLETE' and comparison['maps_equal'] is True
        result.update(status='OBSERVATIONS_COMPLETE', guard_controls=controls, foreign_keys=foreign,
                      comparison=comparison)
    except BaseException:
        result['status'] = 'DIAGNOSTIC_FAILURE'
        result['error'] = traceback.format_exc()
    finally:
        try:
            final_original = snapshot(source, expected)
            write_json(evidence / 'ORIGINAL-SOURCE-AFTER.json', final_original)
            result['original_source_unchanged'] = original == final_original
            final_candidate = source_map(candidate) if candidate.exists() else None
            write_json(evidence / 'CANDIDATE-AFTER.json', final_candidate)
            result['candidate_source_unchanged_after_preparation'] = prepared is not None and final_candidate == prepared
            if not result['original_source_unchanged'] or not result['candidate_source_unchanged_after_preparation']:
                result['status'] = 'DIAGNOSTIC_FAILURE'
        except BaseException:
            result['final_check_error'] = traceback.format_exc()
            result['status'] = 'DIAGNOSTIC_FAILURE'
        if work.exists():
            for child in work.iterdir():
                if child.name != 'source':
                    destination = evidence / 'raw' / child.name
                    destination.parent.mkdir(exist_ok=True)
                    if child.is_dir(): shutil.copytree(child, destination)
                    else: shutil.copyfile(child, destination)
        if candidate.exists():
            for name in ('tools/hia_selfhost_contract.py', 'docs/HIA_SELFHOST_CORE_SUPPORT.json'):
                path = candidate / name
                if path.is_file():
                    destination = evidence / 'candidate' / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
        write_json(evidence / 'REPORT.json', result)
        print(json.dumps({k: v for k, v in result.items() if k not in ('guard_controls', 'foreign_keys', 'comparison')}, sort_keys=True))
    return 0 if result['status'] == 'OBSERVATIONS_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
