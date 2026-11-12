"""Static and byte-bound harness checks; no product or native test execution."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import sys
import yaml

KIT = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT / 'inputs'))
import run_development as driver

checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


def main():
    for path in sorted((KIT / 'inputs').glob('*.py')):
        ast.parse(path.read_bytes(), filename=str(path))
        check('syntax:' + path.name, True)
    check('exact retained harness and all input hashes', bool(driver.check_frozen_inputs()))
    base = driver.decode_packet('baseline-joint-r2.json', driver.BASELINE_WRAPPER_SHA, 1122923)
    final = driver.decode_packet('final-r4.json', driver.FINAL_WRAPPER_SHA, 750700)
    check('authentic published base pinned', base['base_commit'] == driver.HEAD and base['base_tree'] == driver.TREE)
    check('baseline exact 51 paths and 3181 final files', len(base['files']) == 51 and len(base['final_files']) == 3181)
    check('finite R4 13 paths and 3184 final files', len(final['files']) == 13 and len(final['final_files']) == 3184)
    state = dict(base['final_files'])
    for row in final['files']:
        check('exact before:' + row['path'], row['before'] == state.get(row['path']))
        check('exact content:' + row['path'], driver.validate_record(row['content'].encode('utf-8'), row))
        state[row['path']] = {key: row[key] for key in ('bytes', 'sha256', 'blob', 'mode')}
    check('finite metadata overlay matches complete final map', state == final['final_files'])
    def as_original(records):
        return {name: {'git_mode': row['mode'], 'git_blob_sha1': row['blob']} for name, row in records.items()}
    check('independent baseline Git tree encoding', driver.original.tree_id(as_original(base['final_files'])) == driver.BASELINE_TREE)
    check('independent final Git tree encoding', driver.original.tree_id(as_original(final['final_files'])) == driver.FINAL_TREE)
    sample = final['files'][0]
    data = sample['content'].encode('utf-8')
    altered = copy.deepcopy(sample)
    altered['bytes'] = True
    check('bool cannot stand for byte count', not driver.validate_record(data, altered))
    altered = copy.deepcopy(sample)
    altered['sha256'] = '0' * 64
    check('changed hash rejected', not driver.validate_record(data, altered))
    altered = copy.deepcopy(sample)
    altered['mode'] = '120000'
    check('symbolic or unreviewed Git mode rejected', not driver.validate_record(data, altered))
    check('modified bytes rejected', not driver.validate_record(data + b'x', sample))
    raw = (KIT / 'inputs/run_development.py').read_bytes()
    tree = ast.parse(raw)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == 'run_workflow_step']
    check('all process supervisors retain 1800', len(calls) == 2 and all(
        any(k.arg == 'seconds' and isinstance(k.value, ast.Constant) and k.value.value == 1800
            for k in n.keywords) for n in calls))
    workflow = yaml.safe_load((KIT / '.github/workflows/hia-core-plan-r4-development.yml').read_text())
    job = workflow['jobs']['original-gates']
    steps = job['steps']
    check('same independent workflow outer limit', job['timeout-minutes'] == 100)
    check('actual CPython 3.14.4 setup', any(s.get('uses') == 'actions/setup-python@v5'
          and s['with']['python-version'] == '3.14.4' for s in steps))
    check('separate authentic product checkout', any(s.get('uses') == 'actions/checkout@v4'
          and s['with'].get('ref') == driver.HEAD and s['with'].get('path') == 'source'
          and s['with'].get('persist-credentials') is False for s in steps))
    by_id = {s['id']: s for s in steps if 'id' in s}
    check('baseline and fixed gates all declared', set(by_id) == {'baseline', 'observe_baseline', 'prepare', 'panel60', 'complete124', 'plan44'})
    for name in ('panel60', 'complete124', 'plan44'):
        check('independent gate condition:' + name,
              by_id[name]['if'] == "${{ !cancelled() && steps.prepare.outcome == 'success' }}"
              and '--stage ' + name in by_id[name]['run'])
    check('fixed gates not cancelled by a baseline mismatch', by_id['prepare']['if'] == "${{ !cancelled() && steps.baseline.outcome == 'success' }}")
    check('all raw evidence uploaded on failure', steps[-1]['if'] == 'always()'
          and steps[-1]['uses'] == 'actions/upload-artifact@v4'
          and steps[-1]['with']['retention-days'] == 90
          and steps[-1]['with']['include-hidden-files'] is True)
    collection = json.loads((KIT.parent / 'local-panel60-r4-r1/COLLECTION.json').read_bytes())
    check('actual local loader 60 IDs including inheritance', collection['count'] == collection['unique'] == 60
          and len(collection['ids']) == 60 and not collection['errors'])
    report = {'schema': 'hia.shared-r4-independent-ci-static-review.v1', 'status': 'PASS',
              'scope': 'STATIC_AND_INPUT_IDENTITY_ONLY', 'python': sys.version,
              'checks': checks, 'count': len(checks), 'native_tests_executed': 0,
              'current_cold': False, 'actual_314_executed': False,
              'baseline_tree': driver.BASELINE_TREE, 'final_tree': driver.FINAL_TREE,
              'actual_local_loader_file_sha256': hashlib.sha256((KIT.parent / 'local-panel60-r4-r1/COLLECTION.json').read_bytes()).hexdigest()}
    path = KIT / 'STATIC-REVIEW.json'
    if path.exists():
        raise AssertionError('do not overwrite the original review')
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'checks': len(checks), 'native_tests_executed': 0}))


if __name__ == '__main__':
    main()
