"""Fixed-input local diagnostic; does not confer original-runtime qualification."""
import hashlib
import importlib.util
import json
import pathlib
import shutil
import stat
import subprocess
import sys
import traceback
import zipfile

BASE = pathlib.Path('/workspace/scratch/dda74a4fae35/recovered-v85')
RUN = BASE.parent / 'v93-union-r11'
DRIVER = RUN / 'harness/tools/materialize_candidate_r14.py'
DRIVER_BLOB = 'cfe319279641b124bcd724437857686f36d1aa07'
PLAN_BLOB = 'c19cd878115b1e9d3d4b81024838b36575a6bf30'
BASELINE = '4d3cdbfd6aa2bdb76cdb1eab097bed9a5af1fc2d'
BASE_TREE = 'f5610f07a4a43bfc83aaffaedec2c0c89933126a'

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

driver_raw = DRIVER.read_bytes()
assert blob(driver_raw) == DRIVER_BLOB
plan_raw = (RUN / 'harness/inputs/MATERIALIZATION-R11.json').read_bytes()
assert blob(plan_raw) == PLAN_BLOB
spec = importlib.util.spec_from_file_location('fixed_r11_materializer', DRIVER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
plan = module.strict_json(plan_raw)
capture = module.Capture(RUN / 'local-generation-r1', '')
capture.basic = ''
capture.repo = RUN / 'local-source-r1'
capture.put('harness/DRIVER.py', driver_raw)
capture.put('harness/LOCAL-DIAGNOSTIC-DRIVER.py', pathlib.Path(__file__).read_bytes())
capture.put('harness/INPUTS.json', plan_raw)
archive = zipfile.ZipFile(BASE / 'first-build.zip')
original = module.strict_json(archive.read('raw/terminal-worktree/INDEX.json'))
materialized = module.strict_json(archive.read('raw/sources/FIXED-TREE-BLOB-MATERIALIZATION.json'))
capture.original_oids = {row['oid'] for row in materialized['after']}
capture.original_path_sets = {'recovered-original-failure': {row['path'] for row in original['files']}}
result = {'schema': 'hepta.local-development-generation.v1',
          'scope': 'PYTHON312_LOCAL_DEBUG_NOT_ORIGINAL_RUNTIME_QUALIFICATION',
          'python': sys.version, 'started_at': module.now(), 'status': 'RUNNING',
          'product_tests_executed': 0, 'native_qualification': False,
          'whole_native': False, 'product_refs_changed': False,
          'local_baseline_commit': BASELINE, 'original_failure_source_tree': BASE_TREE,
          'driver_blob': DRIVER_BLOB, 'plan_blob': PLAN_BLOB, 'full_frozen_merge_recovery_reapplied': True,
          'all_64_source_packets_checked': True, 'r4_test_qualification_inherited': False, 'failures': []}
try:
    expected = {row['path']: row for row in original['files']}
    source = BASE / 'failed-r1-source'
    actual_paths = {path.relative_to(source).as_posix() for path in source.rglob('*')
                    if path.is_file() or path.is_symlink()}
    assert actual_paths == set(expected), 'recovery file set differs'
    for name, row in expected.items():
        path = source / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == row['mode'], name
        raw = path.read_bytes()
        assert len(raw) == row['bytes'] and blob(raw) == row['blob'], name
        assert hashlib.sha256(raw).hexdigest() == row['sha256'], name
    shutil.copytree(source, capture.repo)
    shutil.copytree(BASE / 'candidate-r3/.git', capture.repo / '.git')
    head, _ = capture.git(['rev-parse', 'HEAD', 'HEAD^{tree}'], label='local-original-baseline', auth=False)
    assert head.decode().splitlines() == [BASELINE, BASE_TREE]
    capture.git(['read-tree', BASELINE], label='restore-original-baseline-index', auth=False)
    module.assert_current_tree(capture, BASE_TREE, 'local-fixed-original-recovery')
    cache = {}
    for pin in plan['packets']:
        name = pin['blob']
        path = RUN / 'input-blobs' / (name + '.blob')
        if not path.is_file():
            path = BASE / 'r4-input-blobs' / (name + '.blob')
        if not path.is_file():
            path = BASE / 'source-r2-artifact/raw/input-blobs' / (name + '.blob')
        raw = path.read_bytes()
        assert len(raw) == pin['bytes'] and blob(raw) == name, name
        cache[name] = raw
        capture.put('input-blobs/' + name + '.blob', raw)
    authored, origins = module.compose(capture, plan, cache)
    independently_composed = module.strict_json((RUN / 'harness/inputs/AUTHORING-R11.json').read_bytes())
    assert len(independently_composed) == len(authored) == 448
    assert {r['path'] for r in independently_composed} == set(authored)
    for row in independently_composed:
        assert authored[row['path']] == row['text'].encode('utf-8')
        assert blob(authored[row['path']]) == row['sha']
        assert origins[row['path']]['mode'] == row['mode']
    pins = {r['blob'] for r in plan['exact_retained'] + plan['regeneration_seeds']}
    pins.update(r['sha'] for r in plan['asset_references'])
    for name in sorted(pins):
        raw, check = None, subprocess.run(['git', '--no-lazy-fetch', 'cat-file', 'blob', name],
            cwd=capture.repo, env=capture.env, capture_output=True, timeout=30)
        if check.returncode == 0:
            raw = check.stdout
        else:
            raw = archive.read('raw/input-blobs/' + name + '.blob')
        assert blob(raw) == name
        cache[name] = raw
        capture.put('input-blobs/' + name + '.blob', raw)
    conflicts = module.strict_json(archive.read('raw/composition/ACTUAL-CONFLICTS.json'))
    result['composition'] = module.apply_sources(capture, plan, cache, authored, origins, {}, conflicts)
    result['syntax'] = module.syntax_all(capture)
    result['generation'] = module.regenerate(capture, plan)
    module.assert_current_tree(capture, result['generation']['tree'], 'local-after-all-generation')
    result['status'] = 'LOCAL_GENERATION_PASS'
except BaseException as error:
    result['status'] = 'FAIL'
    result['failures'].append({'type': type(error).__name__, 'error': str(error),
                               'traceback': traceback.format_exc()})
finally:
    try:
        result['terminal_source_snapshot'] = module.snapshot_failure_or_terminal_sources(capture)
    except BaseException as error:
        result['failures'].append({'stage': 'terminal_snapshot', 'type': type(error).__name__,
            'error': str(error), 'traceback': traceback.format_exc()})
        result['status'] = 'FAIL'
    result['finished_at'] = module.now()
    capture.json('LOCAL-RESULT.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
raise SystemExit(0 if result['status'] == 'LOCAL_GENERATION_PASS' else 1)
