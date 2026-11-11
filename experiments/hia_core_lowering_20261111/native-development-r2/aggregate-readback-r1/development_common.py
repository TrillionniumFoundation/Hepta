"""Exact source, ABI, and observation checks for isolated Core development.

This controller never qualifies a source-bound cold build. The process owner,
compile limits, original tests, and ordinary caller budgets are unchanged.
"""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import subprocess

BASE_HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
BASE_TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
ROOT_TREE = '25f984b7dc88eb55fb34e1fb1561bcf5d0529304'
CANDIDATE = '9b350732ce1dac60ec5689838ab80b853d700751'
CANDIDATE_TREE = '7191e2e9926d0c1f653e775e891c35d48efeb46f'
LEAVES = 3984
COMPILER = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PYTHON = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
OWNER = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
PREPARE_ROOT = Path('/home/qian-qi/he26corelowering-native-r1')
BASE_SOURCE = Path('/home/qian-qi/he26v67r2/s')
OBJECT_SOURCE = Path('/home/qian-qi/he26instructions-native-prepare-r1/source')
AUTHOR_ROOT = Path('/home/qian-qi/he26corelowering-authoring-r3')
ROOTS = {
    'prepare': PREPARE_ROOT,
    'component': Path('/home/qian-qi/he26corelowering-component-r1'),
    'original-machine': Path('/home/qian-qi/he26corelowering-machine-callers-r1'),
    'original-core': Path('/home/qian-qi/he26corelowering-core-callers-r1'),
}

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(raw):
    return sha256(raw).hexdigest()

def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def save(root, name, value):
    path = root / name
    path.write_bytes(wire(value))
    return binding(path)

def relative(value):
    require(type(value) is str and value and '\0' not in value, 'invalid relative path')
    path = Path(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == value,
            'noncanonical relative path')
    return path

def private_bytes(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'nonregular private input: ' + str(path))
    raw = path.read_bytes()
    return raw, stat.S_IMODE(info.st_mode)

def binding(path):
    path = Path(path)
    raw, mode = private_bytes(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'git_blob': blob(raw), 'posix_mode': mode}

def verify_binding(row):
    require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'git_blob', 'posix_mode'},
            'incomplete frozen file binding')
    actual = binding(Path(row['path']))
    require(actual == row, 'frozen file changed: ' + row['path'])
    return Path(row['path']).read_bytes()

def verify_source(raw, row):
    require(len(raw) == row['bytes'] and digest(raw) == row['sha256']
            and blob(raw) == row['git_blob'], 'source bytes differ: ' + row['path'])

def git(path, arguments):
    environment = dict(os.environ)
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    return subprocess.check_output(['git', '--no-replace-objects', *arguments],
                                   cwd=path, env=environment)

def metadata(path, index_tree):
    git(path, ['diff', '--cached', '--quiet', index_tree, '--'])
    index = git(path, ['ls-files', '--stage', '-z'])
    return {'head': git(path, ['rev-parse', 'HEAD']).decode().strip(),
            'head_tree': git(path, ['rev-parse', 'HEAD^{tree}']).decode().strip(),
            'index_tree': index_tree, 'index_sha256': digest(index),
            'tracked_status': git(path, ['status', '--porcelain', '--untracked-files=no']).decode(),
            'owner_sha256': digest((path / 'tools/hia_selfhost_process_owner.py').read_bytes())}

def snapshot(path, expected_count):
    rows = []
    for entry in git(path, ['ls-files', '--stage', '-z']).split(b'\0'):
        if not entry:
            continue
        header, encoded = entry.split(b'\t', 1)
        mode, expected, stage = header.decode().split()
        name = encoded.decode('utf-8')
        target = path / relative(name)
        raw, actual_mode = private_bytes(target)
        require(stage == '0' and mode in {'100644', '100755'}, 'invalid index stage or mode')
        require(bool(actual_mode & 0o111) == (mode == '100755'), 'source execute mode differs: ' + name)
        require(blob(raw) == expected, 'source bytes differ from actual index: ' + name)
        rows.append({'path': name, 'mode': mode, 'bytes': len(raw), 'git_blob': expected,
                     'sha256': digest(raw), 'posix_mode': actual_mode})
    require(len(rows) == expected_count and len({r['path'] for r in rows}) == expected_count,
            'complete source population differs')
    return rows

def candidate_snapshot(path):
    meta = metadata(path, CANDIDATE_TREE)
    require(meta['head'] == BASE_HEAD and meta['head_tree'] == BASE_TREE
            and meta['owner_sha256'] == OWNER, 'actual checkout provenance differs')
    return {'canonical_commit': CANDIDATE, 'canonical_tree': CANDIDATE_TREE,
            'actual_git': meta, 'leaves': snapshot(path, LEAVES),
            'actual_HEAD_is_candidate': False}

def natural_owner(life):
    cleanup = life.get('cleanup', {})
    return bool(life.get('exit_observed_before_deadline') is True
        and life.get('timed_out') is False and not life.get('interrupted_signals')
        and not life.get('event_overflow') and not life.get('owner_error')
        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True and not cleanup.get('deadline_exceeded')
        and not cleanup.get('errors') and not cleanup.get('remaining_direct_children')
        and not any(e.get('kind') == 'owned_child_sigkill' for e in life.get('events', [])))

def inspect_bundle(manifest, source, compiler_sha=COMPILER):
    manifest = Path(manifest)
    bundle_raw, _ = private_bytes(manifest)
    bundle = json.loads(bundle_raw)
    abi_raw = (source / 'hepta/hia_core_lowering_abi.json').read_bytes()
    abi = json.loads(abi_raw)
    names = ['core_lowering_pool', *abi['units']]
    require(len(names) == 32 and len(set(names)) == 32, 'complete 32 units required')
    require(set(bundle) == {'schema', 'abi_sha256', 'compiler_sha256', 'unit_manifests'}
            and bundle['schema'] == 'hepta.hia.core-lowering-native.v1'
            and bundle['abi_sha256'] == digest(abi_raw)
            and bundle['compiler_sha256'] == compiler_sha
            and bundle['unit_manifests'] == {n: n + '/manifest.json' for n in names},
            'complete bundle binding differs')
    files, images, sources, unit_files = [binding(manifest)], [], {}, {}
    for name in names:
        unit_path = manifest.parent / name / 'manifest.json'
        raw, _ = private_bytes(unit_path)
        unit = json.loads(raw)
        require(set(unit) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                and unit['schema'] == 'hepta.hia.core-lowering-unit-native.v1'
                and unit['compiler_sha256'] == compiler_sha,
                'unit schema or compiler differs')
        image_relative = relative(unit['image_path'])
        require(len(image_relative.parts) == 1, 'unexpected unit image location')
        image = unit_path.parent / image_relative
        image_raw, _ = private_bytes(image)
        source_raw = (source / 'examples/hia_bootstrap' / (name + '.hiaasm')).read_bytes()
        require(digest(image_raw) == unit['image_sha256']
                and digest(source_raw) == unit['source_sha256'], 'unit source/image differs: ' + name)
        unit_files[name] = [binding(unit_path), binding(image)]
        images.append(unit['image_sha256'])
        sources[name] = unit['source_sha256']
    for name in bundle['unit_manifests']:
        files.extend(unit_files[name])
    return {'manifest': str(manifest), 'manifest_sha256': digest(bundle_raw),
            'bundle_sha256': digest(bundle_raw), 'abi_sha256': digest(abi_raw),
            'unit_names': names, 'unit_image_sha256': images, 'source_sha256': sources,
            'input_bindings': files}

def validate_group(report, group, frozen, source, original):
    require(report['schema'] == 'hepta.hia.core-lowering-selected-callers.v1'
            and report['status'] == 'DEVELOPMENT_GROUP_PASS'
            and report['scope'] == 'EXPLICIT_DEVELOPMENT_GROUP_ONLY'
            and report['development_group'] == group
            and report['complete_three_groups_executed'] is False
            and report['complete_three_groups_required_for_qualification'] is True,
            'development-only phase status differs')
    require(report['public_control_mode_count'] == 27 and report['abi_control_mode_count'] == 28
            and report['private_fixture_modes'] == ['_native_globals'],
            'public/fixture mode populations differ')
    require(report['expected_groups'] == [group] and len(report['groups']) == 1,
            'development group population differs')
    row = report['groups'][0]
    require(row['label'] == group and row['modules'] == frozen['modules']
            and row['expected_methods'] == frozen['count']
            and row['tests_run'] == frozen['count']
            and row['loaded_ids'] == row['executed_ids'] == frozen['ids']
            and len(set(row['executed_ids'])) == frozen['count']
            and row['strict_pass'] is True, 'original complete group identity differs')
    require(not row['loader_errors'] and all(not row[k] for k in (
        'errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')),
        'original group contains a unittest anomaly')
    require(not report['retained_owner_entries']
            and report['source_stable'] is True
            and report['manifest_images_bundle_stable'] is True,
            'retained owner or unstable source entered')
    expected_roles = ['caller', 'component'] if group == 'component' else ['caller']
    require(report['expected_bundle_roles'] == expected_roles
            and set(report['bundle_observations']) == set(expected_roles),
            'actual group bundle roles differ')
    observations = {}
    for role in expected_roles:
        observed = report['bundle_observations'][role]
        actual = inspect_bundle(observed['manifest'], source)
        require(observed['stable'] is True
                and observed['input_bindings_before'] == observed['input_bindings_after'],
                'bundle observations were not stable')
        recorded = observed['input_bindings_after']
        require(recorded == [{'path': r['path'], 'bytes': r['bytes'], 'sha256': r['sha256']}
                             for r in actual['input_bindings']],
                'actual copied bundle files differ from recorded observations')
        for key in ('manifest_sha256', 'bundle_sha256', 'abi_sha256', 'unit_names',
                    'unit_image_sha256', 'source_sha256'):
            require(observed[key] == actual[key], 'actual bundle observation differs: ' + key)
        require(actual['unit_image_sha256'] == original['unit_image_sha256']
                and actual['source_sha256'] == original['source_sha256']
                and actual['abi_sha256'] == original['abi_sha256'],
                'phase bundle does not contain the original compiled units')
        observations[role] = actual
    require(report['source_before'] == report['source_after']
            and type(report['source_after']) is dict and report['source_after'],
            'source pin observations differ')
    for name, identity in report['source_after'].items():
        require(digest((source / relative(name)).read_bytes()) == identity,
                'actual source differs from the recorded pin: ' + name)
    attempts = report['native_mode_entries']
    require(type(attempts) is dict and attempts
            and all(type(v) is int and v > 0 for v in attempts.values()),
            'mode attempts missing or invalid')
    recorded_attempts = {}
    for entry in report['group_native_mode_attempts']:
        require(entry['group'] == group and entry['mode'] not in recorded_attempts
                and type(entry['count']) is int and entry['count'] > 0,
                'invalid grouped mode attempt')
        recorded_attempts[entry['mode']] = entry['count']
    require(recorded_attempts == attempts, 'grouped and global attempts differ')
    normal_seen = set()
    for entry in report['native_mode_normal_returns']:
        require(entry['group'] == group and entry['mode'] not in normal_seen
                and type(entry['count']) is int and 0 < entry['count'] <= attempts.get(entry['mode'], 0),
                'normal method returns exceed actual attempts')
        normal_seen.add(entry['mode'])
    per_test = report['per_test_native_mode_entries']
    require(type(per_test) is dict and per_test
            and all((k in frozen['ids'] or k == 'outside-test') and type(v) is int and v > 0
                    for k, v in per_test.items())
            and sum(per_test.values()) == sum(attempts.values()),
            'per-test and grouped attempts differ')
    ledger = report['native_step_returns']
    require(report['native_step_ledger_schema'] == 'hepta.hia.core-lowering-native-step-returns.v1'
            and type(ledger) is list and ledger, 'actual native return ledger missing')
    abi = json.loads((source / 'hepta/hia_core_lowering_abi.json').read_bytes())
    bound = observations['component' if group == 'component' else 'caller']
    totals, seen, modes = {'0': 0, '1': 0, '2': 0}, set(), set()
    for entry in ledger:
        require(entry['group'] == group and entry['mode'] in abi['modes']
                and entry['mode_number'] == abi['modes'][entry['mode']]['number'],
                'native return mode/group differs')
        index = entry['unit_index']
        require(type(index) is int and 0 <= index < 31
                and entry['bundle_image_index'] == index + 1
                and entry['unit_name'] == bound['unit_names'][index + 1]
                and entry['image_sha256'] == bound['unit_image_sha256'][index + 1]
                and entry['abi_sha256'] == bound['abi_sha256']
                and entry['bundle_sha256'] == bound['bundle_sha256'],
                'actual native unit return does not match bound image')
        require(type(entry['status']) is int and entry['status'] in (0, 1, 2)
                and type(entry['count']) is int and entry['count'] > 0,
                'invalid actual native return count')
        identity = (entry['group'], entry['mode'], index, entry['status'])
        require(identity not in seen, 'duplicate native return ledger row')
        seen.add(identity)
        modes.add(entry['mode'])
        totals[str(entry['status'])] += entry['count']
    reported = report['actual_native_step_statuses']
    require(set(reported) <= set(totals) and all(reported.get(k, 0) == v for k, v in totals.items()),
            'native return matrix and global totals differ')
    if group == 'component':
        require('_native_globals' in modes and report['private_fixture_mode_has_actual_step_returns'] is True,
                'private ABI mode28 actual return missing')
    return {'group': group, 'methods': frozen['count'], 'actual_native_step_statuses': totals,
            'actual_modes': sorted(modes), 'actual_units': sorted({e['unit_name'] for e in ledger}),
            'bundle_observations': observations, 'whole_qualification_claimed': False}
