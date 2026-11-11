"""Independent real-SQLite selector timing comparison, with real HIA images.

Run ROOT JOURNAL_DEVELOPMENT_MANIFEST NEW_DIRECTORY.  This is finite development
evidence, never a matching-source cold qualification.  All changes are confined
to the new directory and temporary environment/function wrappers; the wrappers
delegate admission and execution to the original implementations.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch

ROOT, JOURNAL, OUT = map(Path, sys.argv[1:])
OUT.mkdir()
sys.path.insert(0, str(ROOT))
from hepta import hia_agent_data_json_native as data
from hepta import hia_json_preflight_native as preflight
from hepta import hia_agent_binary64_native as binary64
from hepta.hia_agent_journal_native import JournalSession, SELECTOR
from hepta.hia_agent_service import HIAAgentService
from tools.qualify_hia_selfhost import compile_stage

DSEL = 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST'
PSEL = 'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST'
BSEL = 'HEPTA_HIA_AGENT_BINARY64_MANIFEST'
MISSING = str(OUT / 'missing-binary64-manifest.json')
MISSING_DATA = str(OUT / 'missing-data-manifest.json')
MISSING_PREFLIGHT = str(OUT / 'missing-preflight-manifest.json')
MODULES = {'data': (data, DSEL, 'installed_agent_data_json'),
           'preflight': (preflight, PSEL, 'installed_preflight')}
SOURCE_FILES = ['hepta/hia_agent_journal_native.py',
    'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
    'hepta/hia_agent_data_json_native.py', 'hepta/hia_json_decode_native.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_agent_binary64_native.py',
    'examples/hia_bootstrap/agent_journal.hiaasm',
    'examples/hia_bootstrap/agent_data_json.hiaasm',
    'examples/hia_bootstrap/json_preflight.hiaasm']

def pins():
    return {name: {'bytes': (ROOT/name).stat().st_size,
                   'sha256': sha256((ROOT/name).read_bytes()).hexdigest()}
            for name in SOURCE_FILES}

def write_json(path, value):
    with path.open('x') as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write('\n')

def observed_error(exc):
    return {'type': type(exc).__name__, 'message': str(exc),
            'args': [repr(x) for x in exc.args]}

def rows(db):
    return {name: [list(row) for row in db.execute('SELECT * FROM '+name+' ORDER BY '+order)]
            for name, order in (('requests', 'key'), ('costs', 'rowid'))}

before = pins()
journal_bytes = JOURNAL.read_bytes()
journal_record = json.loads(journal_bytes)
request = json.loads((JOURNAL.parent / 'agent-journal.request.json').read_bytes())
compiler = Path(request['image'])
compiler_sha = sha256(compiler.read_bytes()).hexdigest()
assert compiler_sha == request['image_sha256'] == journal_record['compiler_sha256']
assert before['examples/hia_bootstrap/agent_journal.hiaasm']['sha256'] == journal_record['source_sha256']
builds = {}
for name, (module, _selector, _factory) in MODULES.items():
    folder = OUT / ('build-'+name)
    folder.mkdir()
    image, receipt = compile_stage(folder, name, compiler, module.SOURCE.read_bytes())
    record = {'schema': module.SCHEMA,
              'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
              'image_path': image.name,
              'image_sha256': sha256(image.read_bytes()).hexdigest(),
              'compiler_sha256': compiler_sha}
    write_json(folder/'manifest.json', record)
    builds[name] = {'manifest': record, 'image': image.read_bytes(), 'receipt': receipt}

valid_payload = '{"status":"completed","result":1.25}'
malformed_payload = '{"status":"completed","result":1e}'
cases = []
for name in MODULES:
    for fault in ('warm-image-append', 'new-image-path-bad-hash'):
        cases.append({'id': name+'-'+fault, 'module': name, 'fault': fault,
                      'payload': valid_payload, 'initial_binary64': '', 'env_after': {}})
cases += [
    {'id': 'data-disable-and-enable-binary64-after-admission', 'module': 'data',
     'fault': 'after-cached-admission', 'payload': valid_payload,
     'initial_binary64': '', 'env_after': {DSEL: '', BSEL: MISSING}},
    {'id': 'data-switch-after-admission-malformed-profile', 'module': 'data',
     'fault': 'after-cached-admission', 'payload': malformed_payload,
     'initial_binary64': '', 'env_after': {DSEL: MISSING_DATA, BSEL: MISSING}},
    {'id': 'ordinary-enable-data-and-binary64-after-admission', 'module': 'preflight',
     'fault': 'after-cached-admission', 'payload': valid_payload,
     'initial_binary64': '', 'env_after': {DSEL: MISSING_DATA, BSEL: MISSING, PSEL: MISSING_PREFLIGHT}},
    {'id': 'ordinary-enable-data-after-admission-malformed-profile', 'module': 'preflight',
     'fault': 'after-cached-admission', 'payload': malformed_payload,
     'initial_binary64': '', 'env_after': {DSEL: MISSING_DATA, BSEL: MISSING, PSEL: MISSING_PREFLIGHT}},
    {'id': 'data-disable-already-captured-missing-binary64', 'module': 'data',
     'fault': 'after-cached-admission', 'payload': valid_payload,
     'initial_binary64': MISSING, 'env_after': {BSEL: ''}},
    {'id': 'ordinary-disable-already-captured-missing-binary64', 'module': 'preflight',
     'fault': 'after-cached-admission', 'payload': valid_payload,
     'initial_binary64': MISSING, 'env_after': {BSEL: ''}},
]
observations = []
for spec in cases:
    case = OUT/spec['id']; case.mkdir()
    module, selector, factory_name = MODULES[spec['module']]
    record = builds[spec['module']]['manifest']
    image = case/record['image_path']
    manifest = case/'manifest.json'
    bad_image = case/'new-corrupted.image.bin'
    bad_image.write_bytes(builds[spec['module']]['image'] + b'\x00')
    lanes = {}
    for lane in ('reference', 'native'):
        image.write_bytes(builds[spec['module']]['image'])
        manifest.write_text(json.dumps(record, sort_keys=True)+'\n')
        # Prevent either lane from obtaining the other lane's immutable mapping.
        preflight._load_manifest.cache_clear()
        service = HIAAgentService(case/lane)
        args = {'request_key': 'independent-cached-selector'}
        compact = lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False,
                                      separators=(',', ':'), allow_nan=False).encode()
        digest = sha256(compact({'tool': 'hia_artifact', 'arguments': args})).hexdigest()
        key = sha256(compact({'tool': 'hia_artifact', 'key': args['request_key']})).hexdigest()
        service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
            (key, digest, 'hia_artifact', 'completed', spec['payload'], '1'))
        actual_db = service.store.db
        dbpath = actual_db.execute('PRAGMA database_list').fetchone()[2]
        state = {'cached': False, 'mutated': False, 'initial_image': None}
        events, stages = [], []
        original_factory = getattr(module, factory_name)
        original_binary64 = binary64.installed_agent_binary64
        original_run = JournalSession._run
        def factory(path):
            event = {'kind': 'admit', 'phase': 'cached' if state['cached'] else 'arguments',
                     'selector': selector, 'path': str(path)}
            events.append(event)
            try:
                loaded = original_factory(path)
            except BaseException as exc:
                event['error'] = observed_error(exc)
                raise
            event['returned_image'] = True
            if not state['cached']:
                state['initial_image'] = loaded
            else:
                event['same_as_argument_mapping'] = loaded is state['initial_image']
                if spec['fault'] == 'after-cached-admission':
                    assert not state['mutated']
                    os.environ.update(spec['env_after'])
                    state['mutated'] = True
                    events.append({'kind': 'environment_changed_after_real_admission',
                                   'values': spec['env_after']})
            return loaded
        def convert_factory(path):
            events.append({'kind': 'binary64_admit', 'path': str(path),
                           'phase': 'cached' if state['cached'] else 'arguments'})
            return original_binary64(path)
        def run(session, stage, *args, **kwargs):
            stages.append({'stage': stage, 'cached': state['cached'],
                           'data_profile': kwargs.get('data_profile', False)})
            return original_run(session, stage, *args, **kwargs)
        class ObservedDB:
            def __getattr__(self, name): return getattr(actual_db, name)
            def execute(self, sql, *args):
                result = actual_db.execute(sql, *args)
                if sql.startswith('SELECT * FROM requests') and not state['cached']:
                    state['cached'] = True
                    events.append({'kind': 'requests_lookup_completed'})
                    if spec['fault'] == 'warm-image-append':
                        image.write_bytes(image.read_bytes()+b'\x00')
                        state['mutated'] = True
                    elif spec['fault'] == 'new-image-path-bad-hash':
                        changed = dict(record, image_path=bad_image.name)
                        manifest.write_text(json.dumps(changed, sort_keys=True)+'\n')
                        state['mutated'] = True
                return result
        service.store.db = ObservedDB()
        env = {name: '' for name in os.environ if name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST')}
        env.update({DSEL: '', PSEL: '', BSEL: spec['initial_binary64'],
                    'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST': '',
                    SELECTOR: '', selector: str(manifest)})
        outcome = None
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, env))
            stack.enter_context(patch.object(module, factory_name, side_effect=factory))
            stack.enter_context(patch.object(binary64, 'installed_agent_binary64', side_effect=convert_factory))
            stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1,9]))
            stack.enter_context(patch.object(service, '_hia_artifact',
                side_effect=AssertionError('cached request must not execute a business effect')))
            if lane == 'native':
                os.environ[SELECTOR] = str(JOURNAL)
                stack.enter_context(patch.object(HIAAgentService, '_reference_call',
                    side_effect=AssertionError('native selection entered retained owner')))
                stack.enter_context(patch.object(JournalSession, '_run', run))
            try:
                value = service.call('hia_artifact', args) if lane == 'native' else service._reference_call('hia_artifact', args)
                outcome = {'value': value}
            except BaseException as exc:
                outcome = {'exception': observed_error(exc)}
            live_rows = rows(actual_db)
        service.close()
        with sqlite3.connect(dbpath) as reopened:
            durable_rows = rows(reopened)
        assert live_rows == durable_rows
        assert durable_rows['requests'][0][4] == spec['payload']
        assert state['cached'] and state['mutated']
        assert any(e['kind'] == 'admit' and e['phase'] == 'cached' for e in events)
        lanes[lane] = {'outcome': outcome, 'rows_after_close_reopen': durable_rows,
                       'events': events, 'native_stages': stages}
    equal = all(lanes['reference'][field] == lanes['native'][field]
                for field in ('outcome', 'rows_after_close_reopen', 'events'))
    value = lanes['reference']['outcome'].get('value')
    if spec['fault'] == 'warm-image-append':
        assert value == json.loads(valid_payload)
        assert not lanes['reference']['rows_after_close_reopen']['costs']
        assert any(e.get('same_as_argument_mapping') for e in lanes['reference']['events'])
    elif spec['fault'] == 'new-image-path-bad-hash':
        assert value['status'] == 'rejected'
        assert any('digest mismatch' in e.get('error', {}).get('message', '')
                   for e in lanes['reference']['events'])
        assert len(lanes['reference']['rows_after_close_reopen']['costs']) == 1
    elif spec['initial_binary64']:
        assert value['status'] == 'rejected'
        assert any(e['kind'] == 'binary64_admit' and e['path'] == MISSING
                   for e in lanes['reference']['events'])
    elif spec['payload'] == valid_payload:
        assert value == json.loads(valid_payload)
        assert not any(e['kind'] == 'binary64_admit' for e in lanes['reference']['events'])
    else:
        assert value['status'] == 'rejected'
    observations.append({'case': spec, 'equal': equal, **lanes})
    write_json(case/'observation.json', observations[-1])
    print(spec['id'], 'PASS' if equal else 'MISMATCH', flush=True)

after = pins()
assert before == after
assert JOURNAL.read_bytes() == journal_bytes
report = {'schema': 'hia.journal.independent-selector-snapshot-review.v1',
          'scope': 'finite real-SQLite development differential; no cold qualification',
          'python': sys.version, 'root': str(ROOT),
          'owner_head_observed_after': subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
          'journal_manifest': str(JOURNAL), 'journal_manifest_record': journal_record,
          'compiler_sha256': compiler_sha, 'source_before': before, 'source_after': after,
          'source_unchanged': before == after,
          'compiled_candidates': {k: {'manifest': v['manifest'], 'receipt': v['receipt']} for k,v in builds.items()},
          'cases': observations, 'all_equal': all(row['equal'] for row in observations),
          'script_sha256': sha256(Path(__file__).read_bytes()).hexdigest()}
write_json(OUT/'audit.json', report)
raise SystemExit(0 if report['all_equal'] else 1)
