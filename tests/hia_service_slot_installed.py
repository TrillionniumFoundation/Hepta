"""Actual installed original worker, both service Slot handlers and retained request replay."""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as api
from hepta import hia_service_slot_native as native
from hepta import hia_store_artifact_profile_native as store_native
from hepta.hia_native_helpers import native_helpers_scope
from tests.hia_service_slot_controls import encoded as canonical, put, digest
from tests.hia_service_slot_controls import bundle
from tests.hia_service_slot_controls import environment as clean_environment, run_child


WORKER = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed service Slot imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_store as store
from hepta import hia_service_slot_native as native
from hepta import hia_store_artifact_profile_native as child_native
from hepta import hia_agent_service as service
from hepta import hia_native_delivery as delivery
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{},'store_startup':{},'store_request':{},'original_close_body_entries':0}
active=False
def forbidden(*a,**k):raise AssertionError('installed selected service Slot or Store executed a retained body')
service._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE=forbidden
service._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE=forbidden
for name in store._STORE_ARTIFACT_PROFILE_REFERENCES:
    store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden
    setattr(store.AgentStore,'_'+name.lstrip('_')+'_reference',forbidden)
call=service.HIAAgentService._reference_call
def request(self,*a,**k):
    global active
    active=True
    try:return call(self,*a,**k)
    finally:active=False
service.HIAAgentService._reference_call=request
close=store._NATIVE_STORE_CLOSE_REFERENCE
def observed_close(self):
    counts['original_close_body_entries']+=1
    return close(self)
store._NATIVE_STORE_CLOSE_REFERENCE=observed_close
initialize=native.NativeServiceSlot.__init__
def image_initialize(image,*a,**k):
    initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        bucket=counts['request' if active else 'startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        if active and packet[1]==native.SUCCEEDED and packet[3]==native.PORT['rollback_receipt' if packet[5]==native.ROLLBACK else 'adopt_receipt']:
            if mode=='lost_receipt_ack':raise ValueError('actual receipt acknowledgement lost')
            if mode=='process_exit':os._exit(73)
        return result
    image._entry=observed
native.NativeServiceSlot.__init__=image_initialize
child_initialize=child_native.NativeStoreArtifactProfile.__init__
def child_image_initialize(image,*a,**k):
    child_initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==child_native.REQUEST_MAGIC and result==child_native.OUTPUT_BYTES
        bucket=counts['store_request' if active else 'store_startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        return result
    image._entry=observed
child_native.NativeStoreArtifactProfile.__init__=child_image_initialize
try:status=main(sys.argv[1:])
finally:
    counts['unknown_records']=sum(row['lost'] for row in delivery.custody_snapshot())
    counts['retained_resource_observations']=len(delivery._RESOURCE_OBSERVATIONS)
    print('SERVICE_SLOT_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''


def counts_from(raw):
    prefix = b'SERVICE_SLOT_COUNTS='
    rows = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise AssertionError(('worker has no unique service Slot counter record', raw))
    return json.loads(rows[0])


def state(case):
    with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
        db.row_factory = sqlite3.Row
        return {'slots': [dict(row) for row in db.execute('SELECT * FROM slots ORDER BY name')],
                'versions': [dict(row) for row in db.execute('SELECT * FROM versions ORDER BY slot,generation')],
                'requests': [dict(row) for row in db.execute('SELECT * FROM requests ORDER BY key')],
                'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}


def run(args):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    staging = args.output / 'source'; staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        target = staging / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    environment = clean_environment()
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    def command(label, arguments, *, body=None, expected_code=0):
        return run_child(args.output, label, arguments, timeout=60, body=body,
                         env=environment, expected_code=expected_code)
    command('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', args.output / 'wheels', staging])
    wheel, = (args.output / 'wheels').glob('*.whl')
    installed = args.output / 'installed'
    command('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
    files = {}
    with zipfile.ZipFile(wheel) as archive:
        record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
        for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode())):
            raw = archive.read(name)
            if digest:
                assert digest == 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
                assert size == str(len(raw))
            if name != record_name:
                assert (installed / name).read_bytes() == raw, name
                files[name] = sha256(raw).hexdigest()
    source = installed / 'hepta/_data/examples/hia_bootstrap/service_slot.hepta'
    assert source.read_bytes() == native.SOURCE.read_bytes()
    installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
    for name in ('hepta/hia_agent_service.py', 'hepta/hia_native_delivery.py',
                 'hepta/hia_service_slot_native.py', 'hepta/hia_service_slot_protocol.py',
                 str(source.relative_to(installed))):
        raw = (installed / name).read_bytes()
        digest = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
        assert installed_record[name] == [digest, str(len(raw))]

    authority = json.loads(args.authority.read_bytes())
    path = args.output / 'bundle.json'
    original_bundle = Path(authority['bundle']).read_bytes()
    path.write_bytes(original_bundle)
    pin = sha256(original_bundle).hexdigest()
    assert pin == authority['bundle_sha256']
    script = args.output / 'worker.py'; script.write_text(WORKER)
    identity_stdout, identity_stderr = command('installation-manifest',
        [script, installed, 'normal', '--installation-manifest',
         '--native-helpers-manifest', path, '--expected-native-helpers-sha256', pin])
    identity = json.loads(identity_stdout)
    assert set(identity) == {'worker_sha256', 'backend_sha256', 'catalog_sha256', 'native_helpers_sha256'}
    assert all(type(v) is str and len(v) == 64 and set(v) <= set('0123456789abcdef')
               for v in identity.values())
    assert identity['native_helpers_sha256'] == pin
    identity_counts = counts_from(identity_stderr)
    assert not any(identity_counts[key] for key in ('startup', 'request', 'store_startup', 'store_request'))
    assert identity_counts['unknown_records'] == identity_counts['retained_resource_observations'] == 0
    assert identity_counts['original_close_body_entries'] == 0
    observations = {}

    def prepare(tool):
        case = AgentToolCase('runTest')
        with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(path), pin):
            case.setUp()
            try:
                base, revised, baseline, built, receipts = case.build_pair()
                evaluation = case.session.evaluate(baseline, built, receipts=receipts)
                arguments = case.session.arguments(target_slot='installed-slot',
                    expected_current={'generation': '0', 'epoch': '0'},
                    candidate_artifact=built['native_artifact'],
                    evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)
                if tool == 'hia_rollback':
                    adopted = case.client.result('hia_adopt', arguments)
                    arguments = case.session.arguments(target_slot='installed-slot',
                        expected_current=adopted['current'],
                        retained_generation=adopted['previous']['generation'],
                        reason='actual installed retained rollback')
                request = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
                    'arguments': arguments, 'profile_sha256': 'a' * 64,
                    'catalog_sha256': case.service.catalog_sha256}
                request['request_sha256'] = api.digest(request)
                case.service.close()
            except BaseException:
                case.tearDown()
                raise
        return case, request

    def worker(label, case, request, *, mode='normal', code=0):
        return command(label, [script, installed, mode,
            '--state-root', case.state_root, '--artifact-root', case.files_root,
            '--request-json-stdin', '--native-helpers-manifest', path,
            '--expected-native-helpers-sha256', pin,
            '--expected-worker-sha256', identity['worker_sha256'],
            '--expected-backend-sha256', identity['backend_sha256'],
            '--expected-catalog-sha256', identity['catalog_sha256']],
            body=canonical(request), expected_code=code)

    for tool in ('hia_adopt', 'hia_rollback'):
        for mode in ('normal', 'lost_receipt_ack', 'process_exit'):
            label = tool + '.' + mode
            case, request = prepare(tool)
            try:
                before = state(case)
                code = 0 if mode == 'normal' else 1 if mode == 'lost_receipt_ack' else 73
                stdout, stderr = worker(label + '.first', case, request, mode=mode, code=code)
                after = state(case)
                first_counts = None if mode == 'process_exit' else counts_from(stderr)
                requested = [r for r in after['requests'] if r['key'] == api.digest({'tool': tool, 'key': request['arguments']['request_key']})]
                assert len(requested) == 1
                if mode == 'normal':
                    first = json.loads(stdout)
                    assert first['response']['status'] == 'completed', first
                    assert first['native_helpers_sha256'] == pin
                    assert requested[0]['state'] == 'completed'
                    assert first_counts['unknown_records'] == first_counts['retained_resource_observations'] == 0
                    assert first_counts['original_close_body_entries'] == 1
                    assert after['costs'] == before['costs'] + 1
                    assert after['slots'] != before['slots']
                else:
                    first = None
                    assert stdout == b''
                    assert requested[0]['state'] == 'running' and requested[0]['response'] is None
                    # These are the original SQLite transaction outcomes after
                    # the real child exits, not an invented rollback in the test.
                    assert after['slots'] == before['slots']
                    assert after['versions'] == before['versions']
                    assert after['artifacts'] == before['artifacts']
                    assert after['costs'] == before['costs']
                    if mode == 'lost_receipt_ack':
                        assert first_counts['unknown_records'] > 0
                        assert first_counts['retained_resource_observations'] > 0
                        assert first_counts['original_close_body_entries'] == 0
                if first_counts is not None:
                    assert sum(first_counts['request'].values()) > 0
                    assert sum(first_counts['store_request'].values()) > 0
                raw, err = worker(label + '.replay', case, request)
                repeated, repeated_counts = json.loads(raw), counts_from(err)
                replay_state = state(case)
                assert sum(repeated_counts['request'].values()) == 0
                assert repeated_counts['unknown_records'] == repeated_counts['retained_resource_observations'] == 0
                assert repeated_counts['original_close_body_entries'] == 1
                if mode == 'normal':
                    assert repeated['response'] == first['response']
                    assert replay_state == after
                else:
                    assert repeated['response']['status'] == 'rejected'
                    assert repeated['response']['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                    assert replay_state['requests'] == after['requests']
                    assert replay_state['slots'] == after['slots']
                    assert replay_state['versions'] == after['versions']
                    assert replay_state['artifacts'] == after['artifacts']
                    assert replay_state['costs'] == after['costs'] + 1
                observations[label] = {'tool': tool, 'mode': mode, 'before': before,
                    'after_first': after, 'after_replay': replay_state,
                    'first_exit': code, 'first_response': first, 'first_counts': first_counts,
                    'replay_response': repeated, 'replay_counts': repeated_counts,
                    'same_request_replayed_without_handler': True,
                    'process_exit_finally_unavailable': mode == 'process_exit'}
            finally:
                case.tearDown()

    case, request = prepare('hia_adopt')
    original_source = source.read_bytes()
    extra = installed / 'hepta/service_slot_unlisted_probe.py'
    try:
        before = state(case)
        try:
            source.write_bytes(original_source + b'\n')
            stdout, stderr = worker('source-plus-LF', case, request, code=2)
            count = counts_from(stderr)
            assert stdout == b'' and not count['request'] and state(case) == before
            observations['source_plus_LF'] = {'exit': 2, 'counts': count, 'database_unchanged': True}
        finally:
            source.write_bytes(original_source)
        try:
            extra.write_text('UNLISTED_SLOT_MODULE = True\n')
            stdout, stderr = worker('installed-extra-module', case, request, code=2)
            count = counts_from(stderr)
            assert stdout == b'' and not count['request'] and state(case) == before
            observations['installed_extra_module'] = {'exit': 2, 'counts': count, 'database_unchanged': True}
        finally:
            extra.unlink(missing_ok=True)
    finally:
        source.write_bytes(original_source)
        case.tearDown()
    assert len(observations) == 8
    assert source.read_bytes() == native.SOURCE.read_bytes()
    for name, expected in files.items():
        assert sha256((installed / name).read_bytes()).hexdigest() == expected
    return {'schema': 'hepta.hia.service-slot-installed-worker.v1', 'status': 'PASS',
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'installed': str(installed), 'wheel_files_checked_against_installed': files,
        'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
        'bundle_sha256': pin, 'worker_script_sha256': sha256(script.read_bytes()).hexdigest(),
        'installed_identity': identity, 'installation_manifest_counts': identity_counts,
        'source_pins_supplied_to_every_worker': True, 'observations': observations,
        'unknown_custody_reported_as_cleanup_success': False,
        'source_LF_and_extra_module_restored': True,
        'scope': 'actual installed original worker; both complete service handlers plus real Store/TX/Slot',
        'runtime_authoring_imports_forbidden': True,
        'whole_native_stack_qualified': False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--authority', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    from tools.build_hia_service_slot import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    report = run(args)
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report.update(source_before=before, source_after=after, source_unchanged=True)
    put(args.output / 'report.json', report)
    print(canonical({'status': report['status'], 'scope': report['scope']}).decode(), end='')

if __name__ == '__main__': main()
