"""Actual wheel/original worker read controls; preserve stateless read semantics."""
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
from hepta import hia_service_read_native as native
from hepta import hia_store_artifact_profile_native as store_native
from hepta.hia_native_helpers import native_helpers_scope
from tests.hia_service_artifact_worker_terminal import worker_profile
from tests.hia_service_read_fixture import canonical
from tests.hia_service_read_controls import bundle
from tests.test_hia_service_read_native import clean_environment, run_child


WORKER = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed read imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_store as store
from hepta import hia_service_read_native as native
from hepta import hia_store_artifact_profile_native as child_native
from hepta import hia_agent_service as service
from hepta import hia_native_delivery as delivery
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{},'store_startup':{},'store_request':{},'original_close_body_entries':0}
active=False
def forbidden(*a,**k):raise AssertionError('installed selected read or Store executed a retained body')
service._SERVICE_READ_REFERENCE=forbidden
service.HIAAgentService._hia_read_reference=forbidden
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
initialize=native.NativeServiceRead.__init__
def image_initialize(image,*a,**k):
    initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        bucket=counts['request' if active else 'startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        if active and packet[1]==native.SUCCEEDED and packet[3]==native.PORT['cursor_insert']:
            if mode=='lost_insert_ack':raise ValueError('actual cursor INSERT acknowledgement lost')
            if mode=='process_exit':os._exit(73)
        return result
    image._entry=observed
native.NativeServiceRead.__init__=image_initialize
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
    print('SERVICE_READ_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''


def counts_from(raw):
    prefix = b'SERVICE_READ_COUNTS='
    rows = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise AssertionError(('worker has no unique read counter record', raw))
    return json.loads(rows[0])


def state(case):
    with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
        db.row_factory = sqlite3.Row
        return {'cursors': [dict(row) for row in db.execute('SELECT * FROM cursors ORDER BY id')],
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
                         environment=environment, expected_code=expected_code)
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
    source = installed / 'hepta/_data/examples/hia_bootstrap/service_read.hepta'
    assert source.read_bytes() == native.SOURCE.read_bytes()
    installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
    for name in ('hepta/hia_agent_service.py', 'hepta/hia_native_delivery.py',
                 'hepta/hia_service_read_native.py', 'hepta/hia_service_read_protocol.py',
                 str(source.relative_to(installed))):
        raw = (installed / name).read_bytes()
        digest = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
        assert installed_record[name] == [digest, str(len(raw))]
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest), (store_native.SELECTOR, args.store_manifest)])
    script = args.output / 'worker.py'; script.write_text(WORKER)
    # Capture the original installed worker's identities before any mutation.
    # A v1 native-helper bundle pins its images, not the whole Python package.
    identity_stdout, identity_stderr = command('installation-manifest',
        [script, installed, 'normal', '--installation-manifest',
         '--native-helpers-manifest', path, '--expected-native-helpers-sha256', pin])
    installed_identity = json.loads(identity_stdout)
    assert set(installed_identity) == {
        'worker_sha256', 'backend_sha256', 'catalog_sha256', 'native_helpers_sha256'}
    assert all(type(value) is str and len(value) == 64
               and set(value) <= set('0123456789abcdef')
               for value in installed_identity.values())
    profile = worker_profile((installed / 'hepta/hia_agent_worker.py').read_bytes())
    assert installed_identity['native_helpers_sha256'] == pin
    identity_counts = counts_from(identity_stderr)
    assert identity_counts == {'startup': {}, 'request': {}, 'store_startup': {},
        'store_request': {}, 'original_close_body_entries': 0,
        'unknown_records': 0, 'retained_resource_observations': 0}
    observations = {}

    def prepare():
        case = AgentToolCase('runTest')
        with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(path), pin):
            case.setUp()
            try:
                reference = case.service.store.put(('x' * 511 + '雪z').encode(), 'input')
                arguments = case.session.arguments(mutable=False, context=False, artifact=reference, max_bytes=512)
                request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_read',
                    'arguments': arguments, 'profile_sha256': 'a' * 64,
                    'catalog_sha256': case.service.catalog_sha256}
                request['request_sha256'] = api.digest(request)
                case.service.close()
            except BaseException:
                case.tearDown()
                raise
        return case, request

    def worker(label, case, request, *, mode='normal', code=0):
        return command(label, [script, installed, mode, '--state-root', case.state_root,
            '--artifact-root', case.files_root, '--request-json-stdin',
            '--native-helpers-manifest', path, '--expected-native-helpers-sha256', pin,
            '--expected-worker-sha256', installed_identity['worker_sha256'],
            '--expected-backend-sha256', installed_identity['backend_sha256'],
            '--expected-catalog-sha256', installed_identity['catalog_sha256']],
            body=canonical(request), expected_code=code)

    for mode in ('normal', 'lost_insert_ack', 'process_exit'):
        case, request = prepare()
        try:
            before = state(case)
            code = 0 if mode == 'normal' else profile['lost_ack_exit'] if mode == 'lost_insert_ack' else 73
            stdout, stderr = worker(mode + '-first', case, request, mode=mode, code=code)
            after = state(case)
            first_counts = None if mode == 'process_exit' else counts_from(stderr)
            added = [row for row in after['cursors'] if row not in before['cursors']]
            assert len(added) == 1 and added[0]['offset'] == 511
            assert after['requests'] == before['requests']
            assert after['artifacts'] == before['artifacts']
            if mode == 'normal':
                first = json.loads(stdout)
                assert first['response']['status'] == 'completed', first
                assert first['response']['result']['content'] == 'x' * 511
                assert first['response']['result']['next_cursor'] == added[0]['id']
                assert first['native_helpers_sha256'] == pin
                assert first_counts['unknown_records'] == 0
                assert first_counts['retained_resource_observations'] == 0
                assert first_counts['original_close_body_entries'] == 1
                assert after['costs'] == before['costs'] + 1
            else:
                first = None
                assert stdout == b''
                assert after['costs'] == before['costs']
                if mode == 'lost_insert_ack':
                    if code == 2:
                        lines = stderr.splitlines()
                        assert lines[0] == b'HIA_WORKER_DELIVERY_UNKNOWN'
                        primary = lines.index(b'REQUEST_PRIMARY_EXCEPTION')
                        cleanup = lines.index(b'REQUEST_CLEANUP_EXCEPTION')
                        assert 0 < primary < cleanup
                        assert b'actual cursor INSERT acknowledgement lost' in stderr
                    assert first_counts['unknown_records'] > 0
                    assert first_counts['retained_resource_observations'] > 0
                    assert first_counts['original_close_body_entries'] == 0
            if first_counts is not None:
                assert sum(first_counts['request'].values()) > 0
                assert sum(first_counts['store_request'].values()) > 0
            repeated_stdout, repeated_stderr = worker(mode + '-repeat', case, request)
            repeated, repeated_counts = json.loads(repeated_stdout), counts_from(repeated_stderr)
            repeated_state = state(case)
            assert repeated['response']['status'] == 'completed', repeated
            assert repeated['response']['result']['content'] == 'x' * 511
            assert repeated['response']['result']['next_cursor'] == added[0]['id']
            assert repeated_state['cursors'] == after['cursors']
            assert repeated_state['requests'] == after['requests']
            assert repeated_state['artifacts'] == after['artifacts']
            assert repeated_state['costs'] == after['costs'] + 1
            assert sum(repeated_counts['request'].values()) > 0
            assert repeated_counts['unknown_records'] == 0
            assert repeated_counts['retained_resource_observations'] == 0
            assert repeated_counts['original_close_body_entries'] == 1
            if first is not None:
                assert repeated['response'] == first['response']
            observations[mode] = {'before': before, 'after_first': after, 'after_repeat': repeated_state,
                'first_exit': code, 'first_response': first, 'first_counts': first_counts,
                'repeat_response': repeated, 'repeat_counts': repeated_counts,
                'original_read_is_stateless_without_request_key': True,
                'repeat_reenters_owner': True, 'additional_cursor_rows_on_repeat': 0,
                'process_exit_finally_counts_unavailable': mode == 'process_exit'}
        finally:
            case.tearDown()

    case, request = prepare()
    original_source = source.read_bytes()
    added_module = installed / 'hepta/read_unlisted_probe.py'
    try:
        before = state(case)
        try:
            source.write_bytes(original_source + b'\n')
            stdout, stderr = worker('source-plus-LF', case, request, code=2)
            count = counts_from(stderr)
            assert stdout == b'' and sum(count['request'].values()) == 0
            assert state(case)['cursors'] == before['cursors']
            observations['source_plus_LF'] = {'worker_exit': 2, 'counts': count,
                                             'request_read_entries': 0}
        finally:
            source.write_bytes(original_source)
        try:
            added_module.write_text('UNLISTED_READ_MODULE = True\n')
            stdout, stderr = worker('installed-extra-module', case, request, code=2)
            count = counts_from(stderr)
            assert stdout == b'' and sum(count['request'].values()) == 0
            assert state(case)['cursors'] == before['cursors']
            observations['installed_extra_module'] = {'worker_exit': 2, 'counts': count,
                                                      'request_read_entries': 0}
        finally:
            added_module.unlink(missing_ok=True)
    finally:
        source.write_bytes(original_source)
        case.tearDown()
    assert source.read_bytes() == native.SOURCE.read_bytes()
    for name, digest in files.items():
        assert sha256((installed / name).read_bytes()).hexdigest() == digest
    return {'schema': 'hepta.hia.service-read-installed-worker.v1', 'status': 'PASS',
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'installed': str(installed), 'wheel_files_checked_against_installed': files,
        'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
        'bundle_sha256': pin, 'worker_script_sha256': sha256(script.read_bytes()).hexdigest(),
        'installed_identity': installed_identity,
        'installation_manifest_counts': identity_counts,
        'source_pins_supplied_to_every_worker': True,
        'observations': observations,
        'scope': 'actual installed original worker; read and Store selected; original stateless repeat',
        'runtime_compiler_or_authoring_imports_forbidden': True,
        'retained_read_and_Store_reference_bodies_forbidden': True,
        'source_LF_and_extra_module_restored': True,
        'whole_native_stack_qualified': False,
        'independent_opaque_DB_close_or_dead_resource_retention_proved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--store-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    from tools.build_hia_service_read import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    report = run(args)
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report.update(source_before=before, source_after=after, source_unchanged=True)
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({'status': report['status'], 'scope': report['scope']}))


if __name__ == '__main__':
    main()
