"""Real wheel and original worker; two handlers, exact replay and source custody."""
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
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as api
from hepta import hia_service_inspection_native as native
from hepta import hia_store_artifact_profile_native as store_native
from hepta.hia_native_helpers import native_helpers_scope
from tests.hia_service_inspection_oracle import canonical
from tests.hia_service_inspection_controls import bundle
from tests.test_hia_service_inspection_native import clean_environment, run_child

WORKER = "import ctypes,importlib.abc,json,os,struct,sys\nfrom pathlib import Path\ninstalled=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)\nclass NoAuthoring(importlib.abc.MetaPathFinder):\n    def find_spec(self,name,path=None,target=None):\n        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed inspection imported authoring')\nsys.meta_path.insert(0,NoAuthoring())\nfrom hepta import hia_agent_store as store\nfrom hepta import hia_service_inspection_native as native\nfrom hepta import hia_store_artifact_profile_native as child_native\nfrom hepta import hia_agent_service as service\nfrom hepta import hia_native_delivery as delivery\nfrom hepta.hia_agent_worker import main\nassert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')\ncounts={'startup':{},'request':{},'store_startup':{},'store_request':{},\n        'handler_modes':{},'original_close_body_entries':0}\nrequest_active=False\nhandler_active=0\nfired=False\ndef forbidden(*a,**k):raise AssertionError('installed selected inspection or Store executed retained body')\nfor name in ('_SERVICE_INSPECTION_INSPECT_REFERENCE','_SERVICE_INSPECTION_CANDIDATE_REFERENCE'):\n    setattr(service,name,forbidden)\nfor name in ('_hia_inspect_reference','_hia_candidate_reference'):\n    setattr(service.HIAAgentService,name,forbidden)\nfor name in store._STORE_ARTIFACT_PROFILE_REFERENCES:\n    store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden\n    setattr(store.AgentStore,'_'+name.lstrip('_')+'_reference',forbidden)\ncall=service.HIAAgentService._reference_call\ndef request(self,*a,**k):\n    global request_active\n    request_active=True\n    try:return call(self,*a,**k)\n    finally:request_active=False\nservice.HIAAgentService._reference_call=request\ndef handler(real,number):\n    def run(self,arguments):\n        global handler_active\n        previous=handler_active;handler_active=number\n        key=str(number);counts['handler_modes'][key]=counts['handler_modes'].get(key,0)+1\n        try:return real(self,arguments)\n        finally:handler_active=previous\n    return run\nfor name,number in (('_hia_inspect',1),('_hia_candidate',2)):\n    setattr(service.HIAAgentService,name,handler(getattr(service.HIAAgentService,name),number))\nclose=store._NATIVE_STORE_CLOSE_REFERENCE\ndef observed_close(self):\n    counts['original_close_body_entries']+=1\n    return close(self)\nstore._NATIVE_STORE_CLOSE_REFERENCE=observed_close\ninitialize=native.NativeServiceInspection.__init__\ndef image_initialize(image,*a,**k):\n    initialize(image,*a,**k);entry=image._entry\n    def observed(source,size,output,capacity,state,extent):\n        global fired\n        packet=struct.unpack('<16Q',ctypes.string_at(source,size))\n        result=entry(source,size,output,capacity,state,extent)\n        assert packet[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES\n        bucket=counts['request' if request_active else 'startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1\n        last=native.PORT['inspect_result' if packet[5]==1 else 'candidate_diagnostics_json']\n        if handler_active and not fired and (packet[1],packet[3])==(native.SUCCEEDED,last):\n            if mode=='lost_parent':\n                fired=True\n                raise ValueError('actual handler result acknowledgement withheld')\n            if mode=='process_exit':\n                os._exit(73)\n        return result\n    image._entry=observed\nnative.NativeServiceInspection.__init__=image_initialize\nchild_initialize=child_native.NativeStoreArtifactProfile.__init__\ndef child_image_initialize(image,*a,**k):\n    child_initialize(image,*a,**k);entry=image._entry\n    def observed(source,size,output,capacity,state,extent):\n        global fired\n        packet=struct.unpack('<10Q',ctypes.string_at(source,size))\n        result=entry(source,size,output,capacity,state,extent)\n        assert packet[0]==child_native.REQUEST_MAGIC and result==child_native.OUTPUT_BYTES\n        bucket=counts['store_request' if request_active else 'store_startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1\n        if handler_active and not fired and mode=='lost_child' and packet[1]==2:\n            fired=True\n            raise ValueError('actual Store child acknowledgement withheld')\n        return result\n    image._entry=observed\nchild_native.NativeStoreArtifactProfile.__init__=child_image_initialize\ntry:status=main(sys.argv[1:])\nfinally:\n    counts['unknown_records']=sum(row['lost'] for row in delivery.custody_snapshot())\n    counts['retained_resource_observations']=len(delivery._RESOURCE_OBSERVATIONS)\n    counts['fault_fired']=fired\n    print('SERVICE_INSPECTION_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)\nraise SystemExit(status)\n"


def counts_from(raw):
    prefix = b'SERVICE_INSPECTION_COUNTS='
    rows = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    assert len(rows) == 1, ('no unique installed counter record', raw)
    return json.loads(rows[0])


def state(case):
    with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
        db.row_factory = sqlite3.Row
        return {'requests': [dict(row) for row in db.execute('SELECT * FROM requests ORDER BY key')],
            'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
            'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}


def tree(path):
    records = {}
    for item in sorted(Path(path).rglob('*')):
        relative = str(item.relative_to(path))
        if item.is_symlink():
            raise AssertionError('fixture tree contains a symlink')
        if item.is_file():
            raw = item.read_bytes()
            records[relative] = {'kind': 'file', 'bytes': len(raw),
                'sha256': sha256(raw).hexdigest(), 'mode': item.stat().st_mode & 0o7777}
        elif item.is_dir():
            records[relative] = {'kind': 'directory', 'mode': item.stat().st_mode & 0o7777}
        else:
            raise AssertionError('fixture tree has a non-file/non-directory member')
    return records


def run(args):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import add_program, exhaustive_u8_workload
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
    source = installed / 'hepta/_data/examples/hia_bootstrap/service_inspection.hepta'
    assert source.read_bytes() == native.SOURCE.read_bytes()
    installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
    for name in ('hepta/hia_agent_service.py', 'hepta/hia_native_delivery.py',
                 'hepta/hia_service_inspection_native.py', 'hepta/hia_service_inspection_protocol.py',
                 str(source.relative_to(installed))):
        raw = (installed / name).read_bytes()
        digest = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
        assert installed_record[name] == [digest, str(len(raw))]
    path = args.output / 'bundle.json'
    pin = bundle(path, [(native.SELECTOR, args.manifest), (store_native.SELECTOR, args.store_manifest)])
    script = args.output / 'worker.py'; script.write_text(WORKER)
    identity_stdout, identity_stderr = command('installation-manifest',
        [script, installed, 'normal', '--installation-manifest',
         '--native-helpers-manifest', path, '--expected-native-helpers-sha256', pin])
    identities = json.loads(identity_stdout)
    assert set(identities) == {'worker_sha256', 'backend_sha256', 'catalog_sha256', 'native_helpers_sha256'}
    assert all(type(value) is str and len(value) == 64 and set(value) <= set('0123456789abcdef')
               for value in identities.values())
    assert identities['native_helpers_sha256'] == pin
    manifest_counts = counts_from(identity_stderr)
    assert manifest_counts == {'startup': {}, 'request': {}, 'store_startup': {}, 'store_request': {},
        'handler_modes': {}, 'original_close_body_entries': 0, 'unknown_records': 0,
        'retained_resource_observations': 0, 'fault_fired': False}

    baseline = AgentToolCase('runTest')
    initialized = False
    observations, copies, commands = {}, {}, []
    baseline_tree = files_tree = None
    original_source = source.read_bytes()
    added_module = installed / 'hepta/inspection_unlisted_probe.py'
    def worker(label, case, request, *, mode='normal', code=0):
        commands.append(label)
        return command(label, [script, installed, mode, '--state-root', case.state_root,
            '--artifact-root', case.files_root, '--request-json-stdin',
            '--native-helpers-manifest', path, '--expected-native-helpers-sha256', pin,
            '--expected-worker-sha256', identities['worker_sha256'],
            '--expected-backend-sha256', identities['backend_sha256'],
            '--expected-catalog-sha256', identities['catalog_sha256']],
            body=canonical(request), expected_code=code)
    try:
        with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(path), pin):
            baseline.setUp(); initialized = True
            # One real closed baseline, then complete independent SQLite/CAS
            # copies. The original absolute files root stays alive and constant.
            baseline.session.freeze(exhaustive_u8_workload())
            document = add_program()
            program = baseline.session.import_program(document)
            incoming = baseline.session.artifact(document)
            arguments = {
                'inspect': baseline.session.arguments(mutable=False,
                    program=program, view='summary'),
                'candidate': baseline.session.arguments(change={
                    'kind': 'import', 'format': 'core-json', 'source': incoming})}
            requests = {}
            for kind in ('inspect', 'candidate'):
                request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_' + kind,
                    'arguments': arguments[kind], 'profile_sha256': 'a' * 64,
                    'catalog_sha256': baseline.service.catalog_sha256}
                request['request_sha256'] = api.digest(request)
                requests[kind] = request
            baseline.service.close()
            try:
                baseline.service.store.db.execute('SELECT 1')
            except sqlite3.ProgrammingError:
                pass
            else:
                raise AssertionError('baseline database was not really closed')
        baseline_tree, files_tree = tree(baseline.state_root), tree(baseline.files_root)
        baseline_inode = baseline.state_root.joinpath('state.sqlite3').stat().st_ino
        labels = [kind + '-' + mode for kind in ('inspect', 'candidate')
                  for mode in ('normal', 'lost_parent', 'lost_child', 'process_exit')]
        for label in (*labels, 'source-drift'):
            destination = args.output / 'states' / label
            shutil.copytree(baseline.state_root, destination)
            copied = tree(destination)
            assert copied == baseline_tree
            inode = destination.joinpath('state.sqlite3').stat().st_ino
            assert inode != baseline_inode and all(inode != row['database_inode'] for row in copies.values())
            copies[label] = {'path': str(destination), 'tree': copied,
                'database_inode': inode, 'baseline_database_inode': baseline_inode,
                'complete_bytes_and_modes_equal': True}
        for kind in ('inspect', 'candidate'):
            for mode in ('normal', 'lost_parent', 'lost_child', 'process_exit'):
                label = kind + '-' + mode
                case = SimpleNamespace(state_root=Path(copies[label]['path']), files_root=baseline.files_root)
                request = requests[kind]
                before = state(case)
                code = 0 if mode == 'normal' else 73 if mode == 'process_exit' else 1
                stdout, stderr = worker(label + '-first', case, request, mode=mode, code=code)
                after = state(case)
                first_counts = None if mode == 'process_exit' else counts_from(stderr)
                new_requests = [row for row in after['requests'] if row not in before['requests']]
                if kind == 'candidate':
                    assert len(new_requests) == 1
                    assert new_requests[0]['state'] == ('completed' if mode == 'normal' else 'running')
                else:
                    assert not new_requests and after['requests'] == before['requests']
                if mode == 'normal':
                    first = json.loads(stdout)
                    assert first['response']['status'] == 'completed'
                    assert first['native_helpers_sha256'] == pin
                    assert first_counts['unknown_records'] == first_counts['retained_resource_observations'] == 0
                    assert first_counts['original_close_body_entries'] == 1 and not first_counts['fault_fired']
                    assert after['costs'] == before['costs'] + 1
                else:
                    first = None
                    assert stdout == b'' and after['costs'] == before['costs']
                    if first_counts is not None:
                        assert first_counts['fault_fired'] and first_counts['unknown_records'] > 0
                        assert first_counts['retained_resource_observations'] > 0
                        assert first_counts['original_close_body_entries'] == 0
                if first_counts is not None:
                    assert sum(first_counts['request'].values()) > 0
                    assert sum(first_counts['store_request'].values()) > 0
                    assert first_counts['handler_modes'] == {str(1 if kind == 'inspect' else 2): 1}
                repeated_stdout, repeated_stderr = worker(label + '-repeat', case, request)
                repeated, repeat_counts = json.loads(repeated_stdout), counts_from(repeated_stderr)
                repeated_state = state(case)
                assert repeated_state['requests'] == after['requests']
                assert repeat_counts['unknown_records'] == repeat_counts['retained_resource_observations'] == 0
                assert repeat_counts['original_close_body_entries'] == 1
                if kind == 'candidate':
                    assert sum(repeat_counts['request'].values()) == 0 and repeat_counts['handler_modes'] == {}
                    assert repeated_state['artifacts'] == after['artifacts']
                    if mode == 'normal':
                        assert repeated['response'] == first['response']
                        assert repeated_state['costs'] == after['costs']
                    else:
                        assert repeated['response']['status'] == 'rejected'
                        assert repeated['response']['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                        assert repeated_state['costs'] == after['costs'] + 1
                else:
                    assert repeated['response']['status'] == 'completed'
                    assert repeat_counts['handler_modes'] == {'1': 1} and sum(repeat_counts['request'].values()) > 0
                    assert repeated_state['costs'] == after['costs'] + 1
                    if first is not None:
                        assert repeated['response'] == first['response']
                observations[label] = {'tool': 'hia_' + kind, 'mode': mode, 'request': request,
                    'before': before, 'after_first': after, 'after_repeat': repeated_state,
                    'first_exit': code, 'first_response': first, 'first_counts': first_counts,
                    'repeat_response': repeated, 'repeat_counts': repeat_counts,
                    'candidate_is_mutable_with_exact_journal_replay': kind == 'candidate',
                    'inspection_is_stateless_and_repeat_reenters': kind == 'inspect',
                    'process_exit_counts_unavailable': mode == 'process_exit'}
                (args.output / (label + '-observation.json')).write_bytes(canonical(observations[label]))
        case = SimpleNamespace(state_root=Path(copies['source-drift']['path']), files_root=baseline.files_root)
        before = state(case)
        try:
            source.write_bytes(original_source + b'\n')
            stdout, stderr = worker('source-plus-LF', case, requests['inspect'], code=2)
            counts = counts_from(stderr)
            assert stdout == b'' and counts['request'] == {} and counts['handler_modes'] == {}
            assert state(case) == before
            observations['source_plus_LF'] = {'worker_exit': 2, 'counts': counts, 'database_unchanged': True}
        finally:
            source.write_bytes(original_source)
        try:
            added_module.write_text('UNLISTED_INSPECTION_MODULE = True\n')
            stdout, stderr = worker('installed-extra-module', case, requests['inspect'], code=2)
            counts = counts_from(stderr)
            assert stdout == b'' and counts['request'] == {} and counts['handler_modes'] == {}
            assert state(case) == before
            observations['installed_extra_module'] = {'worker_exit': 2, 'counts': counts, 'database_unchanged': True}
        finally:
            added_module.unlink(missing_ok=True)
        assert tree(baseline.state_root) == baseline_tree and tree(baseline.files_root) == files_tree
    finally:
        source.write_bytes(original_source)
        added_module.unlink(missing_ok=True)
        if initialized:
            baseline.tearDown()
    assert source.read_bytes() == native.SOURCE.read_bytes()
    for name, digest in files.items():
        assert sha256((installed / name).read_bytes()).hexdigest() == digest
    assert len(commands) == 18 and len(set(commands)) == 18
    return {'schema': 'hepta.hia.service-inspection-installed-worker.v1', 'status': 'PASS',
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'installed': str(installed), 'wheel_files_checked_against_installed': files,
        'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
        'bundle_sha256': pin, 'worker_script_sha256': sha256(script.read_bytes()).hexdigest(),
        'installed_identity': identities, 'installation_manifest_counts': manifest_counts,
        'source_pins_supplied_to_every_worker': True, 'commands': commands,
        'closed_baseline': {'tree': baseline_tree, 'files_root_tree': files_tree,
            'database_really_closed': True, 'complete_independent_copies': copies,
            'serial_pairs': True, 'worker_processes': 16, 'cases': labels},
        'observations': observations,
        'scope': 'actual installed original worker; inspect/candidate and Store selected',
        'original_handler_and_Store_reference_bodies_forbidden': True,
        'source_LF_and_extra_module_restored': True,
        'actual_opaque_Core_and_Store_providers_remain_hosted': True,
        'whole_native_stack_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--store-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    from tools.build_hia_service_inspection import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    report = run(args)
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report.update(source_before=before, source_after=after, source_unchanged=True)
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({'status': report['status'], 'scope': report['scope']}))


if __name__ == '__main__':
    main()
