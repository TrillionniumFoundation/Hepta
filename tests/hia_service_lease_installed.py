"""Installed package and original worker authority for public lease consumers.

The four consumer methods are not RPC tool names. This gate records a genuine
default worker adoption request separately from the installed consumer process,
which performs acquire -> invoke -> release through the four selected methods.
It does not relabel a lease loss as an unconfirmed adoption RPC.
"""
from __future__ import annotations
import argparse
import base64
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import zipfile
from tests.hia_service_lease_controls import (
    ROOT, bundle_images, clean_environment, run_owned, successful_exit, write_json, read_json, pin)
from hepta.hia_native_helpers import native_helpers_scope

WORKER = r"""import importlib.abc,sys
from pathlib import Path
installed=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name in ('tools','tests') or name.startswith(('tools.','tests.')):
            raise AssertionError('installed worker imported development source')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_worker import main
from hepta.hia_service_lease_native import SOURCE
assert SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')
raise SystemExit(main(sys.argv[1:]))
"""

CONSUMER = r"""import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed,mode,bundle,bundle_sha,state_root,artifact_root,payload_path=sys.argv[1:]
sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name in ('tools','tests') or name.startswith(('tools.','tests.')):
            raise AssertionError('installed consumer imported development source')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_service as api
from hepta import hia_agent_store as store_api
from hepta import hia_service_lease_native as native
from hepta import hia_native_delivery as delivery
from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')
counts={'events':{},'modes':{},'close_body':0}
initialize=native.NativeServiceLease.__init__
def image_init(image,*args,**kwargs):
    initialize(image,*args,**kwargs);entry=image._entry
    def actual(source,size,output,capacity,state,extent):
        words=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert words[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        for field,key in (('events',str(words[1])),('modes',str(words[5]))):
            counts[field][key]=counts[field].get(key,0)+1
        if mode=='lost_buffer_ACK' and words[1]==native.SUCCEEDED and words[3]==native.PORT['captured_append']:
            raise ValueError('installed real buffer publication parent ACK lost')
        return result
    image._entry=actual
native.NativeServiceLease.__init__=image_init
def forbidden(*args,**kwargs):
    raise AssertionError('installed selected lease/ledger policy reached a retained body')
for key in ('ACQUIRE','LEASE','INVOKE','RELEASE'):
    setattr(api,'_SERVICE_LEASE_'+key+'_REFERENCE',forbidden)
for name in ('_reference_slot_acquire','_reference_slot_lease','_reference_slot_release'):
    setattr(api.HIAAgentService,name,forbidden)
close=store_api._NATIVE_STORE_CLOSE_REFERENCE
def counted_close(self):
    counts['close_body']+=1
    return close(self)
store_api._NATIVE_STORE_CLOSE_REFERENCE=counted_close
payload=json.loads(Path(payload_path).read_bytes())
report={'mode':mode,'counts':counts,'qualified_whole_native':False}
with native_helpers_scope(bundle,bundle_sha):
    service=api.HIAAgentService(Path(state_root),artifact_roots=(Path(artifact_root),))
    assert native_helpers_identity()['native_helpers_sha256']==bundle_sha
    try:
        lease=service.acquire_slot('installed-lease')
        report['lease']=lease
        result=service.invoke_lease(lease,'copy_bytes',
            [{'bytes_hex':'0102fe'},{'byte_length':4,'fill_byte':3}])
        report['result']=result
        assert mode=='normal', 'injected installed loss did not occur'
        assert result['status']=='returned' and result['termination_confirmed'] is True
        assert result['artifact']==payload['artifact'] and result['generation']==lease['generation']
        assert len(result['buffers'])==2
        report['released']=service.release_slot(lease)
        try:
            service.invoke_lease(lease,'copy_bytes',[])
        except store_api.AgentRejected as error:
            assert error.code=='E_HIA_LEASE'
            report['released_refusal']=error.code
        else:
            raise AssertionError('released installed lease executed')
    except (native.ServiceLeaseUnknown,delivery.NativeDeliveryUnknown) as error:
        assert mode=='lost_buffer_ACK'
        report['unknown']={'type':type(error).__name__,'message':str(error)}
        try:service.close()
        except delivery.NativeDeliveryUnknown:
            report['close_refused']=True
        else:raise AssertionError('unknown installed resource was closed')
    else:
        service.close()
    report['unknown_records']=sum(row['lost'] for row in delivery.custody_snapshot())
    report['retained_resources']=len(delivery._RESOURCE_OBSERVATIONS)
if mode=='normal':
    assert set(counts['modes'])=={'1','2','3','4'}
    assert counts['close_body']==1 and report['unknown_records']==0 and report['retained_resources']==0
else:
    assert counts['close_body']==0 and report['unknown_records']>0 and report['retained_resources']>0
print(json.dumps(report,sort_keys=True))
"""

def sqlite_state(state_root):
    connection = sqlite3.connect(Path(state_root) / 'state.sqlite3')
    try:
        connection.row_factory = sqlite3.Row
        return {table: [dict(row) for row in connection.execute('SELECT * FROM ' + table)]
                for table in ('slots', 'versions', 'leases', 'requests', 'artifacts', 'costs')}
    finally:
        connection.close()


def run(args):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tests.test_hia_native_byte_abi import byte_program
    from tests.test_hia_agent_buffer_lifecycle import workload
    from hepta import hia_agent_service as api
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    staging = args.output / 'source'
    staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    environment = clean_environment()
    command_records = {}
    def command(label, arguments, *, body=None, expected=0, cwd=ROOT):
        result = run_owned([sys.executable, '-I', '-B', *map(str, arguments)],
            cwd=cwd, directory=args.output / label, timeout_seconds=60,
            environment=environment, stdin=body)
        command_records[label] = result
        if (type(result['exit_code']) is not int or result['exit_code'] != expected
                or result['timed_out'] or result['interruption']
                or not result['owned_cleanup']['reaped'] or result['owned_cleanup']['after']
                or result['owned_cleanup']['signals']):
            raise AssertionError(('installed owned command failed', label, result))
        return (args.output / label / 'stdout.log').read_bytes()
    command('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                     '--wheel-dir', args.output / 'wheels', staging])
    wheel, = (args.output / 'wheels').glob('*.whl')
    installed = args.output / 'installed'
    command('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                       '--target', installed, wheel])
    installed_pins = {}
    with zipfile.ZipFile(wheel) as archive:
        record, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
        for name, digest, size in csv.reader(io.StringIO(archive.read(record).decode())):
            raw = archive.read(name)
            if digest:
                actual = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
                if digest != actual or size != str(len(raw)):
                    raise AssertionError('wheel RECORD differs')
            if name != record:
                if (installed / name).read_bytes() != raw:
                    raise AssertionError('installed bytes differ: ' + name)
                installed_pins[name] = sha256(raw).hexdigest()
    source = installed / 'hepta/_data/examples/hia_bootstrap/service_lease.hepta'
    if source.read_bytes() != (ROOT / 'examples/hia_bootstrap/service_lease.hepta').read_bytes():
        raise AssertionError('new lease source is not a packaged installed resource')
    manifests = read_json(args.manifest_list)
    bundle = args.output / 'bundle.json'
    bundle_sha = bundle_images(bundle, manifests)
    worker, consumer = args.output / 'worker.py', args.output / 'consumer.py'
    worker.write_text(WORKER)
    consumer.write_text(CONSUMER)
    identity_raw = command('worker-identity', [worker, installed, '--installation-manifest',
        '--native-helpers-manifest', bundle, '--expected-native-helpers-sha256', bundle_sha])
    identity = json.loads(identity_raw)
    if identity['native_helpers_sha256'] != bundle_sha:
        raise AssertionError('actual worker did not admit the declared lease helper')
    observations = {}
    previous_environment = dict(os.environ)
    try:
        for mode in ('normal', 'lost_buffer_ACK'):
            case = AgentToolCase('runTest')
            os.environ.clear(); os.environ.update(environment)
            with native_helpers_scope(str(bundle), bundle_sha):
                case.setUp()
                try:
                    _, _, baseline, built, receipts = case.build_pair(
                        document=byte_program(), candidate=byte_program(), workload=workload())
                    evaluation = case.session.evaluate(baseline, built, receipts=receipts)
                    arguments = case.session.arguments(target_slot='installed-lease',
                        expected_current={'generation': '0', 'epoch': '0'},
                        candidate_artifact=built['native_artifact'],
                        evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)
                    request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_adopt',
                        'arguments': arguments, 'profile_sha256': 'a' * 64,
                        'catalog_sha256': case.service.catalog_sha256}
                    request['request_sha256'] = api.digest(request)
                    payload = args.output / (mode + '-payload.json')
                    write_json(payload, {'artifact': built['native_artifact']})
                    case.service.close()
                    before = sqlite_state(case.state_root)
                    response_raw = command(mode + '-actual-worker-adopt', [
                        worker, installed, '--state-root', case.state_root, '--artifact-root', case.files_root,
                        '--request-json-stdin', '--native-helpers-manifest', bundle,
                        '--expected-native-helpers-sha256', bundle_sha,
                        '--expected-worker-sha256', identity['worker_sha256'],
                        '--expected-backend-sha256', identity['backend_sha256'],
                        '--expected-catalog-sha256', identity['catalog_sha256']],
                        body=json.dumps(request, sort_keys=True, separators=(',', ':')).encode())
                    response = json.loads(response_raw)
                    if response['response']['status'] != 'completed':
                        raise AssertionError(('actual installed worker adoption failed', response))
                    adopted = sqlite_state(case.state_root)
                    raw = command(mode + '-consumer', [consumer, installed, mode, bundle, bundle_sha,
                        case.state_root, case.files_root, payload])
                    result = json.loads(raw)
                    after = sqlite_state(case.state_root)
                    if mode == 'normal':
                        if not all(row['active'] == 0 for row in after['leases']):
                            raise AssertionError('installed normal release left an active lease')
                    else:
                        if result.get('close_refused') is not True:
                            raise AssertionError('installed unknown Store retirement was not refused')
                    # Adoption is a previously completed RPC. The lease consumer
                    # is a separate public API operation; do not invent a
                    # running adoption request or claim request-key replay.
                    observations[mode] = {'worker_response': response, 'consumer': result,
                        'before_adoption': before, 'after_adoption': adopted, 'after_consumer': after,
                        'adoption_RPC_and_lease_consumer_are_distinct': True}
                finally:
                    case.tearDown()
    finally:
        os.environ.clear(); os.environ.update(previous_environment)
        write_json(args.output / 'commands.json', command_records)
        write_json(args.output / 'observations.json', observations)
    raw = source.read_bytes()
    try:
        source.write_bytes(b'controlled installed source drift\n')
        command('worker-source-drift', [worker, installed, '--installation-manifest',
            '--native-helpers-manifest', bundle, '--expected-native-helpers-sha256', bundle_sha], expected=2)
    finally:
        source.write_bytes(raw)
    if any(sha256((installed / name).read_bytes()).hexdigest() != digest
           for name, digest in installed_pins.items()):
        raise AssertionError('installed files did not return to exact RECORD identities')
    write_json(args.output / 'commands.json', command_records)
    report = {'status': 'PASS', 'actual_worker_entry': True,
        'installed_four_public_methods_selected': True,
        'normal_and_actual_parent_ACK_loss': True,
        'whole_native_execution_claimed': False,
        'bundle': pin(bundle), 'identity': identity,
        'installed_record': installed_pins, 'observations': pin(args.output / 'observations.json'),
        'commands': command_records}
    write_json(args.output / 'report.json', report)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-list', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
