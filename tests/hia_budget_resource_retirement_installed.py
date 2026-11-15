"""Installed real Budget B connection and actual parent/child ACK controls."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None, ''):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import clean_environment,manifest_pins
from tests.hia_service_bootstrap_installed import WORKER,wheel_records,database_rows,describe_worker_controls
from tests.hia_slot_operations_qualification_support import run_owned

CONSUMER="import ctypes,importlib.abc,json,os,sqlite3,struct,sys\nfrom pathlib import Path\ninstalled,mode,bundle,bundle_sha,state_root,files_root=sys.argv[1:]\nsys.path.insert(0,installed)\nclass NoAuthoring(importlib.abc.MetaPathFinder):\n    def find_spec(self,name,path=None,target=None):\n        if name in ('tools','tests') or name.startswith(('tools.','tests.')):\n            raise AssertionError('installed Budget consumer imported authoring code')\nsys.meta_path.insert(0,NoAuthoring())\nfrom hepta import hia_agent_service as api\nfrom hepta import hia_service_bootstrap_native as native\nfrom hepta import hia_candidate_budget_native as candidate\nfrom hepta import hia_budget_resource_custody as budget_custody\nfrom hepta import hia_native_delivery as delivery\nfrom hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity\nassert Path(budget_custody.__file__).resolve()==Path(installed).resolve()/'hepta/hia_budget_resource_custody.py'\nassert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')\nassert candidate.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')\nfault=ValueError('actual installed native Budget return lost')\nentries=[];traces=[]\noriginal_init=native.NativeServiceBootstrap.__init__\noriginal_candidate_init=candidate.NativeCandidateBudgetImage.__init__\ndef record(owner,source,size,output,capacity,state,extent,code):\n    words=struct.unpack('<16Q' if owner=='bootstrap' else '<12Q',\n        ctypes.string_at(source,128 if owner=='bootstrap' else 96))\n    row={'owner':owner,'event':words[1],'code':code,\n         'request_bytes':size,'output_bytes':capacity,'state_bytes':extent,\n         'request':ctypes.string_at(source,size).hex(),\n         'output':ctypes.string_at(output,capacity).hex(),\n         'state':ctypes.string_at(state,extent).hex(),'actual_entry_returned':True}\n    if owner=='bootstrap':row.update(port=words[3],mode=words[5])\n    entries.append(row)\n    return words\ndef initialize(image,*args,**kwargs):\n    original_init(image,*args,**kwargs);actual=image._entry\n    def entry(source,size,output,capacity,state,extent):\n        code=actual(source,size,output,capacity,state,extent)\n        words=record('bootstrap',source,size,output,capacity,state,extent,code)\n        if (mode=='lost_parent_init_ACK' and words[5]==native.INIT\n                and words[1]==native.SUCCEEDED\n                and words[3]==native.PORT['init_budget_construct']):\n            raise fault\n        return code\n    image._entry=entry\ndef initialize_candidate(image,*args,**kwargs):\n    original_candidate_init(image,*args,**kwargs);actual=image._entry\n    def entry(source,size,output,capacity,state,extent):\n        code=actual(source,size,output,capacity,state,extent)\n        words=record('candidate',source,size,output,capacity,state,extent,code)\n        if mode=='lost_child_commit_ACK' and words[1]==4:\n            raise fault\n        return code\n    image._entry=entry\nnative.NativeServiceBootstrap.__init__=initialize\ncandidate.NativeCandidateBudgetImage.__init__=initialize_candidate\ndef forbidden(*args,**kwargs):\n    raise AssertionError('selected installed bootstrap entered a retained whole body')\napi._SERVICE_BOOTSTRAP_REFERENCES={key:forbidden for key in api._SERVICE_BOOTSTRAP_REFERENCES}\ndef contains(error,target):\n    work=[error];seen=set()\n    while work:\n        item=work.pop()\n        if item is target:return True\n        if item is None or id(item) in seen:continue\n        seen.add(id(item));work.extend((item.__cause__,item.__context__))\n    return False\ndef live(db):\n    try:return db.execute('SELECT 1').fetchone()[0]==1\n    except sqlite3.ProgrammingError:return False\nreport={'schema':'hepta.hia.budget-resource-installed-consumer.v1','mode':mode,\n        'manual_registration':False,'loss_fields_written':False,\n        'whole_native_stack_qualified':False,'entries':entries,'SQL':traces}\nwith native_helpers_scope(bundle,bundle_sha):\n    assert native_helpers_identity()['native_helpers_sha256']==bundle_sha\n    service=object.__new__(api.HIAAgentService)\n    caught=None\n    try:api.HIAAgentService.__init__(service,Path(state_root),artifact_roots=(Path(files_root),))\n    except BaseException as error:\n        assert mode=='lost_parent_init_ACK' and contains(error,fault)\n        caught=error\n    else:assert mode!='lost_parent_init_ACK','installed init ACK loss was not reached'\n    budget=service._candidate_budget\n    assert type(budget) is candidate.NativeCandidateBudgetStore\n    assert budget.db is not service.store.db\n    assert delivery._registered_resource_identity(budget) is not None\n    report['actual_distinct_budget_connection']=True\n    report['budget_selected']=True\n    report['open_before_close']=live(budget.db)\n    assert report['open_before_close'] is True\n    if mode!='lost_parent_init_ACK':\n        service.store.db.execute('INSERT INTO contexts VALUES (?,?,?,?,?)',\n            ('installed-budget','a'*64,'{}','1',0))\n        budget.db.set_trace_callback(traces.append)\n        try:\n            budget.consume('installed-budget',3)\n            assert mode=='normal','installed child COMMIT loss was not reached'\n        except BaseException as error:\n            assert mode=='lost_child_commit_ACK' and contains(error,fault)\n            caught=error\n        report['commit_SQL_count']=sum(sql=='COMMIT' for sql in traces)\n        assert report['commit_SQL_count']==1\n        assert budget.db.execute(\"SELECT attempts FROM contexts WHERE id='installed-budget'\").fetchone()[0]==1\n        report['actual_original_attempts']=1\n    if mode=='normal':\n        service.close()\n        assert budget.closed and not live(budget.db)\n        budget.close()\n        assert budget.closed and not live(budget.db)\n        report.update(public_close_completed=True,repeated_close_completed=True,\n                      actual_connection_open_after=False,loss_contains_actual_fault=False)\n    else:\n        assert caught is not None and contains(caught,fault)\n        try:budget.close()\n        except delivery.NativeDeliveryUnknown as error:\n            assert contains(error,fault)\n            report['public_close_refused']=True\n        else:raise AssertionError('unknown actual installed Budget B was closed')\n        assert not budget.closed and live(budget.db)\n        report.update(actual_connection_open_after=True,loss_contains_actual_fault=True,\n                      unknown_resource_not_manually_closed=True)\n    report['lost_records']=sum(row['lost'] for row in delivery.custody_snapshot())\n    report['resources']=len(delivery._RESOURCE_OBSERVATIONS)\n    if mode=='normal':\n        assert report['lost_records']==0 and report['resources']==0\n    else:\n        assert report['lost_records']>0\n    report['status']='PASS_INSTALLED_CONTROL_ONLY'\nprint(json.dumps(report,sort_keys=True,separators=(',',':')))\n"
MODES=('normal','lost_parent_init_ACK','lost_child_commit_ACK')


def run(args):
    from tests.test_hia_agent_installed_resources import RESOURCES,SDIST_SUPPORT_FILES
    from hepta import hia_agent_service as api
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    authority_raw,authority,authority_pin=support.capture_json(args.authority,{
        'bytes':args.authority_bytes,'sha256':args.authority_sha256})
    list_path=Path(authority['manifest_list_path'])
    list_raw,manifests,list_pin=support.capture_json(list_path,authority['manifest_list'])
    bundle_path=Path(authority['bundle_path'])
    bundle_raw,bundle_value,bundle_pin=support.capture_json(bundle_path,authority['bundle'])
    before=support.source_snapshot()
    images=manifest_pins(manifests)
    if not support.same(before,authority['source_before']) or not support.same(images,authority['images']):
        raise AssertionError('installed Budget source or images differ from actual authority')
    report={'schema':'hepta.hia.budget-resource-installed.v2',**support.child_identity(),
            'status':'HOLD','authority':authority_pin,'manifest_list':list_pin,'bundle':bundle_pin,
            'scope':authority['scope'],'source_before':before,'images_before':images,
            'whole_native_stack_qualified':False,'manual_resource_registration':False,
            'loss_fields_written':False}
    commands={};observations={};environment=clean_environment()
    def command(label,arguments,*,body=None,expected=0):
        target=args.output/label
        result=run_owned([sys.executable,'-I','-B',*map(str,arguments)],cwd=ROOT,
            directory=target,timeout_seconds=60,environment=environment,stdin=body)
        commands[label]=result
        raw=(target/'stdout.log').read_bytes()
        stderr=(target/'stderr.log').read_bytes()
        observations[label]={'stdout':support.bytes_pin(raw),'stderr':support.bytes_pin(stderr)}
        if (type(result['exit_code']) is not int or result['exit_code']!=expected
                or result['timed_out'] or result['interruption']
                or not result['owned_cleanup']['reaped'] or result['owned_cleanup']['after']
                or result['owned_cleanup']['signals']):
            raise AssertionError('installed Budget owned command failed: '+label)
        return raw
    try:
        staging=args.output/'source';staging.mkdir()
        shutil.copytree(ROOT/'hepta',staging/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
            target=staging/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,target)
        command('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation','--no-index',
                         '--wheel-dir',args.output/'wheels',staging])
        wheel,=(args.output/'wheels').glob('*.whl')
        installed=args.output/'installed'
        command('install',['-m','pip','install','--no-deps','--no-index','--no-compile',
                           '--target',installed,wheel])
        installation=wheel_records(wheel,installed);report['installation']=installation
        for name in ('hepta/hia_budget_resource_custody.py',
                     'hepta/_data/examples/hia_bootstrap/service_bootstrap.hepta',
                     'hepta/_data/examples/hia_bootstrap/candidate_budget.hepta'):
            original=name.removeprefix('hepta/_data/')
            if (installed/name).read_bytes()!=(ROOT/original).read_bytes():
                raise AssertionError('installed exact Budget runtime/source omitted: '+name)
        worker=args.output/'worker.py';worker.write_text(WORKER)
        consumer=args.output/'consumer.py';consumer.write_text(CONSUMER)
        identity_raw=command('identity',[worker,installed,'--installation-manifest',
            '--native-helpers-manifest',bundle_path,'--expected-native-helpers-sha256',bundle_pin['sha256']])
        identity=support.parse(identity_raw)
        if identity['native_helpers_sha256']!=bundle_pin['sha256']:
            raise AssertionError('actual installed worker bundle identity differs')
        report['worker_identity']={'raw':support.bytes_pin(identity_raw),'value':identity}
        def flags():
            return ['--expected-worker-sha256',identity['worker_sha256'],
                    '--expected-backend-sha256',identity['backend_sha256'],
                    '--expected-catalog-sha256',identity['catalog_sha256']]
        files=args.output/'files';files.mkdir()
        describe_worker_controls(args.output,command,worker,installed,bundle_path,bundle_pin['sha256'],
            identity,files,flags(),observations,report,api)
        for mode in MODES:
            raw=command('consumer-'+mode,[consumer,installed,mode,bundle_path,bundle_pin['sha256'],
                args.output/('consumer-state-'+mode),files])
            value=support.parse(raw);observations['consumer-'+mode]['response']=value
            if (value['status']!='PASS_INSTALLED_CONTROL_ONLY'
                    or value['budget_selected'] is not True
                    or value['actual_distinct_budget_connection'] is not True):
                raise AssertionError('actual installed distinct Budget B not reached')
        changed=installed/'hepta/hia_budget_resource_custody.py'
        original=changed.read_bytes()
        try:
            changed.write_bytes(original+b'\n')
            command('worker-budget-source-LF',[worker,installed,'--installation-manifest',
                '--native-helpers-manifest',bundle_path,'--expected-native-helpers-sha256',
                bundle_pin['sha256'],*flags()],expected=2)
        finally:changed.write_bytes(original)
        if not support.same(installation,wheel_records(wheel,installed)):
            raise AssertionError('installed full wheel/RECORD did not return to exact bytes')
        report['source_after']=support.source_snapshot()
        report['images_after']=manifest_pins(manifests)
        if (not support.same(before,report['source_after'])
                or not support.same(images,report['images_after'])):
            raise AssertionError('installed Budget source or image changed')
        support.exact_reread(args.authority,authority_raw)
        support.exact_reread(list_path,list_raw)
        support.exact_reread(bundle_path,bundle_raw)
        report['all_repeated_worker_expected_flags']=True
        report['actual_budget_connection_and_public_close']=True
        report['status']='PASS_INSTALLED_ONLY'
        return 0
    finally:
        support.write_json(args.output/'commands.json',commands)
        support.write_json(args.output/'observations.json',observations)
        report['commands']=support.file_pin(args.output/'commands.json')
        report['observations']=support.file_pin(args.output/'observations.json')
        support.write_json(args.output/'report.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority',type=Path,required=True)
    parser.add_argument('--authority-sha256',required=True)
    parser.add_argument('--authority-bytes',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    return run(parser.parse_args())


if __name__=='__main__':raise SystemExit(main())
