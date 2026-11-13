"""One separately authorized 20/3 synthetic source owner, never a receiver."""
from pathlib import Path
import importlib.util
import json
import os
import stat
import sys

ROOT=Path(__file__).resolve().parent.parent
if 'v92_view_common' in sys.modules:c=sys.modules['v92_view_common']
else:
    spec=importlib.util.spec_from_file_location('v92_view_common',ROOT/'control/common.py')
    c=importlib.util.module_from_spec(spec);sys.modules[spec.name]=c;spec.loader.exec_module(c)
require,io=c.require,c.io

def request_inputs(request):
    rows={}
    for name,expected in request['inputs'].items():
        actual=c.seal(ROOT/name,64<<20)
        require(actual['bytes']==expected['bytes'] and actual['sha256']==expected['sha256'], 'source-control bytes differ')
        rows[str(ROOT/name)]=actual
    return rows

def closed_source(request, root):
    life,life_pin,_=c.document(root/'lifecycle.json')
    returned,_,_=c.document(root/'OWNER-RETURN.json')
    actual,actual_pin,_=c.document(root/'lifecycle.json.request.json',262144)
    projected=dict(returned);supervisor_rc=projected.pop('supervisor_returncode',None)
    returned_sha=projected.pop('receipt_sha256',None)
    require(projected==life and type(supervisor_rc) is int and returned_sha==life_pin['sha256']
            and life.get('schema')=='hepta.hia.selfhost-process-owner.v1'
            and life.get('implementation_sha256')==request['inputs']['control/process_owner_impl.py']['sha256']
            and life.get('request_sha256')==actual_pin['sha256']
            and actual['command']==request['command'] and actual['cwd']==str(ROOT)
            and actual['env']==request['environment'] and actual['qualification_seconds']==20
            and actual['cleanup_seconds']==3 and life['qualification_seconds']==20 and life['cleanup_seconds']==3,
            'source original owner/request/return binding differs')
    cleanup=life.get('cleanup',{})
    closed=(life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children')==[]
            and cleanup.get('errors')==[] and cleanup.get('deadline_exceeded') is False)
    require(closed,'source child outputs wait for bound ECHILD')
    natural=(supervisor_rc==0 and life.get('status')=='OWNED_PROCESS_COMPLETED'
            and life.get('returncode')==0 and life.get('exit_observed_before_deadline') is True
            and life.get('timed_out') is False and life.get('interrupted_signals')==[] and life.get('owner_error') is None
            and not any(e.get('kind')=='owned_child_sigkill' for e in life.get('events',[])))
    return life_pin,natural

def actual_source_gate():
    request,request_pin,_=c.document(ROOT/'CONTROL-REQUEST.json')
    root=Path(request['operation_root']);life_pin,natural=closed_source(request,root)
    final,final_pin,_=c.document(root/'FINAL.json');report,report_pin,_=c.document(root/'tests/REPORT.json')
    require(final.get('status')=='TWENTY_SOURCE_IO_PASS_ONLY' and final.get('errors')==[]
            and final.get('closed_owner') is True and final.get('natural_owner') is True and natural
            and final.get('request')==request_pin and final.get('report')==report_pin,
            'mandatory actual source20 final not accepted')
    require(report.get('status')=='TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY' and report.get('exception') is None
            and report.get('expected_ids')==report.get('loaded_ids')==report.get('actual_ids')==report.get('success_ids')==request['expected_ids']
            and report.get('tests_run')==20
            and all(report.get(k)==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','denied_effects'))
            and report.get('inputs_before')==report.get('inputs_after')==request['inputs']
            and report.get('network_bytes')==0 and report.get('product_execution') is False
            and report.get('receiver_executed') is False and report.get('private_proxy_capture_performed') is False,
            'mandatory complete twenty source controls differ')
    request_inputs(request)
    return {'request':request_pin,'lifecycle':life_pin,'report':report_pin,'FINAL':final_pin,
            'actual_source_only_controls':20,'network_bytes':0,'product_execution':False}

def main():
    request,request_pin,raw=c.document(ROOT/'CONTROL-REQUEST.json')
    require(len(sys.argv)==1 and request['schema']=='hia.v92-three-view-source20-request.v1'
            and request['qualification_seconds']==20 and request['cleanup_seconds']==3
            and len(request['expected_ids'])==20,'fixed finite source-control request differs')
    runtime=c.seal(Path(sys.executable).resolve(),64<<20)
    require(all(runtime[k]==request['runtime'][k] for k in ('path','bytes','sha256','identity'))
            and list(sys.version_info[:3])==[3,12,14], 'source-control fixed runtime differs')
    environment={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'','PYTHONDONTWRITEBYTECODE':'1',
                 'PYTHONNOUSERSITE':'1','PYTHONUNBUFFERED':'1'}
    require(request['command']==[runtime['path'],'-I','-S','-B',str(ROOT/'controls/run_controls.py')]
            and request['environment']==environment,'source-control original argv/env differ')
    before=request_inputs(request);root=Path(request['operation_root'])
    require(root.parent==Path('/tmp') and not os.path.lexists(root),'fresh source-control output required')
    s=os.statvfs(root.parent)
    require(s.f_bavail*s.f_frsize>=request['minimum_free_bytes'] and s.f_favail>=4096,'finite source-control reserve unavailable')
    c.mkdir(root);c.create(root/'REQUEST.original.json',raw,raw=True);c.create(root/'INPUTS-BEFORE.json',before)
    owner=c.module('v92_source20_original_owner',ROOT/'control/process_owner_impl.py')
    final={'schema':'hia.v92-three-view-source20-final.v1','status':'HOLD','request':request_pin,
           'closed_owner':False,'natural_owner':False,'errors':[],'receiver_executed':False,'product_execution':False}
    try:
        returned=owner.run_owned(request['command'],cwd=ROOT,env=environment,stdout_path=root/'stdout.log',
            stderr_path=root/'stderr.log',receipt_path=root/'lifecycle.json',qualification_seconds=20,cleanup_seconds=3)
        c.create(root/'OWNER-RETURN.json',returned)
        final['lifecycle'],final['natural_owner']=closed_source(request,root);final['closed_owner']=True
        originals=[];total=0
        for path in sorted(root.rglob('*')):
            s=path.lstat();require(not stat.S_ISLNK(s.st_mode),'source output symlink refused')
            if stat.S_ISDIR(s.st_mode):continue
            record=c.seal(path,16<<20);total+=record['bytes'];originals.append(record)
            require(len(originals)<=128 and total<=32<<20,'full finite output cap exceeded')
        c.create(root/'ORIGINALS.json',{'files':originals,'bytes':total,'after_bound_ECHILD':True})
        report,report_pin,_=c.document(root/'tests/REPORT.json');final['report']=report_pin
        require(final['natural_owner'] and report.get('status')=='TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY'
                and report.get('exception') is None and report.get('tests_run')==20
                and report.get('expected_ids')==report.get('loaded_ids')==report.get('actual_ids')==report.get('success_ids')==request['expected_ids']
                and all(report.get(k)==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','denied_effects'))
                and report.get('inputs_before')==report.get('inputs_after')==request['inputs'],
                'twenty complete finite source controls did not pass')
        after=request_inputs(request);require(after==before,'source inputs changed')
        c.create(root/'INPUTS-AFTER.json',after);final['status']='TWENTY_SOURCE_IO_PASS_ONLY'
    except BaseException as error:
        final['status']='HOLD';final['errors'].append(io.safe_error(error))
    c.create(root/'FINAL.json',final)
    print(json.dumps({'status':final['status'],'closed_owner':final['closed_owner'],'receiver_executed':False}))
    return 0 if final['status']=='TWENTY_SOURCE_IO_PASS_ONLY' and not final['errors'] else 1

if __name__=='__main__':raise SystemExit(main())
