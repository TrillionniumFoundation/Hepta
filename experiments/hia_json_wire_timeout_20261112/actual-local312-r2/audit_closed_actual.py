from pathlib import Path
from hashlib import sha256, sha1
import json, os, stat, time

SOURCE = Path('/tmp/hia-wire89-timeout-diagnostic-local312-r2')
OUT = Path('/tmp/hia-wire89-actual-r2-publication-20261112-r1')
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
CHECKS = []
READS = {}

def require(name, value):
    CHECKS.append({'name':name,'passed':bool(value)})
    if not value:
        raise AssertionError(name)

def identity(s):
    return {k:getattr(s,k) for k in FIELDS}

def read(path, expected=None, *, check_identity=True):
    path=Path(path)
    require('absolute fixed read '+str(path),path.is_absolute() and '..' not in path.parts)
    for parent in path.parents:
        require('directory link absent '+str(parent),not parent.is_symlink() and parent.is_dir())
    before=path.lstat()
    require('regular single leaf '+str(path),stat.S_ISREG(before.st_mode) and before.st_nlink==1)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        require('opened same leaf '+str(path),identity(os.fstat(f.fileno()))==identity(before))
        raw=f.read(before.st_size+1)
        require('read stable descriptor '+str(path),len(raw)==before.st_size and identity(os.fstat(f.fileno()))==identity(before))
    require('read stable path '+str(path),identity(path.lstat())==identity(before))
    pin={'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'git_blob_sha1':sha1(('blob %d\0'%len(raw)).encode()+raw).hexdigest(),'identity':identity(before)}
    if expected is not None:
        require('expected raw pin '+str(path),pin['bytes']==expected['bytes'] and pin['sha256']==expected['sha256'])
        if 'git_blob_sha1' in expected:
            require('expected Git pin '+str(path),pin['git_blob_sha1']==expected['git_blob_sha1'])
        if check_identity and 'identity' in expected:
            require('expected identity '+str(path),pin['identity']==expected['identity'])
    READS[str(path)]=pin
    return raw

def obj(path,expected=None):
    return json.loads(read(path,expected))

def close(root,request,wrapper_name,seconds,env,cwd):
    raw=read(root/'lifecycle.json'); life=json.loads(raw)
    wr=obj(root/wrapper_name)
    req_raw=read(root/'lifecycle.json.request.json'); req=json.loads(req_raw)
    require('raw owner/wrapper projection '+root.name,
        wr.get('receipt_sha256')==sha256(raw).hexdigest() and
        set(wr)==set(life)|{'receipt_sha256','supervisor_returncode'} and
        all(wr[k]==v for k,v in life.items()))
    require('owner bound request '+root.name,
        life['request_sha256']==sha256(req_raw).hexdigest() and req['command']==request['command'] and req['env']==env and req['cwd']==cwd)
    require('original limits '+root.name,
        life['qualification_seconds']==req['qualification_seconds']==seconds and
        life['cleanup_seconds']==req['cleanup_seconds']==3 and
        req['deadline_ns']-req['started_ns']==seconds*1000000000)
    cleanup=life['cleanup']
    require('bound closure '+root.name,
        cleanup['complete'] is True and cleanup['leader_reaped'] is True and cleanup['observed_echild'] is True and
        cleanup['remaining_direct_children']==[] and not cleanup['errors'] and not cleanup['deadline_exceeded'])
    require('natural successful exit '+root.name,
        life['schema']=='hepta.hia.selfhost-process-owner.v1' and life['status']=='OWNED_PROCESS_COMPLETED' and
        life['implementation_sha256']==req['implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2' and
        life['returncode']==wr['supervisor_returncode']==0 and life['qualification_started'] and life['exit_observed_before_deadline'] and
        not life['timed_out'] and life.get('owner_error') is None and not life['interrupted_signals'] and not life['event_overflow'])
    observed={(e['pid'],e['start_ticks']) for e in life['events'] if e['kind']=='owned_child_observed'}
    reaped={(e['pid'],e['start_ticks']) for e in life['events'] if e['kind']=='owned_child_reaped'}
    recorded={(e['pid'],e['start_ticks']) for e in life['direct_and_adopted_children']}
    require('all observed children reaped '+root.name,observed==reaped==recorded and bool(observed))
    require('no signal events '+root.name,not any('kill' in e['kind'] for e in life['events']) and all(e['returncode']==0 for e in life['events'] if e['kind']=='owned_child_reaped'))
    begin=next(e['monotonic_ns'] for e in life['events'] if e['kind']=='qualification_started')
    end=next(e['monotonic_ns'] for e in life['events'] if e['kind']=='qualification_exit_observed')
    return {'closed':True,'qualification_seconds':seconds,'cleanup_seconds':3,'observed_children':len(observed),
        'event_count':len(life['events']),'natural_execution_seconds':(end-begin)/1000000000,
        'raw_lifecycle_sha256':sha256(raw).hexdigest(),'owner_request_sha256':sha256(req_raw).hexdigest(),
        'historical_descendant_inventory_complete':life['historical_descendant_inventory_complete']}

def main():
    started=time.monotonic()
    source_raw=read(SOURCE/'RECORDING-CONTROLS-REQUEST.json')
    request_raw=read(SOURCE/'REQUEST.json')
    require('canonical source5 request',sha256(source_raw).hexdigest()=='3262e0afc52fcaa3cc3230a51f0fc3aa66391f5a7d2e1e2b4e13172c87cc7da0')
    require('canonical diagnostic request',sha256(request_raw).hexdigest()=='714382cdae121e8d06bd66d01f6b9e1796ced5dc7bda34a996a3040925c8aeff')
    sreq=json.loads(source_raw); dreq=json.loads(request_raw)
    sroot=SOURCE/'recording-controls-actual'; droot=SOURCE/'actual'
    sclosed=close(sroot,sreq,'OWNER-RETURN.json',20,sreq['environment'],str(SOURCE))
    dclosed=close(droot,dreq,'wrapper.json',180,dreq['env'],dreq['cwd'])
    # All child-body reads below occur only after the corresponding bound closure proof.
    sfinal=obj(sroot/'FINAL.json'); dfinal=obj(droot/'FINAL.json')
    require('source final narrow scope',sfinal['closed'] and sfinal['natural'] and sfinal['status']=='SOURCE5_PASS_ONLY' and sfinal['native_executed'] is False and sfinal['wire_test_executed'] is False)
    soriginals=obj(sroot/'ORIGINALS.json',sfinal['closed_originals'])
    require('source originals exact population',set(soriginals)|{'ORIGINALS.json','FINAL.json'}=={str(x.relative_to(sroot)) for x in sroot.rglob('*') if x.is_file()})
    for rel,pin in soriginals.items(): read(sroot/rel,pin)
    require('source copied exact request',read(sroot/'REQUEST.original.json')==source_raw)
    sbefore=obj(sroot/'INPUTS-BEFORE.json'); safter=obj(sroot/'INPUTS-AFTER.json')
    require('source input snapshots stable',sbefore==safter and set(sbefore)==set(sreq['input_pins']))
    for path,pin in sreq['input_pins'].items():
        actual=read(path,pin);require('source snapshot bound '+path,sbefore[path]['bytes']==len(actual) and sbefore[path]['sha256']==sha256(actual).hexdigest() and sbefore[path]['identity']==READS[path]['identity'])
    sr=obj(sroot/'tests/REPORT.json',sfinal['report'])
    require('exact source5 denominator',sr['expected_ids']==sr['actual_ids']==sreq['expected_ids'] and len(set(sr['actual_ids']))==sr['tests_run']==5 and sr['status']=='PASS')
    require('source5 semantics only',all(sr[k] is False for k in ('native_executed','project_imported','subprocess_created_by_tests','wire_test_executed')) and sr['source_before']==sr['source_after']==sreq['source_pins'])
    require('source5 zero anomalies',all(sr[k]==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes')))
    sresource=obj(sroot/'RESOURCE-CHECK.json')
    require('source fresh resources',sresource['available_bytes']>=sreq['minimum_free_bytes'] and sresource['available_inodes']>=sreq['minimum_free_inodes'])
    require('diagnostic final scope',dfinal['closed'] is True and dfinal['status']=='DEVELOPMENT_DIAGNOSTIC_TEST_PASS_NOT_WIRE89_QUALIFICATION' and dfinal['original_failure_retained'] is True and dfinal['full_wire89_qualification_claimed'] is False and dfinal['request_sha256']==sha256(request_raw).hexdigest())
    originals=dfinal['closed_originals']
    require('diagnostic exact originals',len(originals)==len({x['path'] for x in originals})==81 and {x['path'] for x in originals}|{'FINAL.json'}=={str(x.relative_to(droot)) for x in droot.rglob('*') if x.is_file()})
    for pin in originals: read(droot/pin['path'],pin)
    pre=obj(droot/'PRELAUNCH.json')
    require('diagnostic snapshots stable',pre['request_sha256']==sha256(request_raw).hexdigest() and pre['inputs_before']==dfinal['inputs_after'] and len(pre['inputs_before'])==len(dreq['input_pins'])==866)
    for expected,before,after in zip(dreq['input_pins'],pre['inputs_before'],dfinal['inputs_after']):
        require('bound diagnostic input '+expected['path'],all(expected[k]==before[k]==after[k] for k in ('path','bytes','sha256','identity')))
        read(expected['path'],expected)
    require('diagnostic fresh resources',pre['resource']['available_bytes']>=dreq['minimum_free_bytes'] and pre['resource']['available_inodes']>=dreq['minimum_free_inodes'])
    dr=obj(droot/'diagnostic-report.json',dfinal['diagnostic_report'])
    require('original method once',dr['original_test_id']==dreq['test_id'] and dr['executed_ids']==[dreq['test_id']] and dr['tests_run']==1 and dr['status']=='DIAGNOSTIC_TEST_PASS')
    require('original assertions/workload/instrumentation scope',dr['original_5s_assertion_unchanged'] is True and dr['workload_cases_from_frozen_source']==dreq['original_workload_cases']==256 and dr['observer_binding_unchanged'] is True and dr['instrumentation_cost_included_in_5s'] is True and dr['per_primitive_clock_or_IO'] is False)
    require('diagnostic zero anomalies',all(dr[k]==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','recording_errors','retained_owner_entries','host_encoder_entries')) and dr['recording_failed'] is False)
    require('development scope not expanded',all(dr[k] is False for k in ('fresh_cold_or_compiler_claimed','full_wire89_qualification_claimed','historical_3_14_4_failure_reproduced_claimed','new_selfhost_B3_invocation')) and dr['python']==dreq['python_version'] and dr['wire_image_sha256']==dreq['wire_image_sha256'])
    raw_rows=dr['raw_originals']
    require('diagnostic raw index unique and bounded',len(raw_rows)==len({x['path'] for x in raw_rows})==71 and sum(x['bytes'] for x in raw_rows)==dr['raw_bytes']<=dreq['diagnostic_raw_bytes_limit'])
    for row in raw_rows:read(droot/row['path'],row)
    processes=obj(droot/'processes.json')
    require('all actual process records preserved',processes==dr['processes'] and len(processes)==8 and [x['index'] for x in processes]==list(range(8)) and all(x['exception'] is None and x['final_returncode_observed']==0 for x in processes))
    communications=obj(droot/'process-communications.json')
    require('two actual reference communications',len(communications)==2 and all(x['exception'] is None and x['returncode']==0 and x['phase']=='evaluate' for x in communications))
    for row in communications:
        require('communication actual process',any(p['pid']==row['pid'] for p in processes))
        for key in ('input','stdout','stderr'):read(droot/row[key]['path'],row[key])
    batches=[obj(droot/'batches'/('%03d.json'%i)) for i in range(3)]
    require('original three batches and 256 cases',[x['mode'] for x in batches]==['reference','reference','native'] and all(len(x['cases'])==256 and x['phase']=='evaluate' and x['exception'] is None for x in batches))
    require('both reference case arrays unchanged',batches[0]['cases']==batches[1]['cases']==batches[2]['cases'])
    for phase in ('setup','build_pair','evaluate','outside-test'):
        require('actual cached observer unchanged '+phase,dr['counts'][phase+'/ordinary_wire_calls']==dr['counts'][phase+'/actual_key_cache_True'])
    require('original 5 second assertion actually met',dr['metrics']['evaluate/Session.evaluate']['inclusive_ns']<5000000000)
    summaries={'source5':dict(sclosed,status=sfinal['status'],tests=5,original_files=15),
        'diagnostic':dict(dclosed,status=dfinal['status'],tests=1,original_files=82,raw_originals=71,raw_bytes=dr['raw_bytes'],
            evaluate_seconds=dr['metrics']['evaluate/Session.evaluate']['inclusive_ns']/1e9,
            hia_evaluate_seconds=dr['metrics']['evaluate/_hia_evaluate']['inclusive_ns']/1e9,
            measurements_store_seconds=dr['metrics']['evaluate/store_json/measurements']['inclusive_ns']/1e9,
            wire_encode_seconds=dr['metrics']['evaluate/encode_ordinary']['inclusive_ns']/1e9,
            source_admission_seconds=dr['metrics']['evaluate/wire_source_admission']['inclusive_ns']/1e9,
            reference_batches_seconds=dr['metrics']['evaluate/runner/reference']['inclusive_ns']/1e9,
            evaluate_native_returns=sum(v for k,v in dr['counts'].items() if k.startswith('evaluate/native_step_status_')),
            evaluate_wire_calls=dr['counts']['evaluate/ordinary_wire_calls'],actual_processes=8)}
    report={'schema':'hepta.independent.wire89-diagnostic-r2-originals-audit.v1','status':'PASS_FOR_FROZEN_DEVELOPMENT_SCOPE_ONLY',
        'not_ci_reproduction':True,'no_wire89_qualification_claim':True,'original_ci_failures_retained':[6.503077664999637,5.675053439999829],
        'summaries':summaries,'check_count':len(CHECKS),'checks':CHECKS,'full_readback':READS,'seconds':time.monotonic()-started}
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    with (OUT/'INDEPENDENT-READBACK.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert (OUT/'INDEPENDENT-READBACK.json').read_bytes()==raw
    print(json.dumps({'status':report['status'],'checks':len(CHECKS),'read_files':len(READS),'seconds':report['seconds'],'summary':summaries,'report_bytes':len(raw),'report_sha256':sha256(raw).hexdigest()}))

if __name__=='__main__':
    main()
