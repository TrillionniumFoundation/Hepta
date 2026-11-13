"""One snapshot native owner: original12 plus the separate full-page method."""
from pathlib import Path
import importlib.util,json,os,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common,matrix,trace,support,compile_io
ROOT=support.ROOT
def load_owner():
    p=ROOT/'control/process_owner_impl.py'
    spec=importlib.util.spec_from_file_location('wal_original_369_owner_r1',p)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
    request_path=Path(sys.argv[1]);expected_sha=sys.argv[2]
    pin,raw=common.read(request_path)
    common.require(request_path==ROOT/'REQUEST.json' and pin['sha256']==expected_sha,'exact WAL native request SHA')
    request=json.loads(raw);output=Path(request['output'])
    common.require(request['schema']=='hia.wal-snapshot.native-finite-request.v1'
        and request['status']=='SNAPSHOT_ORIGINAL12_PLUS_FULL_PAGES_NATIVE_UNEXECUTED'
        and request['qualification_seconds']==180 and request['cleanup_seconds']==3
        and request['expected_ids']==list(matrix.IDS) and request['expected_methods']==13
        and request['native_returns']==2704 and request['original_source_methods']==12 and request['original_VM_calls']==608
        and request['original_VM_actual_retained'] is True and request['C_calls_each']==639
        and request['trace_bytes_limit']==256<<20 and request['trace_chunk_limit']==4<<20 and request['trace_record_limit']==1<<20
        and request['output_bytes_limit']==384<<20 and request['output_files_limit']==192
        and request['initial_free_bytes']==1<<30 and request['reserve_free_bytes']==512<<20
        and request['free_inodes']==4096 and dict(os.environ)==request['environment'],
        'frozen complete limits/environment')
    common.require(output==ROOT.parent/'sqlite-wal-snapshot-native-r1-actual' and not os.path.lexists(output),
                   'new exact disjoint actual root required')
    initial_capacity=support.capacity(ROOT.parent,True)
    runtime=support.runtime(request)
    before=support.input_records(request);source_before=support.source_records(request);system_before=support.system_records(request)
    with common.held_parent(output) as (parent,name):os.mkdir(name,0o700,dir_fd=parent);os.fsync(parent)
    (output/'tmp').mkdir(mode=0o700)
    final={'schema':'hia.wal-snapshot.native-final.v1','status':'HOLD','request':pin,
           'runtime':runtime,'initial_capacity':initial_capacity,'owner_closed':False,'owner_natural':False,
           'errors':[],'source12_VM_reexecuted':False,'matching_cold_qualification':False,
           'SQL_engine_or_durability_qualification':False,'output':str(output)}
    common.create(output/'REQUEST.original.json',raw,raw=True)
    common.create(output/'PARENT-INPUTS-BEFORE.json',before)
    common.create(output/'PARENT-SOURCE-BEFORE.json',source_before)
    common.create(output/'PARENT-SYSTEM-BEFORE.json',system_before)
    returned=None;started=time.monotonic_ns()
    try:
        owner=load_owner()
        returned=owner.run_owned(support.command(request,pin['sha256']),cwd=str(ROOT),env=request['environment'],
            stdout_path=output/'stdout.log',stderr_path=output/'stderr.log',receipt_path=output/'lifecycle.json',
            qualification_seconds=180,cleanup_seconds=3)
        common.create(output/'OWNER-RETURN.json',returned)
        life_pin,life=support.read_json(output/'lifecycle.json',4<<20)
        parent_pin,parent=support.read_json(output/'lifecycle.json.request.json',1<<20)
        closed,natural=support.natural_owner(returned,life,parent,request,pin['sha256'],life_pin,parent_pin)
        final['owner_closed']=closed;final['owner_natural']=natural
        # No child enumeration or body read happens before the actual bound ECHILD proof above.
        originals=support.catalog(output)
        final['closed_originals']=common.create(output/'CLOSED-ORIGINAL-CATALOG.json',originals)
        common.require(natural,'closed failure preserved; natural qualification did not pass')
        worker_pin,worker=support.read_json(output/'WORKER.json',4<<20)
        common.require(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' and worker['exception'] is None
            and worker['secondary_errors']==[] and worker['request']==pin
            and worker['native_executed'] is True and worker['HIA_compile_executed'] is True
            and worker['C_compiles_executed']==2 and type(worker['elapsed_ns'])is int
            and 0<=worker['elapsed_ns']<=180000000000,'whole worker result')
        final['worker']=worker_pin
        expected_hia=support.inspect_new_compile(output/'hia-compile',request)
        common.require(expected_hia==worker['HIA_compile'],'independent same-original HIA compile readback')
        final['compiler_originals']=support.inspect_compiler_inputs()
        final['HIA_compile']=expected_hia
        final['C_compiles']={v:compile_io.inspect(request,v,output/('C-'+v)) for v in matrix.VERSIONS}
        child_pin,child=support.read_json(output/'native/REPORT.json',4<<20)
        common.require(child['status']=='FINITE_NATIVE_SNAPSHOT_AND_TWO_C_ORACLES_PASS_ONLY'
            and child['exception'] is None and child['secondary_errors']==[] and child['denied_effects']==[]
            and child['expected_ids']==child['loaded_ids']==child['actual_ids']==child['success_ids']==list(matrix.IDS)
            and child['tests_run']==13 and child['native_returns']==child['actual_native_starts']==child['validated_native_returns']==2704
            and child['observation_errors']==[] and child['native_counts']==request['native_counts']
            and set(child['C_counts'])==set(matrix.VERSIONS)
            and all(v=={'started':639,'returned':639}for v in child['C_counts'].values())
            and all(child[x]==[] for x in ('failures','errors','skipped','expected_failures','unexpected_successes'))
            and child['source12_VM_reexecuted'] is False and child['database_opened'] is False
            and child['network_used'] is False and child['matching_cold_qualification'] is False,
            'whole original12 and full-page finite native/oracle result')
        _,expected=support.read_json(ROOT/'EXPECTED-MATRIX.json')
        final['native_report']=child_pin
        final['trace']=trace.inspect(ROOT,output/'native/trace',expected)
        common.require(final['trace']==child['full_trace_readback']==worker['full_trace_readback'],
            'three independent whole trace readings differ')
        final['official_oracles']=support.inspect_official_oracles()
        final['retained_source12']=support.inspect_retained_source12(request)
        for label in ('INPUTS','SOURCE'):
            first=support.read_json(output/'native'/(label+'-BEFORE.json'))[1]
            last=support.read_json(output/'native'/(label+'-AFTER.json'))[1]
            common.require(first==last==(before if label=='INPUTS'else source_before),'native child full input/source identity')
            common.require(child[label.lower()+'_before']==support.read_json(output/'native'/(label+'-BEFORE.json'))[0]
                and child[label.lower()+'_after']==support.read_json(output/'native'/(label+'-AFTER.json'))[0],'native independent input/source receipt bindings')
        for label,expected_rows in [('INPUTS',before),('SOURCE',source_before),('SYSTEM',system_before)]:
            prefix='WORKER-' if label!='SYSTEM' else ''
            a=support.read_json(output/(prefix+label+'-BEFORE.json'))[1]
            b=support.read_json(output/(prefix+label+'-AFTER.json'))[1]
            common.require(a==b==expected_rows,'whole worker source/system/input before-after')
        after=support.input_records(request);source_after=support.source_records(request);system_after=support.system_records(request)
        common.require(after==before and source_after==source_before and system_after==system_before,
            'parent independent all frozen inputs unchanged')
        final['inputs_after']=common.create(output/'PARENT-INPUTS-AFTER.json',after)
        final['source_after']=common.create(output/'PARENT-SOURCE-AFTER.json',source_after)
        final['system_after']=common.create(output/'PARENT-SYSTEM-AFTER.json',system_after)
        final['capacity_after']=support.capacity(output)
        final['status']='FINITE_NATIVE_WAL_SNAPSHOT_AND_TWO_ORACLES_PASS_ONLY'
    except BaseException as e:
        final['status']='HOLD';final['errors'].append({'type':type(e).__module__+'.'+type(e).__qualname__,
            'message':str(e)[:1024],'traceback':traceback.format_exc()})
    finally:
        final['elapsed_ns']=time.monotonic_ns()-started
        if final['errors']:final['status']='HOLD'
        common.create(output/'FINAL.json',final)
    print(json.dumps({'status':final['status'],'owner_closed':final['owner_closed'],
                      'owner_natural':final['owner_natural'],'output':str(output)}))
    return 0 if final['status']=='FINITE_NATIVE_WAL_SNAPSHOT_AND_TWO_ORACLES_PASS_ONLY' and not final['errors'] else 1
if __name__=='__main__':raise SystemExit(main())
