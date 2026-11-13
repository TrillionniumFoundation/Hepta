"""One original 180/3 owner contains HIA compile, two C compiles and finite trace."""
from pathlib import Path
import importlib,json,os,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common,matrix,trace,support,compile_io,generation
ROOT=support.ROOT
def main():
    path=Path(sys.argv[1]);pin,raw=common.read(path)
    common.require(path==ROOT/'REQUEST.json' and pin['sha256']==sys.argv[2],'frozen native request path/SHA')
    request=json.loads(raw);output=Path(request['output'])
    common.require(request['schema']=='hia.sqlite.wal.native-finite-request.v1'
        and request['qualification_seconds']==180 and request['cleanup_seconds']==3
        and request['native_returns']==238 and request['expected_methods']==10
        and request['expected_ids']==list(matrix.IDS) and dict(os.environ)==request['environment'],
        'same frozen finite scope and exact environment')
    common.require(output.is_dir(),'launcher-created output')
    report={'schema':'hia.sqlite.wal.native-worker.v1','status':'HOLD','request':pin,
        'exception':None,'secondary_errors':[],'native_executed':False,'HIA_compile_executed':False,
        'C_compiles_executed':0,'source10_VM_reexecuted':False,'matching_cold_qualification':False,
        'SQL_or_durability_closed':False,'commands':[]}
    start=time.monotonic_ns()
    try:
        report['runtime']=support.runtime(request)
        before=support.input_records(request);source_before=support.source_records(request);system_before=support.system_records(request)
        report['inputs_before']=common.create(output/'WORKER-INPUTS-BEFORE.json',before)
        report['source_before']=common.create(output/'WORKER-SOURCE-BEFORE.json',source_before)
        report['system_before']=common.create(output/'SYSTEM-BEFORE.json',system_before)
        report['compiler_originals']=support.inspect_compiler_inputs()
        report['original_C']=support.inspect_official_oracles()
        report['new_source_generation']=generation.generate(request)
        _,expected=support.read_json(ROOT/'EXPECTED-MATRIX.json')
        common.require(matrix.manifest(ROOT)==expected,'full frozen matrix authoring differs')
        qdir=output/'hia-compile';qdir.mkdir(mode=0o700)
        sys.path.insert(0,request['source_root'])
        qualifier=importlib.import_module('tools.qualify_hia_selfhost')
        common.require(qualifier.NATIVE_OBSERVER is None and qualifier.NATIVE_LINKED_OBSERVER is None,
                       'original direct 20-wall native compile path')
        report['HIA_compile_executed']=True
        source=common.read(output/'source-generation/sqlite_wal.hiaasm',1<<20)[1]
        qualifier.compile_stage(qdir,'wal',ROOT/'compiler-inputs/B3.image.bin',source)
        report['HIA_compile']=support.inspect_new_compile(qdir,request)
        oracle_pins={}
        for version in matrix.VERSIONS:
            directory=output/('C-'+version);directory.mkdir(mode=0o700);(directory/'tmp').mkdir(mode=0o700)
            q=compile_io.child_request(request,version,directory);qpin=common.create(directory/'REQUEST.json',q)
            argv=[sys.executable,'-I','-S','-B',str(ROOT/'control/compile_child.py'),str(directory/'REQUEST.json'),qpin['sha256']]
            record={'argv':argv,'cwd':str(ROOT),'env':request['environment'],'wall_seconds':20,
                    'start_ns':time.monotonic_ns(),'returncode':None}
            report['commands'].append(record);report['C_compiles_executed']+=1
            try:
                with (directory/'child.stdout.log').open('xb',buffering=0) as stdout,(directory/'child.stderr.log').open('xb',buffering=0) as stderr:
                    p=subprocess.run(argv,cwd=ROOT,env=request['environment'],stdin=subprocess.DEVNULL,
                        stdout=stdout,stderr=stderr,close_fds=True,timeout=20)
                record['returncode']=p.returncode
            finally:record['elapsed_ns']=time.monotonic_ns()-record['start_ns']
            common.require(record['returncode']==0 and record['elapsed_ns']<=20000000000,'one bounded C compile failed')
            result=compile_io.inspect(request,version,directory);report['C-'+version]=result
            oracle_pins[version]=result['image']
        native=output/'native';native.mkdir(mode=0o700)
        image_pin=report['HIA_compile']['pins']['wal.image.bin']
        native_spec={'image':image_pin,'oracles':oracle_pins,'limits':{'cpu_seconds':180,
            'address_bytes':256<<20,'stack_bytes':8<<20,'file_bytes':4<<20,'outer_wall_seconds':180}}
        common.create(native/'NATIVE-INPUTS.json',native_spec)
        argv=[sys.executable,'-I','-S','-B',str(ROOT/'control/native_cases.py'),str(path),pin['sha256']]
        record={'argv':argv,'cwd':str(ROOT),'env':request['environment'],'separate_wall_budget':None,
                'start_ns':time.monotonic_ns(),'returncode':None}
        report['commands'].append(record);report['native_executed']=True
        try:
            with (native/'child.stdout.log').open('xb',buffering=0) as stdout,(native/'child.stderr.log').open('xb',buffering=0) as stderr:
                p=subprocess.run(argv,cwd=ROOT,env=request['environment'],stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,close_fds=True)
            record['returncode']=p.returncode
        finally:record['elapsed_ns']=time.monotonic_ns()-record['start_ns']
        common.require(record['returncode']==0,'finite native child failed')
        childpin,child=support.read_json(native/'REPORT.json',4<<20)
        common.require(child['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY'
            and child['exception'] is None and child['secondary_errors']==[] and child['denied_effects']==[]
            and child['expected_ids']==child['loaded_ids']==child['actual_ids']==child['success_ids']==list(matrix.IDS)
            and child['tests_run']==10 and child['native_returns']==child['actual_native_starts']==238
            and child['native_counts']==expected['counts']
            and all(child[k]==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes')),
            'full native child result population')
        report['native_report']=childpin
        report['full_trace_readback']=trace.inspect(ROOT,native/'trace',expected)
        report['imports']=support.current_imports(request)
        after=support.input_records(request);source_after=support.source_records(request);system_after=support.system_records(request)
        report['inputs_after']=common.create(output/'WORKER-INPUTS-AFTER.json',after)
        report['source_after']=common.create(output/'WORKER-SOURCE-AFTER.json',source_after)
        report['system_after']=common.create(output/'SYSTEM-AFTER.json',system_after)
        common.require(after==before and source_before==source_after and system_before==system_after,
                       'all original/source/system identities unchanged')
        report['status']='FINITE_NATIVE_WORKER_PASS_ONLY'
    except BaseException as e:
        report['status']='HOLD';report['exception']=type(e).__module__+'.'+type(e).__qualname__+': '+str(e)[:1024]
        report['traceback']=traceback.format_exc()
    finally:
        report['elapsed_ns']=time.monotonic_ns()-start
        if report['elapsed_ns']>180000000000 or report['exception'] is not None or report['secondary_errors']:
            report['status']='HOLD'
        common.create(output/'WORKER.json',report)
        print(json.dumps({'status':report['status'],'native_executed':report['native_executed'],
                          'elapsed_ns':report['elapsed_ns']}))
    return 0 if report['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' else 1
if __name__=='__main__':raise SystemExit(main())
