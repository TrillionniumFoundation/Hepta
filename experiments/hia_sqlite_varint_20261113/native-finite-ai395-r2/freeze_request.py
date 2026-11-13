"""Freeze only new ai395 identities and an unexecuted finite request."""
from pathlib import Path
import ast,hashlib,json,os,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'control'))
import common,matrix,support
def main():
    for n in ('REQUEST.json','LAUNCH.json','FROZEN-READBACK.json'):
        if (ROOT/n).exists():raise RuntimeError('new freeze only: '+n)
    _,sysmap=support.read_json(ROOT/'SYSTEM-INPUTS-r4.json')
    _,src=support.read_json(ROOT/'SOURCE-BASE.json')
    _,calc=support.read_json(ROOT/'STATIC-CALCULATIONS.json')
    common.require(calc['status']=='STATIC_CALCULATIONS_ONLY_NO_QUALIFICATION','static calculations did not complete')
    _,prior=support.read_json(ROOT/'reference/source8-actual/tests/REPORT.json')
    common.require(prior['status']=='SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY'
        and prior['expected_ids']==prior['loaded_ids']==prior['actual_ids']==prior['success_ids']
        and len(prior['expected_ids'])==8 and prior['vm']['actual_return_count']==1618,'original Source8 denominator')
    names=[]
    for base in ('candidate','reference','compiler-inputs','control'):
        for p in sorted((ROOT/base).rglob('*')):
            if p.is_file():names.append(str(p.relative_to(ROOT)))
    names+=['SOURCE-BASE.json','SYSTEM-INPUTS-r4.json','RESTORED-ORIGINALS.json',
            'COMPILER-READBACK.json','EXPECTED-MATRIX.json','EXPECTED-TRACE.json','PREEXECUTION-PLAN.md']
    inputs={n:common.read(ROOT/n)[0] for n in names}
    ast_names=[]
    for n in names:
        if n.endswith('.py') and n.startswith(('control/','candidate/inputs/')):
            ast.parse(common.read(ROOT/n)[1],filename=str(ROOT/n));ast_names.append(n)
    runtime=support.system_read(Path(sys.executable).resolve())
    common.require(runtime==sysmap['runtime'] and sys.version_info[:3]==(3,14,4),'fresh runtime differs from captured system')
    output=ROOT.parent/'varint-native-r2-actual'
    environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC',
        'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','TMPDIR':str(output/'tmp')}
    child=support.read_json(ROOT/'SOURCE-BASE.json')[1]
    child_sha=next(r['sha256'] for r in child['files'] if r['path']=='tools/hia_selfhost_child.py')
    request={'schema':'hia.sqlite.varint.native-finite-request.v2',
        'status':'REAUTHORED_CONTROLS_AFTER_ENVIRONMENT_CHANGE_UNEXECUTED',
        'root':str(ROOT),'host':'ai395','runtime':runtime,'python_version':sys.version,
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'uid':os.getuid(),'gid':os.getgid(),'output':str(output),'inputs':inputs,
        'source_commit':src['source_commit'],'source_tree':src['source_tree'],'source_map':'SOURCE-BASE.json',
        'system_map':'SYSTEM-INPUTS-r4.json','system_count':sysmap['count'],'system_bytes':sysmap['bytes'],
        'system_binaries':sysmap['binaries'],'original_child_sha256':child_sha,
        'environment':environment,'command':[runtime['path'],'-I','-S','-B',str(ROOT/'control/worker.py'),str(ROOT/'REQUEST.json'),'@REQUEST_SHA256@'],
        'qualification_seconds':180,'cleanup_seconds':3,'compiler_wall_seconds':20,'compiler_cpu_seconds':10,
        'compiler_output_capacity':1<<20,'compiler_workspace_bytes':1<<20,
        'expected_ids':list(matrix.IDS),'expected_methods':8,'native_returns':76054,
        'source8_original_vectors':1618,'original_source8_ids':prior['expected_ids'],
        'source8_reexecute':False,'source8_commit':'bfe97dc70f0c3470621605946f55aaa2ec67419d',
        'trace_bytes_limit':256<<20,'trace_chunk_limit':4<<20,'trace_record_limit':3072,
        'output_bytes_limit':384<<20,'output_files_limit':192,'initial_free_bytes':1<<30,
        'reserve_free_bytes':512<<20,'free_inodes':4096,
        'development_compiler':{'donor':'df7cc43d9b225108924aef972b10f67a5a0dfb29','historical_run':43220208164,
            'image_sha256':inputs['compiler-inputs/B3.image.bin']['sha256'],'image_bytes':670467,
            'complete_original_count':7,'current_source_matching_cold':False},
        'original_caps':{'input_bytes':1<<20,'lines':16384,'functions':128,'blocks':1536,'operations':8192,
            'ssa_slots':2048,'blocks_per_function':256,'args':16,'results':3},
        'scope':'finite native varint and two complete original C algorithms; no SQL/database/durability or current matching cold'}
    # Full new input/source/system identity reads; no generator, VM, C compilation or native execution.
    common.require(support.input_records(request)==inputs,'whole control input set differs')
    source=support.source_records(request);system=support.system_records(request)
    common.require(len(source)==1686 and len(system)==sysmap['count'],'whole fresh sets')
    common.require(not output.exists(),'actual output already exists')
    pin=common.create(ROOT/'REQUEST.json',request)
    launch={'schema':'hia.sqlite.varint.native-launch.v2','status':'UNEXECUTED_ROOT_REVIEW_REQUIRED',
        'cwd':str(ROOT),'environment':environment,'argv':[runtime['path'],'-I','-S','-B',
             str(ROOT/'control/launch.py'),str(ROOT/'REQUEST.json'),pin['sha256']],
        'request':pin,'single_invocation':True,'qualification_seconds':180,'cleanup_seconds':3,
        'actual_output':str(output),'old_request_replayed':False}
    lpin=common.create(ROOT/'LAUNCH.json',launch)
    proof={'schema':'hia.sqlite.varint.preexecution-readback.v2','status':'FROZEN_UNEXECUTED',
        'request':pin,'launch':lpin,'inputs':inputs,'input_count':len(inputs),'input_bytes':sum(p['bytes'] for p in inputs.values()),
        'AST_only':ast_names,'whole_source_count':len(source),'whole_source_bytes':sum(p['bytes'] for p in source.values()),
        'whole_system_count':len(system),'whole_system_bytes':sum(p['bytes'] for p in system.values()),
        'source8_reexecuted':False,'HIA_compiled':False,'C_compiled':False,'native_executed':False,
        'original_source8_ids':prior['expected_ids'],'expected_native_ids':list(matrix.IDS),
        'expected_matrix':calc['matrix'],'expected_trace':calc['full_trace_projection'],
        'input_after':support.input_records(request),'runtime':runtime}
    common.require(proof['inputs']==proof['input_after'],'freeze changed an input')
    ppin=common.create(ROOT/'FROZEN-READBACK.json',proof)
    print(json.dumps({'status':proof['status'],'request':pin,'launch':lpin,'readback':ppin,
        'inputs':len(inputs),'source':len(source),'system':len(system)}))
if __name__=='__main__':main()
