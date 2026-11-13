"""Freeze one finite selected-cell native request; ordinary-data authoring only, no product execution."""
from pathlib import Path
import ast,difflib,hashlib,json,os,stat,sys
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
ROOT=P/'sqlite-btree-cell-native-r1'
OLD=P/'sqlite-record-native-r1'
SOURCE_PLAN=P/'sqlite-btree-cell-source-r1'
OUTPUT=P/'sqlite-btree-cell-native-r1-actual'
SOURCE_CANONICAL='69a6e96e40499a86db48f76e6d2bc54dd9788d06'
ASM_SHA='86776116010d389bf65c453917fda929627f3ee564330e56a3e33af32726a6b7'
OWNER_SHA='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
    p=Path(p);s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise RuntimeError('fixed regular single-link authoring input '+str(p))
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        if ident(os.fstat(f.fileno()))!=ident(s):raise RuntimeError('open identity changed')
        b=f.read()
        if ident(os.fstat(f.fileno()))!=ident(s):raise RuntimeError('input changed during read')
    if ident(p.lstat())!=ident(s) or len(b)!=s.st_size:raise RuntimeError('named input changed')
    return b
def pin(p):
    b=read(p);s=Path(p).lstat()
    return {'path':str(p),'bytes':len(b),'sha256':sha(b),'git_blob':git(b),'identity':ident(s)}
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(p,b):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    if read(p)!=b:raise RuntimeError('new bytes readback')
def copy(a,b):put(b,read(a))
def require(v,m):
    if not v:raise RuntimeError(m)
def main():
    require(ROOT.is_dir() and not (ROOT/'REQUEST.json').exists() and not os.path.lexists(OUTPUT),
        'one new frozen request and still-absent actual output')
    old_raw=read(OLD/'REQUEST.json')
    require(sha(old_raw)=='48583129f1202d74256190dae479622110e787ae3e744bc1b4f5e596c9fa399c',
        'actual-passed Record scaffold exact request')
    old=json.loads(old_raw)
    # Bind only inert control modules; no project namespace is imported here.
    sys.path.insert(0,str(ROOT/'control'))
    import common,matrix,trace,support
    require(not any(n=='hepta' or n.startswith('hepta.') or n=='tools' or n.startswith('tools.')
                    or n=='tests' or n.startswith('tests.') for n in sys.modules),'no project import in freeze')
    require(sha(read(ROOT/'control/process_owner_impl.py'))==OWNER_SHA,'unchanged original process owner')
    test=ROOT/'candidate/inputs/tests/test_hia_sqlite_btree_cell_source.py'
    gen=ROOT/'candidate/inputs/tools/generate_hia_sqlite_btree_cell.py'
    require(sha(read(test))=='c8031eb8e8b550e27d8a8162374331d281d07a07c9fc01a5e2c5552dd2af69d3',
        'all original twelve method bytes preserved')
    require(sha(read(gen))=='9edaa0a5225b1f39ae0c0e2a72aaceef1a20925bd3d0be170cffd202a1611245','exact R3 generator')
    assembly=ROOT/'reference/source12-actual/tests/sqlite_btree_cell.hiaasm'
    b=read(assembly);require(len(b)==40803 and sha(b)==ASM_SHA and git(b)=='b3501809e552ead73607a690ec45bb78ee1eda6e',
        'actual complete R3 assembly')
    control_before={p.name:pin(p) for p in sorted((ROOT/'control').iterdir())}
    require(len(control_before)==11,'exact ten controls plus unchanged original owner')
    for p in sorted(ROOT.rglob('*.py')):ast.parse(read(p),filename=str(p))
    original_oracles=support.inspect_official_oracles()
    expected=matrix.manifest(ROOT)
    digest=hashlib.sha256();trace_bytes=max_record=records=0
    for spec in matrix.specifications(ROOT):
        for row in trace.expected_records(spec):
            raw=matrix.wire(row);digest.update(raw);trace_bytes+=len(raw);records+=1;max_record=max(max_record,len(raw))
    require(records==678 and trace_bytes<=256<<20 and max_record<=16<<20,'original complete trace bounds')
    # All copied reference bytes are matched to their prior fixed producer before copying.
    for name in ('B3-ORIGINALS-CUSTODY.json','COMPILER-ORIGIN.json'):
        p=OLD/'reference'/name
        require(pin(p)==old['inputs']['reference/'+name],'prior fixed compiler reference changed')
        copy(p,ROOT/'reference'/name)
    copy(OLD/'REQUEST.json',ROOT/'reference/RECORD-NATIVE-REQUEST.original.json')
    copy(OLD/'EXECUTE.json',ROOT/'reference/RECORD-NATIVE-EXECUTE.original.json')
    copy(OLD/'envelope/clean_exec.py',ROOT/'reference/RECORD-CLEAN-EXEC.original.py')
    copy(SOURCE_PLAN/'REQUEST-r3.json',ROOT/'reference/SOURCE12-R3-REQUEST.original.json')
    copy(SOURCE_PLAN/'STATIC-FREEZE-r3.json',ROOT/'reference/SOURCE12-R3-STATIC-FREEZE.original.json')
    copy(P/'sqlite-btree-cell-source12-actual-audit-r3/AUDIT.json',ROOT/'reference/SOURCE12-R3-INDEPENDENT-AUDIT.original.json')
    copy(P/'sqlite-btree-cell-source12-combined-publication-r1/CANONICAL.json',ROOT/'reference/SOURCE12-CANONICAL.original.json')
    peer=P/'peer-btree-cell-native-matrix-trace-r1.json'
    peer_body=read(peer)
    require(len(peer_body)==3201 and sha(peer_body)=='8e73500a367aa9a88387951b9c6d615d55be296a38c3236eb6727475ed382be0',
        'fixed limited independent matrix/trace peer')
    put(ROOT/'reference/MATRIX-TRACE-PEER.original.json',peer_body)
    put(ROOT/'EXPECTED-MATRIX.json',wire(expected))
    expected_trace={'schema':'hia.sqlite.btree.cell.expected-complete-native-trace.v1','native_returns':339,
        'records':records,'bytes':trace_bytes,'sha256':digest.hexdigest(),'largest_record_bytes':max_record,
        'record_limit':16<<20,'chunk_limit':4<<20,'total_limit':256<<20,
        'records_may_cross_physical_chunks':True,'all_full_buffers_no_sampling':True,
        'pure_expectation_only_no_HIA_VM_C_execution':True}
    put(ROOT/'EXPECTED-TRACE.json',wire(expected_trace))
    delta=''.join(''.join(difflib.unified_diff(read(ROOT/'reference/record-control-originals'/p.name).decode().splitlines(True),
                read(p).decode().splitlines(True),fromfile='record-original/'+p.name,tofile='btree-native/'+p.name))
            for p in sorted((ROOT/'control').iterdir()))
    put(ROOT/'proof/RECORD-TO-BTREE-CONTROLS.patch',delta.encode())
    scope={'schema':'hia.sqlite.btree.cell.native-static-authorship.v1','status':'STATIC_AUTHORED_UNEXECUTED',
        'source12_combined_canonical':SOURCE_CANONICAL,'source12_R1_preowner_refusal_preserved':True,
        'source12_R2_cap_HOLD_preserved':True,'source12_R3_scope':'SOURCE12_VM_PASS_ONLY',
        'native_scaffold_request':'b9477753cddf49aad19694bde011caee0e8f6c30',
        'native_scaffold_actual':'a0d3af18bf0cde0bd6e5e977cc0ce5bd53cb97b3',
        'original_method_bodies_unchanged':12,'original_VM_returns_not_reexecuted':339,
        'new_native_returns':339,'C_cells_each':253,'refused_cells_C_not_called':86,
        'C_complete_record_or_page_or_engine_oracle':False,'original_owner':OWNER_SHA,
        'new_generation_must_match_R3_actual':pin(assembly),'original_C':original_oracles,
        'same_owner_new_generation_HIA_compile_two_C_compiles_original_twelve_methods':True,
        'native_calls':0,'C_compiles':0,'HIA_generation':0,'HIA_compiles':0,'VM_calls':0,
        'historical_B3_current_matching_cold':False,
        'matrix_applicability':'Frozen R3 statuses and complete independent valid-cell parsing; never chosen from new HIA status.',
        'raw_C_before_assert':'Returned status, whole source/output/canary and six original CellInfo words are kept before projection assertions.',
        'fields_outside_C':['page_number','page_type','usable_size','cell_count','cell_index','cell_offset','left_child',
            'overflow_page','overflow_pointer_offset','overflow_page_count','last_overflow_payload_size']}
    put(ROOT/'STATIC-AUTHORING.json',wire(scope))
    syntax=[]
    for p in sorted(ROOT.rglob('*.py')):
        body=read(p);ast.parse(body,filename=str(p))
        syntax.append({'path':str(p.relative_to(ROOT)),'bytes':len(body),'sha256':sha(body),'git_blob':git(body)})
    put(ROOT/'AST-PARSE.json',wire({'schema':'hia.sqlite.btree.cell.inert-parse.v1','files':syntax,
        'only_AST_no_project_module_execution':True}))
    source_manifest=json.loads(read(ROOT/'SOURCE-BASE.json'))
    environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1',
        'PYTHONHASHSEED':'0','TMPDIR':str(OUTPUT/'tmp')}
    request={'schema':'hia.sqlite.btree.cell.native-finite-request.v1',
        'status':'BTREE_CELL_ORIGINAL_TWELVE_NATIVE_TWO_C_ORACLES_UNEXECUTED',
        'root':str(ROOT),'output':str(OUTPUT),'runtime':old['runtime'],'python_version':old['python_version'],
        'boot_id':old['boot_id'],'uid':os.getuid(),'gid':os.getgid(),
        'source_commit':old['source_commit'],'source_tree':old['source_tree'],
        'source_root':source_manifest['source_root'],'source_map':'SOURCE-BASE.json',
        'system_map':'SYSTEM-INPUTS.json','system_count':old['system_count'],'system_bytes':old['system_bytes'],
        'system_binaries':old['system_binaries'],'original_child_sha256':old['original_child_sha256'],
        'environment':environment,'qualification_seconds':180,'cleanup_seconds':3,
        'command':[sys.executable,'-I','-S','-B',str(ROOT/'control/worker.py'),str(ROOT/'REQUEST.json'),'@REQUEST_SHA256@'],
        'expected_ids':list(matrix.IDS),'expected_methods':12,'original_source_methods':12,'native_returns':339,
        'native_counts':list(matrix.COUNTS),'oracle_calls_each':expected['oracle_calls_each'],
        'trace_bytes_limit':256<<20,'trace_chunk_limit':4<<20,'trace_record_limit':16<<20,
        'output_bytes_limit':384<<20,'output_files_limit':192,'initial_free_bytes':1<<30,
        'reserve_free_bytes':512<<20,'free_inodes':4096,'original_caps':old['original_caps'],
        'compiler_wall_seconds':20,'compiler_cpu_seconds':10,'compiler_output_capacity':1<<20,
        'compiler_workspace_bytes':1<<20,'development_compiler':old['development_compiler'],'host':'ai395',
        'source12_request_commit':SOURCE_CANONICAL,'source12_actual_commit':SOURCE_CANONICAL,
        'new_same_owner_source_generation':True,'source12_actual_assembly_sha256':ASM_SHA,
        'source12_actual_VM_raw_sha256':matrix.SOURCE12_RAW_SHA,'old_VM_actual_reconstructed':False,
        'source12_VM_reexecute':False,
        'scope':'Original12 methods and339 actual native calls. Two original C versions compare253 complete preadmitted CellInfo results each;86 refused calls NOT_CALLED. No malformed-input C, wholepage/tree, SQL/pager, durability, matching-cold or default application integration.'}
    request['inputs']={str(p.relative_to(ROOT)):pin(p) for p in sorted(ROOT.rglob('*')) if p.is_file()}
    support.runtime(request);source=support.source_records(request);system=support.system_records(request)
    require(len(source)==1686 and len(system)==4806,'unchanged complete physical source/system denominators')
    support.inspect_compiler_inputs()
    require({p.name:pin(p) for p in sorted((ROOT/'control').iterdir())}==control_before,'control bytes/identity changed during freeze')
    require(not any(n=='hepta' or n.startswith('hepta.') or n=='tools' or n.startswith('tools.')
                    or n=='tests' or n.startswith('tests.') for n in sys.modules),'project imported during inert preparation')
    put(ROOT/'REQUEST.json',wire(request));qpin=pin(ROOT/'REQUEST.json')
    launch={'schema':'hia.sqlite.btree.cell.native-launch.v1','status':'UNEXECUTED_ROOT_UNIQUE_INVOCATION_REQUIRED',
        'argv':[sys.executable,'-I','-S','-B',str(ROOT/'control/launch.py'),str(ROOT/'REQUEST.json'),qpin['sha256']],
        'cwd':str(ROOT),'environment':environment,'request':qpin,'qualification_seconds':180,'cleanup_seconds':3,
        'single_invocation':True,'actual_output':request['output'],'Source12_VM_replayed':False}
    put(ROOT/'LAUNCH.json',wire(launch));lpin=pin(ROOT/'LAUNCH.json')
    old_execute=json.loads(read(OLD/'EXECUTE.json'));clean=read(OLD/'envelope/clean_exec.py').decode()
    require(pin(OLD/'envelope/clean_exec.py')==old_execute['clean_exec'],'original clean-exec exact full pin')
    require(old_execute['inner_launch']['bytes']==1403 and old_execute['inner_launch']['sha256']=='9550bc3e79c5fb90eaa76f4f0baec33744d2926d7e6c30358f4d16656aab59f4','old launch template constants')
    clean=clean.replace(str(OLD),str(ROOT)).replace('new record controls','new selected-cell controls')
    clean=clean.replace("LAUNCH_SHA='9550bc3e79c5fb90eaa76f4f0baec33744d2926d7e6c30358f4d16656aab59f4'","LAUNCH_SHA='"+lpin['sha256']+"'")
    clean=clean.replace('!=1403','!='+str(lpin['bytes'])).replace('os.read(fd,1404)','os.read(fd,'+str(lpin['bytes']+1)+')')
    ast.parse(clean);put(ROOT/'envelope/clean_exec.py',clean.encode())
    execute={'schema':'hia.sqlite.btree.cell.clean-execution.v1','status':'UNEXECUTED_ROOT_UNIQUE_INVOCATION_REQUIRED',
        'argv':[sys.executable,'-I','-S','-B',str(ROOT/'envelope/clean_exec.py')],'cwd':str(ROOT),
        'shell_env_overlay':False,'effective_environment':environment,'request':qpin,'inner_launch':lpin,
        'clean_exec':pin(ROOT/'envelope/clean_exec.py'),'qualification_seconds':180,'cleanup_seconds':3,
        'actual_output':request['output'],'original_twelve_methods339_preserved':True,'Source12_VM_replayed':False}
    put(ROOT/'EXECUTE.json',wire(execute))
    proof={'schema':'hia.sqlite.btree.cell.native-static-freeze.v1','status':'FROZEN_NO_QUALIFICATION_EXECUTED',
        'request':qpin,'launch':lpin,'execute':pin(ROOT/'EXECUTE.json'),'input_count':len(request['inputs']),
        'source_count':len(source),'source_bytes':sum(v['bytes'] for v in source.values()),
        'system_count':len(system),'system_bytes':sum(v['bytes'] for v in system.values()),
        'expected_matrix':expected,'trace_projection':expected_trace,'C_section_join_only':original_oracles,
        'original_shared_source_and_system_readonly':True,'no_qualification_execution':True,
        'capacity_now':support.capacity(P,True)}
    put(ROOT/'STATIC-FREEZE.json',wire(proof))
    handoff={'schema':'hia.sqlite.btree.cell.native-request-handoff.v1','status':'UNEXECUTED_ROOT_REVIEW_REQUIRED',
        'root':str(ROOT),'request':qpin,'execute':pin(ROOT/'EXECUTE.json'),'source_commit':request['source_commit'],
        'source_root':request['source_root'],'historical_B3_only':True,'input_count':len(request['inputs']),
        'expected_methods':12,'native_returns':339,'oracle_calls_each':expected['oracle_calls_each'],
        'source12_canonical':SOURCE_CANONICAL,'new_source_generation':'Within original180/3; byte-exact equality to R3 actual40803B assembly; no VM replay.',
        'C_domain':'253 preadmitted complete cells each version;86 refusal cases NOT_CALLED. No C malformed/wholepage/tree oracle.',
        'owner':{'qualification_seconds':180,'cleanup_seconds':3},
        'compilation':{'HIA':1,'C':2,'each_wall_seconds':20,'each_cpu_seconds':10,'image_limit':1<<20},
        'trace':expected_trace,'source_VM_or_native_executions_so_far':0,'canonical_pending':True}
    put(ROOT/'HANDOFF.json',wire(handoff))
    print(json.dumps({'status':proof['status'],'request':qpin,'execute':pin(ROOT/'EXECUTE.json'),
        'fixed_inputs':len(request['inputs']),'source_count':len(source),'system_count':len(system),
        'expected_methods':12,'native_returns':339,'oracle_calls_each':expected['oracle_calls_each'],
        'expected_trace':expected_trace}))
if __name__=='__main__':main()
