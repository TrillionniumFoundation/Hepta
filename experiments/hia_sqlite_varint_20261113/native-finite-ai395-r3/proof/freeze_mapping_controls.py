from pathlib import Path
import ast,hashlib,json,os,stat
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3')
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(path):
    s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    b=path.read_bytes();assert ident(s)==ident(path.lstat())
    return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'identity':ident(s)}
def create(path,value):
    b=wire(value)
    with path.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o600);assert path.read_bytes()==b
q=json.loads((P/'REQUEST.json').read_bytes())
script=P/'proof/mapping_source_controls.py';tree=ast.parse(script.read_bytes())
names=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
assert len(names)==16
controls=pin(script)
plan={'schema':'hia.sqlite.varint.bound-map-pure-control-request.v1','status':'UNEXECUTED_ROOT_UNIQUE_OWNER_REQUIRED',
 'qualification_seconds':20,'cleanup_seconds':3,'original_owner':pin(P/'control/process_owner_impl.py'),
 'runtime':q['runtime'],'python_version':q['python_version'],'boot_id':q['boot_id'],
 'expected_ids':list(names),'expected_methods':16,'positive_current_mapping_cases':2,'negative_refusal_cases':14,
 'command':['/usr/bin/python3.14','-I','-S','-B',str(script),str(P.parent/'varint-native-r3-mapping-controls-actual-r1')],
 'cwd':str(P),'environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0'},
 'actual_root':str(P.parent/'varint-native-r3-mapping-controls-actual-r1'),
 'owner_root':str(P.parent/'varint-native-r3-mapping-controls-owner-r1'),
 'inputs':{'control':controls,'observed_function':pin(P/'control/support.py'),'native_request':pin(P/'REQUEST.json')},
 'scope':'Extract only exact loaded_file_maps AST; all mmap/ctypes/proc-map/file-map actions fake and explicit. No project imports, compiler, native image or C/SQL/network execution.',
 'real_native_returns':0,'original_native_population_unchanged':76054,'original_source8_not_reexecuted':True,
 'required_before_root_native_authorization':True}
create(P/'proof/MAPPING-CONTROL-REQUEST.json',plan)
correction={'schema':'hia.sqlite.varint.mapping-observer-correction.v1','status':'NEW_R3_UNEXECUTED',
 'old_request_commit':'230e6a5ae80ad1725922fd99e49d1ba3069dd2d8','closed_failure_commit':'307708ebd56803dad5b52f3986988313a9765429',
 'root_only_new_execution':True,'prior_qualification_status':'HOLD','prior_actual_native_returns':0,
 'product_sources_unchanged':['generator','bridge','ABI','two official C algorithms','matrix.py','trace.py'],
 'changed_runtime_sources':['support.loaded_file_maps','native_cases Context observer identity and two map observations','launch exact new output/status'],
 'unchanged_native_limits':{'owner_seconds':180,'cleanup_seconds':3,'compiler_wall_seconds':20,'compiler_cpu_seconds':10,'compiler_output_capacity':1048576,
   'source8_vectors':1618,'method_count':8,'returns':76054,'trace_bytes':207481528,'trace_limit':268435456,'output_limit':402653184,
   'initial_free_bytes':1073741824,'reserve_free_bytes':536870912,'free_inodes':4096},
 'mapping_admission':'Exact current mmap object, entry address, logical size, current output image full bytes/SHA and one page-rounded shared RX offset-zero map. Only that segment may use /dev/zero (deleted) or unnamed anonymous representation.',
 'conservative_boundary':'Any split/merged current span, additional same-backing alias, unbound executable anonymous mapping, or unbound deleted path is HOLD. No blanket deleted-path or size waiver.',
 'retention':'Full maps original and initial object/address/image binding are written before parsing/classification; full resulting image binding checked unchanged after all calls.',
 'controls':plan,'unexecuted_authoring_draft_note':'The first authoring-script text omitted LAUNCH.request full metadata replacement; corrected in r1b before the first static preparation. It was never run. Both script texts remain on disk.'}
create(P/'proof/CORRECTION.json',correction)
print(json.dumps({'status':'FROZEN_UNEXECUTED_SOURCE16_ONLY','control_request':pin(P/'proof/MAPPING-CONTROL-REQUEST.json'),'correction':pin(P/'proof/CORRECTION.json'),'source_ast':True}))
