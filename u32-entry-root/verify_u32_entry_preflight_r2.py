"""Root read-only preflight for the frozen finite u32 entry-layout gate."""
import ast,hashlib,json,os,shutil,stat,sys,time
from pathlib import Path
helper=Path('/tmp/hia-root-v141-dda7/verify_drive_r3_generation_plan.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='db1de0e35a29c6fc84ea0e59938d7f8170429959'
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'[Root read-only definitions]','exec'),globals())
D=Path('/tmp/hia-u32-entry-layout-r1-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-U32-ENTRY-PREFLIGHT.json')
started=time.monotonic_ns()
raw=(D/'EXECUTION-PLAN.json').read_bytes()
check(raw,dict(bytes=34811,git_blob='8a1cde51b2330375329bfe5c2e7a79be2c4bfbbf',sha256='6c2b0cb2d21284345d8acca1c8e5ddd5547bc236c0bcd495b0d330a9e29797a1'))
p=json.loads(raw)
assert p['status']=='FROZEN_AUTHORING_ONLY_NOT_EXECUTED'
def fixed(row):
    return read_checked(row['path'],row['identity'],row['identity']['mode'])[0]
for row in p['controls'].values():fixed(row)
source=Path(p['source']['path'])
manifest=json.loads((D/'FROZEN-3180-SOURCE.json').read_bytes())
assert len(manifest)==p['source']['files']==3180
treefiles={n:dict(row,mode=row['git_mode']) for n,row in manifest.items()}
assert tree(treefiles)==p['source']['tree']=='4c62be4ed66ff107fa6f88c6131313a354868bd9'
found=set()
for directory,dirs,files in os.walk(source,followlinks=False):
    for n in dirs:assert stat.S_ISDIR((Path(directory)/n).lstat().st_mode)
    found.update((Path(directory)/n).relative_to(source).as_posix() for n in files)
assert found==set(manifest)
for n,row in manifest.items():read_checked(source/n,row,row['mode'])
spec=json.loads((D/'PROJECTION-SPEC.json').read_bytes())
def body(path,name):
    text=Path(path).read_text();n=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
    return ''.join(text.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
original=body(source/spec['original_file'],'qualify_entry_layout')
projected=body(D/'entry_projection.py','qualify_entry_layout_explicit')
assert original==spec['original_function'] and projected==spec['proposed_function'] and len(spec['replacements'])==3
inverse=projected
for row in reversed(spec['replacements']):
    assert inverse.count(row['after'])==1
    inverse=inverse.replace(row['after'],row['before'],1)
assert inverse==original and ast.dump(ast.parse(inverse))==ast.dump(ast.parse(original))
loader=p['loader_projection'];before=fixed(loader['original']);after=fixed(loader['projected'])
inverse=after.decode()
assert len(loader['insertions'])==3
for insertion in loader['insertions']:
    assert inverse.count(insertion)==1
    inverse=inverse.replace(insertion,'',1)
assert inverse.encode()==before and ast.dump(ast.parse(inverse))==ast.dump(ast.parse(before))
functions=json.loads((D/'ORIGINAL-FUNCTIONS.json').read_bytes())
for row in functions.values():
    actual=body(source/row['relative_path'],row['name']).encode()
    assert actual==row['text'].encode() and pin(actual)==row['identity']
test_text=(source/'tests/test_hia_selfhost.py').read_text()
test_cls=next(n for n in ast.parse(test_text).body if isinstance(n,ast.ClassDef) and n.name=='SelfhostNativeTests')
method=next(n for n in test_cls.body if isinstance(n,ast.FunctionDef) and n.name=='test_entry_last_and_middle_whole_compilers_self_reproduce_and_preserve_owned_flow')
assert ''.join(test_text.splitlines(keepends=True)[method.lineno-1:method.end_lineno])==(D/'ORIGINAL-ENTRY-METHOD.py.txt').read_text()
expected=json.loads((D/'EXPECTED-IDS.json').read_bytes())
assert set(expected)-set(p['expected'])=={'original_function_explicit_source_projection','original_method_executed','original_method_id'}
assert p['expected']=={k:v for k,v in expected.items() if k in p['expected']}
assert expected['original_function_explicit_source_projection'] is True and expected['original_method_executed'] is False
assert expected['original_method_id']=='tests.test_hia_selfhost.SelfhostNativeTests.test_entry_last_and_middle_whole_compilers_self_reproduce_and_preserve_owned_flow'
assert expected['call_counts']==dict(compile=24,executable=4,invoke=32,mutation=1,reference=8,tool=8)
assert len(expected['check_ids'])==20 and len(set(expected['check_ids']))==20
assert p['budgets']==dict(ELF_owner_cleanup_seconds=3,ELF_owner_qualification_seconds=15,all_20_share_one_outer_budget=True,cleanup_seconds=3,compile_subprocess_timeout_seconds=20,loader_cpu_seconds=10,native_tool_timeout_seconds=20,qualification_seconds=180,resource_VM_default_max_steps=1000000,source_output_workspace_span_max_bytes=1048576)
inputs=json.loads((D/'ACTUAL-INPUT-MANIFEST.json').read_bytes())
assert inputs['source_tree']==p['source']['tree'] and inputs['source_files']==3180 and len(inputs['files'])==18
for row in inputs['files']:
    data,s=read_checked(row['local_path'],row['identity'],row['mode'])
    assert s['nlink']==1
    assert {k:pin(data)[k] for k in ('bytes','git_blob','sha256')}=={k:row['original_member'][k] for k in ('bytes','git_blob','sha256')}
    assert row['mode']==row['original_NODE']['mode']
assert sum(row['identity']['bytes'] for row in inputs['files'])==4359489
for label,sha in [('B3','56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764'),('M3','9e3b554aee6b819b2764e5018605a00790b2863014c75f4b6c4a2fe217073718')]:
    image=(D/('actual-inputs/'+label+'.image.bin')).read_bytes()
    output=(D/('actual-inputs/'+label+'.output.bin')).read_bytes()
    assert len(image)==658860 and pin(image)['sha256']==sha and len(output)==1048576 and output[:len(image)]==image
assert (source/p['new_source_relative']).read_bytes()==(D/'actual-inputs/B3.input.bin').read_bytes()
rt=p['runtime'];assert sys.version_info[:3]==(3,14,4)
for row in rt.values():
    fixed(dict(path=row.get('resolved_path',row['path']),identity=row['identity']))
for name,row in p['toolchain'].items():
    assert shutil.which(name,path=p['environment']['PATH'])==row['selected_path']
    assert str(Path(row['selected_path']).resolve())==row['path']
    fixed(row)
assert p['ordinary_SOURCE_path']==str(source/'examples/hia_bootstrap/selfhost.hepta') and not p['ordinary_SOURCE_rebound']
assert not p['automatic_retries'] and not p['new_CI']
launchraw=(D/'FINAL-COMMAND-INTENT.json').read_bytes()
assert pin(launchraw)['git_blob']=='47b39924d452b25c02c43d06e726573ea8ee1a01'
launch=json.loads(launchraw)
assert launch['command']==[rt['executable']['path'],'-I','-S','-B',str(D/'run_entry_layout.py'),'--plan-sha256',pin(raw)['sha256']]
assert launch['environment']==p['environment'] and launch['cwd']==str(source)
assert set(p['environment'])=={'HOME','LANG','LC_ALL','LD_LIBRARY_PATH','PATH','PYTHONDONTWRITEBYTECODE','TZ'}
assert p['environment']['LD_LIBRARY_PATH']==str(Path(rt['library']['path']).parent)
assert not Path(p['output']).exists() and not Path(p['output']).is_symlink()
for f in launch['outer_launch_output_files']:assert not Path(f).exists()
v=os.statvfs(D);free=v.f_bavail*v.f_frsize
assert not(v.f_flag&os.ST_NOEXEC) and free>=p['storage']['required_free_bytes']==402653184
report=dict(schema='hepta.root-u32-entry-layout20-preflight.v1',status='PASS_FROZEN_COMPLETE_INPUTS_AND_EXACT_PROJECTIONS_NO_PRODUCTS',plan=pin(raw),launch=pin(launchraw),source_files=3180,source_tree=p['source']['tree'],complete_current_source_bytes_modes_pathset=True,controls_full_bytes_modes=len(p['controls']),actual_original_inputs=18,actual_input_bytes=4359489,whole_entry_function_inverse=True,entry_projection_replacements=3,whole_loader_inverse=True,loader_insertions=3,original_full_function_bodies=len(functions),original_test_method_exact=True,actual_B3_M3_image_output_prefixes=True,original_u32_source_actual_B3_input_equal=True,counts=expected['call_counts'],check_ids=expected['check_ids'],budgets=p['budgets'],runtime_toolchain_full_bytes_modes=True,clean_launch_environment=True,available_output_bytes=free,required_output_bytes=402653184,output_absent=True,product_executions=0,ordinary_encoding_qualification='NOT_RUN',matching_current_cold=False,whole_native=False,production_legacy_retired=False,elapsed_ns=time.monotonic_ns()-started)
with OUT.open('x') as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report,sort_keys=True))
