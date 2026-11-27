"""Root read-only static and full protected-source preflight for drive R3 generation."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

D = Path('/tmp/hia-inspect-drive-generation-r3-dda7')
OUT = Path('/tmp/hia-root-v141-dda7/ROOT-DRIVE-R3-GENERATION-REVIEW.json')
def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def check(raw, want):
    got=pin(raw)
    assert all(got[k]==want[k] for k in got), (got,want)
    return got
def seven(s):
    return {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),
            'nlink':s.st_nlink,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
def read_checked(path, expected, mode):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==mode
        pieces=[]
        while True:
            b=os.read(fd,1048576)
            if not b:break
            pieces.append(b)
        raw=b''.join(pieces)
        assert seven(before)==seven(os.fstat(fd))==seven(path.lstat())
        check(raw,expected)
        return raw,seven(before)
    finally:os.close(fd)
def tree(files):
    root={}
    for name,row in files.items():
        parts=name.split('/');assert all(p and p not in ('.','..') for p in parts)
        node=root
        for part in parts[:-1]:node=node.setdefault(part,{})
        assert parts[-1] not in node
        node[parts[-1]]=(row['mode'],row['git_blob'])
    def recurse(node):
        rows=[]
        for name,value in node.items():
            directory=isinstance(value,dict)
            mode,sha=('40000',recurse(value)) if directory else value
            rows.append(((name+'/' if directory else name).encode(),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
        body=b''.join(v for _,v in sorted(rows))
        return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
    return recurse(root)
def source_capture(path,capture):
    assert not capture['errors']
    observed=set()
    for directory,dirs,files in os.walk(path,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        for name in files:observed.add((Path(directory)/name).relative_to(path).as_posix())
    assert observed==set(capture['files'])
    inodes=set()
    for name,row in capture['files'].items():
        _,s=read_checked(path/name,row,capture['stat'][name]['mode'])
        assert s==capture['stat'][name],name
        inodes.add((s['device'],s['inode']))
    return inodes

started=time.monotonic_ns()
plan_raw=(D/'PLAN.json').read_bytes()
check(plan_raw,{'bytes':7255,'git_blob':'6c46d078e3f3c35fe4b9c75950451dd3e66d9bb3','sha256':'93248ecbf2708a0cbc0e40540b0fadeb19dd90d3bb1499e62794e9ee89ec8a03'})
plan=json.loads(plan_raw)
runner,_=read_checked(D/'run_generation.py',plan['runner'],0o644)
launch_raw=(D/'LAUNCH.json').read_bytes()
assert pin(launch_raw)['git_blob']=='48a6aa4b38720aef07e27aa8047de75687148379'
launch=json.loads(launch_raw)
assert launch['plan']['pin']==dict(pin(plan_raw),mode='100644')
assert launch['runner']['pin']==plan['runner']
materials={}
for name,row in plan['inputs'].items():
    materials[name],_=read_checked(row['path'],row['pin'],row['posix_mode'])
inverse=json.loads((D/'RUNNER-BYTE-INVERSE.json').read_bytes())
restored=runner.decode()
for change in reversed(inverse['changes']):
    assert restored.count(change['after'])==1,change['label']
    restored=restored.replace(change['after'],change['before'],1)
assert restored.encode()==materials['original_generation_runner']
old=materials['original_generation_runner'].decode();new=runner.decode()
old_ast,new_ast=ast.parse(old),ast.parse(new)
of={n.name:ast.get_source_segment(old,n) for n in old_ast.body if isinstance(n,ast.FunctionDef)}
nf={n.name:ast.get_source_segment(new,n) for n in new_ast.body if isinstance(n,ast.FunctionDef)}
assert set(of)-set(nf)==set()
modified={name for name in of if of[name]!=nf[name]}
assert modified=={'load_plan','authorities','pair_capture','bind_generated_identity','execute'}
assert set(nf)-set(of)=={'evidence_authority','legacy_authority','protected_capture','materialize'}
assert len(of)-len(modified)==26
for name in ('child','install_outputs','read_exact','write_fence','actual_runtime','main'):
    assert of[name]==nf[name]
helpers='\n\n\n'.join(nf[n] for n in ('evidence_authority','legacy_authority','protected_capture','materialize'))
assert (D/'NEW-HELPERS.txt').read_text().strip()==helpers.strip()
assert (D/'AUTHORITIES.txt').read_text().strip()==nf['authorities'].strip()
assert (D/'PAIR-CAPTURE.txt').read_text().strip()==nf['pair_capture'].strip()
base=json.loads(materials['source_capture']);legacy=json.loads(materials['base_capture'])
assert json.loads(materials['source_map'])==base['files']
assert len(base['files'])==3188 and tree(base['files'])=='741fa64dadb37f98ab9b195f1ee7b67fe683fc70'
assert len(legacy['files'])==3187 and tree(legacy['files'])=='7df49dd24bbba4ba3210168e639d6ea35a76a475'
base_inodes=source_capture(Path(plan['base']),base)
legacy_inodes=source_capture(Path(plan['legacy']),legacy)
assert len(base_inodes)==3188 and base_inodes.isdisjoint(legacy_inodes)
design=json.loads(materials['design']);change=design['change'];relative=change['path']
assert relative=='hepta/hia_inspect_program_native.py' and change['before']==base['files'][relative]
before,_=read_checked(Path(plan['base'])/relative,change['before'],0o644)
overlay=materials['overlay'];insertion=change['inserted_method_utf8'].encode()
assert overlay.count(insertion)==1 and overlay.replace(insertion,b'',1)==before
before_ast,after_ast=ast.parse(before),ast.parse(overlay)
bc=next(n for n in before_ast.body if isinstance(n,ast.ClassDef) and n.name=='InspectProgramFrame')
ac=next(n for n in after_ast.body if isinstance(n,ast.ClassDef) and n.name=='InspectProgramFrame')
assert not any(isinstance(n,ast.FunctionDef) and n.name=='drive' for n in bc.body)
added=[n for n in ac.body if isinstance(n,ast.FunctionDef) and n.name=='drive'];assert len(added)==1
ac.body.remove(added[0]);assert ast.dump(before_ast)==ast.dump(after_ast)
wanted=dict(base['files']);wanted[relative]=change['after']
assert tree(wanted)==plan['derived_materialized_tree']=='292de63f31f2634043f6b02559d3e6fa6253c4f1'
scope=Path(plan['evidence_authority']['path']);s=scope.lstat()
assert stat.S_ISDIR(s.st_mode) and not scope.is_symlink() and not list(scope.iterdir())
authority={'path':str(scope),'device':s.st_dev,'inode':s.st_ino,'posix_mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'requires_exec':True}
assert authority==plan['evidence_authority']==launch['evidence_authority']
v=os.statvfs(scope);assert not v.f_flag&os.ST_NOEXEC
assert v.f_bavail*v.f_frsize>=1073741824 and v.f_favail>=4096
assert plan['limits']=={'assembly_source_bytes':1048576,'cleanup_seconds':3,'minimum_free_bytes':1073741824,'qualification_seconds':180}
assert plan['stage_order']==['generation-1','generation-2','generation-check']
runtime=json.loads(materials['runtime_capture']);assert runtime==plan['runtime'] and runtime['version']==[3,14,4]
for key in ('executable','library'):
    row=runtime[key];raw,s=read_checked(row['path'],dict(row,git_blob=pin(Path(row['path']).read_bytes())['git_blob']),row['mode'])
    assert all(s[k]==row[k] for k in ('device','inode','mode','bytes','mtime_ns','ctime_ns'))
failure=json.loads(materials['predecessor_failure'])
assert failure['product_status']=='FAIL' and failure['Native_pass']==11 and failure['Native_error']==1 and failure['VM_actual']==0
assert failure['nonce4_unknown_retirement_preserved'] is True
report={'schema':'hepta.hia.root-drive-r3-generation-preflight.v1','status':'PASS_STATIC_AND_FULL_PROTECTED_SOURCE_READBACK_NO_PRODUCTS',
 'plan':pin(plan_raw),'runner':pin(runner),'launch':pin(launch_raw),'all9_input_descriptors_complete_bytes_modes':True,
 'complete_runner_byte_inverse':True,'unchanged_old_functions':26,'modified_old_functions':sorted(modified),'new_helpers_full_read':True,
 'all3187_3188_original_source_bytes_modes_seven_stats_and_pathsets':True,'base_unique3188_inodes_disjoint_legacy':True,
 'runtime_overlay_complete_byte_AST_inverse':True,'derived_tree':tree(wanted),'derived_not_actual_source_tree':True,
 'new_scope_authority':authority,'fresh_free_bytes':v.f_bavail*v.f_frsize,'fresh_free_inodes':v.f_favail,
 'unchanged_limits':plan['limits'],'actual_products':0,'actual_source_materializations':0,
 'original_failed_Native_preserved':True,'whole_native':False,'production_legacy_retired':False,
 'python':sys.version,'elapsed_ns':time.monotonic_ns()-started}
with OUT.open('x',encoding='utf-8') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
