"""Independently read the author outputs and their complete inverse; no product."""
from pathlib import Path
import ast,base64,copy,hashlib,json,os,stat

ROOT=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    p={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:p.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return p
def read(p):
    for q in reversed(p.parents):assert stat.S_ISDIR(q.lstat().st_mode),q
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,p
    a=tuple(getattr(s,k) for k in FIELDS)
    fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        assert tuple(getattr(os.fstat(fd),k) for k in FIELDS)==a
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
        assert len(b)==s.st_size and tuple(getattr(os.fstat(fd),k) for k in FIELDS)==a==tuple(getattr(p.lstat(),k) for k in FIELDS)
    finally:os.close(fd)
    return b,stat.S_IMODE(s.st_mode)
def functions(b):
    lines=b.splitlines(keepends=True)
    return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
def field_inverse(after,before,paths):
    back=copy.deepcopy(after)
    for parts in paths:
        a=back;b=before
        for k in parts[:-1]:a=a[k];b=b[k]
        a[parts[-1]]=copy.deepcopy(b[parts[-1]])
    assert back==before

def main():
    oldraw=read(OLD/'EXECUTION-PLAN.json')[0];old=json.loads(oldraw)
    newraw=read(ROOT/'EXECUTION-PLAN.json')[0];new=json.loads(newraw)
    inverse=json.loads(read(ROOT/'R9-EXACT-INVERSE.json')[0])
    auth=new['authorization_pin'];material=copy.deepcopy(new);material.pop('authorization_pin')
    assert hashlib.sha256(encode(material)).hexdigest()==auth
    assert len(old['controls'])==63 and len(new['controls'])==67
    assert len(old['fixed_inputs'])==948 and len(new['fixed_inputs'])==962
    for n,p in new['controls'].items():
        b,m=read(ROOT/n);assert pin(b,m)==p,n
        if n.endswith('.py'):ast.parse(b,filename=n)
    changes={x['path']:x for x in inverse['changed_existing_files']}
    assert set(changes)=={'r8_common.py','r8_private_reference.py','semantic/authoring/support.py',
        'aggregate/successor-r2/authoring/support.py','aggregate/successor-r3/authoring/support.py',
        'fixtures/REPORT.json','fixtures/OUTER.json','aggregate/successor-r2/authoring/run_kernel_130_r1.py',
        'aggregate/successor-r3/authoring/run_observer_build.py','aggregate/successor-r3/authoring/run_pipeline_vm_r1.py'}
    for n,p in old['controls'].items():
        b,m=read(OLD/n);a,am=read(ROOT/n);assert pin(b,m)==p and m==am
        if n not in changes:assert a==b,n;continue
        x=changes[n]
        assert base64.b64decode(x['before_base64'],validate=True)==b and base64.b64decode(x['after_base64'],validate=True)==a
        assert pin(b,m)==x['before'] and pin(a,am)==x['after']
        if x['literal_replacements'] is not None:
            back=a
            for e in reversed(x['literal_replacements']):
                aa=e['after'].encode();bb=e['before'].encode()
                assert back.count(aa)==e['count'];back=back.replace(aa,bb)
            assert back==b,n
        elif n=='fixtures/REPORT.json':
            field_inverse(json.loads(a),json.loads(b),[('build','executable'),('build','elf_inspection'),('image',),
                ('images','semantic'),('input_sha256',),('origin',),('status_meaning',)])
        elif n=='fixtures/OUTER.json':
            field_inverse(json.loads(a),json.loads(b),[('actual_outer',),('actual_owner',),('status_meaning',)])
        else:raise AssertionError(n)
    assert read(ROOT/'run_controls.py')==read(OLD/'run_controls.py')
    assert read(ROOT/'ORACLE-RESTORE-PLAN.json')==read(OLD/'ORACLE-RESTORE-PLAN.json')
    for f in ('_checked_components','execute_linux_file_roundtrip','execute_program'):
        assert functions(read(ROOT/'r8_private_reference.py')[0])[f]==functions(read(OLD/'r8_private_reference.py')[0])[f]
    for n in ('semantic/authoring/support.py','aggregate/successor-r2/authoring/support.py','aggregate/successor-r3/authoring/support.py'):
        assert functions(read(ROOT/n)[0])==functions(read(OLD/n)[0])
    roles=new['R9_explicit_successor']['actual_candidate_roles'];assert len(roles)==14
    for k,p in old['fixed_inputs'].items():assert new['fixed_inputs'][k]==p
    assert set(new['fixed_inputs'])-set(old['fixed_inputs'])==set(roles)
    for k,p in roles.items():
        row=new['fixed_inputs'][k]
        assert row=={'path':p['path'],'identity':p['identity'],'phases':['*']}
        b,m=read(Path(row['path']));assert pin(b,m)==row['identity'],k
    back=copy.deepcopy(new);back.pop('R9_explicit_successor')
    for k in roles:back['fixed_inputs'].pop(k)
    for k in ('output','runtime','controls','authorization_pin'):back[k]=copy.deepcopy(old[k])
    assert encode(back)==oldraw
    assert new['runtime']['executable']==old['runtime']['executable'] and new['runtime']['library']==old['runtime']['library']
    newenv=copy.deepcopy(new['runtime']['environment']);newenv['HOME']=old['runtime']['environment']['HOME']
    assert newenv==old['runtime']['environment']
    fixture=json.loads(read(ROOT/'fixtures/REPORT.json')[0]);src=roles['R9-source']['identity'];img=roles['R9-image']['identity'];elf=roles['R9-elf']['identity']
    assert fixture['input_sha256']==src['sha256'] and fixture['image']=={k:img[k] for k in ('bytes','sha256','git_blob')}
    assert fixture['build']['elf_inspection']['file_bytes']==elf['bytes']==1040384
    assert fixture['images']['semantic']=={k:img[k] for k in ('bytes','sha256')}
    method_rows=[]
    for phase in new['phases']:
        n=phase['script']
        if n is None:continue
        b,m=read(ROOT/n);o,om=read(OLD/n)
        method_rows.append({'phase':phase['name'],'path':n,'old':pin(o,om),'new':pin(b,m),'byte_exact':b==o,
            'complete_inverse_equal':True,'literal_replacements':changes.get(n,{}).get('literal_replacements',[])})
    assert len(method_rows)==7 and sum(x['byte_exact'] for x in method_rows)==4
    assert not Path(new['output']).exists() and not Path(new['output']).is_symlink()
    fs=os.statvfs(Path(new['output']).parent)
    result={'schema':'hia.R9.author-full-inverse-readback.v1','status':'PASS_STATIC_AUTHOR_READBACK_ONLY',
        'plan':pin(newraw,0o644),'authorization_pin':auth,'controls':67,'old_controls':63,'changed_existing':10,
        'old948_exact':True,'new_roles':14,'whole_plan_inverse_exact':True,'seven_methods':method_rows,
        'run_controls_and_oracle_plan_full_exact':True,'three_private_function_bodies_full_exact':True,
        'three_support_function_maps_full_exact':True,'original_full_assertions_case_order_budgets_preserved':True,
        'new_fixture_matches_actual_R9':True,'all_new_roles_full_bytes_checked':True,
        'full_original_payload_scan_performed':False,'complete_source_tree_scan_performed':False,
        'output_absent':True,'output_filesystem_free_observed':fs.f_bavail*fs.f_frsize,
        'entry_floor_unchanged':new['minimum_free_bytes'],'phase_count':8,'project_imports':0,'products':0}
    raw=encode(result)
    with (ROOT/'FINAL-STATIC-READBACK.json').open('xb') as f:f.write(raw)
    (ROOT/'FINAL-STATIC-READBACK.json').chmod(0o644)
    print(json.dumps({'status':result['status'],'result':pin(raw,0o644),'plan':result['plan'],'authorization_pin':auth,
        'output_free_observed':result['output_filesystem_free_observed'],'products':0},sort_keys=True))

if __name__=='__main__':main()
