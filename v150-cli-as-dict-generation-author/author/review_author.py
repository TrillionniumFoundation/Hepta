"""Static/data author review only; never imports project/control modules."""
from pathlib import Path
import ast, hashlib, json, stat

A=Path(__file__).absolute().parent
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,mode='100644'):
    return {'bytes':len(b),'mode':mode,'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def read(p):
    p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    b=p.read_bytes();assert {k:getattr(s,k)for k in KEYS}=={k:getattr(p.lstat(),k)for k in KEYS}
    return b
def checked(d):
    p=Path(d['path']);assert {k:getattr(p.lstat(),k)for k in KEYS}==d['stat']
    b=read(p);assert pin(b,d['pin']['mode'])==d['pin'];return b
def funcs(b):
    ls=b.decode().splitlines(keepends=True)
    return {n.name:''.join(ls[n.lineno-1:n.end_lineno]).encode()for n in ast.parse(b).body
            if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def literal(b,name):
    for n in ast.parse(b).body:
        if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id==name for x in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(name)
def tree(files):
    root={}
    for n,v in files.items():
        d=root;parts=n.split('/');assert all(p and p not in ('.','..')for p in parts)
        for p in parts[:-1]:d=d.setdefault(p,{})
        assert parts[-1]not in d;d[parts[-1]]=v
    def digest(d):
        rows=[]
        for n,v in d.items():
            rows.append((n.encode()if'git_blob'in v else(n+'/').encode(),v['mode'].encode()if'git_blob'in v else b'40000',bytes.fromhex(v['git_blob'])if'git_blob'in v else digest(v)))
        b=b''.join(m+b' '+n.rstrip(b'/')+b'\0'+sha for n,m,sha in sorted(rows))
        return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).digest()
    return digest(root).hex()

def main():
    plan=json.loads(read(A/'GENERATION-PLAN.json'));launch=json.loads(read(A/'GENERATION-LAUNCH.json'))
    inverse=json.loads(read(A/'WHOLE-INVERSE.json'));rows={}
    for name,v in inverse['files'].items():
        before=read(A/'before-controls'/name);after=read(A/'controls'/name)
        assert pin(before)==v['before']and pin(after)==v['after']
        forward=before.decode().splitlines(keepends=True);backward=after.decode().splitlines(keepends=True)
        for e in reversed(v['edits']):
            assert ''.join(forward[e['before_start']:e['before_stop']])==e['before_text']
            assert ''.join(backward[e['after_start']:e['after_stop']])==e['after_text']
            forward[e['before_start']:e['before_stop']]=e['after_text'].splitlines(keepends=True)
            backward[e['after_start']:e['after_stop']]=e['before_text'].splitlines(keepends=True)
        assert ''.join(forward).encode()==after and ''.join(backward).encode()==before
        ast.parse(after);compile(after,str(A/'controls'/name),'exec',dont_inherit=True)
        bf,af=funcs(before),funcs(after)
        rows[name]={'full_inverse':True,'before':pin(before),'after':pin(after),
                    'whole_exact_functions':[n for n in bf if bf[n]==af.get(n)],
                    'explicit_changed_functions':[n for n in bf if bf[n]!=af.get(n)],
                    'new_functions':[n for n in af if n not in bf]}
        assert set(bf)<=set(af)and checked(plan['controls'][name])==after
    assert read(A/'before-controls/inspect_exec_support.py')==read(A/'controls/inspect_exec_support.py')
    assert funcs(read(A/'before-controls/execution_support.py'))==funcs(read(A/'controls/execution_support.py'))
    old_child=read(A/'before-controls/run_control_child.py')
    assert read(A/'controls/run_control_child.py').replace(b'len(expected) == 3210',b'len(expected) == 3211').replace(
        b'complete 3210 source scope required',b'complete 3211 source scope required')==old_child
    original_qual=Path('/workspace/hia-patch-terminal-quarantine-qualification-author-r2-dda7/controls/qualification_support.py')
    assert funcs(read(A/'controls/generation_support.py'))['evidence_guard']==funcs(read(original_qual))['evidence_guard']
    before=json.loads(checked(plan['base_source']['map']));state=json.loads(checked(plan['base_source']['state']))
    after=json.loads(checked(plan['projected_source_map']));origins=json.loads(checked(plan['origin_rows']))
    assert len(before)==len(after)==len(origins)==3210 and tree(before)=='b4f7d4862d6b391781808d603547ce3a504ffc83'
    assert tree(after)==plan['source_tree']=='cbaa11e367950b314e419472e3810c8f17f917dc'
    assert set(before)==set(after)and {n for n in before if before[n]!=after[n]}==set(plan['changed_source_paths'])
    assert [r['relative']for r in origins]==sorted(after)
    origin_originals=json.loads(checked(plan['provenance']['base_source_inputs']))
    for r in origins:
        n=r['relative'];d=r['descriptor'];assert d['pin']==after[n]
        if n not in plan['changed_source_paths']:
            assert d==origin_originals[n]=={'path':str(Path(plan['base_source']['root'])/n),'pin':before[n],'stat':state[n]}
        else:
            assert read(A/'before-source'/n)==checked(origin_originals[n])
            assert read(A/'overlay'/n)==checked(d)and pin(read(A/'before-source'/n))==before[n]
    gen_rows={}
    for c,spec in plan['components'].items():
        root=Path(plan['base_source']['root']);p=root/spec['generator_relative'];raw=read(p)
        assert pin(raw)==before[spec['generator_relative']]and raw==read(A/'original-generators'/(c+'.py'))
        assert [literal(raw,n)for n in ('SOURCE_PATH','PORTS_PATH','DATA_PATH')]==spec['generated_paths']
        host_path=root/('hepta/hia_'+('inspect_program'if c=='inspect'else'patch_result')+'_native.py')
        assert list(literal(read(host_path),'HOST_SOURCE_FILES'))==spec['host_source_files']
        assert len(spec['host_source_files'])==13 and 'hia_optional_profiles.py'in spec['host_source_files']
        gen_rows[c]={'generator':str(p),'pin':pin(raw),'host_order':spec['host_source_files'],
                     'original_source_paths':spec['generated_paths']}
    r5=json.loads(checked(plan['r5_before']));p14=json.loads(checked(plan['patch14_before']))
    assert len(r5)==3191 and len(p14)==14 and all(before[n]==v for n,v in r5.items())and all(before[n]==v for n,v in p14.items())
    assert set(plan['changed_source_paths'])<=set(r5)and not set(plan['changed_source_paths'])&set(p14)
    assert len(set(after)-set(r5)-set(p14))==5
    for r in plan['external_tests'].values():
        checked(r);assert not Path(r['path']).is_relative_to(Path(plan['source']))
    assert launch['command']==[plan['expected_runtime']['executable']['path'],'-I','-B',
        plan['controls']['run_generation.py']['path'],'--plan',str(A/'GENERATION-PLAN.json'),
        '--plan-sha256',pin(read(A/'GENERATION-PLAN.json'))['sha256']]
    assert checked(launch['plan'])==read(A/'GENERATION-PLAN.json')
    assert launch['required_product_owners']==6 and launch['qualification_seconds_each']==180 and launch['cleanup_seconds_each']==3
    old_limits=literal(old_child,'LIMITS');assert plan['limits']==old_limits and plan['storage_floor']==1073741824
    assert plan['stages']==[c+'-'+s for c in ('inspect','patch')for s in ('generate-1','generate-2','check')]
    parent=ast.parse(read(A/'controls/run_generation.py'));old_parent=ast.parse(read(A/'before-controls/run_generation.py'))
    owned=lambda t:[ast.dump(n,include_attributes=False)for n in ast.walk(t)if isinstance(n,ast.Call)
        and isinstance(n.func,ast.Attribute)and n.func.attr=='run_owned']
    assert len(owned(parent))==1 and owned(parent)==owned(old_parent)
    child=ast.parse(read(A/'controls/run_generation_child.py'))
    runpy_calls=[n for n in ast.walk(child)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)
                 and isinstance(n.func.value,ast.Name)and n.func.value.id=='runpy'and n.func.attr=='run_path']
    assert len(runpy_calls)==1
    assert plan['future_output_pins']is None and not Path(plan['scope']).exists()
    result={'status':'PASS_STATIC_AUTHOR_REVIEW_ONLY','base_tree':tree(before),'projected_tree':tree(after),
        'full_source_entries':3210,'full_payload_source_rescan_this_review':False,
        'original_roles':{'r5':3191,'patch14':14,'cli_additions':5},'six_original_owners':6,
        'unchanged_limits':old_limits,'storage_floor':1073741824,'controls':rows,'generators':gen_rows,
        'original_run_owned_call_AST_exact':True,'original_generator_program_bodies_full_exact':True,
        'external_tests_fixed_and_outside_source':True,'future_generated_pins':None,
        'source_copy_calls':0,'project_imports':0,'products':0,'generator_calls':0,'CI':0}
    out=A/'STATIC-REVIEW.json'
    with out.open('xb')as f:f.write(encoded(result))
    print(json.dumps({'status':result['status'],'result':pin(read(out)),'source_scope_absent':True},sort_keys=True))

if __name__=='__main__':main()
