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

def admit_predicate_proof(raw, prefix_proof):
    """Require the actual complete independent boundary result, not a prediction."""
    r=json.loads(raw)
    assert r['schema']=='hia.R11.predicate.independent-terminal-readback.v1'
    assert r['status']=='PASS_INDEPENDENT_R11_PREDICATE_TERMINAL_ONLY' and r['errors']==[]
    assert r['products']==r['project_imports']==r['original_eight_groups_executed']==0
    assert r['whole_native'] is False and r['matching_current_cold'] is False
    assert (r['case_pairs'],r['actual_VM_calls'],r['logical_before_after_buffers'])==(1806,3612,6000)
    assert (r['scalar_pairs_without_buffers'],r['full_function_pairs'])==(1056,750)
    assert (r['full_original_domain_files'],r['full_original_domain_bytes'],r['source_files'],r['runtime_files'])==(6777,948620735,3180,2496)
    assert r['complete_byte_event_error_resource_and_trace_equal'] is True
    assert r['actual_Core_structural_path_and_tick_reconstruction'] is True
    assert r['recorded_pure_opcode_values_not_reexecuted'] is True
    assert r['exact_scalar_predicates_from_actual_load_values'] is True and r['all_original_budgets_kept'] is True
    assert r['actual_prefix_independent_proof']==prefix_proof
    assert r['groups']=={'borrow_state':15,'delimiter_neighbors':28,'identifier_edges':20,'identifier_offsets':9,
        'identifier_tail_byte':256,'lexer_edges':25,'lexer_first_byte':256,'preexisting_error':21,'same_owner':3,
        'scalar_delimiter':264,'scalar_identifier_invalid':792,'short_source':12,'short_workspace':74,'short_workspace_error':31}
    assert set(r['outcomes'])==set(r['max_steps'])=={'R10','R11'}
    for name in ('R10','R11'):
        assert set(r['outcomes'][name])<={'returned','trapped','rejected'}
        assert sum(r['outcomes'][name].values())==1806 and all(type(n)is int and n>=0 for n in r['outcomes'][name].values())
        assert type(r['max_steps'][name])is int and 0<r['max_steps'][name]<=10000000
    assert r['fresh_reads']>=6777 and r['raw_files']>0 and r['raw_logical_bytes']>0
    owner=r['original_owner'];outer=r['actual_Root_outer']
    assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==owner['supervisor_returncode']==0
    assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3 and owner['timed_out'] is False
    assert owner['exit_observed_before_deadline'] is True and owner['cleanup']['complete'] is True
    assert owner['cleanup']['observed_echild'] is True and owner['cleanup']['remaining_direct_children']==[]
    assert outer['status']=='PASS_R11_PREDICATE_PARENT_PROCESS_ONLY' and outer['returncode']==0
    assert outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1
    assert outer['timeout'] is False and outer['ECHILD'] is True and outer['process_group_absent'] is True and outer['adopted']==[]
    return r

def main():
    oldraw=read(OLD/'EXECUTION-PLAN.json')[0];old=json.loads(oldraw)
    newraw=read(ROOT/'EXECUTION-PLAN.json')[0];new=json.loads(newraw)
    inverse=json.loads(read(ROOT/'R11-EXACT-INVERSE.json')[0])
    auth=new['authorization_pin'];material=copy.deepcopy(new);material.pop('authorization_pin')
    assert hashlib.sha256(encode(material)).hexdigest()==auth
    assert len(old['controls'])==63 and len(new['controls'])==67
    assert len(old['fixed_inputs'])==948 and len(new['fixed_inputs'])==963
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
    roles=new['R11_explicit_successor']['actual_candidate_roles'];assert len(roles)==15
    successor=new['R11_explicit_successor']
    assert successor['independent_prefix_and_boundary_required'] is True
    assert successor['retained_prior_candidate_roles']==14 and successor['additional_predicate_proof_roles']==1
    proof=successor['root_predicate_proof']
    assert roles['R11-predicate-independent-proof']==proof
    admit_predicate_proof(read(Path(proof['path']))[0],successor['root_prefix_proof'])
    for k,p in old['fixed_inputs'].items():assert new['fixed_inputs'][k]==p
    assert set(new['fixed_inputs'])-set(old['fixed_inputs'])==set(roles)
    for k,p in roles.items():
        row=new['fixed_inputs'][k]
        assert row=={'path':p['path'],'identity':p['identity'],'phases':['*']}
        b,m=read(Path(row['path']));assert pin(b,m)==row['identity'],k
    back=copy.deepcopy(new);back.pop('R11_explicit_successor')
    for k in roles:back['fixed_inputs'].pop(k)
    for k in ('output','runtime','controls','authorization_pin'):back[k]=copy.deepcopy(old[k])
    assert encode(back)==oldraw
    assert new['runtime']['executable']==old['runtime']['executable'] and new['runtime']['library']==old['runtime']['library']
    newenv=copy.deepcopy(new['runtime']['environment']);newenv['HOME']=old['runtime']['environment']['HOME']
    assert newenv==old['runtime']['environment']
    fixture=json.loads(read(ROOT/'fixtures/REPORT.json')[0]);src=roles['R11-source']['identity'];img=roles['R11-image']['identity'];elf=roles['R11-elf']['identity']
    assert fixture['input_sha256']==src['sha256'] and fixture['image']=={k:img[k] for k in ('bytes','sha256','git_blob')}
    assert fixture['build']['elf_inspection']['file_bytes']==elf['bytes']==json.loads(read(Path(roles['R11-root-proof']['path']))[0])['ELF']['bytes']<=1048576
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
    result={'schema':'hia.R11.author-full-inverse-readback.v1','status':'PASS_STATIC_AUTHOR_READBACK_ONLY',
        'plan':pin(newraw,0o644),'authorization_pin':auth,'controls':67,'old_controls':63,'changed_existing':10,
        'old948_exact':True,'new_roles':15,'retained_prior_candidate_roles':14,'additional_predicate_proof_roles':1,
        'independent_prefix_and_boundary_required':True,
        'whole_plan_inverse_exact':True,'seven_methods':method_rows,
        'run_controls_and_oracle_plan_full_exact':True,'three_private_function_bodies_full_exact':True,
        'three_support_function_maps_full_exact':True,'original_full_assertions_case_order_budgets_preserved':True,
        'new_fixture_matches_actual_R11':True,'all_new_roles_full_bytes_checked':True,
        'full_original_payload_scan_performed':False,'complete_source_tree_scan_performed':False,
        'output_absent':True,'output_filesystem_free_observed':fs.f_bavail*fs.f_frsize,
        'entry_floor_unchanged':new['minimum_free_bytes'],'phase_count':8,'project_imports':0,'products':0}
    raw=encode(result)
    with (ROOT/'FINAL-STATIC-READBACK.json').open('xb') as f:f.write(raw)
    (ROOT/'FINAL-STATIC-READBACK.json').chmod(0o644)
    print(json.dumps({'status':result['status'],'result':pin(raw,0o644),'plan':result['plan'],'authorization_pin':auth,
        'output_free_observed':result['output_filesystem_free_observed'],'products':0},sort_keys=True))

if __name__=='__main__':main()
