"""Freeze the actual R11 eight-group binding after its independent readback.

Metadata only. This does not launch a product and cannot accept an absent or
predicted prefix proof. The old R9 preproof-history reconstruction is specific
to that old authoring attempt and is not transplanted into this successor.
"""
from pathlib import Path
import copy,hashlib,json,os,stat

ROOT=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    out={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:out.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return out
def read(path):
    path=Path(path)
    for parent in reversed(path.parents):assert stat.S_ISDIR(parent.lstat().st_mode)
    s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    stamp=[getattr(s,k) for k in FIELDS]
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        assert [getattr(os.fstat(fd),k) for k in FIELDS]==stamp
        with os.fdopen(fd,'rb',closefd=False) as stream:b=stream.read(s.st_size+1)
        assert len(b)==s.st_size and [getattr(os.fstat(fd),k) for k in FIELDS]==stamp==[getattr(path.lstat(),k) for k in FIELDS]
    finally:os.close(fd)
    return b,stat.S_IMODE(s.st_mode),stamp
def row(path):
    b,m,s=read(path);return {'path':str(path),'identity':pin(b,m),'seven_stats':s}
def write(name,b):
    path=ROOT/name;path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(b)
    path.chmod(0o644);assert read(path)[:2]==(b,0o644)

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
    raw,mode,_=read(ROOT/'EXECUTION-PLAN.json');plan=json.loads(raw)
    material=copy.deepcopy(plan);authorization=material.pop('authorization_pin')
    assert pin(encode(material))['sha256']==authorization
    static=json.loads(read(ROOT/'FINAL-STATIC-READBACK.json')[0])
    assert static['status']=='PASS_STATIC_AUTHOR_READBACK_ONLY'
    assert static['plan']==pin(raw,mode) and static['authorization_pin']==authorization
    assert static['controls']==67 and static['old_controls']==63 and static['new_roles']==15
    assert static['retained_prior_candidate_roles']==14 and static['additional_predicate_proof_roles']==1
    assert static['independent_prefix_and_boundary_required'] is True
    assert static['old948_exact'] and static['whole_plan_inverse_exact'] and static['phase_count']==8
    assert static['products']==static['project_imports']==0 and static['output_absent']
    successor=plan['R11_explicit_successor'];roles=successor['actual_candidate_roles']
    assert len(roles)==15 and len(plan['fixed_inputs'])==963
    assert successor['independent_prefix_and_boundary_required'] is True
    observed={}
    for name,identity in plan['controls'].items():
        current=row(ROOT/name);assert current['identity']==identity,name
        observed[name]=current
    for name,expected in roles.items():assert row(expected['path'])==expected,name
    proof=successor['root_prefix_proof'];assert row(proof['path'])==proof
    actual=json.loads(read(proof['path'])[0])
    assert actual['status']=='PASS_INDEPENDENT_R11_PREFIX_TERMINAL_ONLY'
    assert actual['exact_scalar_editpaths']==9 and actual['word64_then_scalar_proof_chain']
    assert actual['exact_ascii_editpaths']==2 and actual['word64_then_scalar_then_ascii_proof_chain'] is True
    assert actual['semantic_VM']==actual['semantic_Native']==actual['ELF_execution']==0
    assert actual['original_capsule_members']==70 and actual['original_product_owners']==3
    predicate_proof=successor['root_predicate_proof']
    assert row(predicate_proof['path'])==predicate_proof==roles['R11-predicate-independent-proof']
    admit_predicate_proof(read(predicate_proof['path'])[0],proof)
    launch_raw=read(ROOT/'PRODUCT-LAUNCH.json')[0];launch=json.loads(launch_raw)
    assert launch['plan']==row(ROOT/'EXECUTION-PLAN.json')
    assert launch['argv'][-2:]==['--plan-sha256',authorization]
    assert launch['output']==plan['output']=='/workspace/hia-r11-controls-r1-dda7'
    assert launch['outer_seconds']==1800 and launch['outer_cleanup_seconds']==3
    assert launch['each_product_owner_seconds']==180 and launch['each_cleanup_seconds']==3
    assert not os.path.lexists(plan['output'])
    write('prior-authority/EXECUTION-PLAN.json',read(OLD/'EXECUTION-PLAN.json')[0])
    write('proofs/R11-PREFIX-INDEPENDENT-RESULT.json',read(proof['path'])[0])
    write('proofs/R11-PREDICATE-INDEPENDENT-RESULT.json',read(predicate_proof['path'])[0])
    h={'schema':'hia.R11.retained-eight-groups-handoff.v1','status':'ACTUALLY_BOUND_NOT_PRODUCT_EXECUTED',
        'author_root':str(ROOT),'plan':row(ROOT/'EXECUTION-PLAN.json'),
        'launch':row(ROOT/'PRODUCT-LAUNCH.json'),'inverse':row(ROOT/'R11-EXACT-INVERSE.json'),
        'static_readback':row(ROOT/'FINAL-STATIC-READBACK.json'),'root_prefix_proof':proof,
        'root_predicate_proof':predicate_proof,'independent_prefix_and_boundary_required':True,
        'authorization_pin':authorization,'output':plan['output'],'output_absent':True,
        'controls':observed,'actual_candidate_roles':roles,'source':plan['source'],
        'old_input_roles_retained':948,'total_input_roles':963,'old_controls':63,'new_controls':67,
        'retained_prior_candidate_roles':14,'additional_predicate_proof_roles':1,
        'changed_existing_controls':10,'unchanged_old_controls':53,
        'seven_methods_whole_exact':4,'seven_methods_unique_literal_inverse':3,
        'private_three_functions_and_support_function_bodies_full_exact':True,
        'old_driver_and_ORACLE_plan_full_exact':True,'phases':plan['phases'],'budgets':plan['budgets'],
        'minimum_free_bytes':plan['minimum_free_bytes'],'maximum_actual_calls':plan['maximum_actual_calls'],
        'fresh_admission':'Original complete input/source/runtime admission remains required before products. This binding readback is not a substitute.',
        'terminal_readback':'Every actual physical/logical span must be fully read, including both 64-byte D3 ends, partial VM state, errors, and all owner/request records.',
        'prior_R9_status':'163 Native PASS; six logical VM 5 PASS / 1 original fuel FAIL; later aggregate groups unstarted. All retained unchanged.',
        'new_helper_gate':'Both actual independent prefix and boundary proofs were required and fully read at binding/verify/handoff. The boundary proof is one additional phase-* fixed input, not a replacement for any original case.',
        'matching_current_cold':False,'whole_native':False,'public_R5_changed':False,
        'products':0,'CI':0,'refs':0,'pending':['Root review and authorization','original full fresh admission and eight groups','complete independent terminal readback']}
    write('HANDOFF.json',encode(h))
    print(json.dumps({'handoff':row(ROOT/'HANDOFF.json'),'products':0},sort_keys=True))

if __name__=='__main__':main()
