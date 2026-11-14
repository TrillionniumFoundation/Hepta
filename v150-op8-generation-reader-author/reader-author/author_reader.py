"""Author an independent data-only terminal reader; never execute it."""
from pathlib import Path
import ast,difflib,hashlib,json,os
A=Path('/workspace/hia-cli-as-dict-generation-terminal-reader-author-r1-dda7')
OLD=Path('/workspace/hia-patch-terminal-quarantine-generation-terminal-reader-r1-dda7/read_terminal.py')
GEN=Path('/workspace/hia-cli-as-dict-generation-author-r1-dda7')
SCOPE='/workspace/hia-cli-as-dict-generation-r1-dda7'
OUTER='/workspace/hia-cli-as-dict-generation-outer-r1-dda7'
OUTPUT='/workspace/hia-cli-as-dict-generation-terminal-actual-r1-dda7'
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def put(n,b):
 p=A/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 return {'path':str(p),**pin(b)}
def funcs(s):
 lines=s.splitlines(keepends=True)
 return {n.name:''.join(lines[n.lineno-1:n.end_lineno])for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def replace(s,b,a,count=1):assert s.count(b)==count,(b,s.count(b));return s.replace(b,a)
assert not A.exists()and not Path(OUTPUT).exists();A.mkdir(mode=0o700)
put('author_reader.py',Path(__file__).read_bytes())
before=OLD.read_text();s=before;plan=json.loads((GEN/'GENERATION-PLAN.json').read_bytes())
put('before-read_terminal.py',before.encode())
s=replace(s,"SCOPE=Path('/workspace/hia-patch-terminal-quarantine-execution-r1-dda7')",'SCOPE=Path('+repr(SCOPE)+')')
s=replace(s,"AUTHOR=Path('/workspace/hia-patch-terminal-quarantine-generation-author-r1-dda7')",'AUTHOR=Path('+repr(str(GEN))+')')
s=replace(s,"OUTER=Path('/workspace/hia-patch-terminal-quarantine-generation-outer-r1-dda7')",'OUTER=Path('+repr(OUTER)+')')
s=replace(s,"GENERATED=('examples/hia_bootstrap/patch_result.hepta','hepta/hia_patch_result_ports.py','hepta/hia_patch_result_data.py')",'GENERATED='+repr(tuple(plan['generated_paths']))+'\nCOMPONENTS='+repr(plan['components'])+'\nSTAGES='+repr(tuple(plan['stages'])))
s=replace(s,'    return base_inodes\n','''    for key in ('mother_source','prior_base'):
        value=plan[key];mapped=decode(fixed(value['map']));saved=decode(fixed(value['state']))
        complete_source(value['root'],mapped,saved,value['files'],value['tree'])
    for r in plan['external_tests'].values():fixed(r)
    fixed(plan['r5_before']);fixed(plan['patch14_before']);fixed(plan['patch14_historical'])
    old=decode(fixed(plan['generation_evidence']));old_states={}
    require(old['schema']=='hepta.hia.patch-terminal.generation-evidence.v1'
            and old['product_execution']==0,'original predecessor evidence map differs')
    for root in old['roots']:
        state=metadata(root['path'])
        state={n:r for n,r in state.items()if not any(n==p or n.startswith(p+'/')for p in root['exclude'])}
        require(state==root['state'],'complete original predecessor pathset/stat differs')
        old_states[root['path']]=state
    for r in old['files']:fixed(r)
    for r in old['directories']:
        require(seven(Path(r['path']).lstat())==r['stat'],'old directory stat differs')
    for root in old['roots']:
        state=metadata(root['path'])
        state={n:r for n,r in state.items()if not any(n==p or n.startswith(p+'/')for p in root['exclude'])}
        require(state==old_states[root['path']],'original predecessor changed during full read')
    earlier=decode(fixed(plan['generation_result']));terminal=decode(fixed(plan['generation_terminal']))
    require(earlier['status']=='PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'
            and terminal['status']=='PASS_COMPLETE_GENERATION_TERMINAL_READBACK'
            and terminal['source_files']==3211 and terminal['actual_owners']==3
            and terminal['source_tree']==plan['mother_source']['tree'],'historical generation authority differs')
    return base_inodes
''')
s=replace(s,"labels=['generate-1','generate-2','check'];require([s['label']for s in result['stages']]==labels,'three original stage order differs')", "labels=list(STAGES);require([s['label']for s in result['stages']]==labels,'six original stage order differs')")
s=replace(s,"    for i,label in enumerate(labels):\n        directory", "    for i,label in enumerate(labels):\n        component,phase=label.split('-',1);spec=COMPONENTS[component]\n        directory")
s=replace(s,"target=attempt/'02-generate-2'/'outputs'if label=='check'else directory/'outputs'", "second_label=component+'-generate-2';second_index=STAGES.index(second_label)\n        target=attempt/('%02d-'%(second_index+1)+second_label)/'outputs'if phase=='check'else directory/'outputs'")
s=replace(s,"paths={'assembly':str(target/'patch_result.hepta'),'ports':str(target/'hia_patch_result_ports.py'),\n            'identity':str(target/'hia_patch_result_data.py')}", "paths={k:str(target/Path(n).name)for k,n in zip(('assembly','ports','identity'),spec['generated_paths'])}")
s=replace(s,"Path(bound['source'])/plan['generator_relative']","Path(bound['source'])/spec['generator_relative']")
s=replace(s,"label=='check'","phase=='check'",2)
s=replace(s,"require(read(directory/'stderr.raw')==b'' and printed['source_sha256']==hashlib.sha256(full['assembly']).hexdigest()", "stderr=read(directory/'stderr.raw')\n        require(printed['source_sha256']==hashlib.sha256(full['assembly']).hexdigest()")
s=replace(s,"outputs==result['stages'][1]['outputs']","outputs==result['stages'][second_index]['outputs']")
s=replace(s,"    require(output_sets[0]==output_sets[1]==output_sets[2],'actual triples differ byte-for-byte')\n    return output_sets[1]", "    require(output_sets[0]==output_sets[1]==output_sets[2]\n            and output_sets[3]==output_sets[4]==output_sets[5],'both actual triples differ byte-for-byte')\n    return {'inspect':output_sets[1],'patch':output_sets[4]}")
s=replace(s,"Path('/workspace/hia-patch-terminal-quarantine-generation-terminal-actual-r1-dda7')",'Path('+repr(OUTPUT)+')')
s=replace(s,"""plan=decode(read(AUTHOR/'GENERATION-PLAN-R2.json',{'bytes':30794,'git_blob':'35114c9be6fdebe0392e28e26762284017022e4c',
            'sha256':'ec6a9c62c9e94139826b81af17c5a010c8ad39213f82b7529a47c32a62eb8450'}))""",
 "plan=decode(read(AUTHOR/'GENERATION-PLAN.json',"+repr(pin((GEN/'GENERATION-PLAN.json').read_bytes()))+"))")
s=replace(s,"launch=decode(read(AUTHOR/'GENERATION-LAUNCH-R2.json'))", "launch=decode(read(AUTHOR/'GENERATION-LAUNCH.json',"+repr(pin((GEN/'GENERATION-LAUNCH.json').read_bytes()))+"))")
s=replace(s,"""actual_raw=read(SCOPE/'generation-attempt-r1/RESULT.json',{'bytes':32379,'git_blob':'ba0bb71338e1cbb91d8cbf280898dd518ada8f6a',
            'sha256':'7dda441a400a9da7fd4c586452e15571f7494955a182f3490b5eb7140c7e4c43'})""", "actual_raw=read(SCOPE/'generation-attempt-r1/RESULT.json')")
s=replace(s,"actual['status']=='PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'", "actual['status']=='PASS_GENERATION_ONLY_BOTH_TWO_RUNS_AND_ORIGINAL_CHECKS'")
s=replace(s,"actual['copy_rows']==3211 and actual['actual_owner_launch_attempts']==3", "actual['copy_rows']==3210 and actual['actual_owner_launch_attempts']==6")
s=replace(s,"        require(bound['runtime']==plan['previous_runtime_context'],'actual runtime context changed')", """        require(bound['runtime']==plan['previous_runtime_context'],'actual runtime context changed')
        preserved={k:v for k,v in plan.items()if k not in {'schema','state','source_copy_performed','project_imports'}}
        require(all(bound[k]==v for k,v in preserved.items())and set(bound)==set(preserved)|{
            'schema','state','source_map','source_state','scope_ancestors','preparation_plan','copies','runtime'},
            'actual bound plan changed a fixed original author field')
        require(bound['schema']==plan['schema'].removesuffix('.preparation')+'.bound'
                and bound['state']=='BOUND_FOR_GENERATION_ONLY'
                and decode(fixed(bound['preparation_plan']))==plan,'actual plan schema/original identity differs')""")
s=replace(s,"material['source_files']==3211","material['source_files']==3210")
s=replace(s,"len(copies)==len(origins)==3211","len(copies)==len(origins)==3210")
s=replace(s,"        born=set()", "        base_inodes|={(r['descriptor']['stat']['st_dev'],r['descriptor']['stat']['st_ino'])for r in origins}\n        born=set()")
s=replace(s,"""require(final['tree']=='aa2608ca25c3a9736a62d549c3130b98893542ff'
            and final['changed_bytes']==['hepta/hia_patch_result_data.py'],'final actual delta differs')
        complete_source(final['source'],final_map,final_state,3211,final['tree'])""", """require(final['source']==bound['source'] and final['files']==3210
            and final['changed_bytes']==['hepta/hia_inspect_program_data.py','hepta/hia_patch_result_data.py']
            and final['replaced_paths']==list(GENERATED)and final['future_products_executed']==0,
            'final actual delta differs')
        require(final['tree']==tree(final_map),'actual generated map/tree differs')
        complete_source(final['source'],final_map,final_state,3210,final['tree'])""")
s=replace(s,"        for n,k in zip(GENERATED,('assembly','ports','identity')):\n            require(read(Path(final['source'])/n,final_map[n],final_state[n])==full[k],'installed complete output differs')", """        derived=dict(pre)
        for component in ('inspect','patch'):
            for n,k in zip(COMPONENTS[component]['generated_paths'],('assembly','ports','identity')):
                raw=full[component][k];derived[n]=pin(raw,pre[n]['mode'])
                require(read(Path(final['source'])/n,final_map[n],final_state[n])==raw,'installed complete output differs')
        require(final_map==derived,'complete final map was not derived from actual six output bytes')""")
s=replace(s,"'three install rows differ'","'six install rows differ'")
s=replace(s,"        for before,after in zip(intent['rows'],journal):", """        require(intent['all_staged_before_replace']is True and intent['multi_path_atomic']is False
                and intent['automatic_retry']is False,'original installation failure contract differs')
        staged_inodes=set()
        for before,after in zip(intent['rows'],journal):""")
s=replace(s,"            fixed(after['installed']);require(after['installed']['stat']==final_state[n],'installed current stat differs')", """            fixed(before['output']);fixed(after['installed'])
            require(after['installed']['stat']==final_state[n],'installed current stat differs')
            key=(before['staged']['stat']['st_dev'],before['staged']['stat']['st_ino'])
            require(key not in staged_inodes and before['staged']['pin']==after['installed']['pin'],
                    'staged new inode alias or bytes drift')
            staged_inodes.add(key)""")
s=replace(s,"""        data={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(full['identity']).body if isinstance(n,ast.Assign)}
        hosts={n:hashlib.sha256(read(Path(final['source'])/'hepta'/n)).hexdigest()for n in plan['host_source_files']}
        require(data['SOURCE_BYTES']==len(full['assembly']) and data['SOURCE_SHA256']==hashlib.sha256(full['assembly']).hexdigest()
            and list(data['HOST_SOURCE_SHA256'])==plan['host_source_files']and data['HOST_SOURCE_SHA256']==hosts,'generated13 host binding differs')""", """        host_checks={}
        for component in ('inspect','patch'):
            host_checks[component]=compatibility(plan,final,full[component],component)
            require(actual['compatibility'][component]['actual_host_sha256']==host_checks[component]['hashes'],
                    'parent compatibility report differs from independent actual host reads')
        authority=authority_maps(plan,bound,actual,final_map)""")
s=replace(s,"complete_source(final['source'],final_map,final_state,3211,final['tree'])", "complete_source(final['source'],final_map,final_state,3210,final['tree'])")
s=replace(s,"status='PASS_COMPLETE_GENERATION_TERMINAL_READBACK',source_files=3211", "status='PASS_COMPLETE_OP8_TWO_GENERATOR_TERMINAL_READBACK',source_files=3210")
s=replace(s,"actual_owners=3,raw_files=len(raw_inventory)","actual_owners=6,raw_files=len(raw_inventory)")
s=replace(s,'actual_new_installations=3','actual_new_installations=6')
s=replace(s,'all13hosts_current=True,protected_R3=3210','all26host_bindings_current=True,host_checks=host_checks,actual_authority_maps=authority,protected_mother=3211,protected_R3=3210')
s=replace(s,"return 0 if result['status']=='PASS_COMPLETE_GENERATION_TERMINAL_READBACK'else 1", "return 0 if result['status']=='PASS_COMPLETE_OP8_TWO_GENERATOR_TERMINAL_READBACK'else 1")
# Additional independent output/map readers and final author freeze follow.
extra='''

def compatibility(plan, final, full, component):
    data={}
    for node in ast.parse(full['identity']).body:
        if isinstance(node,ast.Assign):
            require(len(node.targets)==1 and isinstance(node.targets[0],ast.Name),'generated assignment shape differs')
            key=node.targets[0].id;require(key not in data,'duplicate generated assignment')
            data[key]=ast.literal_eval(node.value)
        else:
            require(isinstance(node,ast.Expr)and isinstance(node.value,ast.Constant)
                    and type(node.value.value)is str,'unknown generated compatibility statement')
    spec=COMPONENTS[component];names=spec['host_source_files']
    require(len(names)==len(set(names))==13 and plan['components'][component]==spec,'complete original host order differs')
    hosts={n:hashlib.sha256(read(Path(final['source'])/'hepta'/n)).hexdigest()for n in names}
    require(set(data)=={'SOURCE_BYTES','SOURCE_SHA256','HOST_SOURCE_SHA256'}
            and data['SOURCE_BYTES']==len(full['assembly'])and data['SOURCE_SHA256']==hashlib.sha256(full['assembly']).hexdigest()
            and type(data['HOST_SOURCE_SHA256'])is dict and list(data['HOST_SOURCE_SHA256'])==names
            and data['HOST_SOURCE_SHA256']==hosts,'generated actual thirteen-host binding differs')
    return {'ordered_hosts':names,'hashes':hosts,'actual_identity':pin(full['identity']),
            'manual_generated_identity':False}


def authority_maps(plan, bound, actual, final_map):
    recorded=decode(read(Path(plan['attempt'])/'ACTUAL-AUTHORITY-MAPS.json'))
    require(recorded==actual['actual_authority_maps']
            and recorded['status']=='ACTUAL_GENERATED_AUTHORITY_MAPS_NOT_QUALIFICATION',
            'actual authority result relation differs')
    old_r5_raw=fixed(plan['r5_before']);old_patch_raw=fixed(plan['patch14_before'])
    require(fixed(recorded['r5_before'])==old_r5_raw and fixed(recorded['patch14_before'])==old_patch_raw,
            'prior full authority maps were rewritten')
    r5=decode(old_r5_raw);patch=decode(old_patch_raw)
    now_r5=decode(fixed(recorded['r5_actual']));now_patch=decode(fixed(recorded['patch14_actual']))
    base=decode(fixed(plan['base_source']['map']))
    cli={'hepta/hia_cli_patch_result_native.py','hepta/hia_patch_cli_records.py',
         'tests/hia_patch_cli_support.py','tests/test_hia_patch_cli_source.py','tests/test_hia_patch_cli_native.py'}
    require(len(r5)==len(now_r5)==3191 and len(patch)==len(now_patch)==14 and len(final_map)==3210
            and set(now_r5)==set(r5)and set(now_patch)==set(patch)
            and set(final_map)==set(base)==set(r5)|set(patch)|cli and not set(r5)&set(patch),
            'original full3191/14/3210 authority domains differ')
    require(now_r5=={n:final_map[n]for n in r5}and now_patch=={n:final_map[n]for n in patch},
            'new authority maps do not contain every actual generated source byte identity')
    require(all(base[n]==p for n,p in r5.items())and all(base[n]==p for n,p in patch.items()),
            'retained authority preimages differ from actual base')
    require({n for n in r5 if r5[n]!=now_r5[n]}==set(plan['changed_source_paths'])|{'hepta/hia_inspect_program_data.py'}
            and {n for n in patch if patch[n]!=now_patch[n]}=={'hepta/hia_patch_result_data.py'},
            'actual new map changes exceed the reviewed hosts/generated data')
    require(all(final_map[n]==base[n]for n in base if n.startswith('tests/'))
            and recorded['all_old_test_files_complete_bytes_unchanged']is True
            and recorded['source_files']==3210 and recorded['r5_files']==3191 and recorded['patch14_files']==14
            and recorded['source_map']==actual['final_source']['map']and recorded['source_tree']==tree(final_map)
            and recorded['historical_patch14']==plan['patch14_historical']
            and recorded['external_tests']==plan['external_tests']
            and recorded['future_qualification_executed']is False
            and recorded['old_R5_or_Patch14_PASS_transferred']is False,'actual qualification boundary differs')
    return {'r5':recorded['r5_actual'],'patch14':recorded['patch14_actual'],'source':recorded['source_map'],
            'complete_actual_domains':[3191,14,3210],'old_PASS_transferred':False}
'''
s=replace(s,"if __name__=='__main__':",extra+"\nif __name__=='__main__':")
ast.parse(s);compile(s,str(A/'read_terminal.py'),'exec',dont_inherit=True)
row=put('read_terminal.py',s.encode())
aa=before.splitlines(keepends=True);bb=s.splitlines(keepends=True);edits=[]
for kind,i,j,k,l in difflib.SequenceMatcher(a=aa,b=bb,autojunk=False).get_opcodes():
 if kind!='equal':edits.append({'before_start':i,'before_stop':j,'after_start':k,'after_stop':l,'before_text':''.join(aa[i:j]),'after_text':''.join(bb[k:l])})
x=aa[:];y=bb[:]
for e in reversed(edits):
 assert ''.join(x[e['before_start']:e['before_stop']])==e['before_text']and ''.join(y[e['after_start']:e['after_stop']])==e['after_text']
 x[e['before_start']:e['before_stop']]=e['after_text'].splitlines(keepends=True);y[e['after_start']:e['after_stop']]=e['before_text'].splitlines(keepends=True)
assert ''.join(x)==s and ''.join(y)==before
put('WHOLE-INVERSE.json',enc({'before':pin(before.encode()),'after':pin(s.encode()),'edits':edits,'full_forward_and_inverse':True}))
put('READER.diff',''.join(difflib.unified_diff(aa,bb,fromfile='original/read_terminal.py',tofile='op8/read_terminal.py')).encode())
bf,af=funcs(before),funcs(s)
report={'status':'AUTHOR_ONLY_STATIC_SYNTAX_AND_INVERSE_PASS','before':str(OLD),'reader':row,
 'whole_exact_original_functions':[n for n in bf if af.get(n)==bf[n]],
 'projected_functions':[n for n in bf if af.get(n)!=bf[n]],'new_functions':[n for n in af if n not in bf],
 'future_actual_result_pin':None,'future_generated_tree':None,'reader_executions':0,'products':0,
 'stderr_contract':'Read/retain complete actual stderr. Prior empty stderr was a fact of prior Patch run; do not suppress or discard new warnings.',
 'outer_schema':'Requires original independent Popen1800+3 INTENT/RESULT format, clean argv/cwd and complete ECHILD/group absent.',
 'failure_contract':'This verifies complete successful six-owner generation. A failed/incomplete producer is retained and the reader must fail; no automatic product retry or guessed future pins.'}
put('STATIC-REVIEW.json',enc(report))
launch={'schema':'hia.op8.generation-terminal-reader.launch.v1','status':'AUTHOR_ONLY_NOT_EXECUTED',
 'command':['python3','-B',str(A/'read_terminal.py'),'--output',OUTPUT],'cwd':str(A),
 'reader':row,'source_root':SCOPE,'outer_root':OUTER,'output':OUTPUT,'products':0,
 'plan':{'path':str(GEN/'GENERATION-PLAN.json'),**pin((GEN/'GENERATION-PLAN.json').read_bytes())}}
put('LAUNCH.json',enc(launch))
print(json.dumps({'root':str(A),'reader':row,'whole_exact_helpers':report['whole_exact_original_functions'],
 'output_absent':not Path(OUTPUT).exists(),'reader_runs':0,'products':0},sort_keys=True))
