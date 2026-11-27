"""Author a reversible R9 projection; do not import or run the reader or products."""
from pathlib import Path
import ast
import base64
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parent
OLD = Path('/tmp/hia-u32-r8-r4-terminal-reader-r1-dda7/verify_terminal.py')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def dump(name, value):
    with (ROOT/name).open('x') as f:
        json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')

def main():
    original=OLD.read_bytes()
    assert pin(original)['git_blob']=='ced99939a0e7de4c1841503112949ea525fdfee1'
    text=original.decode();changes=[]
    def replace(before,after,reason,count=1):
        nonlocal text
        assert text.count(before)==count,(reason,text.count(before),count)
        text=text.replace(before,after)
        changes.append({'before':before,'after':after,'count':count,'reason':reason})
    replace("AUTHOR = Path('/tmp/hia-u32-r8-post-reset-r4-dda7')", "AUTHOR = Path('/tmp/hia-r8-r9-controls-author-r1-dda7')", 'Actual R9 author root')
    replace("PRODUCT = Path('/dev/shm/hia-u32-r8-controls-r4-dda7')", "PRODUCT = Path('/hia-r8-r9-controls-20261114-dda7')", 'Actual R9 output root')
    replace("OUTER = Path('/tmp/hia-r8-original-controls-r4-outer-dda7')", "OUTER = Path('/tmp/hia-r9-controls-outer-r1-dda7')", 'Actual R9 outer root')
    replace("ADMISSION = Path('/tmp/hia-u32-r8-r4-fresh-admission-r1-dda7')", "ADMISSION = Path('/tmp/hia-r9-controls-fresh-admission-r1-dda7')", 'Actual R9 admission root')
    replace("ROOT_AUTHOR = Path('/tmp/hia-progress-v148-20261114-dda7')", "ROOT_AUTHOR = Path('/tmp/hia-progress-v149-20261114-dda7')\nCUSTODY = Path('/tmp/hia-r9-controls-complete-custody-r1-dda7')\nPREVIOUS = Path('/dev/shm/hia-u32-r8-controls-r4-dda7')\nPREVIOUS_READER = Path('/tmp/hia-u32-r8-r4-terminal-readback-r1-dda7')", 'Root R9 originals and immutable actual R4 comparison authorities')
    replace('VM_STEPS = (4426100,3267145,8506363,216015,302985,10000001)', 'VM_STEPS = (4028084,2974291,7746379,192888,275860,10000001)\nPREVIOUS_VM_STEPS = (4426100,3267145,8506363,216015,302985,10000001)', 'Actual original reports, never an earlier summary')
    replace("plan=j(AUTHOR/'EXECUTION-PLAN.json','2374488181b268a9ea557832302025c135e63f36')", "plan=j(AUTHOR/'EXECUTION-PLAN.json','125dc522389049145d6f63166b39ed9754993327')", 'Frozen R9 plan identity')
    replace("top=j(PRODUCT/'RESULT.json','b0d626eb6e6633c38ee0445d495513586dc5cc08')", "top=j(PRODUCT/'RESULT.json','e71435798df5407edcb472bd8b80aedcffa20876')", 'Actual R9 terminal identity')
    replace("admission=j(ADMISSION/'RESULT.json','89cfd770a82284ff65d34173573719606c6546f8')\n    need(admission['status']=='PASS_FULL_FRESH_R4_DATA_ADMISSION_ONLY' and admission['fresh_file_reads']==6777\n         and admission['fresh_bytes']==948620735 and admission['storage_before']['free_bytes']>=3221225472\n         and admission['storage_after']['free_bytes']>=3221225472,'actual fresh admission differs')", """admission=j(ADMISSION/'RESULT.json','ab25ae2113554b444c38f09e23ca36bd75d5eb57')
    need(admission['status']=='PASS_FULL_FRESH_R9_EIGHT_GROUP_ADMISSION_ONLY' and
         admission['full_original_domain_files']==6777 and admission['full_original_domain_bytes']==948620735 and
         admission['free_bytes_at_admission']>=3221225472 and admission['new_controls']==67 and
         admission['all962_full_roles'] is True and admission['old948_roles_exact'] is True,
         'actual R9 fresh admission differs')
    sealed=j(CUSTODY/'MANIFEST.json','2849d18a18a46d01e8150738fcd173101361255e')
    need(sealed['file_count']==2213 and sealed['logical_bytes']==1122457162,'sealed R9 denominator differs')
    for logical,wanted in sealed['files'].items():
        if logical.startswith(('root_author/','r9_author/')):
            full(wanted['source_path'],{**wanted['identity'],'mode':wanted['mode']},wanted['seven_stats'])
    original_plan=j(Path('/tmp/hia-u32-r8-post-reset-r4-dda7/EXECUTION-PLAN.json'),
                    '2374488181b268a9ea557832302025c135e63f36')
    need(len(original_plan['fixed_inputs'])==948 and len(plan['fixed_inputs'])==962 and
         all(plan['fixed_inputs'][name]==row for name,row in original_plan['fixed_inputs'].items()),
         'original 948 role bindings differ')
    new_roles=plan['R9_explicit_successor']['actual_candidate_roles']
    need(set(new_roles)==set(plan['fixed_inputs'])-set(original_plan['fixed_inputs']) and len(new_roles)==14,
         'explicit R9 14-role additions differ')
    frozen_roles=j(ADMISSION/'ALL-962-FULL-ROLES.json','2e9a901ca157392f1a764f677a2f856bd52245c7')
    need(frozen_roles['reference_count']==len(frozen_roles['roles'])==962 and
         set(frozen_roles['roles'])==set(plan['fixed_inputs']),'actual admission role set differs')
    original_fresh=j(ADMISSION/'FULL-FRESH-6777.json','8e7671a3b37465c66e63af409f50578d2dc75fd6')
    need(original_fresh=={'groups':mapping['groups'],'extra_authorities':mapping['extra_authorities'],
         'files':6777,'bytes':948620735},'actual original-domain admission map differs')""", 'R9 admission has one original free-space observation and complete 962 roles; do not invent the R4 AFTER record')
    replace("    dump(output/'INPUT-READBACK.json',input_rows)", """    original_input_count=len(input_rows)
    original_input_bytes=sum(r['identity']['bytes'] for r in input_rows.values())
    need(set(admission['controls'])==set(plan['controls']) and len(plan['controls'])==67,
         'all R9 control admission names differ')
    for name,wanted in plan['controls'].items():
        observed=admission['controls'][name]
        need(observed['identity']==wanted,'R9 control admission identity differs')
        path=str(AUTHOR/name)
        need(path not in input_rows,'new control aliases original input path')
        input_rows[path]=full(path,wanted,observed['seven_stats'])
    for name,wanted in new_roles.items():
        observed=admission['new_candidate_roles'][name]
        need(observed=={'identity':wanted['identity'],'seven_stats':wanted['seven_stats']} and
             {k:v for k,v in plan['fixed_inputs'][name].items() if k!='phases'}==
             {'path':wanted['path'],'identity':wanted['identity']},'R9 candidate role admission differs')
        need(wanted['path'] not in input_rows,'R9 role aliases original/control path')
        input_rows[wanted['path']]=full(wanted['path'],wanted['identity'],wanted['seven_stats'])
    need(len(input_rows)==6777+67+14,'post-run original plus R9 extension denominator differs')
    role_readback={}
    for name,wanted in plan['fixed_inputs'].items():
        observed=frozen_roles['roles'][name]
        actual=full(wanted['path'],wanted['identity'],observed['seven_stats'])
        need(actual==input_rows[wanted['path']] and actual['identity']==observed['identity'],
             'full actual role differs from pre-run admission')
        role_readback[name]={'path':wanted['path'],'identity':actual['identity'],'seven_stats':actual['seven_stats'],
                             'phases':wanted['phases']}
    need(sum(row['identity']['bytes'] for row in role_readback.values())==frozen_roles['reference_bytes']==724909501,
         'all 962 full role-reference bytes differ')
    dump(output/'ALL-962-ROLE-READBACK.json',role_readback)
    prefix=plan['R9_explicit_successor']['prefix_plan']
    prefix_plan=json.loads(full(prefix['path'],prefix['identity'],prefix['seven_stats'],contents=True))
    prefix_root=Path(prefix['path']).parent;prefix_readback={}
    prefix_expected={name:row for name,row in prefix_plan['fixed_controls'].items()}
    for name,identity in prefix_plan['author_files'].items():
        need('author:'+name not in prefix_expected,'prefix authority name collision')
        prefix_expected['author:'+name]={'path':str(prefix_root/name),'identity':identity}
    need(set(prefix_expected)==set(admission['prefix_controls']) and len(prefix_expected)==43,
         'all prefix-admission authority names differ')
    for name,wanted in prefix_expected.items():
        observed=admission['prefix_controls'][name]
        need(observed['identity']==wanted['identity'],'prefix authority identity differs')
        prefix_readback[name]=full(wanted['path'],wanted['identity'],observed['seven_stats'])
    dump(output/'PREFIX-AUTHORITY-READBACK.json',prefix_readback)
    for label in ('plan','launch'):
        observed=admission[label]
        full(observed['path'],observed['identity'],observed['seven_stats'])
    dump(output/'INPUT-READBACK.json',input_rows)""", 'Fresh full-byte R9 controls, all 962 ordered roles, and the same 43 prefix authorities without shrinking original 6777')
    replace("        for name,wanted in state['files'].items(): raw_inventory[label+'/'+name]=full(root/name,wanted_stat=wanted)", """        sealed_label={'product':'r9_actual','outer':'r9_outer','fresh_admission':'fresh_admission'}[label]
        wanted_paths={n[len(sealed_label)+1:] for n in sealed['files'] if n.startswith(sealed_label+'/')}
        need(set(state['files'])==wanted_paths,'complete actual raw pathset differs from sealed original')
        for name,wanted in state['files'].items():
            frozen_row=sealed['files'][sealed_label+'/'+name]
            need(frozen_row['source_path']==str(root/name) and wanted==frozen_row['seven_stats'],
                 'sealed actual raw path/stat differs')
            raw_inventory[label+'/'+name]=full(root/name,
                {**frozen_row['identity'],'mode':frozen_row['mode']},wanted)""", 'Bind the complete raw tree to the already sealed original pathset, bytes, modes and seven stats')
    replace('==1110378385', '==1110456844', 'Actual R9 complete product plus outer byte count')
    replace("    auth=read(ROOT_AUTHOR/'R8-PRODUCT-AUTHORIZATION-R4.json')\n    need(pin(auth)['git_blob']=='74320d23292860f3314c38acaa40d1b9a563b0c7' and intent['authorization']==pin(auth),\n         'Root actual authorization differs')", """    launch=j(AUTHOR/'PRODUCT-LAUNCH.json','acd6c350f3eec17941292d92da1989390e1b24aa')
    correction=j(ROOT_AUTHOR/'R9-CONTROLS-ROOT-LAUNCHER-R1-FAILURE-RETAINED.json',
                 'c72d69134afefc2d8c43d85c9bb032f7bc45a27c')
    first=read(ROOT_AUTHOR/'launch_r9_controls_r1.py');second=read(ROOT_AUTHOR/'launch_r9_controls_r2.py')
    old_literal=correction['before_literal'].encode();new_literal=correction['after_literal'].encode()
    need(pin(first)==correction['before'] and pin(second)==correction['after'] and
         first.count(old_literal)==second.count(new_literal)==1 and
         first.replace(old_literal,new_literal)==second and second.replace(new_literal,old_literal)==first,
         'actual Root launcher one-literal whole inverse differs')
    first_return=j(ROOT_AUTHOR/'R9-CONTROLS-EXEC.json','df85fd758536fc23f57a906bb227984ebfd51138')
    need(pin(read(ROOT_AUTHOR/'R9-CONTROLS-EXEC.json'))==correction['failure_exec_receipt'] and
         first_return['exit_code']==1 and 'AssertionError' in first_return['output'] and
         correction['prior_product_child_launches']==correction['original_eight_group_attempts_so_far']==0 and
         correction['prior_outer_directory_absent'] is True and correction['prior_product_directory_absent'] is True,
         'original zero-child launcher failure record differs')
    started=j(ROOT_AUTHOR/'R9-CONTROLS-R2-EXEC.json','6decad95ad59fce058d38564864c2c58d83fe184')
    returned=j(ROOT_AUTHOR/'R9-CONTROLS-R2-RETURN.json','483d8855ff9863be324504386826f1418317b295')
    need(started['session_id']==79468 and returned['exit_code']==1 and json.loads(returned['output'])==outer,
         'actual tool execution/terminal does not bind outer')
    need(intent['admission']==pin(read(ADMISSION/'RESULT.json')) and
         intent['argv']==launch['argv'] and intent['cwd']==launch['cwd']==plan['source']['path'] and
         intent['outer_watchdog_seconds']==launch['outer_seconds']==1800 and
         launch['outer_cleanup_seconds']==3 and launch['each_product_owner_seconds']==180 and
         launch['each_cleanup_seconds']==3 and launch['no_stage_retries'] is True and
         launch['outer_root']==str(OUTER) and launch['output']==str(PRODUCT) and
         launch['plan']==admission['plan'] and intent['launch_seven_stats']==admission['launch']['seven_stats'] and
         launch['argv'][-2:]==['--plan-sha256',authorization],
         'Root actual R9 launch/admission/request binding differs')""", 'Actual R9 uses the fixed launch and admission, plus retained R1 type-check failure and exact R2 inverse, not an invented R4 authorization file')
    replace("full(image,plan['fixed_inputs']['R8-image']['identity'])", "full(image,plan['fixed_inputs']['R9-image']['identity'])", 'Actual R9 private semantic image')
    replace("edge_vm['steps']==8506363", "edge_vm['steps']==7746379", 'Actual R9 edge steps')
    replace("    vm_rows=[]\n", """    previous_proof=j(PREVIOUS_READER/'RESULT.json','4b8c87f5f98161f0dc92530a9ee73947ab0633ba')
    previous_inventory=json.loads(read(PREVIOUS_READER/'FULL-RAW-INVENTORY.json',previous_proof['raw_inventory']))
    def previous_raw(path):
        path=Path(path)
        key='product/'+path.relative_to(PREVIOUS).as_posix()
        need(key in previous_inventory,'previous raw member missing from actual Root readback')
        old=previous_inventory[key]
        need(old['path']==str(path),'previous raw path binding differs')
        return full(path,old['identity'],old['seven_stats'],contents=True)
    previous_folder=PREVIOUS/plan['phases'][3]['out']
    previous_report=json.loads(previous_raw(previous_folder/'REPORT.json'))
    need(pin(previous_raw(previous_folder/'REPORT.json'))['git_blob']=='868d44d6e34fce5e02bcf0339c3aeb3039f6a508' and
         previous_report['status']=='FAIL' and previous_report['count']==6 and
         previous_report['failures']==['root-v8-cross-target-loans'] and
         [[x['group'],x['name']] for x in previous_report['rows']]==plan['original_semantic_six_order'],
         'actual R4 six-case report differs')
    previous_frames=json.loads(previous_raw(previous_folder/'VM-SIX-BUFFER-READBACK.json'))
    need(previous_frames['calls_or_logical_rows']==len(previous_frames['rows'])==6 and
         previous_frames['VM_reruns']==0 and previous_frames['required_complete'] is False,
         'actual R4 six-frame report differs')
    predecessor_comparison=[];vm_rows=[]
""", 'Use exact original R4 report and all six actual initial-buffer references to resolve the misleading old summary')
    replace("        actual=j(prior/'native/OBSERVATION.json');reused=name=='edge-256-reversed-origin'", """        actual=j(prior/'native/OBSERVATION.json');reused=name=='edge-256-reversed-origin'
        previous_frame=previous_frames['rows'][index];previous_row=previous_report['rows'][index]
        need(previous_frame['name']==previous_row['name']==name and previous_frame['complete_six_buffers'] is True and
             previous_frame['exact_current_R8_edge_reused'] is reused,'R4/R9 case identity differs')
        before_pins=[]
        for label,value in zip(NAMES,initial,strict=True):
            old_before=previous_frame['frames'][label+'.before']
            old_bytes=previous_raw(old_before['path'])
            need(old_before=={'path':old_before['path'],**pin(old_bytes)} and old_bytes==value,
                 'R4/R9 complete actual VM initial buffer differs')
            before_pins.append({'name':label,**pin(value)})
        old_vm=json.loads(previous_raw(previous_folder/name/'VM-REPORT.json'))
        old_result=json.loads(previous_raw(previous_folder/name/'RESULT.json'))
        need(old_result==previous_row and old_vm['steps']==previous_row['VM_steps']==PREVIOUS_VM_STEPS[index],
             'R4 actual VM steps/result differ')
        predecessor_comparison.append({'name':name,'same_complete_initial_buffers':True,'initial_buffers':before_pins,
            'R4_steps':old_vm['steps'],'R9_steps':VM_STEPS[index],'difference_R9_minus_R4':VM_STEPS[index]-old_vm['steps'],
            'R4_status':old_vm['status'],'R4_phase':previous_row['phase_word'],'R4_error':previous_row['semantic_error_word'],
            'R9_phase':row['phase_word'],'R9_error':row['semantic_error_word'],
            'not_a_general_fuel_monotonicity_or_performance_claim':True})""", 'Strict per-case actual input equality and exact original result binding; no R4 retest')
    replace("and 'E_HIA_BUDGET_STEPS: finite step limit reached' in exception and row['phase_word']==row['semantic_error_word']==0,", "and 'E_HIA_BUDGET_STEPS: finite step limit reached' in exception and row['phase_word']==1 and row['semantic_error_word']==0,", 'Actual R9 failure progressed to phase1 at unchanged 10M limit')
    replace("    need(sum(row['pass'] for row in r['rows'])==5,'actual six-VM pass denominator differs')", "    need(sum(row['pass'] for row in r['rows'])==5,'actual six-VM pass denominator differs')\n    dump(output/'R4-R9-ACTUAL-VM-INPUT-COMPARISON.json',predecessor_comparison)", 'Preserve exact actual comparison as its own proof')
    replace("'post_run_input_full_fresh_files':len(input_rows),'post_run_input_full_fresh_bytes':948620735,", "'post_run_original_domain_files':original_input_count,'post_run_original_domain_bytes':original_input_bytes,\n        'post_run_input_full_fresh_files':len(input_rows),\n        'post_run_input_full_fresh_bytes':sum(x['identity']['bytes'] for x in input_rows.values()),\n        'all_fixed_role_references':len(role_readback),'fixed_role_reference_bytes':frozen_roles['reference_bytes'],\n        'fresh_prefix_authorities':len(prefix_readback),'R4_R9_actual_VM_comparison':predecessor_comparison,", 'Separate original 6777 domain from new R9 controls and actual14 role paths')
    replace("'actual_product_outer_bytes':1110378385", "'actual_product_outer_bytes':1110456844", 'Actual R9 complete raw bytes')
    replace('hepta.r8.r4.', 'hepta.r8.r9.', 'Reader/proof schema successor labels',count=2)
    replace('PASS_READBACK_OF_ACTUAL_R4_VM_FUEL_FAILURE','PASS_READBACK_OF_ACTUAL_R9_VM_FUEL_FAILURE','R9 proof scope')
    replace('ORIGINAL_R4_FAIL_UNCHANGED','ORIGINAL_R9_FAIL_UNCHANGED','Reader failure leaves product unchanged')
    replace("Path('/tmp/hia-u32-r8-r4-terminal-readback-r1-dda7'))", "Path('/tmp/hia-r9-controls-terminal-readback-r1-dda7'))", 'New reader-only output default')
    projected=text.encode();restored=text
    for row in reversed(changes):
        assert restored.count(row['after'])==row['count'],row['reason']
        restored=restored.replace(row['after'],row['before'])
    assert restored.encode()==original
    compile(projected,'verify_terminal.py','exec')
    def functions(raw):
        lines=raw.splitlines(keepends=True)
        return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
    old_functions=functions(original);new_functions=functions(projected)
    unchanged=sorted(set(old_functions)-{'verify','main'})
    assert set(old_functions)==set(new_functions)
    assert all(old_functions[n]==new_functions[n] for n in unchanged)
    with (ROOT/'R4-READER-ORIGINAL.py').open('xb') as f:f.write(original)
    with (ROOT/'verify_terminal.py').open('xb') as f:f.write(projected)
    with (ROOT/'READER.diff').open('x') as f:f.write(''.join(difflib.unified_diff(original.decode().splitlines(True),text.splitlines(True),fromfile='R4/verify_terminal.py',tofile='R9/verify_terminal.py')))
    dump('EXACT-INVERSE.json',{'schema':'hia.R9.terminal-reader.whole-inverse.v1','before':pin(original),'after':pin(projected),
         'edits':changes,'whole_inverse':True,'original_raw_base64':base64.b64encode(original).decode(),
         'projected_raw_base64':base64.b64encode(projected).decode(),'products':0,'reader_executions':0})
    dump('STATIC-REVIEW.json',{'schema':'hia.R9.terminal-reader.static.v1','status':'AUTHOR_ONLY_NOT_EXECUTED',
         'original':pin(original),'projected':pin(projected),'whole_inverse':True,'changed_top_level_functions':['verify','main'],
         'all_other_function_bytes_exact':{n:pin(old_functions[n]) for n in unchanged},
         'all_Native_and_VM_frame_helper_bytes_exact':True,'bytecode_compile_only':True,'project_imports':0,
         'full_payload_reads':0,'products':0,'reader_executions':0,'CI':0})
    print(json.dumps({'status':'AUTHOR_ONLY','reader':pin(projected),'edits':len(changes),'unchanged_functions':unchanged},sort_keys=True))

if __name__=='__main__':main()
