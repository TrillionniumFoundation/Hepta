"""Author an exact R9-to-R10 terminal reader; never run the reader/product."""
from pathlib import Path
import ast,difflib,hashlib,json,stat
HERE=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-r9-controls-terminal-reader-r2-dda7/verify_terminal.py')
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(n,b):
    p=HERE/n;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644);assert p.read_bytes()==b
    return pin(b)
old=OLD.read_text();assert pin(old.encode())['git_blob']=='b97a012ee2ce1870aa4a1e39195f0523c60cd4b6';new=old;changes=[]
def change(a,b,expected=None):
    global new
    count=new.count(a);assert count and (expected is None or count==expected),(a,count,expected)
    changes.append({'before':a,'after':b,'count':count});new=new.replace(a,b)
change('R9','R10');change('r9','r10');change('R4','R9')
change("AUTHOR = Path('/tmp/hia-r8-r10-controls-author-r1-dda7')","AUTHOR = Path('/tmp/hia-r10-controls-author-r1-dda7')",1)
change("PRODUCT = Path('/hia-r8-r10-controls-20261114-dda7')","PRODUCT = Path('/workspace/hia-r10-controls-r1-dda7')",1)
change("ROOT_AUTHOR = Path('/tmp/hia-progress-v149-20261114-dda7')","ROOT_AUTHOR = Path('/tmp/hia-progress-v150-20261114-dda7')\nHISTORICAL_ROOT_AUTHOR = Path('/tmp/hia-progress-v149-20261114-dda7')\nPREVIOUS_OUTER = Path('/tmp/hia-r9-controls-outer-r1-dda7')",1)
change("CUSTODY = Path('/tmp/hia-r10-controls-complete-custody-r1-dda7')","CUSTODY = Path('/workspace/hia-r10-controls-complete-custody-r1-dda7')",1)
change("PREVIOUS = Path('/dev/shm/hia-u32-r8-controls-r4-dda7')","PREVIOUS = Path('/hia-r8-r9-controls-20261114-dda7')",1)
change("PREVIOUS_READER = Path('/tmp/hia-u32-r8-r4-terminal-readback-r1-dda7')","PREVIOUS_READER = Path('/tmp/hia-r9-controls-terminal-readback-r2-dda7')",1)
change("\nVM_STEPS = (4028084,2974291,7746379,192888,275860,10000001)\nPREVIOUS_VM_STEPS = (4426100,3267145,8506363,216015,302985,10000001)","\nVM_STEPS = (3774295,2779096,7285022,188901,254951,10000001)\nPREVIOUS_VM_STEPS = (4028084,2974291,7746379,192888,275860,10000001)",1)
for a,b in [
('125dc522389049145d6f63166b39ed9754993327','64437dc3c669d41867c645128632481d386f89c4'),
('e71435798df5407edcb472bd8b80aedcffa20876','0ba3f9fa101729ad9e194fbbb3507234dbc981d8'),
('ab25ae2113554b444c38f09e23ca36bd75d5eb57','9440c2f2b55858faee16f9aa952d467ef715ff52'),
('2849d18a18a46d01e8150738fcd173101361255e','5e7e12a4a92f1312a818e0b6730548ea685e3de8'),
('2e9a901ca157392f1a764f677a2f856bd52245c7','17a5975a47dc826557b3990dbcb0c1d399bfb724'),
('acd6c350f3eec17941292d92da1989390e1b24aa','5e94c203c66348f8579b7029b97dfdaf07398231'),
('4b8c87f5f98161f0dc92530a9ee73947ab0633ba','858f8a4096028555c4040c53f758b97b9dd62148'),
('868d44d6e34fce5e02bcf0339c3aeb3039f6a508','b4ff2f9569679c4fced58d26f0a511ed7312c013'),
('1110456844','1110455563'),('1122457162','1122002129'),("sealed['file_count']==2213","sealed['file_count']==2217"),
('724909501','725196980'),('len(prefix_expected)==43','len(prefix_expected)==78'),("edge_vm['steps']==7746379","edge_vm['steps']==7285022"),
("Path('/tmp/hia-r10-controls-terminal-readback-r2-dda7')","Path('/workspace/hia-r10-controls-terminal-readback-r1-dda7')")]:change(a,b)
change('import argparse\n','import argparse\nimport ast\n',1)
start=new.index("    correction=j(ROOT_AUTHOR/");end=new.index("    need(intent['admission']",start);projected_old_block=new[start:end]
original_start=old.index("    correction=j(ROOT_AUTHOR/");original_end=old.index("    need(intent['admission']",original_start)
historical=old[original_start:original_end].replace('ROOT_AUTHOR/','HISTORICAL_ROOT_AUTHOR/').replace("json.loads(returned['output'])==outer","json.loads(returned['output'])==j(PREVIOUS_OUTER/'RESULT.json')")
new_binding='''    inverse=j(ROOT_AUTHOR/'R10-CONTROLS-R1-ROOT-OUTER-INVERSE.json',
              'ff0fd51d6c32390dbbd90d5b42a1ead8bc2c6465')
    actual_launcher=read(ROOT_AUTHOR/'launch_r10_controls_r1.py')
    need(pin(second)==inverse['before']['identity'] and pin(actual_launcher)==inverse['after'],
         'R10 actual launcher before/after differs')
    inserted=inverse['helper_gate_assertion_insert'].encode()
    need(pin(inserted)==inverse['helper_gate_insert_identity'] and actual_launcher.count(inserted)==1,
         'actual helper predecessor assertion differs')
    reconstructed=actual_launcher.replace(inserted,b'',1)
    for edit in reversed(inverse['literal_replacements']):
        after=edit['after'].encode();before=edit['before'].encode()
        need(reconstructed.count(after)==edit['count'],'R10 launcher literal inverse count differs')
        reconstructed=reconstructed.replace(after,before)
    need(reconstructed==second and ast.dump(ast.parse(reconstructed))==ast.dump(ast.parse(second)),
         'R10 launcher is not the complete original owner/subreaper body')
    helper_raw=read(Path('/tmp/hia-r10-helper-independent-readback-r1-dda7/RESULT.json'))
    need(pin(helper_raw)==inverse['actual_helper_proof'] and
         inverse['actual_fresh_admission']==pin(read(ADMISSION/'RESULT.json')),
         'actual R10 helper/admission proof binding differs')
    helper=json.loads(helper_raw)
    need(helper['status']=='PASS_INDEPENDENT_R10_HELPER_TERMINAL_ONLY' and helper['errors']==[] and
         helper['case_pairs']==553 and helper['actual_VM_calls']==1106 and
         helper['logical_before_after_buffers']==2212 and helper['all_original_budgets_kept'] is True and
         helper['full_original_domain_files']==6777,'R10 helper predecessor is not the actual complete PASS')
    current_started=j(ROOT_AUTHOR/'R10-CONTROLS-R1-EXEC.json','631f146b8cdb7b530ddbfff686c6360d0f0c536a')
    current_returned=j(ROOT_AUTHOR/'R10-CONTROLS-R1-RETURN.json','201ba031b5a2db8513a0912adc557d3b51c4ed0b')
    need(current_started['session_id']==66583 and current_returned['exit_code']==1 and
         json.loads(current_returned['output'])==outer,'actual R10 execution/terminal does not bind outer')
'''
change(projected_old_block,historical+new_binding,1)
ast.parse(new)
reverse=new
for row in reversed(changes):
    assert reverse.count(row['after'])==row['count'],('inverse count',row['after'][:100],reverse.count(row['after']),row['count'])
    reverse=reverse.replace(row['after'],row['before'])
assert reverse==old and ast.dump(ast.parse(reverse))==ast.dump(ast.parse(old))
def definitions(text):
    lines=text.splitlines(True)
    return {x.name:''.join(lines[x.lineno-1:x.end_lineno]) for x in ast.parse(text).body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
before_defs=definitions(old);after_defs=definitions(new);unchanged={name:pin(body.encode()) for name,body in before_defs.items() if name not in ('verify','main')}
assert len(unchanged)==12 and all(after_defs[n]==before_defs[n] for n in unchanged)
put('before/verify_terminal.py',old.encode());put('verify_terminal.py',new.encode());put('READER.diff',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='R9/verify_terminal.py',tofile='R10/verify_terminal.py')).encode())
proof={'status':'STATIC_AUTHOR_ONLY','before':pin(old.encode()),'after':pin(new.encode()),'whole_byte_inverse':True,'whole_AST_inverse':True,'ordered_changes':changes,'unchanged_12_helpers':unchanged,'original_R9_failed_launcher_history_retained':True,'new_R10_launcher_complete_inverse_and_actual_helper_proof_required':True,'product_execution':0,'reader_execution':0}
put('EXACT-INVERSE.json',enc(proof))
contract='''# R10 terminal evidence reader

This is a source-only successor of the complete R9 R2 reader. It must read every original 6,777-file fresh domain, all 67 controls and 962 role references, all current actual raw bytes and modes/seven-stat/pathsets, every Native/VM buffer, all Native request/canary/preimage/receipt fields, all four owner results and cleanup, and the full original fail-stop order.

The prior R9 launcher failure and successful one-shot R9 invocation remain explicit immutable historical checks. The new R10 invocation is separately bound to the actual Root launcher, its complete reverse projection to the original owner/subreaper body, the actual 553-pair helper independent PASS, the actual admission, and session 66583. R9 and R10 six-case initial buffers must compare completely byte for byte. The five returned cases and the cross-target original 10M+1 failure are recomputed from complete actual buffers; the four aggregate groups remain unstarted.

Running this reader is reserved to Root. Reader PASS means only that the actual R10 qualification FAIL is faithfully preserved and independently read. It does not rerun a product, grant current-cold/ordinary/default/whole qualification, modify any source/test/budget, or rewrite the original failure.
'''
put('CONTRACT.md',contract.encode())
launch={'schema':'hia.R10.terminal-reader.launch.v1','argv':['python3','-B',str(HERE/'verify_terminal.py'),'--out','/workspace/hia-r10-controls-terminal-readback-r1-dda7'],'cwd':'/tmp','reader':pin(new.encode()),'products':0,'execution_authority':'Root only','status':'AUTHORED_NOT_EXECUTED'}
put('READER-LAUNCH.json',enc(launch))
paths=[p for p in HERE.rglob('*') if p.is_file()];files={str(p.relative_to(HERE)):{'path':str(p),'identity':pin(p.read_bytes()),'mode':stat.S_IMODE(p.stat().st_mode)} for p in sorted(paths)}
handoff={'schema':'hia.R10.terminal-reader.author.handoff.v1','status':'AUTHORED_NOT_EXECUTED','files':files,'source_product_changes':0,'reader_executions':0,'products':0,'original_qualification':'FAIL','actual_raw_manifest':{'path':'/workspace/hia-r10-controls-complete-custody-r1-dda7/MANIFEST.json','git_blob':'5e7e12a4a92f1312a818e0b6730548ea685e3de8'},'actual_VM_steps':[3774295,2779096,7285022,188901,254951,10000001],'parent_should_review_then_run_once':True}
ident=put('HANDOFF.json',enc(handoff));print(json.dumps({'handoff':ident,'reader':pin(new.encode()),'unchanged_helpers':len(unchanged),'products':0,'reader_execution':0},sort_keys=True))
