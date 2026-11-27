"""Correct the reader's metadata projection only; no reader/product invocation."""
from pathlib import Path
import ast,base64,difflib,hashlib,json,os,stat
R=Path(__file__).resolve().parent
BEFORE=Path('/tmp/hia-r9-controls-terminal-reader-r1-dda7')
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def dump(p,x):
    with p.open('x') as f:json.dump(x,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')
def main():
    original=(BEFORE/'verify_terminal.py').read_bytes()
    assert pin(original)['git_blob']=='540c48fd27c522d7e7dca9a437b6f487a9368479'
    old="""    need(original_fresh=={'groups':mapping['groups'],'extra_authorities':mapping['extra_authorities'],
         'files':6777,'bytes':948620735},'actual original-domain admission map differs')"""
    new="""    need(all(set(row)=={'identity','roles','seven_stats'}
             for group in mapping['groups'] for row in group['files'].values()) and
         all(set(row)=={'path','identity','roles','seven_stats'} for row in mapping['extra_authorities']),
         'original mapping row schema differs')
    observed_groups=[{**group,'files':{name:{k:v for k,v in row.items() if k!='roles'}
                     for name,row in group['files'].items()}} for group in mapping['groups']]
    observed_extras=[{k:v for k,v in row.items() if k!='roles'} for row in mapping['extra_authorities']]
    need(original_fresh=={'groups':observed_groups,'extra_authorities':observed_extras,
         'files':6777,'bytes':948620735},'actual original-domain admission map differs')"""
    s=original.decode();assert s.count(old)==1;s=s.replace(old,new)
    old_out="Path('/tmp/hia-r9-controls-terminal-readback-r1-dda7'))"
    new_out="Path('/tmp/hia-r9-controls-terminal-readback-r2-dda7'))"
    assert s.count(old_out)==1;s=s.replace(old_out,new_out)
    reconstructed=s.replace(new_out,old_out).replace(new,old)
    assert reconstructed.encode()==original
    projected=s.encode();compile(projected,'verify_terminal.py','exec')
    original_inverse=json.loads((BEFORE/'EXACT-INVERSE.json').read_bytes());restored=reconstructed
    for row in reversed(original_inverse['edits']):
        assert restored.count(row['after'])==row['count'];restored=restored.replace(row['after'],row['before'])
    base=base64.b64decode(original_inverse['original_raw_base64'],validate=True)
    assert restored.encode()==base and pin(base)['git_blob']=='ced99939a0e7de4c1841503112949ea525fdfee1'
    def functions(raw):
        lines=raw.splitlines(keepends=True)
        return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
    a=functions(base);b=functions(projected);unchanged=sorted(set(a)-{'verify','main'})
    assert set(a)==set(b) and all(a[n]==b[n] for n in unchanged)
    prior=R/'prior-r1';prior.mkdir()
    captured={}
    for p in sorted(BEFORE.iterdir()):
        assert p.is_file() and not p.is_symlink();raw=p.read_bytes();mode=stat.S_IMODE(p.lstat().st_mode)
        q=prior/p.name
        with q.open('xb') as f:f.write(raw)
        q.chmod(mode);assert q.read_bytes()==raw
        captured[p.name]={'identity':pin(raw),'mode':mode,'original_path':str(p)}
    with (R/'verify_terminal.py').open('xb') as f:f.write(projected)
    with (R/'R1-R2.diff').open('x') as f:f.write(''.join(difflib.unified_diff(original.decode().splitlines(True),s.splitlines(True),fromfile='R1/verify_terminal.py',tofile='R2/verify_terminal.py')))
    with (R/'R4-R9-FULL.diff').open('x') as f:f.write(''.join(difflib.unified_diff(base.decode().splitlines(True),s.splitlines(True),fromfile='actual-R4/verify_terminal.py',tofile='R9-R2/verify_terminal.py')))
    dump(R/'EXACT-INVERSE-R2.json',{'schema':'hia.R9.terminal-reader.R2.exact-inverse.v1','R4_original':pin(base),
         'R1':pin(original),'R2':pin(projected),'whole_R1_inverse':True,'whole_R4_inverse':True,
         'edits':[{'before':old,'after':new,'count':1,'reason':'Exact original producer emits identity and seven_stats; role annotations remain bound by original mapping hash and full962 role checks'},
                  {'before':old_out,'after':new_out,'count':1,'reason':'Independent reader output root only'}],
         'R1_edits':original_inverse['edits'],'R4_original_raw_base64':base64.b64encode(base).decode(),
         'R2_raw_base64':base64.b64encode(projected).decode(),'products':0,'reader_executions':0})
    dump(R/'PRIOR-R1-RETENTION.json',{'original_readonly_root':str(BEFORE),'files':captured,
         'original_R1_static_metadata_failure_preserved':True,'no_R1_reader_execution':True,'products':0})
    m=json.loads(Path('/tmp/hia-u32-r8-r4-admission-author-r1-dda7/EXPECTED-MAPPING.json').read_bytes())
    f=json.loads(Path('/tmp/hia-r9-controls-fresh-admission-r1-dda7/FULL-FRESH-6777.json').read_bytes())
    assert all(set(row)=={'identity','roles','seven_stats'} for g in m['groups'] for row in g['files'].values())
    assert all(set(row)=={'path','identity','roles','seven_stats'} for row in m['extra_authorities'])
    expected={'groups':[{**g,'files':{n:{k:v for k,v in row.items() if k!='roles'} for n,row in g['files'].items()}} for g in m['groups']],
              'extra_authorities':[{k:v for k,v in row.items() if k!='roles'} for row in m['extra_authorities']],
              'files':6777,'bytes':948620735}
    assert f==expected
    dump(R/'STATIC-REVIEW.json',{'schema':'hia.R9.terminal-reader.R2.static.v1','status':'AUTHOR_ONLY_NOT_EXECUTED',
         'reader':pin(projected),'whole_R4_and_R1_inverse':True,'exact_actual_admission_producer_projection':True,
         'all_other_function_bytes_exact':{n:pin(a[n]) for n in unchanged},'Native_VM_frame_helpers_unchanged':True,
         'original948_roles_and_new14_checks_retained':True,'full_original6777_read_unchanged':True,
         'R1_metadata_equality_FAILURE_is_not_product_failure':True,'project_imports':0,'products':0,'reader_executions':0,'CI':0})
    print(json.dumps({'status':'AUTHOR_ONLY_METADATA_PROJECTION_PASS','reader':pin(projected),'prior_files':len(captured),'unchanged_functions':unchanged},sort_keys=True))
if __name__=='__main__':main()
