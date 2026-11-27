"""Verify actual immutable Git GET author bytes and both exact inverse chains."""
from pathlib import Path
import ast,base64,hashlib,json,stat,time
R=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(p):return [getattr(p.lstat(),k) for k in FIELDS]
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def main():
    start=time.monotonic_ns();inputs=json.loads((R/'PUBLICATION-INPUTS.json').read_bytes());actual={};rows=[]
    assert len(inputs['files'])==20
    for row in inputs['files']:
        n=row['path'];expected=row['identity'];stem=''.join(c if c.isalnum() or c in '_-' else '_' for c in n)
        post=json.loads((R/'git-receipts'/(stem+'.POST.json')).read_bytes())
        get=json.loads((R/'git-receipts'/(stem+'.GET.json')).read_bytes())
        receipt=json.loads((R/'git-receipts'/(stem+'.READBACK.json')).read_bytes())
        assert post.get('isError') is not True and post['structuredContent']['sha']==expected['git_blob']
        assert get.get('isError') is not True
        b=get['structuredContent']['content'].encode('utf-8')
        assert pin(b)=={k:expected[k] for k in ('bytes','sha256','git_blob')}
        assert receipt['identity']==expected and receipt['POST_ACK'] is True and receipt['full_GET'] is True
        p=Path(row['local_path']);before=seven(p)
        assert stat.S_ISREG(p.lstat().st_mode) and p.lstat().st_nlink==1
        assert p.read_bytes()==b and before==seven(p) and stat.S_IMODE(p.lstat().st_mode)==expected['mode']
        actual[n]=b;rows.append({'path':n,'identity':expected,'seven_stats':before,'complete_actual_GET':True})
    assert sum(len(b) for b in actual.values())==458366
    r2=json.loads(actual['EXACT-INVERSE-R2.json']);r1=json.loads(actual['prior-r1/EXACT-INVERSE.json'])
    final=actual['verify_terminal.py'];middle=actual['prior-r1/verify_terminal.py'];original=actual['prior-r1/R4-READER-ORIGINAL.py']
    assert base64.b64decode(r2['R2_raw_base64'],validate=True)==final
    value=final.decode()
    for e in reversed(r2['edits']):
        assert value.count(e['after'])==e['count'];value=value.replace(e['after'],e['before'])
    assert value.encode()==middle
    for e in reversed(r1['edits']):
        assert value.count(e['after'])==e['count'];value=value.replace(e['after'],e['before'])
    assert value.encode()==original==base64.b64decode(r2['R4_original_raw_base64'],validate=True)
    def functions(raw):
        lines=raw.splitlines(keepends=True)
        return {x.name:b''.join(lines[x.lineno-1:x.end_lineno]) for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef)}
    before=functions(original);after=functions(final);unchanged=sorted(set(before)-{'verify','main'})
    assert set(before)==set(after) and len(unchanged)==12 and all(before[n]==after[n] for n in unchanged)
    result={'schema':'hia.R9.terminal-reader.R2.actual-Git-readback.v1','status':'PASS_COMPLETE_AUTHOR_BYTES_AND_FULL_INVERSES',
            'files':20,'bytes':458366,'rows':rows,'R4_to_R1_to_R2_full_inverse':True,'all12_original_helpers_exact':True,
            'reader':pin(final),'R1_author_precheck_failure_preserved':True,'reader_executions':0,'products':0,'CI':0,'refs':0,
            'elapsed_ns':time.monotonic_ns()-start}
    with (R/'GIT-FULL-READBACK.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},sort_keys=True))
if __name__=='__main__':main()
