"""Stdlib-only custody of three small frozen authors; no project calls."""
from pathlib import Path
import base64,hashlib,json,os,re,stat,zlib
ROOT=Path('/workspace/hia-cli-as-dict-inspect-author-publication-r2-dda7')
SPECS={'inspect_r2': ('/workspace/hia-cli-as-dict-inspect-qualification-author-r2-dda7', ['HANDOFF.json', 'FILES.json', 'CONTRACT.md', 'STATIC-REVIEW.json', 'WHOLE-INVERSE.json', 'CONTROLS.diff', 'SOURCE-PLAN.json', 'NATIVE-PLAN.json', 'SOURCE-PREPARATION-LAUNCH.json', 'NATIVE-PREPARATION-LAUNCH.json', 'INDEX-VALIDATION-LAUNCH.json', 'INDEX-VALIDATION-REQUEST.json', 'R1-FAILURE.json', 'controls/streaming_metadata.py', 'validate_original_index.py'])}
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(st):return {k:getattr(st,k) for k in FIELDS}
def read(path):
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
    raw=path.read_bytes();assert seven(path.lstat())==seven(st);raw.decode('utf-8')
    assert not re.search(rb'https?[^\s"<>]*[?&](?:sig|access_token|X-Amz-Signature)=',raw,re.I)
    assert not re.search(rb'"(?:Authorization|Set-Cookie)"\s*:\s*"(?:Bearer\s+|[^"\s]+=)',raw,re.I)
    return raw,{'path':str(path),**pin(raw),'mode':'100755' if st.st_mode&0o111 else '100644',
        'posix_mode':stat.S_IMODE(st.st_mode),'seven_stat':seven(st)}
def write(path,v):
    raw=encoded(v)
    with path.open('xb') as stream:stream.write(raw)
    os.chmod(path,0o644);assert path.read_bytes()==raw
def seal(name,root,selected):
    root=Path(root);out=ROOT/name;out.mkdir()
    fs=json.loads((root/'FILES.json').read_bytes())['files']
    expected={r['relative']:r for r in fs} if isinstance(fs,list) else fs
    paths=sorted(p for p in root.rglob('*') if p.is_file())
    assert {str(p.relative_to(root)) for p in paths}==set(expected)|({'FILES.json','HANDOFF.json'} if name=='patch20' else {'FILES.json'})
    records=[];source_rows={}
    for p in paths:
        raw,row=read(p);relative=str(p.relative_to(root));row['relative']=relative
        if relative in expected:
            old=expected[relative]
            if 'pin' in old:
                assert old['pin']=={k:row[k] for k in ('bytes','sha256','git_blob','mode')} and old['stat']==row['seven_stat']
            else:assert old['identity']==pin(raw) and old['posix_mode']==row['posix_mode']
        records.append({**row,'raw_base64':base64.b64encode(raw).decode()});source_rows[relative]=row
    payload=encoded({'schema':'hepta.hia.complete-author-files.v1','origin':str(root),'files':records})
    compressed=zlib.compress(payload,9)
    write(out/'COMPLETE-AUTHOR-CAPSULE.json',{'schema':'hepta.hia.zlib-author-capsule.v1','encoding':'base64+zlib',
        'payload':pin(payload),'compressed':pin(compressed),'file_count':len(records),
        'logical_bytes':sum(r['bytes'] for r in records),'compressed_base64':base64.b64encode(compressed).decode(),
        'products_executed_by_seal':0,'original_author_only_states_unchanged':True})
    stored=json.loads((out/'COMPLETE-AUTHOR-CAPSULE.json').read_bytes())
    packed=base64.b64decode(stored['compressed_base64'],validate=True)
    dec=zlib.decompressobj();decoded=dec.decompress(packed,len(payload)+1)+dec.flush()
    assert dec.eof and not dec.unused_data and not dec.unconsumed_tail and packed==compressed and decoded==payload
    assert pin(decoded)==stored['payload']
    rebuilt=json.loads(decoded);assert rebuilt['origin']==str(root) and len(rebuilt['files'])==len(records)
    for row in rebuilt['files']:
        raw=base64.b64decode(row['raw_base64'],validate=True);current,current_row=read(Path(row['path']))
        assert raw==current and pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
        assert current_row['seven_stat']==row['seven_stat'] and current_row['posix_mode']==row['posix_mode']
    write(out/'MANIFEST.json',{'schema':'hepta.hia.complete-author-manifest.v1','source':str(root),'files':source_rows,
        'file_count':len(records),'logical_bytes':sum(r['bytes'] for r in records),'payload':pin(payload),
        'capsule':read(out/'COMPLETE-AUTHOR-CAPSULE.json')[1]})
    write(out/'LOCAL-READBACK.json',{'status':'PASS_COMPLETE_FROZEN_AUTHOR_READBACK','files':len(records),
        'logical_bytes':sum(r['bytes'] for r in records),'whole_compressed_payload_decoded':True,
        'all_bytes_modes_seven_stats_equal':True,'actual_product_results_included':False,
        'excluded_access_credential_files':[],'public_payload_scope':'all frozen author files only','products_executed':0})
    leaves=[]
    for rel in selected:
        raw,row=read(root/rel);leaves.append({**row,'relative':'author/'+rel})
    for rel in ('COMPLETE-AUTHOR-CAPSULE.json','MANIFEST.json','LOCAL-READBACK.json'):
        raw,row=read(out/rel);leaves.append({**row,'relative':rel})
    raw,row=read(ROOT/'seal_authors.py');leaves.append({**row,'relative':'seal_authors.py'})
    write(out/'PUBLICATION-INPUTS.json',{'schema':'hepta.hia.immutable-author-publication.v1',
        'name':name,'root':str(out),'leaves':leaves,'ref_writes':0,'products_executed':0})
    return {'name':name,'files':len(records),'logical_bytes':sum(r['bytes'] for r in records),
        'capsule':read(out/'COMPLETE-AUTHOR-CAPSULE.json')[1],'leaves':len(leaves)}
if __name__=='__main__':
    results=[seal(name,*v) for name,v in SPECS.items()];write(ROOT/'SEAL-RESULT.json',results);print(json.dumps(results))
