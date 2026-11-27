"""Verify complete remote GET bodies and reconstruct every public metadata member."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'publication-r2'
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def main():
    inputs=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes());remote={};verified=[]
    for row in inputs['files']:
        name=row['path'];stem=''.join(c if c.isascii() and (c.isalnum() or c in '_-') else '_' for c in name)
        prefix=OUT/'git-receipts'/stem
        ack=json.loads(Path(str(prefix)+'.POST.json').read_bytes());get=json.loads(Path(str(prefix)+'.GET.json').read_bytes());receipt=json.loads(Path(str(prefix)+'.READBACK.json').read_bytes())
        assert not ack.get('isError') and ack['structuredContent']['sha']==row['identity']['git_blob']
        assert not get.get('isError');raw=get['structuredContent']['content'].encode('utf-8')
        assert pin(raw)=={k:row['identity'][k] for k in ('bytes','sha256','git_blob')}
        assert raw==(ROOT/name).read_bytes() and stat.S_IMODE((ROOT/name).stat().st_mode)==row['identity']['mode']
        assert receipt['POST_ACK'] and receipt['full_GET'] and receipt['identity']==row['identity']
        remote[name]=raw;verified.append({'path':name,'identity':row['identity'],'POST_ACK':True,'full_GET':True})
    assert len(remote)==16
    index=json.loads(remote['publication-r2/INDEX.json']);chunks=[];offset=0
    for ordinal,row in enumerate(index['parts']):
        raw=remote['publication-r2/'+row['path']];assert pin(raw)==row['identity']
        part=json.loads(raw);assert part['index']==ordinal and part['offset']==row['offset']==offset
        data=base64.b64decode(part['data_base64'],validate=True);assert pin(data)==part['decoded_identity']==row['decoded_identity']
        chunks.append(data);offset+=len(data)
    compressed=b''.join(chunks);assert pin(compressed)==index['compressed_identity']
    z=zlib.decompressobj();payload=z.decompress(compressed)+z.flush();assert z.eof and not z.unused_data and not z.unconsumed_tail
    assert pin(payload)==index['payload_identity'];files=json.loads(payload)['files'];assert len(files)==index['files']==534
    seen=set();total=0
    for row,wanted in zip(files,index['members']):
        assert row['path'] not in seen;seen.add(row['path']);assert {'path':row['path'],'identity':row['identity']}==wanted
        raw=base64.b64decode(row['data_base64'],validate=True);assert pin(raw)=={k:row['identity'][k] for k in ('bytes','sha256','git_blob')}
        p=ROOT/row['path'];assert p.read_bytes()==raw and stat.S_IMODE(p.lstat().st_mode)==row['identity']['mode'];total+=len(raw)
    assert total==index['logical_bytes']==8948992
    report={'schema':'hepta.r8.source-recovery.git-complete-readback.v1','status':'PASS','verified_git_leaves':verified,'leaf_count':16,'metadata_files_reconstructed':534,'metadata_logical_bytes':total,'compressed_bytes':len(compressed),'source_map_git':'cc1c16fb747e03ade545e8d4fa8827a16fcc33a2','source_tree':'4c62be4ed66ff107fa6f88c6131313a354868bd9','source_bytes':98471253,'source_files':3180,'private_credentials_excluded':4,'full_source_GET_response_bodies_local_only':index['source_GET_response_bodies_local_only'],'original_source_restoration_scope':'no new source scan or product execution in this metadata GET verifier','products':0,'refs':0}
    with (OUT/'GIT-FULL-READBACK.json').open('xb') as f:f.write((json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({k:report[k] for k in ['status','leaf_count','metadata_files_reconstructed','metadata_logical_bytes','compressed_bytes','products']},sort_keys=True))
if __name__=='__main__':main()
