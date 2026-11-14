"""Verify actual Git GET payloads and every current original; no products."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,stat,time,zlib
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('C',HERE/'seal_actual.py');C=importlib.util.module_from_spec(sp);sp.loader.exec_module(C)
def main():
    p=argparse.ArgumentParser();p.add_argument('transport');a=p.parse_args();root=Path(a.transport);started=time.monotonic_ns()
    plan=json.loads(C.read(root/'PUBLISH-PLAN.json')[0]);payloads={};receipts=[]
    for i,row in enumerate(plan['leaves']):
        prefix=root/'GIT-ACK'/('%03d-'%i+row['mount'].replace('/','_'));post_raw,_=C.read(str(prefix)+'.POST.json');get_raw,_=C.read(str(prefix)+'.GET.json');post=json.loads(post_raw);get=json.loads(get_raw)
        assert post['structuredContent']['sha']==row['identity']['git_blob'];text=get['structuredContent']['content'];raw=text.encode();assert C.pin(raw)==row['identity'] and C.read(row['path'])[0]==raw
        payloads[row['mount']]=raw;receipts.append({'mount':row['mount'],'identity':row['identity'],'post':C.pin(post_raw),'full_get':C.pin(get_raw)})
    index=json.loads(payloads['TRANSPORT-INDEX.json']);pieces=[];offset=0
    for i,row in enumerate(index['parts']):
        raw=payloads[row['path']];assert C.pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')};piece=json.loads(raw);b=base64.b64decode(piece['base64'],validate=True)
        assert piece['index']==i and piece['offset']==offset and C.pin(b)==piece['piece'];offset+=len(b);pieces.append(b)
    archive=b''.join(pieces);assert C.pin(archive)==index['archive'];decoder=zlib.decompressobj(31);raw=decoder.decompress(archive)+decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and C.pin(raw)==index['capsule'];capsule=json.loads(raw)
    assert len(capsule['files'])==index['logical_files'] and len(capsule['objects'])==index['objects'];seen=set();used=set();total=0
    for row in capsule['files']:
        assert row['logical'] not in seen;seen.add(row['logical']);key=row['identity']['git_blob'];used.add(key);obj=capsule['objects'][key];expected=base64.b64decode(obj['base64'],validate=True)
        assert obj['identity']==row['identity']==C.pin(expected);actual,s=C.read(row['path']);assert actual==expected and C.pin(actual)==row['identity'] and s==row['seven_stat'] and stat.S_IMODE(s['st_mode'])==row['mode'];total+=len(actual)
    assert used==set(capsule['objects']) and total==index['logical_bytes']
    for name,path in capsule['header']['scopes'].items():assert C.state(Path(path))==capsule['header']['scope_states'][name]
    result={'schema':'hia.R10.actual.git-full-readback.v1','status':'PASS_ACTUAL_GIT_FULL_GET_CRC_CAS_ALL_ORIGINALS','scope':index['scope'],'files':len(seen),'logical_bytes':total,'objects':len(used),'parts':len(pieces),'archive':index['archive'],'capsule':index['capsule'],'receipts':receipts,'every_reference_read_and_decoded':True,'all_current_original_bytes_modes_seven_stats_pathsets':True,'single_member_complete_CRC':True,'elapsed_ns':time.monotonic_ns()-started,'products':0,'qualification_boundary':index['qualification_boundary']}
    C.put(root,'ACTUAL-GIT-READBACK.json',C.encode(result));print(json.dumps({k:v for k,v in result.items() if k!='receipts'},sort_keys=True))
if __name__=='__main__':main()
