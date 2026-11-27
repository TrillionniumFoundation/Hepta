"""Decode the actual Git GET capsules and compare every frozen author byte."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
ROOT=Path('/workspace/hia-cli-as-dict-inspect-author-publication-r2-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(st):return {k:getattr(st,k) for k in FIELDS}
def main(name):
    directory=ROOT/name;plan=json.loads((directory/'PUBLICATION-INPUTS.json').read_bytes())
    gets={};identities=[]
    for index,row in enumerate(plan['leaves']):
        record=json.loads((directory/'VERIFIED'/('%03d.json'%index)).read_bytes())
        response=json.loads((directory/'GET'/('%03d.json'%index)).read_bytes())
        raw=response['structuredContent']['content'].encode('utf-8')
        assert pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
        assert raw==Path(row['path']).read_bytes() and seven(Path(row['path']).lstat())==row['seven_stat']
        assert record['full_get_exact'] is True and record['post_ack_sha']==row['git_blob']
        gets[row['relative']]=raw;identities.append({'relative':row['relative'],**pin(raw)})
    capsule=json.loads(gets['COMPLETE-AUTHOR-CAPSULE.json'])
    packed=base64.b64decode(capsule['compressed_base64'],validate=True);assert pin(packed)==capsule['compressed']
    decoder=zlib.decompressobj();raw=decoder.decompress(packed,capsule['payload']['bytes']+1)+decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(raw)==capsule['payload']
    value=json.loads(raw);rows=value['files'];seen=set();total=0
    for row in rows:
        assert row['relative'] not in seen;seen.add(row['relative'])
        path=Path(row['path']);before=path.lstat();assert seven(before)==row['seven_stat']
        restored=base64.b64decode(row['raw_base64'],validate=True)
        assert pin(restored)=={k:row[k] for k in ('bytes','sha256','git_blob')}
        assert restored==path.read_bytes() and seven(path.lstat())==seven(before)
        assert stat.S_IMODE(before.st_mode)==row['posix_mode'];total+=len(restored)
    assert seen=={str(p.relative_to(value['origin'])) for p in Path(value['origin']).rglob('*') if p.is_file()}
    assert len(rows)==capsule['file_count'] and total==capsule['logical_bytes']
    result={'status':'PASS_ACTUAL_GIT_FULL_GET_WHOLE_AUTHOR_DECODE','name':name,
        'git_leaves':identities,'author_files':len(rows),'author_logical_bytes':total,
        'payload':capsule['payload'],'all_original_bytes_modes_seven_stats_equal':True,
        'full_original_pathset_equal':True,'all_author_only_states_preserved':True,
        'products_executed':0,'ref_writes':0,'excluded_credential_files':[],
        'actual_product_custody_claimed':False}
    with (directory/'GIT-READBACK.json').open('xb') as stream:stream.write(encoded(result))
    return {'name':name,'files':len(rows),'bytes':total,'proof':pin(encoded(result))}
if __name__=='__main__':print(json.dumps([main(name) for name in ('inspect_r2',)]))
