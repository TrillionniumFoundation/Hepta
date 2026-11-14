#!/usr/bin/env python3
"""Verify complete actual Git responses against eight untouched terminal-readback originals."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/tmp/hia-r8-r4-terminal-readback-custody-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(s):return [getattr(s,k) for k in FIELDS]
def capture(path):
    s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        assert seven(os.fstat(fd))==seven(s)
        parts=[];left=s.st_size+1
        while left:
            part=os.read(fd,min(left,1048576))
            if not part:break
            parts.append(part);left-=len(part)
        raw=b''.join(parts)
        assert len(raw)==s.st_size and seven(os.fstat(fd))==seven(s)==seven(path.lstat())
    finally:os.close(fd)
    return raw,s
def fetched(name):
    stem=''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
    obj=json.loads((ROOT/'git-receipts'/(stem+'.GET.json')).read_bytes())
    assert not obj.get('isError')
    return obj['structuredContent']['content'].encode('utf-8')
def main():
    index_raw=fetched('INDEX.json');assert index_raw==(ROOT/'INDEX.json').read_bytes()
    index=json.loads(index_raw);parts=[];offset=0
    for i,row in enumerate(index['parts']):
        raw=fetched(row['path']);assert pin(raw)==row['identity'];obj=json.loads(raw)
        assert obj['index']==i and obj['offset']==row['offset']==offset
        part=base64.b64decode(obj['base64'],validate=True)
        assert pin(part)==obj['decoded_part']==row['decoded_part']
        assert obj['complete_archive']==index['compressed_zlib']
        parts.append(part);offset+=len(part)
    packed=b''.join(parts);assert pin(packed)==index['compressed_zlib']
    decoder=zlib.decompressobj();raw=decoder.decompress(packed,index['capsule_json']['bytes']+1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(raw)==index['capsule_json'];capsule=json.loads(raw)
    assert capsule['directories']==index['directories'] and capsule['source']==index['source']
    expected={r['logical_path']:r for r in index['files']};seen=set();total=0
    assert len(expected)==index['logical_files']==8
    for row in capsule['files']:
        name=row['logical_path'];assert name not in seen and name in expected
        assert not name.startswith('/') and '..' not in Path(name).parts
        seen.add(name);assert {k:v for k,v in row.items() if k!='content_base64'}==expected[name]
        decoded=base64.b64decode(row['content_base64'],validate=True)
        actual,s=capture(Path(row['path']))
        assert pin(decoded)==row['identity'] and actual==decoded
        assert stat.S_IMODE(s.st_mode)==row['mode'] and seven(s)==row['seven_stats']
        total+=len(decoded)
    assert seen==set(expected) and total==index['logical_bytes']==9512551
    source=Path(index['source']);assert len(index['directories'])==1
    assert seven(source.lstat())==index['directories'][0]['seven_stats']
    assert sorted(p.name for p in source.iterdir())==sorted(Path(r['logical_path']).name for r in index['files'] if r['logical_path'].startswith('readback/'))
    report={'schema':'hepta.r8.r4.terminal-readback.Git-full-readback.v1','status':'PASS_ALL_EIGHT_ORIGINALS_FROM_ACTUAL_GIT_FULL_GET','fetched_parts':len(parts),'logical_files':len(seen),'logical_bytes':total,'compressed_zlib':index['compressed_zlib'],'all_complete_bytes_modes_seven_stats_and_pathsets_match':True,'Root_reader_result':'PASS_READBACK_OF_ACTUAL_R4_VM_FUEL_FAILURE','original_product_qualification':'FAIL','products_executed_by_custody':0,'CI':0,'refs':0}
    path=ROOT/'GIT-DECODED-READBACK.json'
    with path.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'report':report,'identity':pin(path.read_bytes())},sort_keys=True))
if __name__=='__main__':main()
