"""Validate actual POST/GET envelopes and decode every retained source member."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).absolute().parent.parent
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')


def pairs(values):
    out={}
    for key,value in values:
        assert type(key) is str and key not in out
        out[key]=value
    return out


def decode(raw):
    return json.loads(raw,object_pairs_hook=pairs)


def pin(raw,mode='100644'):
    return {'bytes':len(raw),'mode':mode,'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def seven(info):
    return {key:getattr(info,key) for key in FIELDS}


def run():
    core=decode((ROOT/'GIT-CORE/INTENT.json').read_bytes())
    core_rows=core['rows'] if type(core) is dict else core
    final=decode((ROOT/'GIT-FINAL/INTENT.json').read_bytes())['rows']
    actual,readbacks={},[]
    for dirname,rows in (('GIT-CORE',core_rows),('GIT-FINAL',final)):
        for row in rows:
            name=row['name'];stem=ROOT/dirname/name.replace('/','--')
            post=decode(Path(str(stem)+'.POST.json').read_bytes())
            get=decode(Path(str(stem)+'.GET.json').read_bytes())
            assert not post.get('isError') and not get.get('isError')
            assert post['structuredContent']['sha']==row['pin']['git_blob']
            raw=get['structuredContent']['content'].encode('utf-8')
            assert pin(raw,row['pin']['mode'])==row['pin']
            assert raw==(ROOT/name).read_bytes()
            assert stat.S_IMODE((ROOT/name).lstat().st_mode)==row['posix_mode']
            assert name not in actual
            actual[name]=raw
            readbacks.append({'name':name,'pin':row['pin'],
                'actual_POST_ACK':True,'complete_GET_bytes_match':True})
    assert len(actual)==40
    index=decode(actual['ARCHIVE/SOURCE-PARTS.json'])
    offset=0;pieces=[]
    for row in index['parts']:
        assert row['offset']==offset
        raw=actual[row['path']]
        assert pin(raw)==row['pin']
        offset+=len(raw);pieces.append(raw)
    capsule=b''.join(pieces)
    assert pin(capsule)==index['capsule_pin']
    envelope=decode(capsule)
    packed=base64.b64decode(envelope['data'],validate=True)
    assert pin(packed)==envelope['compressed_pin']==index['compressed_pin']
    decoder=zlib.decompressobj()
    payload=decoder.decompress(packed)+decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(payload)==envelope['payload_pin']==index['payload_pin']
    document=decode(payload)
    count,total=0,0
    for row in document['files']:
        relative=Path(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        path=ROOT/relative;before=path.lstat()
        assert stat.S_ISREG(before.st_mode)
        raw=row['text'].encode('utf-8')
        assert pin(raw,row['pin']['mode'])==row['pin']
        assert path.read_bytes()==raw and seven(path.lstat())==seven(before)==row['new_authoring_stat']
        assert stat.S_IMODE(before.st_mode)==row['posix_mode']
        count+=1;total+=len(raw)
    assert count==index['files']==127 and total==index['logical_bytes']==7380805
    for row in document['directories']:
        directory=ROOT/row['path']
        assert stat.S_ISDIR(directory.lstat().st_mode)
        assert stat.S_IMODE(directory.lstat().st_mode)==row['posix_mode']
    proof={'schema':'hepta.hia.cli-patch-result.actual-git-readback.v3',
        'status':'PASS_COMPLETE_ACTUAL_GIT_AUTHORING_READBACK',
        'repository':'TrillionniumFoundation/Hepta','actual_blobs':40,
        'actual_archive_parts':len(index['parts']),'decoded_files':count,
        'decoded_logical_bytes':total,'decoded_directories':len(document['directories']),
        'capsule_pin':index['capsule_pin'],'payload_pin':index['payload_pin'],
        'every_actual_POST_SHA_and_full_GET_equal':True,
        'every_member_full_bytes_git_sha_posix_modes_and_new_stats_equal':True,
        'products':0,'binder_runs':0,'ref_updates':0,
        'old_product_qualification_not_inherited':True,
        'missing_historical_raw_not_recreated':True,'readbacks':readbacks}
    raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    path=ROOT/'GIT-FINAL/ACTUAL-COMPLETE-READBACK.json'
    with path.open('xb') as stream:stream.write(raw)
    assert path.read_bytes()==raw
    print(json.dumps({'status':proof['status'],'proof':pin(raw),'actual_blobs':40,
        'decoded_files':count,'decoded_logical_bytes':total,'products':0},sort_keys=True))


if __name__=='__main__':
    run()
