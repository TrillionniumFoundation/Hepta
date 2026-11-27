"""Data-only Git GET capsule restoration, without materializing duplicate files."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT=Path('/workspace/hia-cli-as-dict-inspect-qualification-author-r3-publication-dda7')


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path):
    before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    raw=path.read_bytes();assert len(raw)==before.st_size and seven(before)==seven(path.lstat())
    return raw,before


def main():
    inputs=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes())['files']
    exact=[];fetched={}
    for index,row in enumerate(inputs):
        response_path=ROOT/'GET'/('%03d.json'%index)
        response=json.loads(read(response_path)[0])
        raw=response['structuredContent']['content'].encode()
        assert pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
        assert raw==read(Path(row['path']))[0]
        verified=json.loads((ROOT/'VERIFIED'/('%03d.json'%index)).read_bytes())
        assert verified['full_get_exact'] is True and verified['git_blob']==row['git_blob']
        fetched[row['relative']]=raw;exact.append({'path':row['relative'],'identity':pin(raw)})
    capsule=json.loads(fetched['COMPLETE-AUTHOR-CAPSULE.json'])
    compressed=base64.b64decode(capsule['compressed_base64'],validate=True)
    assert pin(compressed)==capsule['compressed_pin']
    decoder=zlib.decompressobj();payload=decoder.decompress(compressed);payload+=decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(payload)==capsule['payload_pin']
    value=json.loads(payload);manifest=json.loads(fetched['MANIFEST.json'])
    assert len(value['files'])==manifest['file_count']==52
    assert [{k:v for k,v in row.items() if k!='content_base64'} for row in value['files']]==manifest['files']
    total=0;seen=set()
    for row in value['files']:
        assert row['path'] not in seen;seen.add(row['path'])
        raw=base64.b64decode(row['content_base64'],validate=True)
        assert pin(raw)==row['identity']
        current,info=read(Path(row['source_path']))
        assert current==raw and seven(info)==row['seven_stats']
        assert stat.S_IMODE(info.st_mode)==row['posix_mode']
        total+=len(raw)
    assert total==capsule['logical_bytes']==manifest['logical_bytes']==1005656
    report={'status':'PASS_GIT_FULL_GET_WHOLE_CAPSULE_READBACK','transport_leaves':len(inputs),
        'transport':exact,'decoded_files':52,'author_files':30,'fixed_input_jsons':10,
        'root_records':12,'logical_bytes':total,'all_bytes_modes_current_seven_stats_exact':True,
        'source_products_executed':0,'readback_product_groups_executed':0,
        'R2_raw_physical_frames_not_reincluded_in_this_author_package':True}
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    with (ROOT/'GIT-FULL-READBACK.json').open('xb') as stream:stream.write(raw)
    print(json.dumps({'report':pin(raw),'decoded_files':52,'logical_bytes':total,'products':0}))


if __name__=='__main__':main()
