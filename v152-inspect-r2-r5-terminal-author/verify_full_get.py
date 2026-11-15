"""Read complete Git responses and restore only small author/metadata bytes."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import zlib

ROOT=Path('/workspace/hia-cli-as-dict-inspect-r2-r5-terminal-publication-r1-dda7')


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=16<<20
        assert seven(before)==seven(path.lstat())
        chunks=[];remaining=before.st_size+1
        while remaining:
            chunk=os.read(fd,min(remaining,1<<20))
            if not chunk:break
            chunks.append(chunk);remaining-=len(chunk)
        raw=b''.join(chunks)
        assert len(raw)==before.st_size and seven(before)==seven(os.fstat(fd))==seven(path.lstat())
        return raw,before
    finally:
        os.close(fd)


def main():
    inputs=json.loads(read(ROOT/'PUBLICATION-INPUTS.json')[0])['files']
    exact=[];fetched={}
    assert len(inputs)==12
    for index,row in enumerate(inputs):
        response_path=ROOT/'GET'/('%03d.json'%index)
        response=json.loads(read(response_path)[0])
        raw=response['structuredContent']['content'].encode()
        assert pin(raw)=={key:row[key] for key in ('bytes','sha256','git_blob')}
        assert raw==read(Path(row['path']))[0]
        verified=json.loads(read(ROOT/'VERIFIED'/('%03d.json'%index))[0])
        assert verified['full_get_exact'] is True and verified['git_blob']==row['git_blob']
        assert row['relative'] not in fetched
        fetched[row['relative']]=raw
        exact.append({'path':row['relative'],'identity':pin(raw)})
    capsule=json.loads(fetched['COMPLETE-AUTHOR-CAPSULE.json'])
    compressed=base64.b64decode(capsule['compressed_base64'],validate=True)
    assert pin(compressed)==capsule['compressed_pin']
    decoder=zlib.decompressobj();payload=decoder.decompress(compressed)+decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(payload)==capsule['payload_pin']
    value=json.loads(payload);manifest=json.loads(fetched['MANIFEST.json'])
    assert len(value['files'])==manifest['file_count']==90
    assert [{k:v for k,v in row.items() if k!='content_base64'} for row in value['files']]==manifest['files']
    expected_roles={'execution_author':21,'actual_r5':39,'actual_r5_outer':5,'fixed_inputs':4,'root_records':21}
    assert manifest['role_counts']==expected_roles
    observed_roles={key:0 for key in expected_roles}
    prefixes={'execution-author/':'execution_author','actual-r5/':'actual_r5',
        'actual-r5_outer/':'actual_r5_outer','fixed_inputs/':'fixed_inputs','root_records/':'root_records'}
    total=0;seen=set()
    for row in value['files']:
        assert row['path'] not in seen;seen.add(row['path'])
        matched=[role for prefix,role in prefixes.items() if row['path'].startswith(prefix)]
        assert len(matched)==1;observed_roles[matched[0]]+=1
        raw=base64.b64decode(row['content_base64'],validate=True)
        assert pin(raw)==row['identity']
        current,info=read(Path(row['source_path']))
        assert current==raw and seven(info)==row['seven_stats']
        assert stat.S_IMODE(info.st_mode)==row['posix_mode']
        total+=len(raw)
    assert observed_roles==expected_roles
    assert total==capsule['logical_bytes']==manifest['logical_bytes']==812898
    report={'status':'PASS_GIT_FULL_GET_WHOLE_AUTHOR_CAPSULE_READBACK',
        'transport_leaves':len(inputs),'transport':exact,'decoded_files':90,
        'role_counts':observed_roles,'logical_bytes':total,
        'all_bytes_modes_current_seven_stats_exact':True,
        'project_imports':0,'source_products_executed':0,'new_terminal_reader_executions':0,
        'complete_source_and_runtime_payloads_not_reincluded':True,
        'generated_assets_or_images_included':False,'original_R2_and_R5_parent_failures_retained':True}
    raw=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with (ROOT/'GIT-FULL-READBACK.json').open('xb') as stream:stream.write(raw)
    os.chmod(ROOT/'GIT-FULL-READBACK.json',0o644)
    assert read(ROOT/'GIT-FULL-READBACK.json')[0]==raw
    print(json.dumps({'report':pin(raw),'decoded_files':90,'logical_bytes':total,'products':0}))


if __name__=='__main__':main()
