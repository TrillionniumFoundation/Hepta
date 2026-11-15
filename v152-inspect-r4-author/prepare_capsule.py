"""Metadata-only custody; no control, reader or project modules are imported."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import zlib

ROOT=Path(__file__).absolute().parent
AUTHOR=Path('/workspace/hia-cli-as-dict-inspect-qualification-author-r4-dda7')


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=16<<20
        assert seven(before)==seven(path.lstat());parts=[];left=before.st_size+1
        while left:
            part=os.read(fd,min(left,1<<20))
            if not part:break
            parts.append(part);left-=len(part)
        raw=b''.join(parts)
        assert len(raw)==before.st_size and seven(before)==seven(os.fstat(fd))==seven(path.lstat())
        return raw,before
    finally:os.close(fd)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def write(name,raw):
    p=ROOT/name
    with p.open('xb') as f:f.write(raw)
    os.chmod(p,0o644)
    assert read(p)[0]==raw


def main():
    plan=json.loads(read(AUTHOR/'PLAN.json')[0]);rows=[]
    sources=[('author/'+str(p.relative_to(AUTHOR)),p) for p in sorted(AUTHOR.rglob('*')) if p.is_file()]
    sources += [('fixed-inputs/'+name+'.json',Path(row['path'])) for name,row in sorted(plan['fixed_inputs'].items())]
    sources += [('root-records/'+name,Path(row['path'])) for name,row in sorted(plan['root_records'].items())]
    sources += [('actual-outers/'+phase+'-INTENT.json',Path(root)/'INTENT.json')
                for phase,root in sorted(plan['outer_roots'].items())]
    for logical,path in sources:
        raw,info=read(path)
        for forbidden in (b'X-Amz-Signature=',b'&sig=',b'?sig=',b'Set-Cookie:',b'"Authorization":'):
            assert forbidden not in raw,'potential credential carrier excluded before any publication'
        rows.append({'path':logical,'source_path':str(path),'identity':pin(raw),
            'posix_mode':stat.S_IMODE(info.st_mode),'seven_stats':seven(info),
            'content_base64':base64.b64encode(raw).decode()})
    assert len({r['path'] for r in rows})==len(rows)
    payload=encoded({'schema':'hepta.hia.inspect-r4-completion-author-capsule.v1','files':rows})
    compressed=zlib.compress(payload,6)
    capsule={'schema':'hepta.hia.lossless-zlib-base64-capsule.v1','compressed_pin':pin(compressed),
        'payload_pin':pin(payload),'compressed_base64':base64.b64encode(compressed).decode(),
        'files':len(rows),'logical_bytes':sum(r['identity']['bytes'] for r in rows),
        'products_executed':0,'project_imports':0}
    manifest={'schema':'hepta.hia.inspect-r4-completion-author-manifest.v1',
        'file_count':len(rows),'logical_bytes':capsule['logical_bytes'],
        'files':[{k:v for k,v in r.items() if k!='content_base64'} for r in rows],
        'author_files':28,'fixed_inputs':10,'root_records':len(plan['root_records']),'actual_outer_intents':2,
        'original_R2_raw_payloads_not_reincluded':True,
        'R3_failed_reader_partial_outputs_other_than_RESULT_not_reincluded':True,
        'old_R2_parent_and_R3_reader_remain_FAIL':True}
    d=zlib.decompressobj();again=d.decompress(compressed)+d.flush()
    assert d.eof and not d.unused_data and not d.unconsumed_tail and again==payload
    assert json.loads(again)['files']==rows
    write('COMPLETE-AUTHOR-CAPSULE.json',encoded(capsule));write('MANIFEST.json',encoded(manifest))
    for name in ('HANDOFF.json','PLAN.json','READBACK-LAUNCH.json','COMPLETION-LAUNCH-TEMPLATE.json',
                 'CONTRACT.md','R3-R4-WHOLE-INVERSE.json','R3-FAILURE-TRIAGE.json','STATIC-REVIEW.json',
                 'AUTHORING-R1-FAILURE.json','AUTHORING-R2-RESULT.json'):
        write(name,read(AUTHOR/name)[0])
    write('LOCAL-READBACK.json',encoded({'status':'PASS_LOSSLESS_LOCAL_AUTHOR_CAPSULE',
        'decoded_files':len(rows),'logical_bytes':capsule['logical_bytes'],
        'all_bytes_modes_seven_stats_preserved':True,'source_products_executed':0,
        'R4_reader_executed':False,'R4_completion_executed':False}))
    inputs=[]
    for p in sorted(ROOT.iterdir()):
        if p.is_file():
            raw,info=read(p)
            inputs.append({'relative':p.name,'path':str(p),**pin(raw),'mode':'100644','posix_mode':stat.S_IMODE(info.st_mode)})
    write('PUBLICATION-INPUTS.json',encoded({'files':inputs,'repository':'TrillionniumFoundation/Hepta',
        'root':str(ROOT),'state':'AUTHOR_ONLY_IMMUTABLE_BLOBS_NO_REF'}))
    print(json.dumps({'files':len(rows),'logical_bytes':capsule['logical_bytes'],'transport_leaves':len(inputs),
        'capsule':pin(encoded(capsule)),'products_executed':0}))


if __name__=='__main__':main()
