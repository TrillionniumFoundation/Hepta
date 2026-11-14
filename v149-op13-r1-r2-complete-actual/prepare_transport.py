"""Partition an already sealed archive and preserve complete metadata.

Never import or invoke seal_originals; never modify raw evidence. No products.
"""
from pathlib import Path
import base64, hashlib, json, os, re, stat, zlib

BASE=Path('/tmp/hia-op13-actual-complete-custody-r1-dda7')
ROOT=Path('/tmp/hia-op13-actual-transport-r1-dda7')
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
PART_BYTES=240*1024
EXPECTED={'bytes':25363782,'git_blob':'00991e6622537b8d4788868de554a2fa88fe84c2',
    'sha256':'db2281a3272f2d59da56e0de9f78e6c5f5b78c90c1953c95357ace141470609b'}

def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def stamp(s):return {k:getattr(s,k)for k in KEYS}
def need(ok,msg):
    if not ok:raise AssertionError(msg)
def read(path):
    s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'unique regular input required')
    b=path.read_bytes();need(stamp(path.lstat())==stamp(s),'input drift')
    return b,{'path':str(path),'pin':pin(b),'mode':stat.S_IMODE(s.st_mode),'stat':stamp(s)}
def put(path,b):
    with path.open('xb')as f:f.write(b)
    need(path.read_bytes()==b,'transport write mismatch')
    return {'logical':path.relative_to(ROOT).as_posix(),'path':str(path),'pin':pin(b),'mode':stat.S_IMODE(path.lstat().st_mode)}
def split(kind,data):
    result=[]
    for i,start in enumerate(range(0,len(data),PART_BYTES)):
        b=data[start:start+PART_BYTES]
        raw=enc({'schema':'hepta.op13.actual.transport-part.v1','kind':kind,'index':i,'offset':start,
            'chunk':pin(b),'data_base64':base64.b64encode(b).decode()})
        row=put(ROOT/'parts'/('%s-%03d.json'%(kind,i)),raw)
        row.update(index=i,offset=start,chunk=pin(b));result.append(row)
    return result
def main():
    (ROOT/'parts').mkdir(mode=0o700);(ROOT/'actual-get').mkdir(mode=0o700)
    report_raw,report_desc=read(BASE/'REPORT.json');report=json.loads(report_raw)
    need(report['status']=='PASS_COMPLETE_ORIGINAL_BYTES_AND_MODES'and report['archive']==EXPECTED
        and report['all_files']==11714 and report['logical_bytes']==135672211
        and report['unique_objects']==10397 and report['unique_bytes']==134246573,'fixed original report differs')
    metadata={}
    for name in ['INPUT-PLAN.json','INTENT.json','MANIFEST.json','REPORT.json','seal_originals.py']:
        raw,desc=read(BASE/name)
        need(not re.search(rb'https?://[^\s"<>]+[?&](?:sig|X-Amz-Signature|X-Goog-Signature)=',raw),'signed URL refused')
        metadata[name]={'descriptor':desc,'encoding':'utf-8','text':raw.decode()}
    for name in ['OP13-CUSTODY-EXEC.json','OP13-CUSTODY-RETURN.json']:
        raw,desc=read(Path('/tmp/hia-progress-v149-20261114-dda7')/name)
        metadata['root/'+name]={'descriptor':desc,'encoding':'utf-8','text':raw.decode()}
    need(metadata['MANIFEST.json']['descriptor']['pin']==report['manifest'],'complete manifest identity differs')
    payload=enc({'schema':'hepta.op13.actual.complete-custody.metadata.v1','files':metadata,
        'metadata_originals':7,'original_product_status':'FAIL','product_executions':0,'whole':False})
    packed=zlib.compress(payload,1)
    meta_parts=split('metadata',packed)
    archive,archive_desc=read(BASE/'COMPLETE-ORIGINALS.tar.gz')
    need(archive_desc['pin']==EXPECTED,'complete original archive differs')
    archive_parts=split('archive',archive)
    # Check every transport part immediately without reading any product raw.
    for parts,expected in [(meta_parts,packed),(archive_parts,archive)]:
        for row in parts:
            wrapper=json.loads(Path(row['path']).read_bytes());data=base64.b64decode(wrapper['data_base64'],validate=True)
            need(pin(data)==row['chunk']and data==expected[row['offset']:row['offset']+len(data)],'part inverse differs')
    for item in metadata.values():need(stamp(Path(item['descriptor']['path']).lstat())==item['descriptor']['stat'],'metadata stat changed')
    need(stamp(Path(archive_desc['path']).lstat())==archive_desc['stat'],'archive stat changed')
    index={'schema':'hepta.op13.actual.complete-custody.transport-index.v1','archive':archive_desc,
        'archive_parts':archive_parts,'metadata_payload':pin(payload),'metadata_zlib':pin(packed),
        'metadata_parts':meta_parts,'metadata_files':{k:v['descriptor']for k,v in metadata.items()},
        'logical_files':11714,'logical_bytes':135672211,'cas_objects':10397,'cas_bytes':134246573,
        'original_report':report_desc,'maximum_part_payload':PART_BYTES,'all_parts_local_inverse':True,
        'seal_rerun':0,'raw_mutations':0,'product_executions':0,'original_product_status':'FAIL','whole':False}
    idx=put(ROOT/'INDEX.json',enc(index))
    prep=put(ROOT/'PREPARATION-RESULT.json',enc({'schema':'hepta.op13.actual.complete-custody.transport-preparation.v1',
        'status':'PASS_LOCAL_PARTITION_ONLY','index':idx,'archive_parts':len(archive_parts),'metadata_parts':len(meta_parts),
        'archive':EXPECTED,'metadata_payload':pin(payload),'metadata_zlib':pin(packed),
        'all_sealed_inputs_unchanged':True,'complete_actual_GET_decode':'PENDING','seal_rerun':0,'products':0}))
    leaves=[idx,prep]
    for path in [ROOT/'prepare_transport.py',BASE/'INPUT-PLAN.json',BASE/'REPORT.json',BASE/'seal_originals.py',
        Path('/tmp/hia-progress-v149-20261114-dda7/OP13-CUSTODY-EXEC.json'),Path('/tmp/hia-progress-v149-20261114-dda7/OP13-CUSTODY-RETURN.json')]:
        raw,desc=read(path);leaves.append({'logical':path.name,**desc})
    leaves.extend(meta_parts);leaves.extend(archive_parts)
    put(ROOT/'PUBLICATION-INPUTS.json',enc(leaves))
    print(json.dumps({'status':'PASS_LOCAL_PARTITION_ONLY','leaves':len(leaves),'archive_parts':len(archive_parts),
        'metadata_parts':len(meta_parts),'metadata_zlib_bytes':len(packed),'archive_bytes':len(archive),
        'sealed_originals_unchanged':True,'seal_rerun':0,'products':0}))

if __name__=='__main__':main()
