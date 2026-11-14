"""Partition the already sealed generation originals; no sealing or products."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
BASE=Path('/workspace/hia-patch-generation-complete-custody-r1-dda7')
AUTHOR=Path('/workspace/hia-patch-generation-custody-author-r1-dda7')
ROOT=Path('/workspace/hia-patch-generation-transport-r1-dda7')
TOOL=Path('/workspace/hia-patch-complete-custody-tool-r1-dda7/seal_originals.py')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
PART_BYTES=240*1024
EXPECTED={'bytes':4230291,'git_blob':'7ce656068f6b0c1a2e7dc139ac33559394c93aab',
    'sha256':'0bb62f869b96eb984e728cf6823af065936751d0d5f38d45e41d93483605a50a'}
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def seven(p):return {k:getattr(p.lstat(),k)for k in FIELDS}
def read(p):
    s=p.lstat();before=seven(p);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    raw=p.read_bytes();assert before==seven(p)
    return raw,{'path':str(p),'pin':pin(raw),'mode':stat.S_IMODE(s.st_mode),'stat':before}
def put(path,raw):
    with path.open('xb')as stream:stream.write(raw)
    assert path.read_bytes()==raw
    return {'logical':path.relative_to(ROOT).as_posix(),'path':str(path),'pin':pin(raw),'mode':stat.S_IMODE(path.lstat().st_mode)}
def split(kind,data):
    rows=[]
    for i,start in enumerate(range(0,len(data),PART_BYTES)):
        chunk=data[start:start+PART_BYTES]
        raw=encoded({'schema':'hepta.hia.patch.complete.transport-part.v1','kind':kind,'index':i,
            'offset':start,'chunk':pin(chunk),'data_base64':base64.b64encode(chunk).decode()})
        row=put(ROOT/'parts'/('%s-%03d.json'%(kind,i)),raw)
        row.update(index=i,offset=start,chunk=pin(chunk));rows.append(row)
    return rows
def main():
    (ROOT/'parts').mkdir(mode=0o700);(ROOT/'actual-get').mkdir(mode=0o700)
    report_raw,report_desc=read(BASE/'REPORT.json');report=json.loads(report_raw)
    assert report['status']=='PASS_COMPLETE_ORIGINAL_BYTES_MODES_AND_FULL_ARCHIVE_READBACK'
    assert report['archive']==EXPECTED and report['files']==127 and report['logical_bytes']==23120711
    assert report['unique_objects']==104 and report['unique_bytes']==22174895
    paths={n:BASE/n for n in ('INPUT-PLAN.json','INTENT.json','MANIFEST.json','REPORT.json')}
    paths.update({'custody_tool/seal_originals.py':TOOL})
    paths.update({'author/'+n:AUTHOR/n for n in ('freeze_plan.py','INPUT-PLAN.json','LAUNCH.json',
        'SEAL.stdout.raw','SEAL.stderr.raw','SEAL-TOOL-RETURN.json')})
    metadata={}
    for n,p in paths.items():
        raw,desc=read(p);metadata[n]={'descriptor':desc,'encoding':'utf-8','text':raw.decode()}
    assert metadata['MANIFEST.json']['descriptor']['pin']==report['manifest']
    payload=encoded({'schema':'hepta.hia.patch.complete.transport-metadata.v1','files':metadata,
        'product_execution':0,'seal_rerun':0,'original_product_status':report['original_product_status']})
    compressed=zlib.compress(payload,1);meta=split('metadata',compressed)
    archive,archive_desc=read(BASE/'COMPLETE-ORIGINALS.tar.gz');assert archive_desc['pin']==EXPECTED
    parts=split('archive',archive)
    for rows,original in ((meta,compressed),(parts,archive)):
        for row in rows:
            raw=Path(row['path']).read_bytes();assert pin(raw)==row['pin']
            obj=json.loads(raw);actual=base64.b64decode(obj['data_base64'],validate=True)
            assert pin(actual)==row['chunk']and actual==original[row['offset']:row['offset']+len(actual)]
    for item in metadata.values():assert seven(Path(item['descriptor']['path']))==item['descriptor']['stat']
    assert seven(Path(archive_desc['path']))==archive_desc['stat']
    index={'schema':'hepta.hia.patch.complete.transport-index.v1','archive':archive_desc,'archive_parts':parts,
        'metadata_payload':pin(payload),'metadata_zlib':pin(compressed),'metadata_parts':meta,
        'metadata_files':{n:r['descriptor']for n,r in metadata.items()},'original_report':report_desc,
        'logical_files':127,'logical_bytes':23120711,'cas_objects':104,'cas_bytes':22174895,
        'maximum_part_payload':PART_BYTES,'all_parts_local_inverse':True,'seal_rerun':0,'products':0,
        'original_product_status':report['original_product_status'],'whole_native':False}
    idx=put(ROOT/'INDEX.json',encoded(index))
    prep=put(ROOT/'PREPARATION-RESULT.json',encoded({'status':'PASS_LOCAL_PARTITION_ONLY','index':idx,
        'archive_parts':len(parts),'metadata_parts':len(meta),'metadata_files':len(metadata),
        'archive':EXPECTED,'all_originals_unchanged':True,'actual_GET_decode':'PENDING','products':0,'seal_rerun':0}))
    leaves=[idx,prep]
    for p in (ROOT/'prepare_transport.py',BASE/'REPORT.json',TOOL):
        raw,desc=read(p);leaves.append({'logical':'core/'+p.name,**desc})
    leaves.extend(meta);leaves.extend(parts)
    put(ROOT/'PUBLICATION-INPUTS.json',encoded(leaves))
    print(json.dumps({'status':'PASS_LOCAL_PARTITION_ONLY','leaves':len(leaves),'archive_parts':len(parts),
        'metadata_parts':len(meta),'metadata_files':len(metadata),'seal_rerun':0,'products':0}))
if __name__=='__main__':main()
