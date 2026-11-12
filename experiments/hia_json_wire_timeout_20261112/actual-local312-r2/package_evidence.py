from pathlib import Path
from hashlib import sha256, sha1
import base64, gzip, io, json, os, stat, tarfile, zipfile

ROOT=Path('/tmp/hia-wire89-actual-r2-publication-20261112-r1')
ACTUAL=Path('/tmp/hia-wire89-timeout-diagnostic-local312-r2')
V90=Path('/tmp/hia-v90-wire89-failure-43289808798-r1')
ROOT_EVIDENCE=Path('/workspace/scratch/e26ed3e2edcf/root')
PREFIX='experiments/hia_json_wire_timeout_20261112/actual-local312-r2'
V90_PREFIX='experiments/hia_json_wire_timeout_20261112/v90-standard-failure-r1'

def pin(raw):return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'git_blob_sha1':sha1(('blob %d\0'%len(raw)).encode()+raw).hexdigest()}
def save(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert path.read_bytes()==raw
def jsonraw(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def ident(s):return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}

def main():
    files={}
    def addtree(source,prefix):
        for p in sorted(source.rglob('*')):
            if p.is_dir():assert not p.is_symlink();continue
            assert p.is_file() and not p.is_symlink()
            files[prefix+'/'+str(p.relative_to(source))]=p
    addtree(ACTUAL/'recording-controls-actual','source5')
    addtree(ACTUAL/'actual','diagnostic')
    assert len(files)==97
    addtree(ROOT_EVIDENCE/'wire89-recorder-source5-r2-invocation','root-source5-invocation')
    addtree(ROOT_EVIDENCE/'wire89-diagnostic-r2-invocation','root-diagnostic-invocation')
    for name in ['run_wire89_recorder_source5_r2_once.py','run_wire89_diagnostic_r2_once.py']:
        files['root-invocation-sources/'+name]=ROOT_EVIDENCE/name
    files['peer/Cold-STATIC-REVIEW.json']=Path('/tmp/hia-wire89-recorder-r2-independent-peer.json')
    for name in ['audit_closed_actual.py','INDEPENDENT-READBACK.json']:
        files['independent/'+name]=ROOT/name
    addtree(V90/'selected-originals','v90-selected-originals')
    addtree(V90/'git-test-reference','v90-git-test-reference')
    v90_names=['audit_zip_stream.py','audit_selected_wire.py','audit_selected_wire_r2.py','audit_selected_wire_r3.py',
        'FULL-ZIP-STREAM-AUDIT.json','WIRE-FAILURE-INDEPENDENT-AUDIT.json','EXACT-HEAD-TREE.json',
        'READER-R1-ERROR.json','READER-R2-ERROR.json','DOWNLOAD-READBACK.json','LOG-METADATA-READBACK.json',
        'SELECTED-ORIGINALS-READBACK.json','run.original.json','jobs.original.json','artifacts.original.json',
        'job-131432730209.original.log']
    for name in v90_names:files['v90-readback/'+name]=V90/name
    old=ROOT_EVIDENCE/'carrier-ci-failure-43274637363/selected-originals'
    for rel in ['hia-json-wire-callers.json','hia-json-wire-callers-evidence/wire/build.json']:
        files['old-carrier-comparison/'+rel]=old/rel
    extra_names=['hia-cold.json','hia-cold.cold/qualification.evidence/B3.receipt.json',
        'hia-cold.cold/qualification.evidence/B3.request.json','hia-cold.cold/qualification.evidence/B3.stdout.log',
        'hia-cold.cold/qualification.evidence/B3.stderr.log','hia-cold.cold/source/tools/qualify_hia_json_wire_native_callers.py',
        'hia-cold.cold/source/tests/test_hia_agent_native_tools.py']
    inventory={r['path']:r for r in json.loads((V90/'FULL-ZIP-STREAM-AUDIT.json').read_bytes())['files']}
    with zipfile.ZipFile(V90/'artifact-13979892259.original.zip') as z:
        for rel in extra_names:
            raw=z.read(rel);assert pin(raw)['sha256']==inventory[rel]['sha256']
            p=ROOT/'additional-v90-originals'/rel;save(p,raw);files['v90-additional-originals/'+rel]=p
    rows=[]
    for name,p in sorted(files.items()):
        s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
        raw=p.read_bytes();assert ident(p.lstat())==ident(s)
        rows.append({'archive_path':name,'original_path':str(p),'identity':ident(s),**pin(raw)})
    manifest={'schema':'hepta.wire89.actual-evidence-archive.v1','source5_actual_count':15,'diagnostic_actual_count':82,
        'files':rows,'file_count':len(rows),'raw_bytes':sum(r['bytes'] for r in rows),
        'metadata_transport':'Archive entry names are role-prefixed; exact original identity is retained here. Each body is copied without edits.',
        'official_v90_zip':{'artifact_id':13979892259,'bytes':182564464,'sha256':'6c17c1c5548b6ee0bf9380b13f5c90a92a3f343df248641fb852a8ce77e0e6c9',
            'path':str(V90/'artifact-13979892259.original.zip'),'full_body_crc_sha_readback':True,'members':9270,'expanded_bytes':864312505,
            'included_in_this_archive':False,'retained_original_locally':True,
            'scope':'The complete official ZIP remains separately retained; this archive persists selected failure originals and the complete member hash inventory, not all 9270 bodies.'}}
    save(ROOT/'ARCHIVE-MANIFEST.json',jsonraw(manifest))
    archive=ROOT/'actual-originals.tar.gz'
    with archive.open('xb') as outf:
        with gzip.GzipFile(filename='',mode='wb',fileobj=outf,mtime=0,compresslevel=6) as gz:
            with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
                for r in rows:
                    p=Path(r['original_path']);raw=p.read_bytes();assert pin(raw)['sha256']==r['sha256'] and ident(p.lstat())==r['identity']
                    info=tarfile.TarInfo(r['archive_path']);info.size=len(raw);info.mode=stat.S_IMODE(r['identity']['st_mode']);info.mtime=0;info.uid=0;info.gid=0
                    tar.addfile(info,io.BytesIO(raw))
    recovered=[]
    expected={r['archive_path']:r for r in rows}
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.name in expected and member.name not in recovered
            raw=tar.extractfile(member).read();r=expected[member.name];assert pin(raw)['sha256']==r['sha256'] and len(raw)==r['bytes']
            recovered.append(member.name)
    assert set(recovered)==set(expected)
    raw=archive.read_bytes()
    archive_pin=pin(raw)
    gitroot=ROOT/'git-files'; parts=[]
    for index,at in enumerate(range(0,len(raw),393216)):
        body=base64.b64encode(raw[at:at+393216])+b'\n';rel='archive/part-%03d.base64'%index;save(gitroot/PREFIX/rel,body)
        parts.append({'path':rel,'offset':at,'decoded_bytes':min(393216,len(raw)-at),**pin(body)})
    summary=json.loads((ROOT/'INDEPENDENT-READBACK.json').read_bytes())
    audit=json.loads((V90/'WIRE-FAILURE-INDEPENDENT-AUDIT.json').read_bytes())
    delivery={'schema':'hepta.wire89.diagnostic-r2-canonical-handoff.v1','status':'DEVELOPMENT_SCOPE_PASS_CI_FAILURES_RETAINED',
        'frozen_control_commit':'f0642f652d3b74a0e118e80ea774d61917fb5ba7',
        'actual':summary['summaries'],'independent_check_count':summary['check_count'],
        'archive':archive_pin,'archive_parts':parts,'archive_file_count':len(rows),'archive_raw_bytes':manifest['raw_bytes'],
        'v90_failure':{k:audit[k] for k in ('run_id','job_id','artifact_id','archive_bytes','archive_sha256','source_head','source_tree','tests_chosen','tests_loaded','tests_executed','exact_failure','failure_assertion_seconds','original_limit_seconds','qualifier_wall_seconds','target_counts','counter_scope','check_count','unarchived_test_modules','test_source_boundary')},
        'not_claimed':['CI 3.14.4 reproduction','full wire89 qualification','performance fix','Core39/18/116 qualification','new matching-source cold build'],
        'next_step':'Independently revise the HIA wire throughput path while retaining source admission, original observer capability, original method/workload/5s and original 89 denominator. New execution requires a frozen request.'}
    save(ROOT/'HANDOFF.json',jsonraw(delivery))
    copies={
        PREFIX+'/HANDOFF.json':ROOT/'HANDOFF.json',PREFIX+'/ARCHIVE-MANIFEST.json':ROOT/'ARCHIVE-MANIFEST.json',
        PREFIX+'/archive/reconstruction.json':None,
        PREFIX+'/audit_closed_actual.py':ROOT/'audit_closed_actual.py',PREFIX+'/package_evidence.py':Path(__file__),
        PREFIX+'/source5/FINAL.json':ACTUAL/'recording-controls-actual/FINAL.json',
        PREFIX+'/source5/REPORT.json':ACTUAL/'recording-controls-actual/tests/REPORT.json',
        PREFIX+'/source5/lifecycle.json':ACTUAL/'recording-controls-actual/lifecycle.json',
        PREFIX+'/diagnostic/FINAL.json':ACTUAL/'actual/FINAL.json',
        PREFIX+'/diagnostic/diagnostic-report.json':ACTUAL/'actual/diagnostic-report.json',
        PREFIX+'/diagnostic/lifecycle.json':ACTUAL/'actual/lifecycle.json',
        PREFIX+'/diagnostic/processes.json':ACTUAL/'actual/processes.json',
        PREFIX+'/diagnostic/process-communications.json':ACTUAL/'actual/process-communications.json',
        PREFIX+'/peer/Cold-STATIC-REVIEW.json':Path('/tmp/hia-wire89-recorder-r2-independent-peer.json'),
        V90_PREFIX+'/WIRE-FAILURE-INDEPENDENT-AUDIT.json':V90/'WIRE-FAILURE-INDEPENDENT-AUDIT.json',
        V90_PREFIX+'/hia-json-wire-callers.json':V90/'selected-originals/hia-json-wire-callers.json',
        V90_PREFIX+'/job-131432730209.original.log':V90/'job-131432730209.original.log',
        V90_PREFIX+'/run.original.json':V90/'run.original.json',V90_PREFIX+'/jobs.original.json':V90/'jobs.original.json',
        V90_PREFIX+'/artifacts.original.json':V90/'artifacts.original.json',V90_PREFIX+'/DOWNLOAD-READBACK.json':V90/'DOWNLOAD-READBACK.json',
        V90_PREFIX+'/READER-R1-ERROR.json':V90/'READER-R1-ERROR.json',V90_PREFIX+'/READER-R2-ERROR.json':V90/'READER-R2-ERROR.json'}
    for rel,p in copies.items():
        body=jsonraw({'schema':'hepta.exact-base64-archive-parts.v1','archive':archive_pin,'parts':parts,'complete_tar_readback':True,'file_count':len(rows),'raw_bytes':manifest['raw_bytes']}) if p is None else p.read_bytes()
        save(gitroot/rel,body)
    publication=[]
    for p in sorted(gitroot.rglob('*')):
        if p.is_file():publication.append({'path':str(p.relative_to(gitroot)),'local':str(p),'mode':'100644',**pin(p.read_bytes())})
    save(ROOT/'PUBLICATION-FILES.json',jsonraw(publication))
    save(ROOT/'ARCHIVE-READBACK.json',jsonraw({'archive':archive_pin,'members_recovered':len(recovered),'raw_bytes':manifest['raw_bytes'],'all_body_hashes_equal':True}))
    print(json.dumps({'files':len(rows),'raw_bytes':manifest['raw_bytes'],'gzip':archive_pin,'parts':len(parts),'publication_files':len(publication),'publication_bytes':sum(x['bytes'] for x in publication)}))

if __name__=='__main__':main()
