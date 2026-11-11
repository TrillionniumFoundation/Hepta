"""Reclaim disjoint envelope raw duplicates using the already audited archive."""
from pathlib import Path
from hashlib import sha256,sha1
import json,stat,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent;OLD=ROOT/'recovery-completed-r12'
archive=OLD/'root-completed-controller-integration.tar.xz';raw=archive.read_bytes();custody=json.loads((OLD/'root-completed-custody.json').read_text());pub=json.loads((OLD/'publication.json').read_text());assert pub['commit']=='815c3ed02025d5532237b8f8a68c7d033f559cd5'
assert sha256(raw).hexdigest()==custody['archive_sha256']=='a8b86959229ce72eec2267285678ca7872302a984d27928ab6bb0db54db06090'
assert sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==custody['archive_git_sha']=='ebcce74079be12bf986fb46e31f62356fc7b00ed'
assert custody['all_original_bytes_modes_and_live_readback_equal'] is True
manifest=OLD/'root-completed-original-index.json';value=json.loads(manifest.read_text())
rows=[r for r in value['files'] if r['path'].startswith('native-edit-controller-next/development/main-query-')
    and '/buffers/' in r['path'] and len(r['path'].rsplit('/',1)[1])==64]
assert rows
result=dict(scope='EXACT_ARCHIVED_COMPLETED_CONTROLLER_BUFFER_DUPLICATES_ONLY',archive_sha256=custody['archive_sha256'],
    archive_git_sha=custody['archive_git_sha'],published_commit='815c3ed02025d5532237b8f8a68c7d033f559cd5',
    original_full_archive_member_byte_mode_readback= str(OLD/'root-completed-custody.json'),
    original_manifest_sha256=sha256(manifest.read_bytes()).hexdigest(),current_per_member_archive_replay=False,
    current_whole_archive_hash_and_local_duplicate_content_rechecked=True,removed=[])
start=time.monotonic_ns()
try:
    for row in rows:
        p=Path(row['source']);assert p==ROOT/row['path']
        assert p.is_file() and not p.is_symlink()
        s=p.stat();assert s.st_size==row['bytes'] and stat.S_IMODE(s.st_mode)==row['mode']
        h=sha256()
        with p.open('rb') as f:
            while block:=f.read(1<<20):h.update(block)
        assert h.hexdigest()==row['sha256']
        now=p.stat();assert (now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns)==(s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        p.unlink();result['removed'].append(dict(row,local_path=str(p)))
    result['status']='PASS'
finally:
    result.update(removed_files=len(result['removed']),removed_bytes=sum(r['bytes'] for r in result['removed']),elapsed_ns=time.monotonic_ns()-start,active_sources_removed=False)
    (OUT/'reclaimed-controller-buffer-duplicates.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='removed'},sort_keys=True))
