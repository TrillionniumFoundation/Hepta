"""Reclaim disjoint envelope raw duplicates using the already audited archive."""
from pathlib import Path
from hashlib import sha256,sha1
import json,stat,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent;OLD=ROOT/'recovery-completed-r10'
archive=OLD/'root-completed-edit-composition.tar.xz';raw=archive.read_bytes();custody=json.loads((OLD/'root-custody.json').read_text())
assert sha256(raw).hexdigest()==custody['sha256']=='127cd3ad574dde65a6483913a57dc7b5338f7cb6afc56796bc2f9251b5599b09'
assert sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==custody['git_sha']=='31b5a36e1aa39335dcb39bba8b627c0c2509e069'
assert custody['all_original_bytes_modes_and_live_readback_equal'] is True
manifest=OUT/'r10-original-manifest.json';value=json.loads(manifest.read_text())
rows=[r for r in value['files'] if r['path'].startswith('development/envelope-wire-native-')
    and '/raw/' in r['path'] and r['bytes']>=1048576 and len(r['path'].rsplit('/',1)[1])==64]
assert rows
result=dict(scope='EXACT_ARCHIVED_ENVELOPE_RAW_DUPLICATES_ONLY',archive_sha256=custody['sha256'],
    archive_git_sha=custody['git_sha'],published_commit='5c8189965d8b407859d990837a6bbf9de7ef237a',
    original_full_archive_member_byte_mode_readback= str(OLD/'root-custody.json'),
    original_manifest_sha256=sha256(manifest.read_bytes()).hexdigest(),current_per_member_archive_replay=False,
    current_whole_archive_hash_and_local_duplicate_content_rechecked=True,removed=[])
start=time.monotonic_ns()
try:
    for row in rows:
        p=ROOT/'native-agent-edit-development'/row['path'].removeprefix('development/')
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
    (OUT/'reclaimed-envelope-duplicates.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='removed'},sort_keys=True))
