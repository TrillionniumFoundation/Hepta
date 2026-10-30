"""Freeze only peer originals; owner originals remain in their separate packet."""
from __future__ import annotations
from datetime import datetime,timezone
import hashlib
import json
import lzma
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
SOURCE=BASE/'nested-returned-view-independent-review-20261030'
PREFIX='evidence/hia_core_closure_20261030/nested-returned-view-local6b-peer'

def digest(path):
    data=path.read_bytes()
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'git_blob_sha1':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),
            'mode':'100755' if path.stat().st_mode & stat.S_IXUSR else '100644'}
def write(name,value):(HERE/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

assert json.loads((SOURCE/'review.json').read_text())['ok']
rows=[]
for path in sorted(SOURCE.rglob('*')):
    if path.is_file():
        assert stat.S_ISREG(path.lstat().st_mode)
        rows.append({'local_path':str(path),'archive_member':str(Path(SOURCE.name)/path.relative_to(SOURCE)),**digest(path)})
write('inputs.json',{'schema':'hepta.independent-nested-peer-inputs.v1','files':rows,
                     'files_count':len(rows),'bytes':sum(r['bytes'] for r in rows),'owner_payload_duplicated':False})
archive=HERE/'nested-returned-view-local6b-peer.tar.xz'
assert not archive.exists()
with tarfile.open(archive,'w:xz',preset=6) as tar:
    for row in rows:
        path=Path(row['local_path'])
        info=tar.gettarinfo(str(path),arcname=row['archive_member'])
        info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
        info.mode=0o755 if row['mode']=='100755' else 0o644
        with path.open('rb') as f:tar.addfile(info,f)
with lzma.open(archive,'rb') as stream:
    uncompressed=0
    while data:=stream.read(1024*1024):uncompressed+=len(data)
with tempfile.TemporaryDirectory(prefix='nested-peer-restore-') as temporary:
    command=[sys.executable,str(HERE/'restore.py'),'--directory',str(Path(temporary)/'restored')]
    completed=subprocess.run(command,capture_output=True,text=True)
    assert completed.returncode==0,completed.stderr
    restored=json.loads(completed.stdout)
    assert restored['ok'] and restored['actual_extracted_members']==len(rows)
for row in rows:
    assert digest(Path(row['local_path']))=={k:row[k] for k in ['bytes','sha256','git_blob_sha1','mode']}
readback={'schema':'hepta.nested-peer-archive-readback.v1','ok':True,
          'finished_utc':datetime.now(timezone.utc).isoformat(),'archive':digest(archive),
          'xz_full_stream_read':True,'uncompressed_tar_bytes':uncompressed,
          'actual_restore':{'argv':command,'returncode':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr},
          'all_original_inputs_unchanged':True,'all_member_modes_and_hashes_verified':True,
          'owner_payload_duplicated':False,'remote_publication_performed':False}
write('archive-readback.json',readback)
payload=[SOURCE/'README.md',SOURCE/'review.json',SOURCE/'static-review.json',SOURCE/'owner-review.json',
         SOURCE/'controls-summary.json',HERE/'inputs.json',HERE/'archive-readback.json',HERE/'restore.py',HERE/'freeze.py',archive]
files=[{'local_path':str(path),'repository_path':PREFIX+'/'+path.name,**digest(path)} for path in payload]
write('publication-files.json',{'schema':'hepta.nested-peer-publication.v1',
    'source_commit':'6b83eae0aef1cfbc9654510b55f5c35ed0bd55d5',
    'source_tree':'0cac7421225a2f8bba1de07c08011d79410b8cdc',
    'source_parent':'a6cfb7e00a1c08276d27459bdcc5628aa7622079',
    'public_source_execution':False,'map_repository_path':PREFIX+'/publication-files.json',
    'files':files,'payload_files':len(files),'payload_bytes':sum(row['bytes'] for row in files),
    'archive':{'local_path':str(archive),**digest(archive),'member_count':len(rows)},
    'also_publish_this_map':True,'actual_restore_script_verified':True,
    'all_original_inputs_unchanged':True,'owner_payload_duplicated':False,
    'strict_blockers_closed':0,'remote_publication_performed_by_this_agent':False})
print(json.dumps({'ok':True,'payload_files':len(files),'payload_bytes':sum(row['bytes'] for row in files),'archive_bytes':archive.stat().st_size,'members':len(rows)}))
