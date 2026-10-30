#!/usr/bin/env python3
"""Stream only retained development/frozen-run evidence into one deterministic XZ tar."""
from pathlib import Path
from hashlib import sha256
import io,json,os,stat,tarfile,time
BASE=Path('/workspace/scratch/f0c12f106c89')
HERE=Path(__file__).resolve().parent
roots={'integrated953':BASE/'p1-p2-scoped-cleanup-final-launches-20261030',
       'directory-readback':HERE/'directory-readback',
       'review-index':BASE/'compiler-next2-readonly-reviews-20261030'}
started=time.monotonic_ns();members={};total=0
archive_path=HERE/'evidence.tar.xz'
assert not archive_path.exists()
with tarfile.open(archive_path,'w:xz',format=tarfile.USTAR_FORMAT,preset=1) as archive:
 for prefix,root in roots.items():
  assert root.is_dir() and not root.is_symlink()
  for path in sorted(root.rglob('*')):
   assert not path.is_symlink()
   if path.is_dir():continue
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
   try:
    before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_size<=16*1024*1024
    blocks=[];count=0
    while True:
     block=os.read(fd,65536)
     if not block:break
     blocks.append(block);count+=len(block);assert count<=16*1024*1024
    after=os.fstat(fd)
    assert (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    data=b''.join(blocks);assert len(data)==before.st_size
   finally:os.close(fd)
   name=prefix+'/'+path.relative_to(root).as_posix();assert name not in members
   item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o644;item.uid=item.gid=item.mtime=0;item.uname=item.gname=''
   archive.addfile(item,io.BytesIO(data));total+=len(data);assert total<64*1024*1024 and len(members)<256
   members[name]={'bytes':len(data),'sha256':sha256(data).hexdigest(),'original_path':str(path)}
raw=archive_path.read_bytes()
manifest={'schema':'hepta.scoped-cleanup.953-evidence-manifest.v1','source_head':'953fa62dee5aa563551d57b1374ab95b6d548b45',
 'source_tree':'aa0683509a02ca97e4e0c1dd723e4047f50d81b3','archive':{'file':archive_path.name,'bytes':len(raw),'sha256':sha256(raw).hexdigest()},
 'members':members,'member_bytes':total,'max_member_bytes':16*1024*1024,'max_members':256,'max_expanded_bytes':64*1024*1024,
 'historical_3533_reference':{'source_head':'3533b95c53d23de2d22c91fcc05cb601b8448eb3','archive_sha256':'cd6ad1181899e7be44d478557cb6101248d6995d4b9034cc5d4833553c481f59','manifest_sha256':'29a6a4808cef3fb36756a66df55e98c7d0a4722b74082753a1a7f2a87a4d42ce','current_head_qualified':False},'later_source_head_qualified':False,'raw_originals_preserved':True,
 'scope':'exact 953 execution and actual directory readback; older development and3533pack remain separately referenced, never relabelled'}
(HERE/'MANIFEST.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
receipt={'schema':'hepta.scoped-cleanup.bundle-construction.v1','status':'completed','wall_ns':time.monotonic_ns()-started,
 'members':len(members),'member_bytes':total,'archive':manifest['archive'],'native_or_model_executed':False,'preset':1,
 'full_human_agent_development_cost':None,'cost_is_not_in_prior_execution_interval':True}
(HERE/'BUILD.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');print(json.dumps(receipt,sort_keys=True))
