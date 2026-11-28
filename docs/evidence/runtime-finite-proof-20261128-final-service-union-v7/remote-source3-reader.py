from pathlib import Path
import hashlib,io,json,os,stat,sys,tarfile
R=Path('/home/qian-qi/hia-finite-proof-union-01db-20261128-2ac5');Q=R/'qualification'
terminal=json.loads((Q/'terminal.json').read_bytes())
assert terminal['returncode']==0 and terminal['physical_unchanged'] is True and terminal['files']==475
assert (Q/'physical-before.json').read_bytes()==(Q/'physical-after.json').read_bytes()
names=sorted(str(p.relative_to(R)) for p in Q.rglob('*'))+['linux_driver.py','manifest.json']
assert len(names)==len(set(names))
inventory={}
def identity(st):return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,stat.S_IMODE(st.st_mode),stat.S_IFMT(st.st_mode))
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz',compresslevel=6) as tf:
 for n in sorted(names):
  p=R/n;s=p.lstat();m=tarfile.TarInfo(n);m.mode=stat.S_IMODE(s.st_mode);m.mtime=0
  if stat.S_ISDIR(s.st_mode):
   m.type=tarfile.DIRTYPE;tf.addfile(m);inventory[n]={'type':'directory','mode':m.mode}
  elif stat.S_ISLNK(s.st_mode):
   target=os.readlink(p);assert identity(p.lstat())==identity(s)
   m.type=tarfile.SYMTYPE;m.linkname=target;tf.addfile(m)
   inventory[n]={'type':'symlink','mode':m.mode,'target':target}
  else:
   assert stat.S_ISREG(s.st_mode),(n,s.st_mode)
   raw=p.read_bytes();assert identity(p.lstat())==identity(s) and len(raw)==s.st_size,n
   m.size=len(raw);tf.addfile(m,io.BytesIO(raw))
   inventory[n]={'type':'file','mode':m.mode,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 assert json.loads((Q/'terminal.json').read_bytes())==terminal
 manifest={'root':str(R),'terminal':terminal,'entries':inventory,'scope':'Post-terminal read-only archival; no product execution'}
 raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
 m=tarfile.TarInfo('custody-readback-manifest.json');m.size=len(raw);m.mode=0o400;m.mtime=0;tf.addfile(m,io.BytesIO(raw))
print(json.dumps({'files':sum(x['type']=='file' for x in inventory.values()),'entries':len(inventory),'bytes':sum(x.get('bytes',0) for x in inventory.values())}),file=sys.stderr,flush=True)
