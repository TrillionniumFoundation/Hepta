"""Restore immutable evidence bytes and check every hash; executes no experiment."""
from pathlib import Path, PurePosixPath
import argparse,hashlib,json,os,tarfile,tempfile
def require(v,m):
 if not v: raise ValueError(m)
def read(p):
 def pairs(xs):
  d={}
  for k,v in xs:
   require(k not in d,'duplicate key');d[k]=v
  return d
 return json.loads(p.read_bytes(),object_pairs_hook=pairs)
a=argparse.ArgumentParser();a.add_argument('--package',type=Path,required=True);a.add_argument('--output',type=Path,required=True);x=a.parse_args()
p=x.package.resolve();m=read(p/'MANIFEST.json');inv=p/m['inventory']['name']
require(hashlib.sha256(inv.read_bytes()).hexdigest()==m['inventory']['sha256'],'inventory hash')
i=read(inv);rows=i['retained'];expected={r['path']:r for r in rows};require(len(expected)==len(rows),'duplicate expected path')
x.output.mkdir(parents=True,exist_ok=False);out=x.output.resolve();seen=set();whole=hashlib.sha256();size=0
with tempfile.TemporaryFile() as stream:
 for part in m['archive']['parts']:
  n=PurePosixPath(part['name']);require(len(n.parts)==1 and n.name not in ('.','..'),'part path')
  f=p/n.name;require(f.is_file() and not f.is_symlink(),'part regular file');b=f.read_bytes()
  require(len(b)==part['bytes'] and hashlib.sha256(b).hexdigest()==part['sha256'],'part bytes')
  stream.write(b);whole.update(b);size+=len(b)
 require(size==m['archive']['bytes'] and whole.hexdigest()==m['archive']['sha256'],'whole archive')
 stream.seek(0)
 with tarfile.open(fileobj=stream,mode='r:xz') as tar:
  for item in tar:
   n=PurePosixPath(item.name);require(item.isreg() and not n.is_absolute() and '..' not in n.parts,'unsafe member')
   require(item.name in expected and item.name not in seen,'unexpected or duplicate member');r=expected[item.name]
   require(item.size==r['bytes'] and item.mode==r['mode'],'member metadata')
   f=out.joinpath(*n.parts);f.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();count=0
   with tar.extractfile(item) as src,f.open('xb') as dst:
    while b:=src.read(1024*1024): dst.write(b);h.update(b);count+=len(b)
   require(count==r['bytes'] and h.hexdigest()==r['sha256'],'restored file hash');f.chmod(r['mode']);seen.add(item.name)
 require(seen==set(expected),'missing file')
print(json.dumps({'files':len(seen),'bytes':sum(r['bytes'] for r in rows),'archive_sha256':whole.hexdigest(),'all_retained_bytes_verified':True,'experiments_executed':0},sort_keys=True))
