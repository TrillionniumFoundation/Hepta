"""Verify and optionally restore the retained bytes; never execute any input."""
from pathlib import Path
import argparse, base64, gzip, hashlib, io, json, os, tarfile
def digest(b):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def check(b,row):
 actual=digest(b)
 for k in actual:
  if k in row and actual[k]!=row[k]: raise ValueError('digest mismatch: '+k)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path);a=ap.parse_args()
 root=Path(__file__).resolve().parent
 m=json.loads((root/'ARCHIVE-MANIFEST.json').read_bytes())
 chunks=[];offset=0
 for p in m['parts']:
  assert p['offset']==offset and '..' not in Path(p['path']).parts
  b=(root/p['path']).read_bytes();check(b,p)
  raw=base64.b64decode(b.rstrip(b'\n'),validate=True);check(raw,p['decoded'])
  chunks.append(raw);offset+=len(raw)
 archive=b''.join(chunks);check(archive,m['archive'])
 tar=gzip.decompress(archive);check(tar,m['tar'])
 expected={r['name']:r for r in m['originals']}
 assert len(expected)==m['original_count']
 bodies=[]
 with tarfile.open(fileobj=io.BytesIO(tar),mode='r:') as tf:
  members=tf.getmembers()
  assert [x.name for x in members]==sorted(expected)
  for member in members:
   assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
   raw=tf.extractfile(member).read();r=expected[member.name];check(raw,r)
   assert member.size==r['bytes'] and member.mode==(r['identity'][2]&0o7777)
   bodies.append((member,raw))
 assert sum(len(b) for _,b in bodies)==m['original_bytes']
 if a.output is not None:
  assert a.output.is_absolute()
  a.output.mkdir(mode=0o700,parents=False,exist_ok=False)
  for member,raw in bodies:
   p=a.output/member.name;p.parent.mkdir(parents=True,exist_ok=True)
   with p.open('xb') as f: f.write(raw);f.flush();os.fsync(f.fileno())
   os.chmod(p,member.mode&0o777)
   assert p.read_bytes()==raw
 print(json.dumps({'originals':len(bodies),'bytes':m['original_bytes'],'archive_sha256':m['archive']['sha256'],'qualification_executed':False,'restored':str(a.output) if a.output else None}))
if __name__=='__main__': main()
