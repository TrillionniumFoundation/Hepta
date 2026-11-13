"""Restore complete immutable original bytes from downloaded UTF-8 Git wrappers.

Usage: python restore.py TRANSPORT.json directory-containing-parts target-directory
The wrappers are literal base64 without LF. No Git/API credentials are required.
"""
from pathlib import Path,PurePosixPath
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile

def digest(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def verify(raw,row):
 assert type(row['bytes']) is int and len(raw)==row['bytes']
 assert digest(raw)==row['sha256'] and blob(raw)==row['git_blob']
def safe(name):
 p=PurePosixPath(name);assert not p.is_absolute() and p.parts and all(x not in ('.','..','') for x in p.parts);return p

def main():
 transport=Path(sys.argv[1]);root=Path(sys.argv[2]);target=Path(sys.argv[3]);assert not target.exists()
 meta=json.loads(transport.read_text());chunks=[];offset=0
 for row in meta['chunks']:
  raw=(root/row['file']).read_bytes();verify(raw,row)
  assert b'\n' not in raw and b'\r' not in raw
  decoded=base64.b64decode(raw,validate=True);assert base64.b64encode(decoded)==raw
  assert row['offset']==offset and len(decoded)==row['decoded_bytes'] and digest(decoded)==row['decoded_sha256']
  assert blob(decoded)==row['decoded_computed_git_blob'];chunks.append(decoded);offset+=len(decoded)
 archive=b''.join(chunks);verify(archive,meta['archive'])
 all_tar=gzip.decompress(archive);members={}
 with tarfile.open(fileobj=io.BytesIO(all_tar),mode='r:') as tar:
  for member in tar:
   assert member.isfile() and member.mode==0o644 and member.name not in members;safe(member.name)
   members[member.name]=tar.extractfile(member).read()
 verify(members['MANIFEST.json'],meta['manifest']);manifest=json.loads(members['MANIFEST.json'])
 expected={'MANIFEST.json'}|{row['cas'] for row in manifest['logical_files'].values()};assert set(members)==expected
 assert len(manifest['logical_files'])==manifest['logical_count']
 for name,row in manifest['logical_files'].items():safe(name);verify(members[row['cas']],row)
 target.mkdir(parents=True)
 for name,row in manifest['logical_files'].items():
  p=target/name;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb') as f:f.write(members[row['cas']])
  os.chmod(p,int(row['mode'],8));verify(p.read_bytes(),row)
  assert stat.S_ISREG(p.lstat().st_mode) and stat.S_IMODE(p.lstat().st_mode)==int(row['mode'],8)
 print(json.dumps({'status':'RESTORED','logical_count':manifest['logical_count'],'logical_bytes':manifest['logical_bytes'],'archive_sha256':meta['archive']['sha256'],'whole_native':False},sort_keys=True))
if __name__=='__main__':main()
