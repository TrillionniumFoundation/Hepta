"""Restore the complete completed-scope originals from immutable UTF-8 wrappers.
Usage: restore.py TRANSPORT.json EXTRA-MEMBERS.json wrapper_root target
The target must not exist. This performs no product import, build, test, or Git mutation.
"""
from pathlib import Path,PurePosixPath
import base64,gzip,hashlib,json,os,stat,sys,tarfile,tempfile

def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def verify(raw,row):assert identity(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
def safe(name):
 p=PurePosixPath(name);assert not p.is_absolute() and p.parts and all(x not in ('','..','.') for x in p.parts),name;return p

def main():
 transport=Path(sys.argv[1]);extra_path=Path(sys.argv[2]);wrappers=Path(sys.argv[3]);target=Path(sys.argv[4]);assert not target.exists()
 meta=json.loads(transport.read_text());extras=json.loads(extra_path.read_text());offset=0
 with tempfile.TemporaryDirectory(prefix='hepta-originals-restore-',dir=target.parent) as temporary:
  scratch=Path(temporary);archive=scratch/'COMPLETE.tar.gz'
  with archive.open('xb') as output:
   for row in meta['chunks']:
    raw=(wrappers/row['file']).read_bytes();verify(raw,row);assert b'\n' not in raw and b'\r' not in raw
    decoded=base64.b64decode(raw,validate=True);assert base64.b64encode(decoded)==raw
    assert row['offset']==offset and len(decoded)==row['decoded_bytes'] and hashlib.sha256(decoded).hexdigest()==row['decoded_sha256']
    assert identity(decoded)['git_blob']==row['decoded_computed_git_blob'];output.write(decoded);offset+=len(decoded)
  verify(archive.read_bytes(),meta['archive'])
  with gzip.open(archive,'rb') as gz:
   while gz.read(1<<20):pass
  expected_names=None;seen=set();manifest=None;cas=scratch/'cas';cas.mkdir()
  with tarfile.open(archive,'r:gz') as tar:
   for member in tar:
    safe(member.name);assert member.isfile() and member.mode==0o644 and member.name not in seen;seen.add(member.name)
    raw=tar.extractfile(member).read()
    if member.name=='MANIFEST.json':
     verify(raw,meta['manifest']);manifest=json.loads(raw)
     expected_names=set(extras)|{r['cas'] for r in manifest['logical_files'].values()}
    if member.name in extras:verify(raw,extras[member.name])
    elif member.name.startswith('cas/'):
     assert len(member.name)==72 and member.name.endswith('.bin')
     assert hashlib.sha256(raw).hexdigest()==member.name[4:-4]
     with (cas/member.name[4:]).open('xb') as f:f.write(raw)
    else:raise AssertionError(('unexpected member',member.name))
  assert manifest is not None and seen==expected_names and len(seen)==meta['tar_member_count']
  assert len(manifest['logical_files'])==meta['logical_count']
  for name,row in manifest['logical_files'].items():safe(name);verify((scratch/row['cas']).read_bytes(),row)
  target.mkdir()
  for name,row in sorted(manifest['directories'].items(),key=lambda item:(len(PurePosixPath(item[0]).parts),item[0])):
   safe(name);p=target/name;p.mkdir(parents=True,exist_ok=True)
  for name,row in manifest['logical_files'].items():
   p=target/name;p.parent.mkdir(parents=True,exist_ok=True);raw=(scratch/row['cas']).read_bytes()
   if row['kind']=='file':
    with p.open('xb') as f:f.write(raw)
    os.chmod(p,int(row['mode'],8));assert stat.S_ISREG(p.lstat().st_mode);back=p.read_bytes()
   elif row['kind']=='symlink':os.symlink(os.fsdecode(raw),p);back=os.fsencode(os.readlink(p))
   else:raise AssertionError(row['kind'])
   verify(back,row);assert stat.S_IMODE(p.lstat().st_mode)==int(row['mode'],8)
  for name,row in sorted(manifest['directories'].items(),reverse=True):
   os.chmod(target/name,int(row['mode'],8));assert stat.S_ISDIR((target/name).lstat().st_mode)
  report={'status':'RESTORED_FULLY','logical_files':len(manifest['logical_files']),'logical_bytes':manifest['logical_bytes'],'directories':len(manifest['directories']),'all_bytes_sha256_git_and_modes_verified':True,'complete_gzip_crc_isize':True,'archive_sha256':meta['archive']['sha256'],'whole_native':False}
  print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
