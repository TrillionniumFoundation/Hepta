#!/usr/bin/env python3
"""Reassemble only the original official ZIP; do not extract or execute it."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, os, stat, tempfile

def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('duplicate JSON key')
  result[key]=value
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent)
 parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args(); base=args.directory.resolve(); out=args.output.absolute()
 if out.exists() or out.is_symlink():raise ValueError('output must not exist')
 manifest=json.loads((base/'raw-parts.json').read_text(),object_pairs_hook=unique)
 assert manifest['schema']=='hepta.official-release-raw-parts.v1'
 assert manifest['artifact_id']==12898133203
 assert manifest['official_zip_bytes']==344601243
 assert manifest['official_zip_sha256']=='0bd04d40b4a88be8f244d93d6adfb6460680ddc0b1c03e4524c9a02c6bbb613e'
 assert manifest['part_count']==len(manifest['parts'])==83
 out.parent.mkdir(parents=True,exist_ok=True)
 handle,tmp=tempfile.mkstemp(prefix=out.name+'.partial-',dir=out.parent)
 total=0;whole=hashlib.sha256();seen=set()
 with os.fdopen(handle,'wb') as dst:
  for index,row in enumerate(manifest['parts'],1):
   name=row['path'];p=PurePosixPath(name)
   assert name==f'raw-artifacts/12898133203.zip.part{index:04d}'
   assert name not in seen and not p.is_absolute() and all(x not in ('','.','..') for x in p.parts) and '\\' not in name
   seen.add(name)
   assert type(row['bytes']) is int and 0<row['bytes']<=4194304 and row['offset']==total
   fd=os.open(base/name,os.O_RDONLY|os.O_NOFOLLOW)
   with os.fdopen(fd,'rb') as src:
    before=os.fstat(src.fileno());assert stat.S_ISREG(before.st_mode) and before.st_size==row['bytes']
    sha=hashlib.sha256();blob=hashlib.sha1(b'blob '+str(row['bytes']).encode()+b'\0');count=0
    for chunk in iter(lambda:src.read(1024*1024),b''):
     dst.write(chunk);sha.update(chunk);blob.update(chunk);whole.update(chunk);count+=len(chunk)
    after=os.fstat(src.fileno())
    assert (before.st_ino,before.st_dev,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    assert count==row['bytes'] and sha.hexdigest()==row['sha256'] and blob.hexdigest()==row['git_blob_sha1']
    total+=count
  dst.flush();os.fsync(dst.fileno())
 assert total==manifest['official_zip_bytes'] and whole.hexdigest()==manifest['official_zip_sha256']
 actual=hashlib.sha256();n=0
 with open(tmp,'rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):actual.update(chunk);n+=len(chunk)
 assert n==total and actual.hexdigest()==whole.hexdigest()
 os.chmod(tmp,0o644)
 os.link(tmp,out) # atomically refuse an existing destination
 os.unlink(tmp)
 print(json.dumps({'output':str(out),'artifact_id':12898133203,'bytes':total,'sha256':actual.hexdigest(),'parts_checked':83,'written_output_read_back':True,'archive_extracted_or_executed':False}))

if __name__=='__main__':main()
