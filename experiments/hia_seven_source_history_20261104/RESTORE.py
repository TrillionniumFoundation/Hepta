#!/usr/bin/env python3
"""Verify parts and restore exact original files. Does not extract TAR or run code."""
import argparse,gzip,hashlib,json
from pathlib import Path
def checksum(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--package',type=Path,default=Path(__file__).resolve().parent)
 ap.add_argument('--output',type=Path,required=True)
 args=ap.parse_args()
 manifest=json.loads((args.package/'MANIFEST.json').read_text())
 if manifest.get('schema')!='hepta.retained.lossless-parts.v1':raise ValueError('unsupported manifest')
 args.output.mkdir(parents=True,exist_ok=True)
 for group in manifest['groups']:
  name=group['output_name']
  if Path(name).name!=name:raise ValueError('nonlocal output name')
  destination=args.output/name
  encoded=destination if group['encoding']=='identity' else args.output/(name+'.gz')
  with encoded.open('xb') as out:
   for part in group['parts']:
    if Path(part['path']).name!=part['path']:raise ValueError('nonlocal part name')
    p=args.package/part['path']
    if p.stat().st_size!=part['bytes'] or checksum(p)!=part['sha256']:raise ValueError('part identity differs: '+p.name)
    with p.open('rb') as src:
     for b in iter(lambda:src.read(1048576),b''):out.write(b)
  if encoded.stat().st_size!=group['encoded_bytes'] or checksum(encoded)!=group['encoded_sha256']:raise ValueError('assembled payload differs')
  if group['encoding']=='gzip':
   count=0
   with gzip.open(encoded,'rb') as src,destination.open('xb') as out:
    for b in iter(lambda:src.read(1048576),b''):
     count+=len(b)
     if count>group['original_bytes']:raise ValueError('decoded size exceeds frozen original')
     out.write(b)
  elif group['encoding']!='identity':raise ValueError('unsupported encoding')
  if destination.stat().st_size!=group['original_bytes'] or checksum(destination)!=group['original_sha256']:raise ValueError('original bytes not restored')
  print(json.dumps({'path':str(destination),'bytes':destination.stat().st_size,'sha256':checksum(destination)},sort_keys=True))
if __name__=='__main__':main()
