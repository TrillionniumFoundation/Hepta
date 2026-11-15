from pathlib import Path
import base64,hashlib,json,os,stat,zlib
ROOT=Path(__file__).absolute().parent
SOURCES={'retained-r1':Path('/workspace/hia-store-codecs-controls-author-r1-20261115-dda7'),
         'active-r2':Path('/workspace/hia-store-codecs-controls-author-r2-20261115-dda7')}
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
def emit(name,value):
 raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 with (ROOT/name).open('xb') as f:f.write(raw)
 assert (ROOT/name).read_bytes()==raw
 return dict(relative=name,path=str(ROOT/name),**pin(raw),mode='100644',posix_mode=420)
def main():
 rows=[];payload=[]
 for label,root in SOURCES.items():
  for file in sorted(root.iterdir()):
   s=file.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
   before={k:getattr(s,k) for k in FIELDS};raw=file.read_bytes()
   assert {k:getattr(file.lstat(),k) for k in FIELDS}==before
   row=dict(path=label+'/'+file.name,origin=str(file),mode=stat.S_IMODE(s.st_mode),seven_stat=before,**pin(raw))
   rows.append(row);packed=zlib.compress(raw,9)
   data=base64.b64encode(packed).decode();reader=zlib.decompressobj();got=reader.decompress(base64.b64decode(data,validate=True));got+=reader.flush()
   assert reader.eof and not reader.unused_data and not reader.unconsumed_tail and got==raw
   payload.append(dict(**row,codec='zlib-base64',data=data))
 assert len(rows)==30
 leaves=[emit('AUTHOR-CAPSULE.json',dict(schema='hepta.hia.lossless-author-capsule.v1',files=payload,
  products=0,refs=0,payload_scope='all14 retained R1 and all16 active R2 author files only'))]
 leaves.append(emit('MANIFEST.json',dict(files=rows,logical_bytes=sum(r['bytes'] for r in rows),products=0,refs=0)))
 leaves.append(emit('LOCAL-READBACK.json',dict(status='PASS_ALL30_WHOLE_ZLIB_BYTES_AND_ORIGIN_STATS',
  files=len(rows),logical_bytes=sum(r['bytes'] for r in rows),products=0,refs=0)))
 for name in ('HANDOFF.json','PLAN.json','LAUNCH.json','MATRIX.json','CONTRACT.md','STATIC-REVIEW.json','R1-AUTHOR-ERROR.json','R1-R2-WHOLE-INVERSE.json'):
  raw=(SOURCES['active-r2']/name).read_bytes()
  with (ROOT/name).open('xb') as f:f.write(raw)
  leaves.append(dict(relative=name,path=str(ROOT/name),**pin(raw),mode='100644',posix_mode=420))
 leaves.append(dict(relative='seal_author.py',path=str(Path(__file__).absolute()),**pin(Path(__file__).read_bytes()),mode='100644',posix_mode=420))
 emit('PUBLICATION-INPUTS.json',dict(root=str(ROOT),repository='TrillionniumFoundation/Hepta',
  files=leaves,state='IMMUTABLE_AUTHOR_BLOBS_ONLY_NO_REF',products=0,refs=0))
 print(json.dumps(dict(leaves=len(leaves),files=len(rows),bytes=sum(r['bytes'] for r in rows),capsule=leaves[0])))
if __name__=='__main__':main()
