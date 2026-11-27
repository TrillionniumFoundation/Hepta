from pathlib import Path,PurePosixPath
import base64,gzip,hashlib,io,json,os,stat,tarfile,time,zlib
ROOT=Path(__file__).resolve().parent
SOURCE=Path('/workspace/scratch/dda74a4fae35/v88-store-snapshot-native-r1')
COMPILER=Path('/workspace/scratch/dda74a4fae35/v86-native-entry-development-r1/development-build-r1/B3.image.bin')
def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def canonical(x):return (json.dumps(x,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
def main():
 started=time.monotonic_ns();inputs={str(p.relative_to(SOURCE)):p for p in sorted(SOURCE.rglob('*')) if p.is_file()}
 inputs['external-inputs/B3.image.bin']=COMPILER
 nodes={};pool={}
 for name,p in inputs.items():
  info=p.lstat();assert stat.S_ISREG(info.st_mode) and not p.is_symlink(),p
  raw=p.read_bytes();row=identity(raw);row.update({'mode':format(stat.S_IMODE(info.st_mode),'04o'),'cas':'cas/'+row['sha256']+'.bin'})
  if row['sha256'] in pool:assert pool[row['sha256']].read_bytes()==raw
  else:pool[row['sha256']]=p
  nodes[name]=row
 manifest={'schema':'hepta.lossless.cas-archive.v1','logical_files':nodes,'logical_count':len(nodes),'logical_bytes':sum(r['bytes'] for r in nodes.values()),'unique_objects':len(pool),'unique_bytes':sum(p.stat().st_size for p in pool.values()),'base_source_packet':'e6956351fcb08a89c30bd02d69a95114bab3112b','base_tree':'b804714e69f6ee851aede5cc4b45fa5d035a73e1','self_contained_execution_environment':False,'all_current_scope_originals_included':True,'root_source_or_refs_modified':False,'whole_native':False}
 mraw=canonical(manifest);(ROOT/'MANIFEST.json').write_bytes(mraw)
 archive=ROOT/'COMPLETE.tar.gz'
 with archive.open('xb') as fout:
  with gzip.GzipFile(fileobj=fout,mode='wb',filename='',mtime=0,compresslevel=1) as gz:
   with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
    for name,raw in [('MANIFEST.json',mraw)]+[(f'cas/{sha}.bin',p.read_bytes()) for sha,p in sorted(pool.items())]:
     info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o644;info.uid=info.gid=info.mtime=0;info.uname=info.gname='';tar.addfile(info,io.BytesIO(raw))
 expected={'MANIFEST.json':identity(mraw)}
 for sha,p in pool.items():expected[f'cas/{sha}.bin']=identity(p.read_bytes())
 actual={}
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar:
   assert member.isfile() and member.mode==0o644 and member.name not in actual
   data=tar.extractfile(member).read();actual[member.name]=identity(data);assert actual[member.name]==expected[member.name]
 assert actual==expected
 for name,p in inputs.items():
  assert identity(p.read_bytes())=={k:nodes[name][k] for k in ('bytes','sha256','git_blob')}
  assert format(stat.S_IMODE(p.lstat().st_mode),'04o')==nodes[name]['mode']
 data=archive.read_bytes();parts=ROOT/'parts';parts.mkdir()
 chunks=[]
 for i,pos in enumerate(range(0,len(data),131072)):
  raw=data[pos:pos+131072];encoded=base64.b64encode(raw);name=f'parts/chunk-{i:03d}.b64';(ROOT/name).write_bytes(encoded)
  assert b'\n' not in encoded and base64.b64decode(encoded,validate=True)==raw
  chunks.append({'file':name,**identity(encoded),'offset':pos,'decoded_bytes':len(raw),'decoded_sha256':hashlib.sha256(raw).hexdigest(),'decoded_computed_git_blob':identity(raw)['git_blob']})
 sourcefiles={}
 for name,p in inputs.items():
  if name.startswith('authored/') or name.startswith('generated/') or name in ('INPUTS.json','BOUNDARY.md','SUMMARY.json'):
   text=p.read_text();sourcefiles[name]={'text':text,**nodes[name]}
 decoded=canonical({'schema':'hepta.hia.development-source-packet.v1','files':sourcefiles,'base_source_packet':manifest['base_source_packet'],'base_tree':manifest['base_tree'],'self_contained_execution_environment':False,'whole_native':False})
 wrapper=canonical({'schema':'hepta.zlib-json-capsule.v1','decoded':identity(decoded),'encoding':'zlib+base64','data':base64.b64encode(zlib.compress(decoded,9)).decode()})
 (ROOT/'SOURCE-CAPSULE.json').write_bytes(wrapper);assert zlib.decompress(base64.b64decode(json.loads(wrapper)['data'],validate=True))==decoded
 metadata={'schema':'hepta.lossless.utf8-base64-transport.v1','archive':{'file':'COMPLETE.tar.gz',**identity(data)},'manifest':{'file':'MANIFEST.json',**identity(mraw)},'source_capsule':{'file':'SOURCE-CAPSULE.json',**identity(wrapper)},'chunks':chunks,'logical_count':len(nodes),'unique_objects':len(pool),'logical_bytes':manifest['logical_bytes'],'unique_bytes':manifest['unique_bytes'],'all_members_bytes_git_sha_mode_read_back':True,'all_originals_unchanged':True,'gzip_complete_decompressed':True,'elapsed_ns':time.monotonic_ns()-started,'raw_binary_git_blobs_uploaded':False,'whole_native':False}
 (ROOT/'TRANSPORT.json').write_bytes(canonical(metadata));print(json.dumps({k:v for k,v in metadata.items() if k!='chunks'},sort_keys=True))
if __name__=='__main__':main()
