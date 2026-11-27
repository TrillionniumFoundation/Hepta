"""Lossless deterministic CAS transport of the frozen completed original scopes."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile,time,zlib
from freeze_inputs import read_identity,byte_identity,canonical
ROOT=Path(__file__).resolve().parent

def read_row(row):
 p=Path(row['source']);return os.fsencode(os.readlink(p)) if row['kind']=='symlink' else p.read_bytes()
def verify(raw,row):assert byte_identity(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
def stable(row):
 current=read_identity(Path(row['source']))
 assert current==row,('frozen original changed',row['source'])

def main():
 started=time.monotonic_ns();frozen_raw=(ROOT/'INPUTS-FROZEN.json').read_bytes();frozen=json.loads(frozen_raw)
 nodes=frozen['logical_files'];pool={}
 for name,row in sorted(nodes.items()):
  sha=row['sha256']
  if sha in pool:
   first=pool[sha];assert row['bytes']==first['bytes'] and row['git_blob']==first['git_blob'];assert read_row(row)==read_row(first)
  else:pool[sha]=row
 manifest={'schema':'hepta.lossless.complete-cas-originals.v1','logical_files':{name:{k:row[k] for k in ('kind','mode','bytes','sha256','git_blob')}|{'cas':'cas/'+row['sha256']+'.bin'} for name,row in nodes.items()},'directories':frozen['directories'],'logical_count':len(nodes),'logical_bytes':frozen['logical_bytes'],'unique_objects':len(pool),'unique_bytes':sum(x['bytes'] for x in pool.values()),'frozen_inputs':byte_identity(frozen_raw),'scope_summary':frozen['scope_summary'],'whole_native':False,'raw_binary_git_objects_uploaded':False}
 mraw=canonical(manifest);(ROOT/'MANIFEST.json').write_bytes(mraw)
 extras={'MANIFEST.json':mraw,'metadata/INPUTS-FROZEN.json':frozen_raw,'metadata/SCOPE-SUMMARY.json':(ROOT/'SCOPE-SUMMARY.json').read_bytes(),'metadata/OUTER-ZIP-RETENTION.json':(ROOT/'OUTER-ZIP-RETENTION.json').read_bytes(),'metadata/freeze_inputs.py':(ROOT/'freeze_inputs.py').read_bytes(),'metadata/package_cas.py':Path(__file__).read_bytes(),'metadata/freeze.stdout':(ROOT/'freeze.stdout').read_bytes(),'metadata/freeze.stderr':(ROOT/'freeze.stderr').read_bytes()}
 archive=ROOT/'COMPLETE.tar.gz'
 with archive.open('xb') as fout:
  with gzip.GzipFile(fileobj=fout,mode='wb',filename='',mtime=0,compresslevel=1) as gz:
   with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
    def add(name,raw):
     info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o644;info.uid=info.gid=info.mtime=0;info.uname=info.gname='';tar.addfile(info,io.BytesIO(raw))
    for name,raw in sorted(extras.items()):add(name,raw)
    for sha,row in sorted(pool.items()):
     raw=read_row(row);verify(raw,row);add('cas/'+sha+'.bin',raw)
 expected={name:byte_identity(raw) for name,raw in extras.items()}
 expected.update({'cas/'+sha+'.bin':{k:row[k] for k in ('bytes','sha256','git_blob')} for sha,row in pool.items()})
 actual={}
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar:
   assert member.isfile() and member.mode==0o644 and member.name not in actual
   raw=tar.extractfile(member).read();actual[member.name]=byte_identity(raw);assert actual[member.name]==expected[member.name]
 assert actual==expected
 # Fully consume gzip to check CRC and ISIZE, including padding after tar end.
 with gzip.open(archive,'rb') as stream:
  while stream.read(1<<20):pass
 for name,row in nodes.items():stable(row)
 original_after={'frozen_files_unchanged':True,'count':len(nodes),'all_bytes_git_sha_mode_and_source_stat_rechecked':True}
 (ROOT/'ORIGINALS-AFTER.json').write_bytes(canonical(original_after))
 archive_raw=archive.read_bytes();parts=ROOT/'parts';parts.mkdir()
 chunks=[]
 for i,pos in enumerate(range(0,len(archive_raw),524288)):
  decoded=archive_raw[pos:pos+524288];encoded=base64.b64encode(decoded);name=f'parts/chunk-{i:03d}.b64';(ROOT/name).write_bytes(encoded)
  assert b'\n' not in encoded and base64.b64decode(encoded,validate=True)==decoded
  chunks.append({'file':name,**byte_identity(encoded),'offset':pos,'decoded_bytes':len(decoded),'decoded_sha256':hashlib.sha256(decoded).hexdigest(),'decoded_computed_git_blob':byte_identity(decoded)['git_blob']})
 # Large human-readable manifests remain exact archive members; this compact
 # UTF-8 capsule also exposes them without a multi-megabyte Git tool response.
 metadata_members={name:{'text':raw.decode('utf-8'),**byte_identity(raw)} for name,raw in extras.items()}
 metadata_raw=canonical({'schema':'hepta.complete-metadata-capsule.v1','files':metadata_members})
 wrapper=canonical({'schema':'hepta.zlib-json-capsule.v1','decoded':byte_identity(metadata_raw),'encoding':'zlib+base64','data':base64.b64encode(zlib.compress(metadata_raw,9)).decode()})
 (ROOT/'METADATA-CAPSULE.json').write_bytes(wrapper)
 assert zlib.decompress(base64.b64decode(json.loads(wrapper)['data'],validate=True))==metadata_raw
 transport={'schema':'hepta.lossless.utf8-base64-transport.v1','archive':{'file':'COMPLETE.tar.gz',**byte_identity(archive_raw)},'manifest':{'file':'MANIFEST.json',**byte_identity(mraw)},'metadata_capsule':{'file':'METADATA-CAPSULE.json',**byte_identity(wrapper)},'chunks':chunks,'raw_chunk_capacity':524288,'logical_count':len(nodes),'logical_bytes':frozen['logical_bytes'],'unique_objects':len(pool),'unique_bytes':manifest['unique_bytes'],'tar_member_count':len(expected),'all_local_archive_members_byte_hash_git_mode_verified':True,'full_gzip_crc_isize_checked':True,'all_frozen_originals_unchanged':True,'outer_zip_original_bytes_retained_not_in_archive':frozen['scope_summary']['outer_zip_bytes_not_in_archive'],'elapsed_ns':time.monotonic_ns()-started,'raw_binary_git_blobs_uploaded':False,'whole_native':False}
 (ROOT/'TRANSPORT.json').write_bytes(canonical(transport));print(json.dumps({k:v for k,v in transport.items() if k!='chunks'},sort_keys=True))
if __name__=='__main__':main()
