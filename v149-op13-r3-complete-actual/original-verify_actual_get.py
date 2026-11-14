"""Full actual-GET transport readback, without extraction or product execution."""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, tarfile, time, traceback, zlib

ROOT=Path('/tmp/hia-op13-actual-transport-r1-dda7')
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
OLD_KEYS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
INDEX_PIN={'bytes':77271,'git_blob':'5fb8cd9e65e51dd0c7c96c5f2ad5b9e50af69c5c',
 'sha256':'de8c1f2e098b82a899ebb84565c602190b9b01035cc346f0913e82b0339f6284'}
READS={};COUNT=0;BYTES=0

def need(ok,msg):
 if not ok:raise AssertionError(msg)
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
 'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def stamp(s):return {k:getattr(s,k)for k in KEYS}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(name,value):
 with (ROOT/name).open('xb')as f:f.write(enc(value))
def fresh(path,identity,mode=None,expected_stat=None):
 global COUNT,BYTES
 path=Path(path);s=path.lstat();before=stamp(s)
 need(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'unique regular input required: '+str(path))
 for parent in path.parents:need(stat.S_ISDIR(parent.lstat().st_mode),'parent symlink refused')
 if expected_stat is not None:need(before==expected_stat,'original stat differs: '+str(path))
 if mode is not None:need(stat.S_IMODE(s.st_mode)==mode,'original mode differs')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  need(stamp(os.fstat(fd))==before,'held input differs')
  with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(s.st_size+1)
  need(len(b)==s.st_size and stamp(os.fstat(fd))==stamp(path.lstat())==before,'input changed while reading')
 finally:os.close(fd)
 need(pin(b)==identity,'full input identity differs: '+str(path))
 if str(path)in READS:need(READS[str(path)]==before,'repeat read changed')
 READS[str(path)]=before;COUNT+=1;BYTES+=len(b)
 return b
def get(row):return fresh(ROOT/'actual-get'/row['logical'],row['pin'])
def joined(kind,parts,publication):
 data=[];offset=0
 for i,row in enumerate(parts):
  leaf=publication[row['logical']];need(leaf['pin']==row['pin'],'part publication differs')
  wrapper=json.loads(get(leaf));chunk=base64.b64decode(wrapper['data_base64'],validate=True)
  need(wrapper['kind']==kind and wrapper['index']==row['index']==i and wrapper['offset']==row['offset']==offset,'part order differs')
  need(pin(chunk)==wrapper['chunk']==row['chunk'],'part bytes differ');data.append(chunk);offset+=len(chunk)
 return b''.join(data)

def main():
 start=time.monotonic_ns()
 rows=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes())
 need(len(rows)==128 and len({r['logical']for r in rows})==128,'full original publication set differs')
 publication={r['logical']:r for r in rows}
 need(publication['INDEX.json']['pin']==INDEX_PIN,'fixed complete index differs')
 receipts=[]
 for i,row in enumerate(rows):
  get(row)
  receipt=json.loads((ROOT/'receipts'/('%03d.json'%i)).read_bytes())
  need(receipt['index']==i and receipt['logical']==row['logical']and receipt['pin']==row['pin']
   and receipt['post_ack_git']==row['pin']['git_blob']and receipt['full_get_equal']is True,'actual receipt differs')
  receipts.append(receipt)
 index=json.loads(get(publication['INDEX.json']))
 packed=joined('metadata',index['metadata_parts'],publication);need(pin(packed)==index['metadata_zlib'],'metadata stream differs')
 z=zlib.decompressobj();payload=z.decompress(packed)+z.flush()
 need(z.eof and not z.unused_data and not z.unconsumed_tail and pin(payload)==index['metadata_payload'],'complete metadata decode differs')
 meta=json.loads(payload);need(len(meta['files'])==7 and meta['metadata_originals']==7,'all seven metadata required')
 rawmeta={}
 for name,row in meta['files'].items():
  need(row['encoding']=='utf-8'and row['descriptor']==index['metadata_files'][name],'metadata authority differs')
  raw=row['text'].encode();desc=row['descriptor'];need(pin(raw)==desc['pin'],'metadata payload differs')
  need(fresh(desc['path'],desc['pin'],desc['mode'],desc['stat'])==raw,'metadata original bytes differ')
  rawmeta[name]=raw
 manifest=json.loads(rawmeta['MANIFEST.json']);intent=json.loads(rawmeta['INTENT.json']);plan=json.loads(rawmeta['INPUT-PLAN.json'])
 report=json.loads(rawmeta['REPORT.json'])
 need(report['status']=='PASS_COMPLETE_ORIGINAL_BYTES_AND_MODES'and report['manifest']==pin(rawmeta['MANIFEST.json']),'retained original report differs')
 files=manifest['files'];objects=manifest['objects'];aliases={}
 need(len(files)==manifest['file_count']==11714 and len(objects)==manifest['unique_objects']==10397,'original counts differ')
 need(sum(r['identity']['bytes']for r in files.values())==manifest['logical_bytes']==135672211,'logical byte count differs')
 need(sum(r['identity']['bytes']for r in objects.values())==manifest['unique_bytes']==134246573,'CAS byte count differs')
 need({n:r['source_path']for n,r in files.items()}==intent['all_original_files'],'intent paths differ')
 for name,row in files.items():
  sha=row['identity']['sha256'];need(row['storage_path']=='objects/'+sha and objects[sha]['identity']==row['identity'],'CAS mapping differs')
  need(row['seven_stats']==intent['before_seven_stats'][name],'original seven stats differ')
  aliases.setdefault(sha,[]).append(name)
 archive=joined('archive',index['archive_parts'],publication)
 need(pin(archive)==index['archive']['pin']==report['archive'],'whole actual-GET archive differs')
 archive_desc=index['archive'];need(fresh(archive_desc['path'],archive_desc['pin'],archive_desc['mode'],archive_desc['stat'])==archive,'retained gzip differs')
 seen=set();compared=0
 with gzip.GzipFile(fileobj=io.BytesIO(archive),mode='rb')as gz:
  with tarfile.open(fileobj=gz,mode='r|')as tar:
   for member in tar:
    need(member.isfile()and not member.issym()and not member.islnk()and member.mode==0o444
     and member.uid==member.gid==member.mtime==0 and not member.uname and not member.gname,'transport member differs')
    need(member.name not in seen,'duplicate transport member');seen.add(member.name)
    stream=tar.extractfile(member);raw=stream.read(member.size+1);need(len(raw)==member.size,'truncated member')
    if member.name=='MANIFEST.json':need(raw==rawmeta['MANIFEST.json'],'internal manifest differs');continue
    need(member.name.startswith('objects/'),'unexpected archive path');sha=member.name[8:]
    need(sha in objects and pin(raw)==objects[sha]['identity'],'full CAS payload differs')
    for logical in aliases[sha]:
     row=files[logical];expected=dict(zip(OLD_KEYS,row['seven_stats']))
     actual=fresh(row['source_path'],row['identity'],row['mode'],expected)
     need(actual==raw,'complete logical bytes differ');compared+=1
  while gz.read(1<<20):pass
 need(seen=={'MANIFEST.json'}|{'objects/'+s for s in objects}and compared==11714,'complete archive denominator differs')
 current_dirs={};root_files={}
 for label,root_name in plan['roots'].items():
  root=Path(root_name)
  for here,ds,ns in os.walk(root,followlinks=False):
   ds.sort();ns.sort();here=Path(here);s=here.lstat();need(stat.S_ISDIR(s.st_mode),'directory link refused')
   current_dirs[label+'/'+here.relative_to(root).as_posix()]=[getattr(s,k)for k in OLD_KEYS]
   for d in ds:need(stat.S_ISDIR((here/d).lstat().st_mode),'directory symlink refused')
   for n in ns:
    p=here/n;need(stat.S_ISREG(p.lstat().st_mode),'nonregular logical original')
    root_files[label+'/'+p.relative_to(root).as_posix()]=str(p)
 expected_roots={n:r['source_path']for n,r in files.items()if n.split('/',1)[0]in plan['roots']}
 need(root_files==expected_roots and current_dirs==manifest['directories']==intent['directories'],'complete current pathsets differ')
 for path,s in READS.items():need(stamp(Path(path).lstat())==s,'terminal seven-stat drift')
 put('ACTUAL-GET-RECEIPTS.json',receipts)
 put('ACTUAL-GET-FILE-STATS.json',{str(ROOT/'actual-get'/r['logical']):READS[str(ROOT/'actual-get'/r['logical'])]for r in rows})
 result={'schema':'hepta.op13.actual.complete-custody.actual-git-readback.v1','status':'PASS_FULL_ACTUAL_GET_DECODE_AND_ORIGINAL_COMPARISON',
  'initial_leaves':128,'archive_parts':len(index['archive_parts']),'metadata_parts':len(index['metadata_parts']),
  'metadata_originals':7,'archive':report['archive'],'manifest':report['manifest'],'archive_members':len(seen),
  'complete_gzip_crc':True,'metadata_zlib_eof':True,'logical_files_full_byte_compared':compared,
  'logical_bytes':135672211,'cas_objects':10397,'cas_bytes':134246573,'directories':len(current_dirs),
  'every_original_mode_and_seven_stats':True,'all_original_pathsets_unchanged':True,'fresh_reads':COUNT,'fresh_read_bytes':BYTES,
  'unique_read_paths':len(READS),'new_full_uncompressed_copy':False,'original_product_status':'FAIL','failed_group':'native-05',
  'compile_full_workspace_observed':False,'all_frames_retired':False,'semantic_qualification_reused':False,
  'seal_rerun':0,'product_executions':0,'CI':0,'whole':False,'elapsed_ns':time.monotonic_ns()-start}
 put('FULL-READBACK.json',result);print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
 try:main()
 except BaseException:
  put('READBACK-FAILURE.json',{'status':'FAIL_TRANSPORT_READBACK','products':0,'traceback':traceback.format_exc(),'all_partial_records_retained':True})
  raise
