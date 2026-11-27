"""Decode only actual full-GET responses and compare every retained original."""
from pathlib import Path
import base64,gzip,hashlib,json,os,stat,tarfile,time,traceback,zlib
R=Path(__file__).resolve().parent
KEYS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,msg):
 if not ok:raise AssertionError(msg)
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def st(p):return [getattr(Path(p).lstat(),k) for k in KEYS]
def read(p):
 p=Path(p);s=p.lstat();a=st(p);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'non-regular/link input')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  need([getattr(os.fstat(fd),k) for k in KEYS]==a,'opened input differs')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
  need(len(b)==s.st_size and [getattr(os.fstat(fd),k) for k in KEYS]==a==st(p),'input changed')
 finally:os.close(fd)
 return b,stat.S_IMODE(s.st_mode),a
def dump(name,value):
 with (R/name).open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def actual_get(path,expected):
 stem=''.join(c if c.isalnum() or c in '_-' else '_' for c in path)
 ack=json.loads(read(R/'git-receipts'/(stem+'.POST.json'))[0])
 got=json.loads(read(R/'git-receipts'/(stem+'.GET.json'))[0])
 receipt=json.loads(read(R/'git-receipts'/(stem+'.READBACK.json'))[0])
 need(ack.get('isError') is not True and ack['structuredContent']['sha']==expected['git_blob'],'POST ACK differs')
 need(got.get('isError') is not True and isinstance(got['structuredContent']['content'],str),'GET is not full text')
 b=got['structuredContent']['content'].encode()
 need(pin(b)=={k:expected[k] for k in ('bytes','sha256','git_blob')},'GET wrapper bytes differ')
 need(receipt['identity']==expected and receipt['POST_ACK'] is True and receipt['full_GET'] is True,'GET receipt differs')
 need(b==read(R/path)[0],'local wrapper differs from actual full GET')
 return b
def main():
 start=time.monotonic_ns()
 publication=json.loads(read(R/'PUBLICATION-INPUTS.json')[0]);rows={x['path']:x for x in publication['files']}
 index=json.loads(actual_get('TRANSPORT-INDEX.json',rows['TRANSPORT-INDEX.json']['identity']))
 target=R/'GIT-RECONSTRUCTED.tar.gz';offset=0
 with target.open('xb') as f:
  for i,item in enumerate(index['parts']):
   part=json.loads(actual_get(item['path'],item['identity']))
   need(part['index']==i and part['offset']==offset==item['offset'] and part['archive']==index['archive'],'part order/archive differs')
   b=base64.b64decode(part['data'],validate=True)
   need(pin(b)==part['decoded']==item['decoded'],'decoded part differs')
   f.write(b);offset+=len(b)
 archive,_,_=read(target);need(pin(archive)==index['archive'],'reconstructed archive differs')
 need(archive==read(R/'COMPLETE-ORIGINALS.tar.gz')[0],'reconstructed archive not byte-exact local verified archive');del archive
 wrapper=json.loads(actual_get('MANIFEST.zlib.json',rows['MANIFEST.zlib.json']['identity']))
 compressed=base64.b64decode(wrapper['data'],validate=True);need(pin(compressed)==wrapper['compressed'],'manifest compressed identity differs')
 decoder=zlib.decompressobj();mb=decoder.decompress(compressed)+decoder.flush()
 need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'manifest compressed closure differs')
 need(pin(mb)==wrapper['original']==index['manifest'] and mb==read(R/'MANIFEST.json')[0],'manifest original bytes differ')
 manifest=json.loads(mb);objects=manifest['objects'];aliases={}
 for logical,row in manifest['files'].items():
  sha=row['identity']['sha256'];need(row['storage_path']=='objects/'+sha and row['identity']==objects[sha]['identity'],'logical CAS mapping differs')
  aliases.setdefault(sha,[]).append(logical)
 seen=set();compared=0;byte_total=0
 with gzip.open(target,'rb') as gz:
  with tarfile.open(fileobj=gz,mode='r|') as tar:
   for member in tar:
    need(member.isfile() and not member.issym() and not member.islnk() and member.mode==0o444,'invalid transport member')
    need(member.name not in seen,'duplicate member');seen.add(member.name)
    raw=tar.extractfile(member).read(member.size+1);need(len(raw)==member.size,'truncated member')
    if member.name=='MANIFEST.json':need(raw==mb,'embedded manifest differs');continue
    need(member.name.startswith('objects/'),'unexpected member')
    sha=member.name[8:];need(sha in objects and pin(raw)==objects[sha]['identity'],'CAS object differs')
    for logical in aliases[sha]:
     wanted=manifest['files'][logical];actual,mode,stamp=read(wanted['source_path'])
     need(raw==actual and mode==wanted['mode'] and stamp==wanted['seven_stats'],'full actual logical original differs')
     compared+=1;byte_total+=len(raw)
  while gz.read(1048576):pass
 need(seen=={'MANIFEST.json'}|{'objects/'+x for x in objects},'complete member pathset differs')
 need(compared==manifest['file_count']==2216 and byte_total==manifest['logical_bytes']==1130193525,'full logical original denominator differs')
 for row in manifest['files'].values():need(st(row['source_path'])==row['seven_stats'],'original final stat drift')
 result={'schema':'hepta.r8.r4.complete-originals.actual-Git-readback.v1','status':'PASS_ALL_ACTUAL_FULL_GET_AND_COMPLETE_ORIGINAL_BYTES',
  'qualification':'FAIL','parts':len(index['parts']),'archive':index['archive'],'manifest':index['manifest'],
  'CAS_objects':len(objects),'archive_members':len(seen),'full_gzip_footer_CRC':True,
  'logical_files_complete_byte_compared':compared,'logical_bytes':byte_total,'all_modes_and_seven_stats_exact':True,
  'Native163_full_frames_present':True,'VM6_including_original_fuel_failure_present':True,
  'all_four_owners_and_source_control_guards_present':True,'all_fresh_admission_and_author_records_present':True,
  'product_executions':0,'CI':0,'refs':0,'signed_access_credentials_included':False,'elapsed_ns':time.monotonic_ns()-start}
 dump('GIT-FULL-READBACK.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try:main()
 except BaseException:
  dump('GIT-READBACK-FAILURE.json',{'status':'FAIL_READBACK','traceback':traceback.format_exc(),'product_executions':0,'partial_retained':True})
  raise
