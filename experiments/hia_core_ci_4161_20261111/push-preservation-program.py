import hashlib,json,os,pathlib,re,stat,sys,time,urllib.request,zipfile
request=json.load(sys.stdin)
root=pathlib.Path.home()/'hia-native-closure-evidence'/'4161e8d12d87906fde144f039da07908ad52d98a'
root.mkdir(mode=0o700,parents=True,exist_ok=True)
assert all(not p.is_symlink() for p in (root,*root.parents))
assert root.stat().st_uid==os.geteuid()
case=root/'ci-push-original-terminal-r1';case.mkdir(mode=0o700)
def write(path,data):
 with path.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,value):write(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def digest(path):
 h=hashlib.sha256();n=0
 with path.open('rb') as f:
  for part in iter(lambda:f.read(1<<20),b''):h.update(part);n+=len(part)
 return n,h.hexdigest()
item=request['artifact'];archive=case/('ci-push-'+str(item['artifact_id'])+'-original.zip')
public={k:v for k,v in item.items() if k!='url'}
dump(case/'DOWNLOAD-INTENT.json',public)
try:
 started=time.monotonic_ns();h=hashlib.sha256();n=0
 with urllib.request.urlopen(item['url'],timeout=60) as response,archive.open('xb') as target:
  while True:
   part=response.read(1<<20)
   if not part:break
   n+=len(part);assert n<=item['bytes']
   target.write(part);h.update(part)
  target.flush();os.fsync(target.fileno())
 assert (n,h.hexdigest())==(item['bytes'],item['sha256'])
 reread=digest(archive);assert reread==(n,item['sha256'])
 dump(case/'DOWNLOAD-VERIFIED.json',dict(public,path=str(archive),download_bytes=n,download_sha256=h.hexdigest(),independent_reread_bytes=reread[0],independent_reread_sha256=reread[1],elapsed_ns=time.monotonic_ns()-started))
 folder=case/'metadata';folder.mkdir(mode=0o700)
 records=[];entries=[];cold=None;index=None;phases={};generations={}
 with zipfile.ZipFile(archive) as z:
  assert len(z.infolist())==len({i.filename for i in z.infolist()})
  for i in z.infolist():
   entries.append({'member':i.filename,'bytes':i.file_size,'compressed_bytes':i.compress_size,'crc32':i.CRC,'external_attr':i.external_attr})
   name=pathlib.PurePosixPath(i.filename).name
   wanted=(name in ('hia-cold.json','phase-index.json','stderr.log','stdout.log') or re.fullmatch(r'phase-.*\.process\.json',name) or re.fullmatch(r'[BM][123]\.receipt\.json',name))
   if not wanted or i.file_size>2<<20:continue
   raw=z.read(i);dest=folder/(str(len(records)).zfill(4)+'-'+name);write(dest,raw)
   row={'member':i.filename,'path':str(dest),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()};records.append(row)
   if not name.endswith('.json'):continue
   value=json.loads(raw)
   if name=='hia-cold.json':cold=value
   elif name=='phase-index.json':index=value
   elif name.endswith('.process.json'):
    key=value['family']+'/'+value['compiler_label'];phases[key]={k:value.get(k) for k in ('wall_elapsed_ns','returncode','started_monotonic_ns','completed_monotonic_ns','archive_completed_monotonic_ns','report_sha256')};phases[key]['raw']=row
   elif re.fullmatch(r'[BM][123]\.receipt\.json',name):
    generations[name]={k:value.get(k) for k in ('wall_elapsed_ns','produced_sha256','status')}
 assert cold is not None and index is not None
 assert cold['profile']=='selfhost-core-linux-x86_64-v65-native-journal-complete-nominal-lowering'
 manifest=cold['source_manifest'];assert len(manifest)==635
 assert manifest['docs/HIA_SELFHOST_CORE_SUPPORT.json']=='30dd711b618a3c67c2ec841eb5f77eb64724f704b7c724bc12f4d2023a8ba533'
 dump(case/'members.json',entries)
 owner=cold['process_owner'];cleanup=owner['cleanup']
 summary={'schema':'hia.416.push-original-cold-metadata.v1','original_artifact':public,'path':str(archive),'archive_bytes':n,'archive_sha256':reread[1],'download_and_independent_reread_verified':True,
 'profile':cold['profile'],'cold_status':cold['status'],'cold_wall_ns':cold['wall_elapsed_ns'],'checks':cold['checks'],
 'source_manifest_count':len(manifest),'source_manifest_sha256':hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
 'owner':{k:owner.get(k) for k in ('status','returncode','timed_out','exit_observed_before_deadline','implementation_sha256')},
 'cleanup':{k:cleanup.get(k) for k in ('complete','leader_reaped','observed_echild','remaining_direct_children','errors','elapsed_ns')},
 'phase_completed':index['completed'],'phase_exceptions':index['exceptions'],'pending':[(x['family'],x['compiler_label'],x['state']) for x in index['phases'] if x['state']!='completed'],
 'phases':phases,'generations':generations,'retained_metadata':records,'payload_archives_replayed':False,'qualification_rerun':False}
 dump(case/'summary.json',summary)
 for d in (folder,case,root):
  fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 print(json.dumps({'status':'ORIGINAL_ARTIFACT_PRESERVED_AND_METADATA_READ','directory':str(case),'summary_bytes':(case/'summary.json').stat().st_size,'summary_sha256':digest(case/'summary.json')[1],'cold_status':summary['cold_status'],'cold_wall_ns':summary['cold_wall_ns'],'phase_completed':summary['phase_completed'],'pending':summary['pending'],'cleanup':summary['cleanup']}),flush=True)
except BaseException as error:
 result={'schema':'hia.original-artifact-preservation-attempt-failure.v1','error_type':type(error).__name__,'errno':getattr(error,'errno',None),'http_code':getattr(error,'code',None),'partial_file_retained':archive.exists(),'qualification_rerun':False,'signed_url_persisted':False}
 dump(case/'FAILURE.json',result);print(json.dumps(result),flush=True);sys.exit(1)
