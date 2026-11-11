import hashlib,json,os,pathlib,re,statistics,sys,time,urllib.request,zipfile
req=json.load(sys.stdin)
base=pathlib.Path.home()/'hia-native-closure-evidence'
root=base/'699451201f51fb4bdbd931568e64aa576143e807'
out=root/'ci-original-terminal-r2';out.mkdir(mode=0o700)
def write(path,data):
 with path.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,x):write(path,(json.dumps(x,sort_keys=True,indent=2)+'\n').encode())
def digest(path):
 h=hashlib.sha256();size=0
 with path.open('rb') as f:
  for part in iter(lambda:f.read(1<<20),b''):h.update(part);size+=len(part)
 return size,h.hexdigest()
p=out/'ci-pr-13837373187-original.zip';h=hashlib.sha256();n=0
with urllib.request.urlopen(req['url'],timeout=90) as r,p.open('xb') as f:
 while True:
  b=r.read(1<<20)
  if not b:break
  f.write(b);h.update(b);n+=len(b)
 f.flush();os.fsync(f.fileno())
assert (n,h.hexdigest())==(48270174,'92ae035b35791e54dee75fdc081966e6c92302b49c9cbf83a36b2a5781aec857')
assert digest(p)==(n,h.hexdigest())
dump(out/'PR-preservation.json',{'artifact_id':13837373187,'path':str(p),'bytes':n,'sha256':h.hexdigest(),'download_and_independent_reread_verified':True,'prior_job':'1a1c9a0c6bc-2564-215','prior_failure':'ConnectionResetError104 with exit_code1/output_complete/output_durable','prior_partial_path':str(root/'ci-original-terminal-r1/ci-pr-13837373187-original.zip'),'payload_archives_replayed':False})
paths=[
 ('699-push',root/'ci-original-terminal-r1/ci-push-13838255146-original.zip'),
 ('699-pr',p),
 ('93-push',base/'93d66bcc3acb88212c9b153d7852ba22eeab24c8/ci-push-13831763390-original.zip'),
 ('93-pr',base/'93d66bcc3acb88212c9b153d7852ba22eeab24c8/ci-pr-13831751807-original.zip')]
summaries=[]
for label,path in paths:
 folder=out/(label+'-metadata');folder.mkdir()
 records=[];cold=None;index=None;phases={};generation={};references={};extras=[]
 with zipfile.ZipFile(path) as z:
  for i in z.infolist():
   name=pathlib.PurePosixPath(i.filename).name
   wanted=(name in ('hia-cold.json','phase-index.json','stderr.log','stdout.log')
       or re.fullmatch(r'phase-.*\.process\.json',name)
       or re.fullmatch(r'[BM][123]\.receipt\.json',name)
       or name.endswith('.reference.json'))
   if not wanted or i.file_size>2<<20:continue
   raw=z.read(i);dest=folder/(str(len(records)).zfill(4)+'-'+name);write(dest,raw)
   records.append({'member':i.filename,'path':str(dest),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
   if not name.endswith('.json'):continue
   value=json.loads(raw)
   if name=='hia-cold.json':cold=value
   elif name=='phase-index.json':index=value
   elif name.endswith('.process.json'):
    key=value['family']+'/'+value['compiler_label'];phases[key]={'wall_ns':value['wall_elapsed_ns'],'returncode':value['returncode'],'raw':str(dest)}
   elif re.fullmatch(r'[BM][123]\.receipt\.json',name):
    generation[name]={'wall_ns':value.get('wall_elapsed_ns'),'produced_sha256':value.get('produced_sha256'),'status':value.get('status')}
   else:references[name]={'wall_ns':value.get('wall_elapsed_ns'),'fields':list(value)}
 assert cold is not None
 size,checksum=digest(path)
 owner=cold['process_owner'];cleanup=owner['cleanup']
 result={'label':label,'archive':str(path),'bytes':size,'sha256':checksum,
    'profile':cold['profile'],'cold_status':cold['status'],'cold_wall_ns':cold['wall_elapsed_ns'],
    'checks':cold['checks'],'source_manifest_count':len(cold['source_manifest']),
    'source_manifest_sha256':hashlib.sha256(json.dumps(cold['source_manifest'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
    'owner':{k:owner.get(k) for k in ('status','returncode','timed_out','exit_observed_before_deadline','implementation_sha256')},
    'cleanup':{k:cleanup.get(k) for k in ('complete','leader_reaped','observed_echild','remaining_direct_children','errors','elapsed_ns')},
    'phase_completed':index['completed'] if index else None,
    'phase_exceptions':index['exceptions'] if index else None,
    'pending':[(x['family'],x['compiler_label'],x['state']) for x in index['phases'] if x['state']!='completed'] if index else None,
    'phases':phases,'generations':generation,'references':references,'retained_metadata':records}
 dump(out/(label+'-comparison-receipt.json'),result);summaries.append(result)
compact=[]
for r in summaries:
 compact.append({k:r[k] for k in ('label','archive','bytes','sha256','profile','cold_status','cold_wall_ns','checks','source_manifest_count','source_manifest_sha256','owner','cleanup','phase_completed','phase_exceptions','pending','generations')})
timing={key:{r['label']:round(r['phases'][key]['wall_ns']/1e9,6) for r in summaries if key in r['phases']} for key in sorted(set().union(*(r['phases'] for r in summaries)))}
ratios={}
for new in summaries[:2]:
 for old in summaries[2:]:
  common=set(new['phases'])&set(old['phases'])
  values=[new['phases'][k]['wall_ns']/old['phases'][k]['wall_ns'] for k in common]
  ratios[new['label']+'/'+old['label']]={'common_phases':len(values),'median_ratio':statistics.median(values),'min_ratio':min(values),'max_ratio':max(values)}
result={'schema':'hia.699.93.original-cold-timing-comparison.v1','scope':'Original immutable CI artifacts only; no reruns, no payload archive replay, no inference that machine conditions match','artifacts':compact,'phase_seconds':timing,'common_phase_ratios':ratios}
dump(out/'comparison.json',result)
fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'status':'PR_ORIGINAL_PRESERVED_COMPARISON_READY','directory':str(out),'pr_archive_sha256':h.hexdigest(),'cold_summary':[{k:r[k] for k in ('label','cold_status','cold_wall_ns','phase_completed','pending')} for r in compact],'common_phase_ratios':ratios,'comparison_file':str(out/'comparison.json'),'comparison_bytes':(out/'comparison.json').stat().st_size}),flush=True)
