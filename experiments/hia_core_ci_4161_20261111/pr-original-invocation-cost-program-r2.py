import collections,hashlib,io,json,os,pathlib,re,sys,time,zipfile
request=json.load(sys.stdin)
archive=pathlib.Path(request['archive'])
out=archive.parent.parent/'ci-pr-invocation-cost-r2';out.mkdir(mode=0o700)
def write(path,data):
 with path.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
def dump(path,value):write(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def digest(path):
 h=hashlib.sha256();total=0
 with path.open('rb') as stream:
  for part in iter(lambda:stream.read(1<<20),b''):h.update(part);total+=len(part)
 return total,h.hexdigest()
before=digest(archive);assert before==(request['bytes'],request['sha256'])
records=[];nested=[];references={};phase_processes={};phase_checks={};request_counts=collections.Counter()
def phase(name):
 m=re.search(r'(?:^|/)phase-runs/([a-z-]+)-(original|modified)(?:/|\.zip$)',name)
 return m[1]+'/'+m[2] if m else 'setup'
def observe(raw,name,group):
 try:value=json.loads(raw)
 except (ValueError,UnicodeError):raise AssertionError('original receipt is not JSON '+name)
 if name.endswith('.request.json'):
  request_counts[(group,str(value.get('format',value.get('return_encoding','other'))))]+=1
  return
 kind=None
 if value.get('format') in ('flat-x86-64','linked-selfhost','seed-shared') and 'wall_elapsed_ns' in value:
  kind=value['format']
 elif 'native_linkage' in value and 'wall_elapsed_ns' in value:kind='specialized-allocator-child'
 elif name.endswith('.command.json') and 'wall_elapsed_ns' in value:kind='external-tool:'+pathlib.Path(value.get('tool',value.get('argv',['unknown'])[0])).name
 if kind is None:return
 records.append({'path':name,'phase':group,'kind':kind,'status':value.get('status'),'returncode':value.get('returncode'),
 'wall_ns':value['wall_elapsed_ns'],'native_ns':value.get('native_elapsed_ns'),
 'receipt_bytes':len(raw),'receipt_sha256':hashlib.sha256(raw).hexdigest(),
 'runner_sha256':value.get('runner_sha256'),'artifact_sha256':value.get('artifact_sha256',value.get('image_sha256')),
 'input_sha256':value.get('input_sha256',value.get('source_sha256')),'output_sha256':value.get('output_sha256'),
 'transport':value.get('transport'),'fresh_native_exec':value.get('fresh_native_exec')})
with zipfile.ZipFile(archive) as outer:
 for info in outer.infolist():
  name=info.filename;base=pathlib.PurePosixPath(name).name;group=phase(name)
  if re.fullmatch(r'phase-.*\.process\.json',base):
   value=json.loads(outer.read(info));phase_processes[value['family']+'/'+value['compiler_label']]={k:value.get(k) for k in ('wall_elapsed_ns','started_monotonic_ns','completed_monotonic_ns','archive_completed_monotonic_ns')}
  elif re.fullmatch(r'phase-[a-z-]+-(original|modified)\.json',base):
   value=json.loads(outer.read(info));phase_checks[value['family']+'/'+value['compiler_label']]={'count':len(value['checks']),'passed':sum(value['checks'].values()),'status':value['status'],'elapsed_ns':value['elapsed_ns']}
  elif re.fullmatch(r'reference-.*\.worker\.json',base):
   checksum=hashlib.sha256();count=0;fields={}
   keys={'before_B0','reference_sha256','source_manifest_sha256','wall_elapsed_ns','worker_pid'}
   with outer.open(info) as stream:
    for line in stream:
     checksum.update(line);count+=len(line)
     m=re.fullmatch(rb'  "([^"]+)": (.*?)(?:,)?\r?\n?',line)
     if m and m[1].decode() in keys:
      key=m[1].decode();assert key not in fields
      fields[key]=json.loads(m[2].rstrip(b','))
   assert count==info.file_size and keys.issubset(fields)
   references[base]=dict(fields,member=name,bytes=count,sha256=checksum.hexdigest(),every_member_byte_read=True)
  if name.endswith('.zip') and '/phase-runs/' in name:
   blob=outer.read(info);row={'member':name,'bytes':len(blob),'sha256':hashlib.sha256(blob).hexdigest(),'payload_members_independently_replayed':False,'receipt_members_read':0}
   with zipfile.ZipFile(io.BytesIO(blob)) as inner:
    for member in inner.infolist():
     if member.filename.endswith(('.receipt.json','.command.json','.request.json')):
      assert member.file_size<=16<<20, (name,member.filename,member.file_size)
      raw=inner.read(member);observe(raw,name+'!/'+member.filename,group);row['receipt_members_read']+=1
   nested.append(row)
  elif name.endswith(('.receipt.json','.command.json','.request.json')) and not base.startswith('phase-'):
   assert info.file_size<=16<<20, (name,info.file_size)
   observe(outer.read(info),name,group)
after=digest(archive);assert after==before
stats={}
for row in records:
 key=row['phase'];kind=row['kind'];group=stats.setdefault(key,{})
 subtotal=group.setdefault(kind,{'count':0,'wall_ns':0,'native_ns':0,'native_observed_count':0,'status_counts':{}})
 subtotal['count']+=1;subtotal['wall_ns']+=row['wall_ns']
 if row['native_ns'] is not None:subtotal['native_ns']+=row['native_ns'];subtotal['native_observed_count']+=1
 status=str(row['status'] if row['status'] is not None else row['returncode'])
 subtotal['status_counts'][status]=subtotal['status_counts'].get(status,0)+1
report={'schema':'hia.original-cold-invocation-cost.v1','scope':'Original immutable ZIP receipts and reference envelopes only; no rerun; native payload files not independently replayed. Wall-minus-native also includes IO/scheduling and is not pure CPython startup cost.',
 'original_archive':dict(request),'archive_before_and_after':{'bytes':before[0],'sha256':before[1],'equal':before==after},
 'phase_processes':phase_processes,'phase_checks':phase_checks,'reference_envelopes':references,'statistics':stats,
 'request_counts':[{'phase':p,'kind':k,'count':n} for (p,k),n in sorted(request_counts.items())],
 'nested_archives':nested,'receipt_observations':records}
dump(out/'analysis.json',report)
compact={'schema':'hia.original-cold-invocation-cost.compact.v1','original_archive':dict(request),'record_count':len(records),'nested_archive_count':len(nested),
 'phase_processes':phase_processes,'phase_checks':phase_checks,'reference_seconds':{k:round(v['wall_elapsed_ns']/1e9,6) for k,v in references.items()},'statistics':stats,
 'analysis_sha256':digest(out/'analysis.json')[1],'analysis_bytes':(out/'analysis.json').stat().st_size,'payload_members_independently_replayed':False}
dump(out/'compact.json',compact)
fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
simple=[]
for p,g in sorted(stats.items()):
 simple.append([p,round(phase_processes.get(p,{}).get('wall_elapsed_ns',0)/1e9,3),
  {k:[v['count'],round(v['wall_ns']/1e9,3),round(v['native_ns']/1e9,6)] for k,v in g.items() if k in ('flat-x86-64','linked-selfhost','seed-shared','specialized-allocator-child')}])
print(json.dumps({'status':'ORIGINAL_RECEIPTS_ANALYZED','directory':str(out),'compact_bytes':(out/'compact.json').stat().st_size,'compact_sha256':digest(out/'compact.json')[1],'receipt_count':len(records),'nested_archives':len(nested),'rows':simple},separators=(',',':')),flush=True)
