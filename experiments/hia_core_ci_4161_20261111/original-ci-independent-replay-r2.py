import hashlib,io,json,os,pathlib,re,resource,sys,time,zipfile
resource.setrlimit(resource.RLIMIT_AS,(768<<20,768<<20))
root=pathlib.Path.home()/'hia-native-closure-evidence'/'4161e8d12d87906fde144f039da07908ad52d98a'
out=root/'ci-independent-replay-r2';out.mkdir(mode=0o700)
items=[
 {'role':'pr','path':str(root/'ci-pr-original-terminal-r1/ci-pr-13841237929-original.zip'),'bytes':48222337,'sha256':'cc2bf5d85383bf9061c00f8d43dbabf2eb1031324c556c0efffd5127c180a4f7','checkout':'e0b22f1190121710c907ec96ef2c396b5cd12c06','cold_status':'FAIL','phase_count':34},
 {'role':'push','path':str(root/'ci-push-original-terminal-r1/ci-push-13843262654-original.zip'),'bytes':75726409,'sha256':'9e10eb09b41514abe57eea6c9b700f2f85d2350582a55e0c9a6a771822d0a1f9','checkout':'4161e8d12d87906fde144f039da07908ad52d98a','cold_status':'COLD_SELFHOST_REPLAY_PASS','phase_count':38}]
def write(path,raw):
 with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def dump(path,value):write(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())
def streamed(stream):
 h=hashlib.sha256();total=0
 for b in iter(lambda:stream.read(1<<20),b''):h.update(b);total+=len(b)
 return total,h.hexdigest()
def digest(path):
 with path.open('rb') as f:return streamed(f)
def json_member(z,name,maximum=32<<20):
 i=z.getinfo(name);assert i.file_size<=maximum,(name,i.file_size)
 raw=z.read(i);return json.loads(raw),hashlib.sha256(raw).hexdigest()
def top_level(z,name):
 # The original writer emits sorted indent=2 JSON. Read every byte while
 # retaining only exact two-space top-level objects and scalar identity fields.
 checksum=hashlib.sha256();count=0;values={};active=None;pieces=[];piece_bytes=0
 with z.open(name) as stream:
  for line in stream:
   checksum.update(line);count+=len(line)
   if active:
    if line in (b'  },\n',b'  }\n'):
     pieces.append(b'}');values[active]=json.loads(b''.join(pieces));active=None;pieces=[]
    else:
     piece_bytes+=len(line);assert piece_bytes<=2<<20;pieces.append(line)
    continue
   if line in (b'  "checks": {\n',b'  "source_manifest": {\n'):
    active='checks' if b'"checks"' in line else 'source_manifest'
    assert active not in values;pieces=[b'{\n'];piece_bytes=0
   else:
    match=re.fullmatch(rb'  "(schema|profile|status)": (.*?)(?:,)?\r?\n?',line)
    if match:
     key=match[1].decode();assert key not in values;values[key]=json.loads(match[2].rstrip(b','))
 assert active is None and count==z.getinfo(name).file_size
 return values,{'member':name,'bytes':count,'sha256':checksum.hexdigest(),'every_byte_read':True}
results=[]
try:
 for item in items:
  if item['role']!='push':continue
  p=pathlib.Path(item['path']);before=digest(p);assert before==(item['bytes'],item['sha256'])
  with zipfile.ZipFile(p) as outer:
   names=outer.namelist();assert len(names)==len(set(names))
   cold_names=[n for n in names if pathlib.PurePosixPath(n).name=='hia-cold.json'];assert len(cold_names)==1
   cold,cold_sha=json_member(outer,cold_names[0]);assert cold['status']==item['cold_status']
   prefix=cold_names[0][:-5]+'.cold/'
   pins=cold['source_manifest'];assert len(pins)==635
   canonical=hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest()
   assert canonical=='95debced0eaad1f94df524cca4d6e9dfd620617f0d44fdd4e3b9b4f09923da94'
   source_prefix=prefix+'source/';source_names={n[len(source_prefix):] for n in names if n.startswith(source_prefix) and not n.endswith('/')}
   assert source_names==set(pins)
   source_bytes=0
   for name,wanted in sorted(pins.items()):
    with outer.open(source_prefix+name) as stream:size,actual=streamed(stream)
    assert actual==wanted,name;source_bytes+=size
   assert cold['qualification_wall_limit_seconds']==180 and cold['cleanup_wall_limit_seconds']==3
   owner=cold['process_owner'];cleanup=owner['cleanup']
   assert cleanup['complete'] and cleanup['leader_reaped'] and cleanup['observed_echild']
   assert cleanup['remaining_direct_children']==[] and cleanup['errors']==[]
   assert owner['implementation_sha256']==pins['tools/hia_selfhost_process_owner.py']
   gen={}
   for label in ('B1','B2','B3','M1','M2','M3'):
    candidates=[n for n in names if n.startswith(prefix) and pathlib.PurePosixPath(n).name==label+'.receipt.json'];assert len(candidates)==1,(label,candidates)
    receipt,_=json_member(outer,candidates[0])
    binaries=[n for n in names if n.startswith(prefix) and pathlib.PurePosixPath(n).name==label+'.image.bin'];assert len(binaries)==1,(label,binaries)
    with outer.open(binaries[0]) as stream:size,actual=streamed(stream)
    assert receipt['produced_sha256']==actual and receipt['produced_bytes']==size
    gen[label]={'member':binaries[0],'bytes':size,'sha256':actual,'actual_bytes_independently_read':True}
   assert gen['B1']['sha256']==gen['B2']['sha256']==gen['B3']['sha256']
   assert gen['M1']['sha256']!=gen['M2']['sha256']==gen['M3']['sha256'] and gen['B3']['sha256']!=gen['M3']['sha256']
   indices=[n for n in names if n.startswith(prefix) and pathlib.PurePosixPath(n).name=='phase-index.json'];assert len(indices)==1
   index,_=json_member(outer,indices[0]);assert index['completed']==item['phase_count'] and index['exceptions']==0
   process={};phase={}
   for n in names:
    if not n.startswith(prefix):continue
    base=pathlib.PurePosixPath(n).name
    if re.fullmatch(r'phase-[a-z-]+-(original|modified)\.process\.json',base):
     value,_=json_member(outer,n);key=value['family']+'/'+value['compiler_label'];assert key not in process
     assert value['returncode']==0 and all(flag in value['command'] for flag in ('-I','-S','-B'));process[key]=value
    elif re.fullmatch(r'phase-[a-z-]+-(original|modified)\.json',base):
     value,sha=json_member(outer,n);key=value['family']+'/'+value['compiler_label'];assert key not in phase
     assert value['status']=='PASS' and value['checks'] and all(type(x) is bool and x for x in value['checks'].values())
     assert value['source_manifest_sha256']==canonical and value['fresh_host_oracle_process'] and not value['successor_process_reuse']
     assert value['python']=={'isolated':True,'no_site':True,'dont_write_bytecode':True}
     phase[key]={'sha256':sha,'check_count':len(value['checks']),'worker_pid':value['worker_pid']}
   assert len(process)==len(phase)==item['phase_count']
   archives=[];members=0;unpacked=0
   for n in names:
    if not n.startswith(prefix) or not n.endswith('.zip') or '/phase-runs/' not in n:continue
    match=re.search(r'/phase-runs/([a-z-]+)-(original|modified)\.zip$',n);assert match,n
    key=match[1]+'/'+match[2];assert key in process
    raw=outer.read(n);archive_sha=hashlib.sha256(raw).hexdigest();original=process[key]['raw_artifacts']
    assert original['archive_sha256']==archive_sha and original['packed_bytes']==len(raw)
    assert process[key]['report_sha256']==phase[key]['sha256'] and process[key]['worker_pid']==phase[key]['worker_pid']
    with zipfile.ZipFile(io.BytesIO(raw)) as inner:
     manifest,manifest_sha=json_member(inner,'HIA_ARCHIVE_MANIFEST.json')
     assert manifest_sha==original['manifest_sha256']
     files=manifest['files'];assert len(files)==original['files']
     assert len(inner.namelist())==len(set(inner.namelist())) and set(inner.namelist())==set(files)|{'HIA_ARCHIVE_MANIFEST.json'}
     total=0
     for member,row in files.items():
      path=pathlib.PurePosixPath(member);assert not path.is_absolute() and '..' not in path.parts
      info=inner.getinfo(member);assert info.file_size==row['bytes'] and info.file_size<=16<<20
      assert (info.external_attr>>16)&0o777==row['mode']
      with inner.open(info) as stream:size,actual=streamed(stream)
      assert size==row['bytes'] and actual==row['sha256'];total+=size
     assert total==manifest['unpacked_bytes']==original['unpacked_bytes'] and total<=512<<20
    archives.append({'phase':key,'member':n,'packed_bytes':len(raw),'sha256':archive_sha,'members':len(files),'unpacked_bytes':total,'all_member_bytes_sizes_modes_and_sha_verified':True})
    members+=len(files);unpacked+=total
   assert len(archives)==item['phase_count']
   nested=None
   if item['role']=='push':
    value,identity=top_level(outer,prefix+'qualification.json')
    assert identity['sha256']==cold['nested_report_sha256'] and value['status']=='SELF_HOSTED_FIXED_CORE_PASS'
    assert value['source_manifest']==pins and len(value['checks'])==5049 and all(type(v) is bool and v for v in value['checks'].values())
    assert all(cold['checks'].values()) and owner['status']=='OWNED_PROCESS_COMPLETED' and owner['exit_observed_before_deadline'] and not owner['timed_out']
    nested={'identity':identity,'checks_total':len(value['checks']),'checks_passed':sum(value['checks'].values()),'source_manifest_matches':True}
   else:
    assert owner['status']=='QUALIFICATION_TIMEOUT' and owner['timed_out'] and not owner['exit_observed_before_deadline']
   after=digest(p);assert after==before
   result={'role':item['role'],'head':'4161e8d12d87906fde144f039da07908ad52d98a','checkout':item['checkout'],'tree':'1c6ab0228f012429149997d1f731833739f433eb',
    'original_archive':item,'original_cold_status':cold['status'],'original_cold_wall_ns':cold['wall_elapsed_ns'],'cold_checks':cold['checks'],'cold_report_sha256':cold_sha,
    'source_manifest_count':len(pins),'source_bytes_independently_read':source_bytes,'source_manifest_sha256':canonical,
    'every_exported_source_byte_independently_read':True,'all_six_generation_images_independently_read':gen,
    'completed_phases':len(phase),'process_receipts_and_report_hashes_verified':True,'phase_checks':phase,
    'stage_archives':archives,'every_stage_member_actually_independently_read':True,'stage_payload_members':members,'stage_payload_bytes':unpacked,
    'uid_gid_in_archive_manifest':False,'uid_gid_scope':'ZIP manifest preserves byte length/hash/permission mode; original UID/GID is not serialized, so this replay cannot reconstruct or independently verify historical UID/GID.',
    'archive_bytes_sha_before_after_identical':True,'cleanup_complete':True,'nested_report':nested,
    'qualification_reexecuted':False,'original_failure_upgraded_to_pass':False}
   dump(out/(item['role']+'-audit.json'),result);results.append(result)
  print(json.dumps({'role':item['role'],'original_cold_status':result['original_cold_status'],'phase_archives':len(archives),'members':members,'unpacked_bytes':unpacked,'source_count':len(pins),'nested_checks':nested['checks_total'] if nested else None}),flush=True)
 report={'schema':'hia.416.original-ci-independent-replay.v1','status':'ORIGINAL_ARTIFACT_REPLAY_MATCHES_RETAINED_RESULTS','audit_source_scope':'Only original archived bytes; no compiler/test/qualification rerun','artifacts':results}
 dump(out/'audit.json',report)
 fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 print(json.dumps({'status':report['status'],'directory':str(out),'report_bytes':(out/'audit.json').stat().st_size,'report_sha256':digest(out/'audit.json')[1]}),flush=True)
except BaseException as error:
 dump(out/'FAILURE.json',{'error_type':type(error).__name__,'error':str(error),'completed_artifact_roles':[r['role'] for r in results],'original_artifacts_modified':False})
 raise
