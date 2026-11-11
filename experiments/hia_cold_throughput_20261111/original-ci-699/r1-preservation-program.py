import hashlib,json,os,pathlib,re,sys,time,urllib.request,zipfile
request=json.load(sys.stdin)
root=pathlib.Path.home()/'hia-native-closure-evidence'/'699451201f51fb4bdbd931568e64aa576143e807'
root.mkdir(mode=0o700,parents=True,exist_ok=True)
assert root.is_dir() and not root.is_symlink()
case=root/'ci-original-terminal-r1'
case.mkdir(mode=0o700)
def write(path, data):
    with path.open('xb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
def canonical(path, data):
    write(path,(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode())
def digest_file(path):
    h=hashlib.sha256();n=0
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b);n+=len(b)
    return n,h.hexdigest()
summaries=[]
for item in request['artifacts']:
    role=item['role'];archive=case/('ci-'+role+'-'+str(item['artifact_id'])+'-original.zip')
    started=time.monotonic_ns();h=hashlib.sha256();count=0
    with urllib.request.urlopen(item['url'],timeout=60) as response,archive.open('xb') as target:
        while True:
            data=response.read(1<<20)
            if not data:break
            target.write(data);h.update(data);count+=len(data)
        target.flush();os.fsync(target.fileno())
    assert count==item['bytes'] and h.hexdigest()==item['sha256'],(role,count,h.hexdigest())
    reread_count,reread_sha=digest_file(archive)
    assert (reread_count,reread_sha)==(count,item['sha256'])
    metadata=case/(role+'-metadata');metadata.mkdir(mode=0o700)
    entries=[];retained=[];cold=None;phase_index=None;processes=[];phases=[]
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            entries.append({'name':info.filename,'bytes':info.file_size,'compressed_bytes':info.compress_size,
                            'crc32':info.CRC,'external_attr':info.external_attr,'date_time':info.date_time})
            name=pathlib.PurePosixPath(info.filename).name
            wanted=(name in ('hia-cold.json','phase-index.json','stdout.log','stderr.log')
                    or re.fullmatch(r'phase-[^/]+\.json',name))
            if not wanted or info.file_size>2<<20:continue
            raw=z.read(info)
            path=metadata/(str(len(retained)).zfill(4)+'-'+name)
            write(path,raw)
            row={'member':info.filename,'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            retained.append(row)
            if name=='hia-cold.json':cold=json.loads(raw)
            elif name=='phase-index.json':phase_index=json.loads(raw)
            elif name.endswith('.process.json'):
                value=json.loads(raw)
                processes.append({k:value.get(k) for k in ('family','compiler_label','pid','returncode','wall_elapsed_ns','report_sha256')})
            elif re.fullmatch(r'phase-[^.]+\.json',name):
                value=json.loads(raw)
                phases.append({k:value.get(k) for k in ('family','compiler_label','status','elapsed_ns','worker_pid')})
    canonical(case/(role+'-members.json'),entries)
    assert cold is not None
    owner=cold.get('process_owner',{})
    summary={'role':role,'artifact_id':item['artifact_id'],'workflow_run_id':item['workflow_run_id'],
      'reported_head':item['head'],'checkout':item['checkout'],'path':str(archive),'bytes':count,
      'sha256':reread_sha,'download_and_independent_reread_verified':True,
      'download_elapsed_ns':time.monotonic_ns()-started,'outer_zip_members':len(entries),
      'metadata_members':retained,'phase_index':phase_index,'phase_processes':processes,'phase_reports':phases,
      'cold':{k:v for k,v in cold.items() if k!='source_manifest'},
      'source_manifest_count':len(cold.get('source_manifest',{})),
      'source_manifest_sha256':hashlib.sha256(json.dumps(cold.get('source_manifest',{}),sort_keys=True,separators=(',',':')).encode()).hexdigest(),
      'payload_archives_replayed':False}
    canonical(case/(role+'-receipt.json'),summary)
    summaries.append(summary)
    print(json.dumps({k:summary[k] for k in ('role','artifact_id','path','bytes','sha256','source_manifest_count','source_manifest_sha256')},sort_keys=True),flush=True)
    print(json.dumps({'role':role,'cold_status':cold.get('status'),'checks':cold.get('checks'),
      'wall_elapsed_ns':cold.get('wall_elapsed_ns'),'owner':owner,'phase_index':phase_index,
      'phase_processes':processes,'phase_reports':phases},sort_keys=True),flush=True)
canonical(case/'PRESERVATION.json',{'schema':'hia.699.ci-original-preservation.v1','artifacts':[
    {k:s[k] for k in ('role','artifact_id','reported_head','checkout','path','bytes','sha256','source_manifest_count','source_manifest_sha256')}
    for s in summaries],'payload_archives_replayed':False})
fd=os.open(case,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'status':'ORIGINALS_PRESERVED_AND_METADATA_READ','directory':str(case)}),flush=True)
