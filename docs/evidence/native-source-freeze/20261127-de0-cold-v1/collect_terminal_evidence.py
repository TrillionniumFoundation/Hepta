from pathlib import Path
from hashlib import sha256
from datetime import datetime,timezone
import gzip,io,json,os,re,stat,struct,subprocess,tarfile
root=Path('/home/qian-qi/hia-native-unified-de0-20261127-2ac5')
out=root/'terminal-evidence-v1';out.mkdir(mode=0o700,exist_ok=False)
def pin(raw):return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
def file_pin(p):
 h=sha256();n=0
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b);n+=len(b)
 return {'bytes':n,'sha256':h.hexdigest()}
campaign=json.loads((root/'native-chain-campaign.json').read_bytes())
assert campaign['passed'] is False and campaign['head']=='de0c0325ef1ece788666695638b6bebbdc329eda'
assert [x['returncode'] for x in campaign['commands']]==[0,0,1]
chain=json.loads((root/'native-chain-v1/qualification.json').read_bytes())
assert chain['passed'] is False and len(chain['commands'])==1 and chain['commands'][0]['observed_entry_process_terminal'] is True
source_pins=json.loads((root/'preparation/after-source-pins.json').read_bytes())
for name,wanted in source_pins.items():assert file_pin(root/'source'/name)==wanted,name
assert subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=root/'source',text=True).strip()==campaign['head']
owner=(root/'cold-data-v1/cold/process-owner.receipt').read_bytes();w=struct.unpack_from('<32Q',owner)
assert owner[:8]==b'HIACOR01' and w[6:8]==(180,3000000000) and w[9:11]==(124,1)
assert w[12:16]==(1,1,0,0) and w[17]==w[21]==w[24]==0 and w[22]==1
assert len(owner)==256+w[16]*40+w[18]*48 and w[19]<=w[23]<=w[20]
custody={}
for p in sorted((root/'cold-data-v1/cold/qualification').rglob('*')):
 if p.is_file():
  assert not p.is_symlink() and p.stat().st_nlink==1
  custody[str(p.relative_to(root))]={**file_pin(p),'mode':stat.S_IMODE(p.stat().st_mode),'mtime_ns':p.stat().st_mtime_ns,'inode':p.stat().st_ino}
trace=(root/'cold-data-v1/evidence/full-cold.exec.trace').read_text()
execs=[line for line in trace.splitlines() if re.search(r'(?:^|\s)execve\(',line)]
assert len(execs)==1 and '/toolchain/hia-cold' in execs[0]
assert all('execveat(' not in x or 'AT_EMPTY_PATH' in x or '<unfinished ...>' in x for x in trace.splitlines())
resources=[json.loads(line) for line in (root/'cold-data-v1/evidence/full-cold.resources.jsonl').read_text().splitlines()]
counter_rows=[x for x in resources if 'child_cgroup_counters' in x and 'cpu.max' in x['child_cgroup_counters']]
report={'schema':'hepta.hia.exact-native-cold-failure-custody.v1','source_head':campaign['head'],'passed':False,'source_pins_preserved':True,'observed_utc':datetime.now(timezone.utc).isoformat(),'pre7_passed':True,'source_export_passed':True,'full_cold_passed':False,'post_release_install_rebuild_started':False,'owner_receipt':pin(owner),'owner_header_words':list(w),'native_timeout':True,'leader_exit':124,'native_nested_ns':w[19]-w[4],'native_cleanup_ns':w[23]-w[19],'cleanup_bounded_and_no_remaining_identities':True,'native_exec_trace_readback':{'execve':len(execs),'execveat_lines':trace.count('execveat('),'all_child_execs_descriptor_bound':True,'original_failed_report_modified':False},'resource_samples':len(resources),'samples_with_cgroup_cpu_counters':len(counter_rows),'cpu_max_values':sorted({x['child_cgroup_counters']['cpu.max'].strip() for x in counter_rows}),'nonempty_archives':sorted(n for n,v in custody.items() if n.endswith('.hiaqar') and v['bytes']),'physical_evidence_files':custody,'physical_evidence_total_bytes':sum(v['bytes'] for v in custody.values())}
(out/'custody.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
names=['native-chain-campaign.json','prelaunch-model-match-v1.json','source-materialization.json','transport-recovery.json','public-build-v1/qualification.json','public-build-v1/toolchain/build.receipt','public-build-v1/toolchain/process-owner.receipt','native-export-v1/qualification.json','native-chain-v1/qualification.json','cold-data-v1/cold/process-owner.receipt','cold-data-v1/evidence/full-cold.exec.trace','cold-data-v1/evidence/full-cold.resources.jsonl','cold-data-v1/evidence/full-cold.stdout','cold-data-v1/evidence/full-cold.stderr','drivers/run_native_campaign_v2.py']
for label in ('public-seven-stage','physical-native-source-export','full-native-chain'):
 for suffix in ('stdout','stderr'):names.append(label+'.'+suffix)
files={name:(root/name).read_bytes() for name in names}
files['terminal-evidence-v1/custody.json']=(out/'custody.json').read_bytes()
files['MANIFEST.json']=(json.dumps({name:pin(raw) for name,raw in sorted(files.items())},indent=2,sort_keys=True)+'\n').encode()
buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as t:
 for name,raw in sorted(files.items()):
  info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o400;info.mtime=0;t.addfile(info,io.BytesIO(raw))
archive=gzip.compress(buffer.getvalue(),mtime=0);target=out/'native-de0-cold-failure.tar.gz';target.write_bytes(archive);target.chmod(0o400)
summary={'report':str(out/'custody.json'),'report_pin':file_pin(out/'custody.json'),'archive':str(target),'archive_pin':pin(archive),'archive_members':len(files),'nonempty_archives':len(report['nonempty_archives']),'physical_files':len(custody),'physical_bytes':report['physical_evidence_total_bytes'],'native_nested_ns':report['native_nested_ns'],'native_cleanup_ns':report['native_cleanup_ns'],'trace':file_pin(root/'cold-data-v1/evidence/full-cold.exec.trace'),'resources':file_pin(root/'cold-data-v1/evidence/full-cold.resources.jsonl')}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('DE0_FAILED_COLD_EVIDENCE_RETAINED',json.dumps(summary),flush=True)
print('TRACE_EXEC_SAMPLE',json.dumps([line for line in trace.splitlines() if 'execveat(' in line][:5]),flush=True)
print('TRACE_SIGNAL_SAMPLE',json.dumps([line for line in trace.splitlines() if 'SIGCHLD' in line][:3]),flush=True)
