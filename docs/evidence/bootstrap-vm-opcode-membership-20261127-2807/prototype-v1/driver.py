from pathlib import Path
import sys,os,json,time,hashlib,stat,shutil,subprocess,traceback
spec=json.load(sys.stdin)
base=Path('/home/qian-qi/hia-bootstrap-throw-frame-20261127-2807/src')
scope=Path('/home/qian-qi/hia-bootstrap-opcode-membership-20261127-2807')
root=scope/'src';out=scope/'controls-and-packet-screen-v1'
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def check(root,pins):
 result={}
 for name,expected in pins.items():
  result[name]=pin((root/name).read_bytes())
  assert result[name]=={k:expected[k] for k in ('bytes','sha256')},name
 return result
check(base,spec['previous_pins']);check(base,spec['extra_pins'])
payload={}
for name,value in spec['files'].items():
 raw=Path(value['path']).read_bytes();assert pin(raw)==value['pin'],name;payload[name]=raw
packets_raw=Path(spec['packets']).read_bytes();assert pin(packets_raw)==spec['packet_pin']
files=[];bytes_total=0
for path in base.rglob('*'):
 if '__pycache__' in path.parts:continue
 mode=path.lstat().st_mode
 assert stat.S_ISDIR(mode) or stat.S_ISREG(mode),str(path)
 if stat.S_ISREG(mode):
  bytes_total+=path.stat().st_size;files.append(path)
assert bytes_total<90_000_000,bytes_total
scope.mkdir(mode=0o700);root.mkdir(mode=0o700);out.mkdir(mode=0o700)
for path in files:
 destination=root/path.relative_to(base);destination.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(path,destination);destination.chmod(stat.S_IMODE(path.stat().st_mode))
check(root,spec['previous_pins']);check(root,spec['extra_pins'])
for name,raw in payload.items():(root/name).write_bytes(raw)
(out/'invocation.json').write_text(json.dumps(spec,sort_keys=True)+'\n')
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
if os.getpriority(os.PRIO_PROCESS,0)<10:os.setpriority(os.PRIO_PROCESS,0,10)
os.chdir(root);sys.path.insert(0,str(root))
before=check(root,spec['candidate_pins'])
extra={name:pin((root/name).read_bytes()) for name in spec['extra_pins']}
record={'schema':'hepta.hia.bootstrap-opcode-membership-source-controls.v1',
 'parent_commit':spec['parent_commit'],'source_before':before,'extra_before':extra,
 'copied_source_bytes':bytes_total,'copied_source_files':len(files),'packet_pin':spec['packet_pin'],
 'source8_qualified':False,'whole_native_stack_qualified':False,'rows':[]}
try:
 commands=[
 ['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py','tests.test_hia_program',
  'tests.test_hia_program_runtime_prepared.PreparedRuntimeSourceTests',
  'tests.test_hia_program_runtime_arithmetic.ArithmeticPreparedRuntimeSourceTests',
  'tests.test_hia_program_runtime_opcode_membership.OpcodeMembershipSourceTests'],
 spec['bootstrap_command']]
 for ordinal,command in enumerate(commands):
  start=time.perf_counter()
  with (out/('controls-'+str(ordinal)+'.stdout')).open('wb') as stdout,(out/('controls-'+str(ordinal)+'.stderr')).open('wb') as stderr:
   result=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,timeout=600)
  row={'command':command,'returncode':result.returncode,'seconds':time.perf_counter()-start,
   'stdout':pin((out/('controls-'+str(ordinal)+'.stdout')).read_bytes()),
   'stderr':pin((out/('controls-'+str(ordinal)+'.stderr')).read_bytes())}
  record.setdefault('controls',[]).append(row);print(json.dumps({'event':'control-terminal','ordinal':ordinal,**row},sort_keys=True),flush=True)
  assert result.returncode==0,'all unchanged and new controls must pass'
 from hepta.hia_agent_assembly import assemble_program
 from hepta import hia_program_runtime as runtime
 from hepta.hia_program_runtime_prepared import prepare_runtime_program
 from hepta import hia_service_bootstrap_native as native
 from tests.test_hia_program_runtime_opcode_membership import previous_machine
 from tests import hia_service_bootstrap_support as support
 assert support.source_snapshot()==before
 reference=previous_machine()
 program=prepare_runtime_program(assemble_program(native.SOURCE.read_bytes()))
 prepared=[(bytes.fromhex(row['source']),bytes.fromhex(row['output_before']),bytes.fromhex(row['state_before']),
            row['returned'],bytes.fromhex(row['output_after']),bytes.fromhex(row['state_after'])) for row in json.loads(packets_raw)]
 fields=('steps','allocations','frees','allocation_attempts','live_bytes','peak_bytes','owner_count','drops','loans_started','loans_ended')
 expected_counters={}
 for ordinal,variant in enumerate(('previous','candidate','candidate','previous')):
  make=reference if variant=='previous' else runtime._Machine
  start=time.perf_counter();cpu=time.process_time();calls=0;digest=hashlib.sha256()
  for repeat in range(100):
   for index,(source,old_output,old_state,returned,output,state) in enumerate(prepared):
    owners=[runtime._Owner(i+1,bytearray(raw)) for i,raw in enumerate((source,old_output,old_state))]
    machine=make(program,4_000_000,16<<20,None,128)
    actual=machine.invoke(machine.functions['f0'],[runtime._View(owner,i!=0) for i,owner in enumerate(owners)])[0]
    assert actual==returned and bytes(owners[0].data)==source and bytes(owners[1].data)==output and bytes(owners[2].data)==state
    values=tuple(getattr(machine,name) for name in fields)
    if index not in expected_counters:expected_counters[index]=values
    assert values==expected_counters[index],(variant,index,values,expected_counters[index])
    digest.update(repr(values).encode());calls+=1
  row={'ordinal':ordinal,'variant':variant,'calls':calls,'cpu_seconds':time.process_time()-cpu,
   'wall_seconds':time.perf_counter()-start,'counter_signature':digest.hexdigest()}
  record['rows'].append(row);print(json.dumps({'event':'actual-packet-screen-row',**row},sort_keys=True),flush=True)
 record.update(status='SOURCE_CONTROLS_AND_EQUAL_PACKET_STATE_ONLY',packet_count=len(prepared),
  counter_fields=fields,expected_packet_counters=expected_counters)
except BaseException as error:
 record.update(status='HOLD',error={'type':type(error).__name__,'message':str(error)});traceback.print_exc()
finally:
 record['source_after']=check(root,spec['candidate_pins']);assert record['source_after']==before
 record['extra_after']={name:pin((root/name).read_bytes()) for name in spec['extra_pins']}
 assert record['extra_after']==extra
 check(base,spec['previous_pins']);check(base,spec['extra_pins'])
 (out/'observation.json').write_text(json.dumps(record,sort_keys=True)+'\n')
 print(json.dumps({'event':'opcode-membership-terminal','status':record['status'],
  'report':pin((out/'observation.json').read_bytes()),'error':record.get('error')},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='SOURCE_CONTROLS_AND_EQUAL_PACKET_STATE_ONLY' else 1)
