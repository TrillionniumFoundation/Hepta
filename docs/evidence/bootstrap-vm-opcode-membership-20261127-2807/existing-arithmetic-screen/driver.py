from pathlib import Path
import sys,os,json,time,hashlib,ctypes,traceback,subprocess
spec=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-throw-frame-20261127-2807/src')
out=Path('/home/qian-qi/hia-bootstrap-throw-frame-20261127-2807/vm-strict-arithmetic-screen-v1')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def checked():
 actual={}
 for name,expected in spec['source_pins'].items():
  actual[name]=pin((root/name).read_bytes())
  assert actual[name]==expected,name
 for name,expected in spec['extra_pins'].items():
  actual[name]=pin((root/name).read_bytes())
  assert actual[name]=={k:expected[k] for k in ('bytes','sha256')},name
 return actual
before=checked()
packet_raw=Path(spec['packets']).read_bytes();assert pin(packet_raw)==spec['packet_pin']
out.mkdir(mode=0o700)
(out/'invocation.json').write_text(json.dumps(spec,sort_keys=True)+'\n')
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
if os.getpriority(os.PRIO_PROCESS,0)<10:os.setpriority(os.PRIO_PROCESS,0,10)
os.chdir(root);sys.path.insert(0,str(root))
record={'schema':'hepta.hia.bootstrap-vm-strict-arithmetic-actual-packet-screen.v1',
 'source_commit':spec['source_commit'],'source_before':before,'packet_pin':spec['packet_pin'],
 'product_source_modified':False,'source8_qualified':False,'whole_native_stack_qualified':False}
rows=[]
try:
 command=['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py',
  'tests.test_hia_program',
  'tests.test_hia_program_runtime_prepared.PreparedRuntimeSourceTests',
  'tests.test_hia_program_runtime_arithmetic.ArithmeticPreparedRuntimeSourceTests']
 start=time.perf_counter()
 with (out/'original-controls.stdout').open('wb') as stdout,(out/'original-controls.stderr').open('wb') as stderr:
  result=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,timeout=600)
 record['original_controls']={'command':command,'returncode':result.returncode,'seconds':time.perf_counter()-start,
  'stdout':pin((out/'original-controls.stdout').read_bytes()),'stderr':pin((out/'original-controls.stderr').read_bytes())}
 print(json.dumps({'event':'original-control-terminal',**record['original_controls']},sort_keys=True),flush=True)
 assert result.returncode==0,'unchanged interpreter gates must succeed before actual packet screen'
 from hepta.hia_agent_assembly import assemble_program
 from hepta import hia_program_runtime as runtime
 from hepta.hia_program_runtime_prepared import prepare_runtime_program
 from hepta.hia_program_runtime_arithmetic import prepare_arithmetic_runtime,_PreparedMachine
 from hepta import hia_service_bootstrap_native as native
 verified=assemble_program(native.SOURCE.read_bytes())
 ordinary_program=prepare_runtime_program(verified)
 optimized_program,factory=prepare_arithmetic_runtime(verified)
 assert factory is not runtime._Machine,'strict arithmetic preparation must actually activate'
 packets=json.loads(packet_raw)
 prepared=[(bytes.fromhex(row['source']),bytes.fromhex(row['output_before']),bytes.fromhex(row['state_before']),
            row['returned'],bytes.fromhex(row['output_after']),bytes.fromhex(row['state_after'])) for row in packets]
 fields=('steps','allocations','frees','allocation_attempts','live_bytes','peak_bytes','owner_count','drops','loans_started','loans_ended')
 expected_counters={}
 for ordinal,variant in enumerate(('old','strict','strict','old')):
  program,make=(ordinary_program,runtime._Machine) if variant=='old' else (optimized_program,factory)
  started=time.perf_counter();cpu=time.process_time();calls=0;active=0
  counters_digest=hashlib.sha256()
  for repeat in range(100):
   for index,(source,old_output,old_state,returned,output,state) in enumerate(prepared):
    owners=[runtime._Owner(i+1,bytearray(data)) for i,data in enumerate((source,old_output,old_state))]
    machine=make(program,4_000_000,16<<20,None,128)
    if variant=='strict':
     assert type(machine) is _PreparedMachine and machine._arithmetic_active
     active+=1
    actual=machine.invoke(machine.functions['f0'],[runtime._View(owner,i!=0) for i,owner in enumerate(owners)])[0]
    assert actual==returned and bytes(owners[0].data)==source and bytes(owners[1].data)==output and bytes(owners[2].data)==state
    values=tuple(getattr(machine,name) for name in fields)
    if index not in expected_counters:expected_counters[index]=values
    assert values==expected_counters[index],(variant,index,values,expected_counters[index])
    counters_digest.update(repr(values).encode());calls+=1
  row={'ordinal':ordinal,'variant':variant,'calls':calls,'prepared_active_calls':active,
       'wall_seconds':time.perf_counter()-started,'cpu_seconds':time.process_time()-cpu,
       'counter_signature':counters_digest.hexdigest()}
  rows.append(row);print(json.dumps({'event':'actual-packet-screen-row',**row},sort_keys=True),flush=True)
 record.update(status='DIAGNOSTIC_EQUAL_PACKET_STATE_AND_COUNTERS_ONLY',packet_count=len(prepared),
  counter_fields=fields,expected_packet_counters=expected_counters)
except BaseException as error:
 record['status']='HOLD';record['error']={'type':type(error).__name__,'message':str(error)};traceback.print_exc()
finally:
 record['rows']=rows
 after=checked();assert before==after;record['source_after']=after
 (out/'observation.json').write_text(json.dumps(record,sort_keys=True)+'\n')
 print(json.dumps({'event':'actual-packet-screen-terminal','status':record['status'],
  'report':pin((out/'observation.json').read_bytes()),'error':record.get('error')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('DIAGNOSTIC_EQUAL') else 1)
