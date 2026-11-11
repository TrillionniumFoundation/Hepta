"""Observe ordinary native-wire overhead without changing its policies or clocks."""
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time
from unittest.mock import patch

parser=argparse.ArgumentParser()
parser.add_argument('--source-root',required=True,type=Path)
parser.add_argument('--manifest',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--calls',type=int,default=32)
args=parser.parse_args()
if args.output.exists():raise FileExistsError(args.output)
sys.path.insert(0,str(args.source_root))
from hepta.hia_json_wire_native import installed_json_wire,WireSession,MAXIMUM,SELECTOR,buffer_sizes
from hepta.hia_program_tools import bounded_json_wire
image=installed_json_wire(str(args.manifest))
counts=Counter()
original_step=WireSession.step

def step(session,packet=None):
 status=original_step(session,packet)
 counts[str(status)]+=1
 return status

def forbidden(*args,**kwargs):raise AssertionError('retained encoder entered benchmark')

value={'z':[None,True,False,0,123], 'a':'雪'}
expected=b'{"a":"\xe9\x9b\xaa","z":[null,true,false,0,123]}'
usage_before=resource.getrusage(resource.RUSAGE_SELF)
started=time.perf_counter_ns();cpu_started=time.process_time_ns()
with patch.dict(os.environ,{SELECTOR:str(args.manifest)}),patch('hepta.hia_program_tools._reference_bounded_json_wire',forbidden),patch('json.JSONEncoder.iterencode',forbidden),patch.object(WireSession,'step',step):
 for _ in range(args.calls):
  actual=bounded_json_wire(value,MAXIMUM,ensure_ascii=False,sort_keys=True)
  assert actual==expected,actual
cpu=time.process_time_ns()-cpu_started;elapsed=time.perf_counter_ns()-started
usage_after=resource.getrusage(resource.RUSAGE_SELF)
report={'schema':'hepta.hia.json-wire-allocation-observation.v1','scope':'DEVELOPMENT_MECHANICAL_OVERHEAD_OBSERVATION_NOT_QUALIFICATION','python':sys.version,'executable':sys.executable,'platform':platform.platform(),'manifest_path':str(args.manifest),'manifest':json.loads(args.manifest.read_bytes()),'calls':args.calls,'maximum':MAXIMUM,'declared_buffer_sizes':buffer_sizes(MAXIMUM),'output_hex':expected.hex(),'native_return_counts':dict(counts),'wall_ns':elapsed,'process_cpu_ns':cpu,'maxrss_before_KiB':usage_before.ru_maxrss,'maxrss_after_KiB':usage_after.ru_maxrss,'source_sha256':{name:sha256((args.source_root/name).read_bytes()).hexdigest() for name in ('hepta/hia_json_wire_native.py','hepta/hia_program_tools.py','examples/hia_bootstrap/json_wire.hiaasm')},'retained_owner_and_encoder_forbidden':True,'timing_threshold_asserted':False}
args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
