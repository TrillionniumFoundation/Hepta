import ctypes
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0, '/workspace/scratch/372e7da9bde9/bootstrap')
from hepta.hia_program import verify_program, execute_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_machine_plan import register_assignment_witness
from tools.qualify_hia_machine_registers import _function, _block, _const, _op, _ret, explicit_plan
p=verify_program({'schema':'hepta.hia.program.v1','module':'snapshot_review','functions':[
 _function('plus7',[('x','u64')],['u64'],[_block('entry',[('x','u64')],[
  _const('seven','u64',7),_op('int.add.wrap',['x','seven'],[('answer','u64')])],_ret('answer'))])]})
hooks=[]
class Hash(str):
 def __deepcopy__(self,memo):
  hooks.append('copy')
  bad['value_registers']['plus7']['x']='rax'
  return str(self)
bad=explicit_plan(p,{'plus7':{'x':'r12','seven':'r13','answer':'r14'}})
bad['core_sha256']=Hash(p.sha256)
try:
 emit_program_machine(p,machine_plan=bad)
 raise AssertionError('hook-bearing plan accepted')
except ValueError as error:
 refusal=str(error)
plan=explicit_plan(p,{'plus7':{'x':'r12','seven':'r13','answer':'r14'}})
retained=json.loads(json.dumps(plan))
def check_then_mutate(checked,assignments):
 witness=register_assignment_witness(checked,assignments)
 plan['value_registers']['plus7']['x']='rax'
 return witness
with patch('hepta.hia_machine_plan.register_assignment_witness',side_effect=check_then_mutate):
 image=emit_program_machine(p,machine_plan=plan)
with tempfile.TemporaryDirectory(prefix='snapshot-fixed-') as directory:
 output=Path(directory)/'fixed.so'
 compile_program_machine(image,program=p,output=output,linker='ld',machine_plan=retained)
 library=ctypes.CDLL(str(output));f=library.plus7
 f.argtypes=[ctypes.c_uint64];f.restype=ctypes.c_uint64
 result={'malicious_plan_rejected':refusal,'user_hooks_called':hooks,
  'caller_mapping_after_validation':plan['value_registers']['plus7']['x'],
  'validated_mapping':retained['value_registers']['plus7']['x'],
  'expected':execute_program(p,'plus7',[10])['result'],'actual':f(10),
  'object_matches_unmutated_plan':image.object_bytes==emit_program_machine(p,machine_plan=retained).object_bytes}
 print(json.dumps(result,sort_keys=True))
 Path('/tmp/hia-p3-snapshot-fixed-result.json').write_text(json.dumps(result,indent=2)+'\n')
