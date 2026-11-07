import ctypes
import json
from pathlib import Path
import sys
sys.path.insert(0, '/workspace/scratch/372e7da9bde9/Hepta')
from hepta.hia_program import verify_program, execute_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_machine_plan import validate_plan
from tools.qualify_hia_machine_registers import _function, _block, _const, _op, _ret, explicit_plan
p=verify_program({'schema':'hepta.hia.program.v1','module':'snapshot_review','functions':[
 _function('plus7',[('x','u64')],['u64'],[_block('entry',[('x','u64')],[
  _const('seven','u64',7),_op('int.add.wrap',['x','seven'],[('answer','u64')])],_ret('answer'))])]})
class Hash(str):
 def __deepcopy__(self, memo):
  self.plan['value_registers']['plus7']['x']='rax'
  return str(self)
def plan():
 value=explicit_plan(p, {'plus7': {'x':'r12','seven':'r13','answer':'r14'}})
 field=Hash(p.sha256);field.plan=value;value['core_sha256']=field
 return value
frozen=validate_plan(p,plan())
print('frozen_value_registers',frozen['value_registers'])
im=emit_program_machine(p,machine_plan=plan())
output=Path('/tmp/hia-p3-adversarial-review/snapshot.so')
compile_program_machine(im,program=p,output=output,linker='ld',machine_plan=plan())
f=ctypes.CDLL(str(output)).plus7;f.argtypes=[ctypes.c_uint64];f.restype=ctypes.c_uint64
print(json.dumps({'expected':execute_program(p,'plus7',[10])['result'],'actual':f(10),'emitted_sha256':im.sha256}))
