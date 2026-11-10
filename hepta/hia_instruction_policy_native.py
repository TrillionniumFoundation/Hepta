"""Explicit native local instruction policy, not a whole Core verifier.

Host code transports exact values in a typed length-delimited tree. It does not
look up signatures, classify literals, decide versions, attributes or effects.
"""
import ctypes
import os
from pathlib import Path
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/instruction_policy.hiaasm'
SCHEMA='hepta.hia.instruction-policy-native.v1'
SELECTOR='HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST'
ERROR_CODES={0xfffffffb:'E_HIA_FORMAT',0xfffffff9:'E_HIA_TYPE',0xfffffff8:'E_HIA_LOAN',
             0xfffffff0:'E_HIA_OPCODE',0xfffffffe:'E_HIA_LIMIT'}
SCRATCH_BYTES=128+129*24


def transport(value):
    """Lossless exact-kind transport; tags are representation, not admission."""
    typ=type(value)
    if value is None:tag,payload=0,b''
    elif typ is bool:tag,payload=1,bytes([int(value)])
    elif typ is int:tag,payload=2,str(value).encode('ascii')
    elif typ is float:tag,payload=3,repr(value).encode('ascii')
    elif typ is str:tag,payload=4,value.encode('utf-8',errors='surrogatepass')
    elif typ in (list,tuple):
        tag,payload=5,struct.pack('<Q',len(value))+b''.join(transport(v) for v in value)
    elif typ is dict:
        tag,payload=6,struct.pack('<Q',len(value))+b''.join(transport(k)+transport(v) for k,v in value.items())
    else:tag,payload=7,b''
    return struct.pack('<QQ',tag,len(payload))+payload


def packet(name,schema,operands,results,attributes):
    return transport([schema,name,operands,results,attributes])


class NativeInstructionPolicy(NativeHiaJsonImage):
    def status(self,wire):
        if type(wire) is not bytes:raise TypeError('exact typed packet bytes required')
        if len(wire)>33554432:return 0xfffffffe
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(128)
        scratch=ctypes.create_string_buffer(SCRATCH_BYTES)
        result=self._entry(source,len(wire),output,128,scratch,SCRATCH_BYTES)
        if result not in {*range(16),0xfffffffd,*ERROR_CODES}:raise RuntimeError('invalid native instruction result')
        return result

    def check(self,name,schema,operands,results,attributes):
        from .hia_opcodes import OpcodeRejected
        result=self.status(packet(name,schema,operands,results,attributes))
        if result==0xfffffffd:raise RuntimeError('native instruction scratch/ABI refusal')
        if result in ERROR_CODES:raise OpcodeRejected('native instruction policy rejected '+str(name),ERROR_CODES[result])
        return frozenset(effect for i,effect in enumerate(('alloc','read','write','trap')) if result&(1<<i))


def installed_instruction_policy(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeInstructionPolicy)


def selected_instruction_policy(name,schema,operands,results,attributes):
    path=os.environ.get(SELECTOR)
    if not path:return None
    return installed_instruction_policy(path).check(name,schema,operands,results,attributes)
