"""Primitive object observations requested by HIA instruction control.

HIA owns operand decisions and instruction scheduling. Actual Python object
values and foreign effects remain explicit primitive runtime boundaries.
"""
from __future__ import annotations
from collections import Counter
from functools import lru_cache
import struct
import sys
from .hia_machine_state_native import MachineStateSession
from .hia_machine_transport import _code_call_names
from .hia_exception_delivery import ExceptionDelivery
from .hia_machine_encoding_native import COMMANDS
from .hia_json_preflight_native import NativeHiaJsonImage,_installed_json_image,_source_resource_path
SOURCE=_source_resource_path('examples/hia_bootstrap/machine_instructions.hepta')
SCHEMA='hepta.hia.machine-instructions-native.v1'
SELECTOR='HEPTA_HIA_MACHINE_INSTRUCTIONS_MANIFEST'
MAGIC=int.from_bytes(b'HIACIN01','little')
MODES=('align','mov_rr','mov_imm','load','store','lea','load_u8','store_u8',
'add','sub','and_','or_','xor','cmp','test','alu_imm','shift','shift_imm',
'shift_cl','shl','shr','sar','imul','imul_rr','mul','imul_full','div','idiv',
'neg','bitnot','cqo','setcc','cmov','push','pop','ret','leave','ud2','jmp','jcc','call')
_LITERAL_BYTES = {}

class MachineInstructionSession(MachineStateSession):
    def __init__(self,image,receiver,mode,*arguments):
        if type(mode) is not int or not 1 <= mode <= len(MODES):
            raise ValueError('invalid native Code instruction')
        super().__init__(image,receiver,1,*arguments)
        self.mode=mode
        words=list(struct.unpack('<10Q',self.packet))
        words[0],words[3]=MAGIC,mode
        self.packet=struct.pack('<10Q',*words)
        self._prepared_packet=self.packet
    def _observe(self):
        opcode,sequence=struct.unpack_from('<2Q',self._frame,8)
        if opcode <= 35:
            packet=super()._observe()
            return struct.pack('<Q',MAGIC)+packet[8:]
        a,b,c,d=struct.unpack_from('<4Q',self._frame,512)
        value,register=self.value,self.register
        self.image.observations[opcode]+=1
        x=0
        if opcode == 36:
            x=register(value(a)==value(b))
        elif opcode == 37:
            x=int(bool(value(a)))
        elif opcode == 38:
            x=register(value(a)(value(b),value(c),value(d)))
        elif opcode == 39:
            struct.pack('<b',value(a))
            raise RuntimeError('native signed-byte refusal unexpectedly admitted')
        elif opcode == 40:
            x=ord(value(a)[b])
        elif opcode == 41:
            x=register(a-(1<<64) if a & (1<<63) else a)
        elif opcode == 42:
            command,r,m,number,auxiliary,mode,offset=struct.unpack_from('<7Q',self._frame,576)
            if not 1 <= command <= len(COMMANDS):
                raise RuntimeError('native instruction requested an unknown byte command')
            x=register(self.receiver._bytes(COMMANDS[command-1],
                r=value(r) if r else 0,m=value(m) if m else 0,
                value=value(number) if number else 0,auxiliary=auxiliary,
                mode=mode,offset=offset))
        elif opcode == 43:
            if a not in (0,1):
                raise RuntimeError('native instruction requested a nonboolean literal')
            x=register(bool(a))
        elif opcode == 44:
            # HIA selects an opaque module-constant slot. The bridge keeps
            # that slot's actual bytes object, as CPython keeps co_consts;
            # it neither chooses constant instructions nor supplies bytes.
            raw=value(a)
            if type(raw) is not bytes:
                raise RuntimeError('native Code literal is not exact bytes')
            previous=_LITERAL_BYTES.setdefault(b,raw)
            if previous != raw:
                raise RuntimeError('native Code literal identity changed its bytes')
            x=register(previous)
        else:
            raise RuntimeError('unknown native Code instruction observation')
        return struct.pack('<10Q',MAGIC,opcode,sequence,0,x,0,0,0,0,0)

class NativeMachineInstructions(NativeHiaJsonImage):
    def __init__(self,image,expected_sha256):
        super().__init__(image,expected_sha256)
        self.calls=Counter();self.transitions=Counter();self.observations=Counter()
        self._exception_delivery=ExceptionDelivery.from_hia(self)
    def run(self,receiver,mode,*arguments):
        session=MachineInstructionSession(self,receiver,mode,*arguments)
        try:
            self.calls[MODES[mode-1]]+=1
            status=session.step()
            while status==1:
                session.observe();status=session.step()
            if status != 0:
                raise RuntimeError('native Code instruction continuation refused: '+hex(status))
            return session.result()
        finally:
            session.close(release=sys.exc_info()[0] is None)

@lru_cache(maxsize=3)
def selected_instruction_code_class(encoding,state,instructions):
    from .hia_machine_state_native import selected_state_code_class
    base=selected_state_code_class(encoding,state)
    class SelectedInstructionCode(base):
        def align(self,boundary):return instructions.run(self,1,boundary)
        def mov_rr(self,dst,src):return instructions.run(self,2,dst,src)
        def mov_imm(self,dst,value):return instructions.run(self,3,dst,value)
        def load(self,dst,base,disp=0):return instructions.run(self,4,dst,base,disp)
        def store(self,base,disp,src):return instructions.run(self,5,base,disp,src)
        def lea(self,dst,base,disp=0):return instructions.run(self,6,dst,base,disp)
        def load_u8(self,dst,base,disp=0):return instructions.run(self,7,dst,base,disp)
        def store_u8(self,base,disp,src):return instructions.run(self,8,base,disp,src)
        def add(self,dst,src):return instructions.run(self,9,dst,src)
        def sub(self,dst,src):return instructions.run(self,10,dst,src)
        def and_(self,dst,src):return instructions.run(self,11,dst,src)
        def or_(self,dst,src):return instructions.run(self,12,dst,src)
        def xor(self,dst,src):return instructions.run(self,13,dst,src)
        def cmp(self,left,right):return instructions.run(self,14,left,right)
        def test(self,left,right):return instructions.run(self,15,left,right)
        def alu_imm(self,op,dst,value):return instructions.run(self,16,op,dst,value)
        def shift(self,op,dst,count):return instructions.run(self,17,op,dst,count)
        def shift_imm(self,op,dst,count):return instructions.run(self,18,op,dst,count)
        def shift_cl(self,op,dst):return instructions.run(self,19,op,dst)
        def shl(self,dst,count):return instructions.run(self,20,dst,count)
        def shr(self,dst,count):return instructions.run(self,21,dst,count)
        def sar(self,dst,count):return instructions.run(self,22,dst,count)
        def imul(self,dst,src):return instructions.run(self,23,dst,src)
        def imul_rr(self,dst,src):return instructions.run(self,24,dst,src)
        def mul(self,src):return instructions.run(self,25,src)
        def imul_full(self,src):return instructions.run(self,26,src)
        def div(self,src):return instructions.run(self,27,src)
        def idiv(self,src):return instructions.run(self,28,src)
        def neg(self,src):return instructions.run(self,29,src)
        def bitnot(self,src):return instructions.run(self,30,src)
        def cqo(self):return instructions.run(self,31)
        def setcc(self,condition,dst):return instructions.run(self,32,condition,dst)
        def cmov(self,condition,dst,src):return instructions.run(self,33,condition,dst,src)
        def push(self,reg):return instructions.run(self,34,reg)
        def pop(self,reg):return instructions.run(self,35,reg)
        def ret(self):return instructions.run(self,36)
        def leave(self):return instructions.run(self,37)
        def ud2(self):return instructions.run(self,38)
        def jmp(self,target):return instructions.run(self,39,target)
        def jcc(self,condition,target):return instructions.run(self,40,condition,target)
        def call(self,symbol):return instructions.run(self,41,symbol)
    return _code_call_names(SelectedInstructionCode)

def installed_machine_instructions(manifest_path):
    return _installed_json_image(manifest_path,SOURCE,SCHEMA,NativeMachineInstructions)
