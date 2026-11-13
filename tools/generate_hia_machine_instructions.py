"""Author HIA continuation control for all 41 public Code instructions.

The generated source is subject to the original compiler limits and actual
native qualification; this authoring program is not an execution receipt.
"""
from __future__ import annotations
import ast
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
MODES=('align','mov_rr','mov_imm','load','store','lea','load_u8','store_u8',
'add','sub','and_','or_','xor','cmp','test','alu_imm','shift','shift_imm',
'shift_cl','shl','shr','sar','imul','imul_rr','mul','imul_full','div','idiv',
'neg','bitnot','cqo','setcc','cmov','push','pop','ret','leave','ud2','jmp','jcc','call')
LITERALS=('emit','_reg','data','fixups','relocations','append','mov_imm','shift',
'imul','move_immediate','alu_immediate','mov32_if_exact','imm8_if_exact',
'cl','shl','shr','sar','offset','symbol','type','addend',
'unreviewed function alignment','immediate is outside the 64-bit word',
'operand is outside signed disp32/imm32','unsupported immediate ALU operation',
'unsupported shift operation','shift count must be 0..63 or cl',
'unknown x86-64 condition','invalid branch target','invalid call symbol')
CONSTANTS={'MAGIC':int.from_bytes(b'HIACIN01','little'),'ABI':0xfffffffd,
'TERMINAL':(1<<64)-1,'TYPE':1,'LEN':2,'GETATTR':3,'CONST':5,'DICT_NEW':6,
'CALL0':23,'CALL1':24,'CALL2':25,'NEW_INT':27,'RAISE_ERROR':29,
'STR_SUMMARY':30,'INT_SUMMARY':31,'TUPLE_TWO':32,'SET_ITEM':19,
'EQUAL':36,'TRUTH':37,'CALL3':38,'SIGNED_BYTE_REFUSAL':39,'CODEPOINT':40,
'NEW_SIGNED':41,'ENCODE':42,'NEW_BOOL':43,'E_ALIGN':21,'E_IMMEDIATE':22,
'E_DISP':23,'E_ALU':24,'E_SHIFT':25,'E_COUNT':26,'E_CONDITION':27,
'E_BRANCH':28,'E_SYMBOL':29}
CONDITIONS=(('o',0),('no',1),('b',2),('c',2),('nae',2),('ae',3),('nb',3),('nc',3),
('e',4),('z',4),('ne',5),('nz',5),('be',6),('na',6),('a',7),('nbe',7),
('s',8),('ns',9),('p',10),('pe',10),('np',11),('po',11),('l',12),('nge',12),
('ge',13),('nl',13),('le',14),('ng',14),('g',15),('nle',15))
SOURCE=r"""
def machine_instructions(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) != 80 or length(o) < 8 or length(w) != 2048:
        return ABI
    if word(s,0) != MAGIC:
        return ABI
    if get(w,0) == 0:
        if word(s,8) != 0 or word(s,16) != 0 or word(s,24) < 1 or word(s,24) > 41:
            return ABI
        if word(s,32) == 0 or word(s,64) == 0 or word(s,72) != 0:
            return ABI
        put(w,0,MAGIC)
        put(w,8,0)
        put(w,16,0)
        put(w,24,word(s,24))
        put(w,32,0)
        put(w,40,word(s,32))
        put(w,48,word(s,40))
        put(w,56,word(s,48))
        put(w,64,word(s,56))
        put(w,72,word(s,64))
        set_encoding(w,command(get(w,24)),0,0,0,0,0,0)
    else:
        if get(w,0) != MAGIC or get(w,32) == TERMINAL or get(w,32) == 991:
            return ABI
        if word(s,8) != get(w,8) or word(s,16) != get(w,16):
            return ABI
        if word(s,24) != 0 or word(s,64) != 0 or word(s,72) != 0:
            return ABI
    pc=get(w,32)
    mode=get(w,24)
    if pc == 990:
        return ask(w,RAISE_ERROR,word(s,32),0,0,0,991)
    if pc >= 900 and pc <= 902:
        return finish_emit(s,o,w)
    if (mode == 32 or mode == 33 or mode == 40) and pc < 3:
        return condition_prefix(s,o,w)
    if mode == 1:
        return align_instruction(s,o,w)
    if mode == 3:
        return move_immediate(s,o,w)
    if mode >= 4 and mode <= 8:
        return memory_instruction(s,o,w)
    if mode == 16:
        return alu_instruction(s,o,w)
    if mode == 17:
        return shift_instruction(s,o,w)
    if (mode >= 18 and mode <= 22) or mode == 24:
        return alias_instruction(s,o,w)
    if (mode >= 25 and mode <= 30) or mode == 34 or mode == 35:
        return unary_instruction(s,o,w)
    if mode == 31 or (mode >= 36 and mode <= 38):
        return simple_instruction(s,o,w)
    if mode == 32:
        return set_condition(s,o,w)
    if mode == 33:
        return conditional_move(s,o,w)
    if mode == 39 or mode == 40:
        return branch_instruction(s,o,w)
    if mode == 41:
        return call_instruction(s,o,w)
    return pair_instruction(s,o,w)

def command(mode:u64) -> u64:
    if mode <= 17:
        return mode
    if mode == 23:
        return 18
    if mode >= 25 and mode <= 30:
        return mode-6
    if mode == 31:
        return 25
    if mode == 32:
        return 26
    if mode == 33:
        return 27
    if mode >= 34 and mode <= 38:
        return mode-6
    if mode >= 39:
        return mode-6
    return 0

def begin_emit(w:mutbuf) -> u32:
    return attribute(w,get(w,40),0,900)

def finish_emit(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 900:
        put(w,160,x)
        return ask(w,ENCODE,0,0,0,0,901)
    if pc == 901:
        return ask(w,CALL1,get(w,160),x,0,0,902)
    if pc == 902:
        return done(w,o)
    return ABI

def align_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return ask(w,TYPE,get(w,48),0,0,0,1)
    if pc == 1:
        if x != 2:
            return error(w,E_ALIGN)
        return ask(w,INT_SUMMARY,get(w,48),0,0,0,2)
    if pc == 2:
        if word(s,40) != 0 or word(s,48) > 7 or (x != 1 and x != 16 and x != 32 and x != 64):
            return error(w,E_ALIGN)
        put(w,608,x)
        return attribute(w,get(w,40),0,3)
    if pc == 3:
        put(w,160,x)
        return attribute(w,get(w,40),2,4)
    if pc == 4:
        return ask(w,LEN,x,0,0,0,5)
    if pc == 5:
        put(w,624,word(s,40))
        return ask(w,ENCODE,0,0,0,0,901)
    return ABI

def pair_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        put(w,80,choose(get(w,24) == 23,get(w,48),get(w,56)))
        put(w,88,choose(get(w,24) == 23,get(w,56),get(w,48)))
        return attribute(w,get(w,40),1,1)
    if pc == 1:
        return ask(w,CALL1,x,get(w,80),0,0,2)
    if pc == 2:
        put(w,96,x)
        return attribute(w,get(w,40),1,3)
    if pc == 3:
        return ask(w,CALL1,x,get(w,88),0,0,4)
    if pc == 4:
        if get(w,24) == 23:
            put(w,584,get(w,96))
            put(w,592,x)
        else:
            put(w,584,x)
            put(w,592,get(w,96))
        return begin_emit(w)
    return ABI

def move_immediate(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return attribute(w,get(w,40),1,1)
    if pc == 1:
        return ask(w,CALL1,x,get(w,48),0,0,2)
    if pc == 2:
        put(w,584,x)
        return ask(w,TYPE,get(w,56),0,0,0,3)
    if pc == 3:
        if x != 2:
            return error(w,E_IMMEDIATE)
        return ask(w,INT_SUMMARY,get(w,56),0,0,0,4)
    if pc == 4:
        negative=word(s,40)
        bits=word(s,48)
        if negative == 0:
            if bits > 64:
                return error(w,E_IMMEDIATE)
        else:
            if bits > 63 and (bits != 64 or x != 9223372036854775808):
                return error(w,E_IMMEDIATE)
        put(w,128,choose(negative == 0 and bits <= 32,1,0))
        put(w,600,get(w,56))
        return attribute(w,get(w,40),9,5)
    if pc == 5:
        put(w,80,x)
        return constant(w,11,6)
    if pc == 6:
        return ask(w,EQUAL,get(w,80),x,0,0,7)
    if pc == 7:
        return ask(w,TRUTH,x,0,0,0,8)
    if pc == 8:
        compact=x != 0 and get(w,128) != 0
        put(w,616,choose(compact,1,0))
        return begin_emit(w)
    return ABI

def signed32(bits:u64,negative:u64,raw:u64) -> u64:
    if negative == 0:
        return choose(bits <= 31,1,0)
    return choose(bits <= 31 or (bits == 32 and raw == 18446744071562067968),1,0)

def memory_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    mode=get(w,24)
    if pc == 0:
        store_mode=mode == 5 or mode == 8
        put(w,80,choose(store_mode,get(w,64),get(w,48)))
        put(w,88,choose(store_mode,get(w,48),get(w,56)))
        put(w,96,choose(store_mode,get(w,56),get(w,64)))
        return attribute(w,get(w,40),1,1)
    if pc == 1:
        return ask(w,CALL1,x,get(w,80),0,0,2)
    if pc == 2:
        put(w,584,x)
        return attribute(w,get(w,40),1,3)
    if pc == 3:
        return ask(w,CALL1,x,get(w,88),0,0,4)
    if pc == 4:
        put(w,592,x)
        return ask(w,TYPE,get(w,96),0,0,0,5)
    if pc == 5:
        if x != 2:
            return error(w,E_DISP)
        return ask(w,INT_SUMMARY,get(w,96),0,0,0,6)
    if pc == 6:
        if signed32(word(s,48),word(s,40),x) == 0:
            return error(w,E_DISP)
        put(w,600,get(w,96))
        return begin_emit(w)
    return ABI

def operation(n:u64,a:u64,b:u64,c:u64,shift:u64) -> u64:
    if n != 3:
        return 99
    if shift != 0:
        if a == 115 and b == 104:
            if c == 108:
                return 0
            if c == 114:
                return 1
        if a == 115 and b == 97 and c == 114:
            return 2
        return 99
    if a == 97 and b == 100 and c == 100:
        return 0
    if a == 97 and b == 110 and c == 100:
        return 2
    if a == 115 and b == 117 and c == 98:
        return 3
    if a == 120 and b == 111 and c == 114:
        return 4
    if a == 99 and b == 109 and c == 112:
        return 5
    return 99

def alu_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return ask(w,TYPE,get(w,48),0,0,0,1)
    if pc == 1:
        if x != 3:
            return error(w,E_ALU)
        return ask(w,STR_SUMMARY,get(w,48),0,0,0,2)
    if pc == 2:
        group=operation(x,word(s,40),word(s,48),word(s,56),0)
        if x == 2 and word(s,40) == 111 and word(s,48) == 114:
            group=1
        if group == 99:
            return error(w,E_ALU)
        put(w,608,group)
        return attribute(w,get(w,40),1,3)
    if pc == 3:
        return ask(w,CALL1,x,get(w,56),0,0,4)
    if pc == 4:
        put(w,584,x)
        return ask(w,TYPE,get(w,64),0,0,0,5)
    if pc == 5:
        if x != 2:
            return error(w,E_DISP)
        return ask(w,INT_SUMMARY,get(w,64),0,0,0,6)
    if pc == 6:
        if signed32(word(s,48),word(s,40),x) == 0:
            return error(w,E_DISP)
        short=word(s,48) <= 7 or (word(s,40) != 0 and word(s,48) == 8 and x == 18446744073709551488)
        put(w,128,choose(short,1,0))
        put(w,600,get(w,64))
        return attribute(w,get(w,40),10,7)
    if pc == 7:
        put(w,80,x)
        return constant(w,12,8)
    if pc == 8:
        return ask(w,EQUAL,get(w,80),x,0,0,9)
    if pc == 9:
        put(w,136,x)
        return ask(w,TRUTH,x,0,0,0,10)
    if pc == 10:
        if x == 0:
            return ask(w,TRUTH,get(w,136),0,0,0,12)
        return ask(w,NEW_BOOL,get(w,128),0,0,0,11)
    if pc == 11:
        put(w,136,x)
        return ask(w,TRUTH,x,0,0,0,12)
    if pc == 12:
        put(w,624,choose(x != 0,1,0))
        if x != 0 and get(w,128) == 0:
            return ask(w,SIGNED_BYTE_REFUSAL,get(w,64),0,0,0,99)
        return attribute(w,get(w,40),0,13)
    if pc == 13:
        put(w,160,x)
        return ask(w,TRUTH,get(w,136),0,0,0,14)
    if pc == 14:
        put(w,616,choose(x != 0,1,0))
        return ask(w,ENCODE,0,0,0,0,901)
    return ABI

def shift_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return ask(w,TYPE,get(w,48),0,0,0,1)
    if pc == 1:
        if x != 3:
            return error(w,E_SHIFT)
        return ask(w,STR_SUMMARY,get(w,48),0,0,0,2)
    if pc == 2:
        group=operation(x,word(s,40),word(s,48),word(s,56),1)
        if group == 99:
            return error(w,E_SHIFT)
        put(w,608,group)
        return attribute(w,get(w,40),1,3)
    if pc == 3:
        return ask(w,CALL1,x,get(w,56),0,0,4)
    if pc == 4:
        put(w,584,x)
        return constant(w,13,5)
    if pc == 5:
        return ask(w,EQUAL,get(w,64),x,0,0,6)
    if pc == 6:
        return ask(w,TRUTH,x,0,0,0,7)
    if pc == 7:
        if x != 0:
            put(w,616,1)
            return begin_emit(w)
        return ask(w,TYPE,get(w,64),0,0,0,8)
    if pc == 8:
        if x != 2:
            return error(w,E_COUNT)
        return ask(w,INT_SUMMARY,get(w,64),0,0,0,9)
    if pc == 9:
        if word(s,40) != 0 or word(s,48) > 6:
            return error(w,E_COUNT)
        put(w,600,get(w,64))
        return begin_emit(w)
    return ABI

def alias_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    mode=get(w,24)
    if pc == 0:
        return attribute(w,get(w,40),choose(mode == 24,8,7),1)
    if pc == 1:
        put(w,80,x)
        if mode == 24:
            return ask(w,CALL2,x,get(w,48),get(w,56),0,4)
        if mode == 18:
            return ask(w,CALL3,x,get(w,48),get(w,56),get(w,64),4)
        if mode == 19:
            return constant(w,13,2)
        return constant(w,mode-6,3)
    if pc == 2:
        return ask(w,CALL3,get(w,80),get(w,48),get(w,56),x,4)
    if pc == 3:
        return ask(w,CALL3,get(w,80),x,get(w,48),get(w,56),4)
    if pc == 4:
        return done(w,o)
    return ABI

def unary_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return attribute(w,get(w,40),1,1)
    if pc == 1:
        return ask(w,CALL1,x,get(w,48),0,0,2)
    if pc == 2:
        put(w,584,x)
        return begin_emit(w)
    return ABI

def simple_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,32) == 0:
        return begin_emit(w)
    return ABI

def condition_prefix(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return ask(w,TYPE,get(w,48),0,0,0,1)
    if pc == 1:
        if x != 3:
            return error(w,E_CONDITION)
        return ask(w,STR_SUMMARY,get(w,48),0,0,0,2)
    if pc == 2:
        value=condition_number(x,word(s,40),word(s,48),word(s,56))
        if value == 16:
            return error(w,E_CONDITION)
        put(w,608,value)
        mode=get(w,24)
        if mode == 40:
            put(w,80,get(w,56))
            return ask(w,ENCODE,0,0,0,0,4)
        return attribute(w,get(w,40),1,4)
    return ABI

def set_condition(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 4:
        return ask(w,CALL1,x,get(w,56),0,0,5)
    if pc == 5:
        put(w,584,x)
        return attribute(w,get(w,40),6,6)
    if pc == 6:
        put(w,80,x)
        return ask(w,NEW_INT,0,0,0,0,7)
    if pc == 7:
        return ask(w,CALL2,get(w,80),get(w,56),x,0,8)
    if pc == 8:
        return begin_emit(w)
    return ABI

def conditional_move(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 4:
        return ask(w,CALL1,x,get(w,56),0,0,5)
    if pc == 5:
        put(w,584,x)
        return attribute(w,get(w,40),1,6)
    if pc == 6:
        return ask(w,CALL1,x,get(w,64),0,0,7)
    if pc == 7:
        put(w,592,x)
        return begin_emit(w)
    return ABI

def branch_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        put(w,80,get(w,48))
        return ask(w,ENCODE,0,0,0,0,4)
    if pc == 4:
        put(w,88,x)
        return ask(w,TYPE,get(w,80),0,0,0,5)
    if pc == 5:
        if x != 3:
            return error(w,E_BRANCH)
        return ask(w,LEN,get(w,80),0,0,0,6)
    if pc == 6:
        if word(s,40) == 0 or word(s,40) > 512:
            return error(w,E_BRANCH)
        return attribute(w,get(w,40),0,7)
    if pc == 7:
        return ask(w,CALL1,x,get(w,88),0,0,8)
    if pc == 8:
        return attribute(w,get(w,40),3,9)
    if pc == 9:
        return attribute(w,x,5,10)
    if pc == 10:
        put(w,96,x)
        return attribute(w,get(w,40),2,11)
    if pc == 11:
        return ask(w,LEN,x,0,0,0,12)
    if pc == 12:
        return ask(w,TUPLE_TWO,x,get(w,80),0,0,13)
    if pc == 13:
        return ask(w,CALL1,get(w,96),x,0,0,14)
    if pc == 14:
        set_encoding(w,36,0,0,0,0,0,0)
        return begin_emit(w)
    return ABI

def symbol_first(code:u64) -> u64:
    return choose(code == 95 or (code >= 65 and code <= 90) or (code >= 97 and code <= 122),1,0)

def call_instruction(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    pc=get(w,32)
    x=word(s,32)
    if pc == 0:
        return ask(w,TYPE,get(w,48),0,0,0,1)
    if pc == 1:
        if x != 3:
            return error(w,E_SYMBOL)
        return ask(w,LEN,get(w,48),0,0,0,2)
    if pc == 2:
        if word(s,40) == 0 or word(s,40) > 192:
            return error(w,E_SYMBOL)
        put(w,80,word(s,40))
        put(w,88,0)
        return ask(w,CODEPOINT,get(w,48),0,0,0,3)
    if pc == 3:
        i=get(w,88)
        if symbol_first(x) == 0 and (i == 0 or x < 48 or x > 57):
            return error(w,E_SYMBOL)
        i=i+1
        put(w,88,i)
        if i < get(w,80):
            return ask(w,CODEPOINT,get(w,48),i,0,0,3)
        return attribute(w,get(w,40),0,4)
    if pc == 4:
        put(w,160,x)
        return ask(w,ENCODE,0,0,0,0,5)
    if pc == 5:
        return ask(w,CALL1,get(w,160),x,0,0,6)
    if pc == 6:
        return attribute(w,get(w,40),4,7)
    if pc == 7:
        return attribute(w,x,5,8)
    if pc == 8:
        put(w,96,x)
        return attribute(w,get(w,40),2,9)
    if pc == 9:
        return ask(w,LEN,x,0,0,0,10)
    if pc == 10:
        put(w,104,x)
        return ask(w,DICT_NEW,0,0,0,0,11)
    if pc == 11:
        put(w,112,x)
        return constant(w,17,12)
    if pc == 12:
        return ask(w,SET_ITEM,get(w,112),x,get(w,104),0,13)
    if pc == 13:
        return constant(w,18,14)
    if pc == 14:
        return ask(w,SET_ITEM,get(w,112),x,get(w,48),0,15)
    if pc == 15:
        return ask(w,NEW_INT,4,0,0,0,16)
    if pc == 16:
        put(w,104,x)
        return constant(w,19,17)
    if pc == 17:
        return ask(w,SET_ITEM,get(w,112),x,get(w,104),0,18)
    if pc == 18:
        return ask(w,NEW_SIGNED,18446744073709551612,0,0,0,19)
    if pc == 19:
        put(w,104,x)
        return constant(w,20,20)
    if pc == 20:
        return ask(w,SET_ITEM,get(w,112),x,get(w,104),0,21)
    if pc == 21:
        return ask(w,CALL1,get(w,96),get(w,112),0,0,22)
    if pc == 22:
        set_encoding(w,36,0,0,0,0,0,0)
        return begin_emit(w)
    return ABI

def set_encoding(w:mutbuf,command:u64,r:u64,m:u64,value:u64,auxiliary:u64,mode:u64,offset:u64) -> u64:
    put(w,576,command)
    put(w,584,r)
    put(w,592,m)
    put(w,600,value)
    put(w,608,auxiliary)
    put(w,616,mode)
    put(w,624,offset)
    return 0

def ask(w:mutbuf,opcode:u64,a:u64,b:u64,c:u64,d:u64,pc:u64) -> u32:
    put(w,8,opcode)
    put(w,16,get(w,16)+1)
    put(w,32,pc)
    put(w,512,a)
    put(w,520,b)
    put(w,528,c)
    put(w,536,d)
    return 1

def constant(w:mutbuf,which:u64,pc:u64) -> u32:
    n=literal(w,which)
    return ask(w,CONST,1024,n,0,0,pc)

def attribute(w:mutbuf,object:u64,which:u64,pc:u64) -> u32:
    n=literal(w,which)
    return ask(w,GETATTR,object,1024,n,0,pc)

def error(w:mutbuf,which:u64) -> u32:
    return constant(w,which,990)

def done(w:mutbuf,o:mutbuf) -> u32:
    put(w,32,TERMINAL)
    put(o,0,get(w,72))
    return 0

def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i < 8:
        value=value | (byte(s,at+i) << (i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i < 8:
        value=value | (byte(w,at+i) << (i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i < 8:
        store(w,at+i,(value >> (i*8)) & 255)
        i=i+1
    return 0
"""
def generated_helpers():
    rows=['def condition_number(n:u64,a:u64,b:u64,c:u64) -> u64:']
    for name,value in CONDITIONS:
        codes=list(name.encode())
        clause=' and '.join(['n == '+str(len(codes))]+[arg+' == '+str(code) for arg,code in zip(('a','b','c'),codes)])
        rows+=['    if '+clause+':','        return '+str(value)]
    rows.append('    return 16')
    rows+=['','def literal(w:mutbuf,which:u64) -> u64:']
    groups=(len(LITERALS)+3)//4
    for group in range(groups):
        rows+=['    if which < '+str((group+1)*4)+':','        return literal_'+str(group)+'(w,which)']
    rows.append('    return 0')
    for group in range(groups):
        rows+=['','def literal_'+str(group)+'(w:mutbuf,which:u64) -> u64:']
        for index in range(group*4,min((group+1)*4,len(LITERALS))):
            raw=LITERALS[index].encode()
            rows.append('    if which == '+str(index)+':')
            rows.extend('        store(w,'+str(1024+j)+','+str(code)+')' for j,code in enumerate(raw))
            rows.append('        return '+str(len(raw)))
        rows.append('    return 0')
    return '\n'.join(rows)+'\n'
def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node) if node.id in CONSTANTS else node
    nodes=ast.parse(SOURCE+'\n'+generated_helpers())
    return ast.unparse(ast.fix_missing_locations(Expand().visit(nodes)))+'\n'
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
        'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'machine_instructions','functions':functions})
if __name__=='__main__':
    path=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'examples/hia_bootstrap/machine_instructions.hepta'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
