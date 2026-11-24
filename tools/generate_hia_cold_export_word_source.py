"""Native original compiler-word witness source and mathematical input producer.

The get/put bodies are copied from the admitted current compiler source. Modes
0/1/2/3 return the generated source, initial bytes, independently computed
expected bytes, or expected outcome words. No target result is consumed.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
PARTS=[b'hia-asm.v1 hepta.hia.program.v9 selfhost\nfn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(start)\nblock start(s:readbuf,o:mutbuf,w:mutbuf)\n  offset:u64 = const() {"value":',b'}\n',b'  value:u64 = const() {"value":81985529216486895}\n  ignored:u64 = call(o,offset,value) {"function":"f36"}\n  result:u32 = const() {"value":7}\n  ret(result)\nend\n',b'  value:u64 = call(o,offset) {"function":"f37"}\n  expected:u64 = const() {"value":',b'}\n  equal:bool = compare.eq(value,expected)\n  yes:u32 = const() {"value":7}\n  no:u32 = const() {"value":0}\n  result:u32 = select(equal,yes,no)\n  ret(result)\nend\n']
SOURCE=r'''
def word_source(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 64 or uint(s,0) != INPUT_MAGIC:
        return 4294967295
    operation = uint(s,8)
    mode = uint(s,16)
    at = uint(s,24)
    size = uint(s,32)
    compiler = uint(s,40)
    if operation > 1 or mode > 3 or size > 1048576 or compiler == 0 or compiler > 1048576:
        return 4294967295
    if uint(s,48) != 0 or uint(s,56) != 0 or length(s) != 64 + compiler:
        return 4294967295
    if mode == 1 or mode == 2:
        if length(o) < size:
            return 4294967294
        i = 0
        while i < size:
            store(o,i,(i*17+3)&255)
            i = i + 1
        if mode == 2 and operation == 1:
            i = 0
            while i < 8:
                position = at + i
                if position >= size:
                    return size
                store(o,position,(81985529216486895 >> (8*i)) & 255)
                i = i + 1
        return size
    trap = 0
    if at > size:
        trap = 1
    elif size - at < 8:
        trap = 1
    if mode == 3:
        if length(o) < 16:
            return 4294967294
        write(o,0,trap,8)
        write(o,8,7,8)
        return 16
    if length(w) < 64:
        return 4294967294
    if find_function(s,w,0,0) == 0 or find_function(s,w,16,1) == 0:
        return 4294967295
    first = get(w,0)
    first_size = get(w,8)
    second = get(w,16)
    second_size = get(w,24)
    if length(o) < 1024 + first_size + second_size:
        return 4294967294
    cursor = literal_0(o,0)
    cursor = decimal(o,cursor,at)
    cursor = literal_1(o,cursor)
    if operation == 1:
        cursor = literal_2(o,cursor)
    else:
        cursor = literal_3(o,cursor)
        expected = 0
        if trap == 0:
            i = 0
            while i < 8:
                expected = expected | (((17*(at+i)+3)&255) << (8*i))
                i = i + 1
        cursor = decimal(o,cursor,expected)
        cursor = literal_4(o,cursor)
    copy(s,o,first,cursor,first_size)
    cursor = cursor + first_size
    copy(s,o,second,cursor,second_size)
    return cursor + second_size

def find_function(s:readbuf,w:mutbuf,slot:u64,which:u64) -> u64:
    found = 0
    i = 64
    while i + 7 <= length(s):
        if (i == 64 or byte(s,i-1) == 10) and byte(s,i) == 102 and byte(s,i+1) == 110 and byte(s,i+2) == 32 and byte(s,i+3) == 102 and byte(s,i+4) == 51 and byte(s,i+5) == 54 + which and byte(s,i+6) == 40:
            if found != 0:
                return 0
            end = function_end(s,i+7)
            if end == 0:
                return 0
            write(w,slot,i,8)
            write(w,slot+8,end+5-i,8)
            found = 1
            i = end + 5
        else:
            i = i + 1
    return found

def function_end(s:readbuf,at:u64) -> u64:
    while at + 5 <= length(s):
        if byte(s,at) == 10 and byte(s,at+1) == 101 and byte(s,at+2) == 110 and byte(s,at+3) == 100 and byte(s,at+4) == 10:
            return at
        at = at + 1
    return 0

def decimal(o:mutbuf,at:u64,value:u64) -> u64:
    i = 0
    emitted = 0
    while i < 20:
        base = power(i)
        digit = 0
        while value >= base:
            value = value - base
            digit = digit + 1
        if digit != 0 or emitted != 0 or i == 19:
            store(o,at,48+digit)
            at = at + 1
            emitted = 1
        i = i + 1
    return at

def uint(s:readbuf,at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s,at+i) << (i*8))
        i = i + 1
    return value

def get(s:mutbuf,at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s,at+i) << (i*8))
        i = i + 1
    return value

def write(o:mutbuf,at:u64,value:u64,count:u64) -> u64:
    i = 0
    while i < count:
        store(o,at+i,(value >> (i*8)) & 255)
        i = i + 1
    return 0

def copy(s:readbuf,o:mutbuf,at:u64,to:u64,size:u64) -> u64:
    i = 0
    while i < size:
        store(o,to+i,byte(s,at+i))
        i = i + 1
    return 0
'''
def source_program():
    source=SOURCE.replace('INPUT_MAGIC',str(int.from_bytes(b'HIAEXWQ1','little')))
    for index,raw in enumerate(PARTS):
        source+=f'\ndef literal_{index}(o:mutbuf,at:u64) -> u64:\n'
        for at in range(0,len(raw),8):
            word=raw[at:at+8];source+=f'    write(o,at+{at},{int.from_bytes(word,"little")},{len(word)})\n'
        source+=f'    return at+{len(raw)}\n'
    source+='\ndef power(i:u64) -> u64:\n'
    for i in range(19):source+=f'    if i == {i}:\n        return {10**(19-i)}\n'
    return source+'    return 1\n'
def main():
    p=ROOT/'examples/hia_bootstrap/cold_export_word_source.hepta';p.write_text(render_assembly(document(source_program(),'cold_export_word_source')));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
