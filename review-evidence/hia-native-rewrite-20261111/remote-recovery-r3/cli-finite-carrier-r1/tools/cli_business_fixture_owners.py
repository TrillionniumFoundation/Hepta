"""New HIA fixtures for the fixed finite CLI/service carrier.

These are protocol test owners, not implementations of CLI businesses. The
production carrier is unchanged. Cases choose one explicit frame mutation;
a matched unmodified control establishes each successful mechanical path.
"""
import ast,importlib.util,json
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
SHARED=ROOT.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py"
SHARED_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
assert sha256(SHARED.read_bytes()).hexdigest()==SHARED_SHA
spec=importlib.util.spec_from_file_location("finite_fixture_common",SHARED)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
KEEP={"word","get","put","zero","refuse","args","event","acknowledge","cap","inside",
      "grow","release","copy","protect","view","wire8"}
# Exact AST adaptation: unparse inserts parentheses in the original predicate.
# Retain every other shared acknowledgement check, including correlation.
_nodes=[node for node in ast.parse(common.COMMON).body if node.name in KEEP]
_acks=[node for node in _nodes if node.name=="acknowledge"]
assert len(_acks)==1
_before=ast.parse("pending != 1 and pending != 14 and word(s, 40) != 0",mode="eval").body
_after=ast.parse("pending != 1 and pending != 14 and pending != 15 and word(s, 40) != 0",mode="eval").body
_matches=[node for node in ast.walk(_acks[0]) if isinstance(node,ast.If)
          and ast.dump(node.test)==ast.dump(_before)]
assert len(_matches)==1,("one original nonzero-return guard",len(_matches))
_matches[0].test=_after
COMMON="\n".join(ast.unparse(node) for node in _nodes)+"\n"
def magic(s):return int.from_bytes(s.encode(),"little")
def constants(mode,service,work):
    result=dict(common.CONSTANTS)
    result.update(MIN_WORK=work,LOWER_MAGIC=magic("HIAFTS01"),FIX_MODE=mode,
        FIX_SERVICE=service,FIX_DRIVER=7 if work==65536 else 56,
        CLI_INIT=magic("HIACLI01"),B_INIT=magic("HIACBI01"),B_REPLY=magic("HIACBR01"),
        B_EVENT=magic("HIACBE01"),B_ACK=magic("HIACBA01"),B_LEASES=magic("HIALSV01"),
        CHILD_SEQ=16000,CHILD_EXTENT=16008,CHILD_LIFE=16016,
        CHILD_REQUEST=16024,INITIAL_BYTES=16032,RESULT_SIZE=16040,
        MARKER=magic("NATIVE!\n"))
    return result

class Flow:
    def __init__(self):self.blocks=[]
    def add(self,name,text):self.blocks.append((name,text.strip("\n")))
    def render(self):
        labels={name:i+1 for i,(name,_) in enumerate(self.blocks)}
        lines=["def fixture_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:"]
        for i,(name,text) in enumerate(self.blocks):
            text=text.replace("@NEXT@",str(i+2))
            for label,value in labels.items():text=text.replace("@"+label+"@",str(value))
            assert "@" not in text,(name,text)
            lines.append("    if phase == "+str(i+1)+":")
            lines.extend("        "+line for line in text.splitlines())
        lines.append("    return refuse(w, 799)")
        return "\n".join(lines)+"\n"
    def event(self,name,call):self.add(name,"return "+call)

HELPERS=r'''
def business(o:mutbuf, w:mutbuf, verb:u64, tablebytes:u64, expected:u64, phase:u64) -> u32:
    if verb == 3:
        put(w, C_OBSERVE, 0)
        args(w, 3, FIX_SERVICE, 2, 0, 0, 0, 0, 0, 0, 0, expected, 0)
    else:
        put(w, C_OBSERVE, 128)
        args(w, verb, FIX_SERVICE, 2, 13, 0, 128, 14, 0, tablebytes, 15, expected, 0)
    return event(o, w, 17, phase)

def parent_ack(w:mutbuf, verb:u64, lifecycle:u64) -> u64:
    if get(w, OBS) != B_ACK or get(w, OBS + 8) != 1 or get(w, OBS + 16) != FIX_SERVICE:
        return 0
    if get(w, OBS + 24) != 2 or get(w, OBS + 32) != 2 or get(w, OBS + 48) != 56:
        return 0
    if get(w, OBS + 40) <= get(w, CHILD_SEQ) or get(w, OBS + 56) != lifecycle:
        return 0
    if get(w, OBS + 64) != 15 or get(w, OBS + 80) != verb:
        return 0
    if verb == 1 or FIX_MODE < 20:
        if get(w, OBS + 72) != 136:
            return 0
    elif get(w, OBS + 72) < 352:
        return 0
    if get(w, OBS + 88) != get(w, C_SEQUENCE):
        return 0
    i = 96
    while i < 128:
        if get(w, OBS + i) != 0:
            return 0
        i = i + 8
    put(w, CHILD_SEQ, get(w, OBS + 40))
    put(w, CHILD_EXTENT, get(w, OBS + 72))
    put(w, CHILD_LIFE, lifecycle)
    put(w, CAPS + 15 * 8, get(w, CHILD_EXTENT))
    return 1

def parent_yield(w:mutbuf, kind:u64) -> u64:
    if get(w, OBS) != B_EVENT or get(w, OBS + 8) != 1 or get(w, OBS + 16) != FIX_SERVICE:
        return 0
    if get(w, OBS + 24) != 2 or get(w, OBS + 32) != get(w, CHILD_SEQ) or get(w, OBS + 48) != kind:
        return 0
    if get(w, OBS + 96) != 128 or get(w, OBS + 104) != get(w, CHILD_EXTENT) - 128 or get(w, OBS + 112) != get(w, CHILD_EXTENT) or get(w, OBS + 120) != 0:
        return 0
    return 1

def terminal(o:mutbuf, w:mutbuf) -> u32:
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, 1)
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 40, 15)
    put(o, 48, 128)
    put(o, 56, get(w, CHILD_EXTENT) - 128)
    return 128

def service_yield(o:mutbuf, w:mutbuf, final:u64, mask:u64, phase:u64) -> u32:
    put(w, C_OBSERVE, 128)
    args(w, 2, final, 10, 0, cap(w, 10), mask, 0, 0, 0, 0, 0, 0)
    return event(o, w, 18, phase)

def fixture_call(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    put(w, C_OBSERVE, 0)
    args(w, 60, 1, 0, cap(w, 1), 6, 8, 7, 64, 0, 0, 0, 0)
    return event(o, w, 1, phase)
'''

def parent(mode=0,service=1,program_bytes=None):
    data=b"source!!" if program_bytes is None else bytes(program_bytes)
    zero=(mode==1)
    f=Flow()
    # Sources are distinct owned readonly views; target 1 also exercises a
    # logical empty readonly source through the always-present empty slot 0.
    f.event("program-grow",f"grow(o, w, 4, {max(1,len(data))}, @NEXT@)")
    f.add("program-copy","program_data(w)\n"+f"return copy(o, w, 2, 20000, 4, 0, {len(data)}, @NEXT@)")
    f.event("program-ro","protect(o, w, 4, 1, @NEXT@)")
    for slot in (5,6):
        f.event(f"input{slot}-grow",f"grow(o, w, {slot}, 8, @NEXT@)")
        f.add(f"input{slot}-copy",f"put(w, WIRE, {slot})\nreturn copy(o, w, 2, WIRE, {slot}, 0, 8, @NEXT@)")
        f.event(f"input{slot}-ro",f"protect(o, w, {slot}, 1, @NEXT@)")
    f.event("command-grow","grow(o, w, 13, 128, @NEXT@)")
    f.event("table-grow","grow(o, w, 14, 128, @NEXT@)")
    f.add("initial-table",f'''zero(w, WIRE, 128)
wire8(w, B_LEASES, 1, 3, 128, {0 if zero else 4}, 0, {0 if zero else len(data)}, 1)
put(w, WIRE + 64, 5)
put(w, WIRE + 80, 8)
put(w, WIRE + 88, 4)
put(w, WIRE + 96, 6)
put(w, WIRE + 112, 8)
put(w, WIRE + 120, 5)
return copy(o, w, 2, WIRE, 14, 0, 128, @NEXT@)''')
    f.event("initial-table-ro","protect(o, w, 14, 1, @NEXT@)")
    f.add("initial-command",f'''zero(w, WIRE, 128)
wire8(w, B_INIT, 1, FIX_SERVICE, 2, 1, get(w, C_SEQUENCE) + 3, 13, 4300)
put(w, WIRE + 64, {0 if zero else len(data)})
put(w, WIRE + 72, 8)
put(w, WIRE + 80, 8)
put(w, WIRE + 88, 16)
put(w, WIRE + 96, 1024)
put(w, WIRE + 104, 32)
return copy(o, w, 2, WIRE, 13, 0, 128, @NEXT@)''')
    f.event("initial-command-ro","protect(o, w, 13, 1, @NEXT@)")
    f.event("begin","business(o, w, 1, 128, 0, @NEXT@)")
    f.add("begin-ack",'''if parent_ack(w, 1, 0) == 0:
    return refuse(w, 701)
return view(o, w, 15, 0, 128, @NEXT@)''')
    tail="put(w, C_PHASE, @NEXT@)\nreturn 0"
    if mode==2:tail="return business(o, w, 3, 0, get(w, CHILD_SEQ), @retired@)"
    elif mode==9:tail="return protect(o, w, 4, 0, @NEXT@)"
    elif mode==11:tail="return release(o, w, 4, @NEXT@)"
    f.add("begin-view",'''if parent_yield(w, 1) == 0:
    return refuse(w, 702)
'''+tail)
    f.event("retire-old-view","release(o, w, 15, @NEXT@)")
    f.event("resume-grow","grow(o, w, 18, 8, @NEXT@)")
    f.add("resume-data","put(w, WIRE, MARKER)\nreturn copy(o, w, 2, WIRE, 18, 0, 8, @NEXT@)")
    f.event("resume-ro","protect(o, w, 18, 1, @NEXT@)")
    f.event("table-rw","protect(o, w, 14, 0, @NEXT@)")
    count=2 if mode==4 else 0 if mode==5 else 1
    target=64 if mode==6 else 5 if mode==7 else 8
    f.add("resume-table",f'''zero(w, WIRE, 128)
wire8(w, B_LEASES, 1, {count}, {32+32*count}, 18, 0, 8, {target})
put(w, WIRE + 64, 18)
put(w, WIRE + 80, 8)
put(w, WIRE + 88, 8)
return copy(o, w, 2, WIRE, 14, 0, {32+32*count}, @NEXT@)''')
    f.event("resume-table-ro","protect(o, w, 14, 1, @NEXT@)")
    f.event("command-rw","protect(o, w, 13, 0, @NEXT@)")
    f.add("resume-command",'''zero(w, WIRE, 128)
wire8(w, B_REPLY, 1, FIX_SERVICE, 2, get(w, CHILD_SEQ), 1, 1, get(w, C_SEQUENCE) + 3)
put(w, WIRE + 64, 13)
put(w, WIRE + 72, 8)
put(w, WIRE + 80, 8)
put(w, WIRE + 88, 8388608)
return copy(o, w, 2, WIRE, 13, 0, 128, @NEXT@)''')
    f.event("resume-command-ro","protect(o, w, 13, 1, @NEXT@)")
    f.event("resume",f"business(o, w, 2, {32+32*count}, get(w, CHILD_SEQ){' + 1' if mode==3 else ''}, @NEXT@)")
    f.add("resume-ack",'''if parent_ack(w, 2, 1) == 0:
    return refuse(w, 703)
return view(o, w, 15, 0, 128, @NEXT@)''')
    f.add("final-view",'''if parent_yield(w, 3) == 0:
    return refuse(w, 704)
return business(o, w, 3, 0, get(w, CHILD_SEQ), @NEXT@)''')
    f.event("retired","view(o, w, 15, 128, 8, @NEXT@)")
    f.add("owned-result",'''if FIX_MODE < 20 and get(w, OBS) != MARKER:
    return refuse(w, 705)
if FIX_MODE >= 20 and get(w, OBS) != ACK_MAGIC:
    return refuse(w, 707)
return protect(o, w, 4, 0, @NEXT@)''')
    f.event("unpinned-release","release(o, w, 4, @NEXT@)")
    f.add("done","return terminal(o, w)")
    chunks=["def program_data(w:mutbuf) -> u64:"]
    assert len(data)<4000
    for at in range(0,len(data),8):
        chunks.append(f"    put(w, {20000+at}, {int.from_bytes(data[at:at+8],'little')})")
    chunks.append("    return 0")
    init=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 65536 or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 64 or word(s, 0) != CLI_INIT or word(s, 8) != 1:
            return refuse(w, 700)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 7)
        put(w, C_LEASE, 1)
        put(w, C_PHASE, 1)
        put(w, CAPS + 8, word(s, 16))
        put(w, CAPS + 16, 65536)
        put(w, CAPS + 24, 128)
    else:
        if acknowledge(s, w, 7) == 0:
            return refuse(w, 706)
    while get(w, L_STATUS) == 1:
        result = fixture_step(o, w, get(w, C_PHASE))
        if result != 0:
            return result
    return ABI
'''
    return init+f.render()+HELPERS+"\n".join(chunks)+"\n"+COMMON,constants(mode,service,65536)

def service(mode=0,service=1,child=False):
    f=Flow()
    if child:
        f.add("child-call",'''put(w, C_OBSERVE, 160)
args(w, 2, 1, 0, cap(w, 1), 20, 9, 4300, 0, 0, 0, 0, 0)
return event(o, w, 15, @NEXT@)''')
        f.add("child-ack",'''if get(w, C_RETURN) != 128 or get(w, OBS) != EVENT_MAGIC or get(w, OBS + 8) != 7:
    return refuse(w, 750)
if get(w, OBS + 136) != 20 or get(w, OBS + 152) != 0:
    return refuse(w, 751)
if get(w, OBS + 32) == 0:
    if get(w, OBS + 144) != 46 or get(w, OBS + 128) != 256 + get(w, OBS + 88):
        return refuse(w, 752)
else:
    if get(w, OBS + 144) != 44 and get(w, OBS + 144) != 46:
        return refuse(w, 753)
put(w, RESULT_SIZE, get(w, OBS + 128))
put(w, CAPS + 20 * 8, get(w, OBS + 128))
put(w, C_PHASE, @NEXT@)
return 0''')
    if mode==12:
        f.event("forbidden-borrow-write","protect(o, w, 1, 0, @NEXT@)")
    if mode in (13,14):
        f.event("callee-command-grow","grow(o, w, 6, 8, @NEXT@)")
        f.add("callee-command-copy","put(w, WIRE, 23)\nreturn copy(o, w, 2, WIRE, 6, 0, 8, @NEXT@)")
        f.event("callee-work-grow","grow(o, w, 7, 64, @NEXT@)")
        f.event("callee","fixture_call(o, w, @NEXT@)")
        f.add("callee-return",'''if get(w, C_RETURN) != 128:
    return refuse(w, 754)
return view(o, w, 6, 0, 8, @NEXT@)''')
        f.add("callee-check",'''if get(w, OBS) != 99:
    return refuse(w, 755)
put(w, C_PHASE, @NEXT@)
return 0''')
    f.event("result-grow","grow(o, w, 10, 136, @NEXT@)")
    f.add("yield-source",'''zero(w, WIRE, 136)
wire8(w, B_EVENT, 1, FIX_SERVICE, 2, get(w, C_SEQUENCE) + 3, 1, 1, 0)
put(w, WIRE + 72, 13)
put(w, WIRE + 80, 8388608)
put(w, WIRE + 88, 8)
put(w, WIRE + 96, 128)
put(w, WIRE + 104, 8)
put(w, WIRE + 112, 136)
put(w, WIRE + 128, MARKER)
return copy(o, w, 2, WIRE, 10, 0, 136, @NEXT@)''')
    f.event("yield-source-ro","protect(o, w, 10, 1, @NEXT@)")
    mask=4 if mode==8 else 32 if mode==7 else 256
    f.event("suspend",f"service_yield(o, w, 0, {mask}, @NEXT@)")
    f.add("resume",'''if get(w, OBS) != B_REPLY or get(w, OBS + 8) != 1 or get(w, OBS + 16) != FIX_SERVICE or get(w, OBS + 24) != 2:
    return refuse(w, 756)
if get(w, OBS + 32) != get(w, C_SEQUENCE) or get(w, OBS + 40) != 1 or get(w, OBS + 48) != 1:
    return refuse(w, 757)
if get(w, OBS + 64) != 13 or get(w, OBS + 72) != 8 or get(w, OBS + 80) != 8 or cap(w, 8) != 0:
    return refuse(w, 758)
put(w, CAPS + 8 * 8, get(w, OBS + 80))
return view(o, w, 8, 0, 8, @NEXT@)''')
    f.add("read-resume",'''if get(w, OBS) != MARKER:
    return refuse(w, 759)
return release(o, w, 8, @NEXT@)''')
    f.event("result-rw","protect(o, w, 10, 0, @NEXT@)")
    if child:
        f.event("final-extent","grow(o, w, 10, 352 + get(w, RESULT_SIZE), @NEXT@)")
        f.event("actual-child-ack","copy(o, w, 2, 20000, 10, 128, 224, @NEXT@)")
        f.add("actual-child-result",'''if get(w, RESULT_SIZE) != 0:
    return copy(o, w, 20, 0, 10, 352, get(w, RESULT_SIZE), @NEXT@)
put(w, C_PHASE, @NEXT@)
return 0''')
    f.add("final-source",'''zero(w, WIRE, 136)
wire8(w, B_EVENT, 1, FIX_SERVICE, 2, get(w, C_SEQUENCE) + 3, 1, 3, 0)
put(w, WIRE + 80, 2)
put(w, WIRE + 96, 128)
put(w, WIRE + 104, 8)
put(w, WIRE + 112, 136)
put(w, WIRE + 128, MARKER)
if FIX_MODE >= 20:
    put(w, WIRE + 104, 224 + get(w, RESULT_SIZE))
    put(w, WIRE + 112, 352 + get(w, RESULT_SIZE))
    return copy(o, w, 2, WIRE, 10, 0, 128, @NEXT@)
return copy(o, w, 2, WIRE, 10, 0, 136, @NEXT@)''')
    f.event("final-ro","protect(o, w, 10, 1, @NEXT@)")
    f.event("final","service_yield(o, w, 1, 0, @NEXT@)")
    f.add("after-final","return refuse(w, 760)")
    init=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 1048576 or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 128 or word(s, 0) != B_INIT or word(s, 8) != 1 or word(s, 16) != FIX_SERVICE or word(s, 24) != 2:
            return refuse(w, 761)
        if word(s, 64) != cap(w, 1) or word(s, 72) != cap(w, 4) or word(s, 80) != cap(w, 5):
            return refuse(w, 762)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 56)
        put(w, C_LEASE, 2)
        put(w, C_PHASE, 1)
    else:
        if get(w, C_PENDING) == 15:
            if length(s) != 224:
                return refuse(w, 764)
            i = 0
            while i < 224:
                store(w, 20000 + i, byte(s, i))
                i = i + 1
        if acknowledge(s, w, 56) == 0:
            return refuse(w, 763)
    while get(w, L_STATUS) == 1:
        result = fixture_step(o, w, get(w, C_PHASE))
        if result != 0:
            return result
    return ABI
'''
    return init+f.render()+HELPERS+COMMON,constants(mode,service,1048576)

WRITE_SECOND=r'''
def entry(s:readbuf, r:mutbuf, w:mutbuf) -> u32:
    if length(r) != 8 or length(w) != 64:
        return 4294967293
    store(r, 0, 99)
    return 128
'''
