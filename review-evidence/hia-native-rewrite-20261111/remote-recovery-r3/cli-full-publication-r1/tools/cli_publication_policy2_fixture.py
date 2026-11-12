"""Private issued-query publication fixture, not the E business service.
The actual public parent receives one policy-2 request and must use the complete
native Path/pretty/temp/write/verify/cleanup chain. This fixture only validates
the returned transport and forms the original JSON-view publication envelope.
No Graph admission, edit preparation or untrusted caller authority is claimed.
"""
from pathlib import Path
from hashlib import sha256
import cli_business_fixture_owners as F
assert sha256(Path(F.__file__).read_bytes()).hexdigest()=="fd66d47a9675567df0b1a2dc42cd33c40a3dba0ca85bfebfe9d29ec112703a67"
def source():
    f=F.Flow()
    f.event("grow","grow(o, w, 10, 128 + cap(w, 1), @NEXT@)")
    f.event("payload","copy(o, w, 1, 0, 10, 128, cap(w, 1), @NEXT@)")
    f.add("header",'''zero(w, WIRE, 128)
wire8(w, B_EVENT, 1, 2, 2, get(w, C_SEQUENCE) + 3, 1, 2, 0)
put(w, WIRE + 72, 2)
put(w, WIRE + 80, 2)
put(w, WIRE + 88, 8)
put(w, WIRE + 96, 128)
put(w, WIRE + 104, cap(w, 1))
put(w, WIRE + 112, 128 + cap(w, 1))
return copy(o, w, 2, WIRE, 10, 0, 128, @NEXT@)''')
    f.event("readonly","protect(o, w, 10, 1, @NEXT@)")
    f.add("yield",'''put(w, C_OBSERVE, 128)
args(w, 2, 0, 10, 0, cap(w, 10), 256, 0, 0, 0, 0, 0, 0)
return event(o, w, 18, @NEXT@)''')
    f.add("resume",'''if get(w, OBS) != B_REPLY or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 2 or get(w, OBS + 24) != 2:
    return refuse(w, 7400)
if get(w, OBS + 32) != get(w, C_SEQUENCE) or get(w, OBS + 40) != 1 or get(w, OBS + 48) != 2 or get(w, OBS + 56) == 0:
    return refuse(w, 7401)
if get(w, OBS + 64) != 2 or get(w, OBS + 72) != 8 or get(w, OBS + 80) < 130 or get(w, OBS + 88) != 2 or cap(w, 8) != 0:
    return refuse(w, 7402)
put(w, CAPS + 64, get(w, OBS + 80))
put(w, EXPECT_PARENT, get(w, OBS + 56))
return view(o, w, 8, 0, 128, @NEXT@)''')
    f.add("publication",'''if get(w, OBS) != PUBLICATION or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 2 or get(w, OBS + 24) != 2:
    return refuse(w, 7403)
if get(w, OBS + 32) != get(w, C_SEQUENCE) - 1 or get(w, OBS + 40) != 1 or get(w, OBS + 48) != get(w, EXPECT_PARENT) or get(w, OBS + 56) != 2:
    return refuse(w, 7404)
if get(w, OBS + 64) != 128 or get(w, OBS + 72) < 2 or get(w, OBS + 80) != 128 + get(w, OBS + 72) or get(w, OBS + 88) == 0:
    return refuse(w, 7405)
if get(w, OBS + 80) > cap(w, 8) or get(w, OBS + 88) != cap(w, 8) - get(w, OBS + 80) or get(w, OBS + 96) != cap(w, 8):
    return refuse(w, 7406)
if get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
    return refuse(w, 7407)
put(w, DEST_N, get(w, OBS + 72))
put(w, RECEIPT_AT, get(w, OBS + 80))
put(w, RECEIPT_N, get(w, OBS + 88))
if get(w, DEST_N) > MAX - 4096 or get(w, RECEIPT_N) > MAX - 4096 - get(w, DEST_N):
    return refuse(w, 7408)
return release(o, w, 10, @NEXT@)''')
    f.event("large-output","grow(o, w, 10, 228 + get(w, DEST_N) + get(w, RECEIPT_N), @NEXT@)")
    prefix=b'{"ok":true,"output":';middle=b',"publication":'
    suffix=b',"schema":"hepta.hia.json-view-output.v1","view_schema":"sample"}'
    constants=F.constants(0,2,1048576)
    constants.update(PUBLICATION=F.magic("HIACPR01"),EXPECT_PARENT=22000,DEST_N=22008,
        RECEIPT_AT=22016,RECEIPT_N=22024,OUTPUT_N=22032)
    literals=[]
    for name,raw in (("prefix",prefix),("middle",middle),("suffix",suffix)):
        lines=[f"def {name}(w:mutbuf) -> u64:"]
        for at in range(0,len(raw),8):
            chunk=raw[at:at+8];lines.append(f"    put(w, {23000+at}, {int.from_bytes(chunk,'little')})")
        lines.append("    return 0");literals.append("\n".join(lines)+"\n")
    f.add("prefix",f"prefix(w)\nreturn copy(o, w, 2, 23000, 10, 128, {len(prefix)}, @NEXT@)")
    f.event("dest",f"copy(o, w, 8, 128, 10, {128+len(prefix)}, get(w, DEST_N), @NEXT@)")
    f.add("middle",f"middle(w)\nreturn copy(o, w, 2, 23000, 10, {128+len(prefix)} + get(w, DEST_N), {len(middle)}, @NEXT@)")
    f.event("receipt",f"copy(o, w, 8, get(w, RECEIPT_AT), 10, {128+len(prefix)+len(middle)} + get(w, DEST_N), get(w, RECEIPT_N), @NEXT@)")
    f.add("suffix",f"suffix(w)\nreturn copy(o, w, 2, 23000, 10, {128+len(prefix)+len(middle)} + get(w, DEST_N) + get(w, RECEIPT_N), {len(suffix)}, @NEXT@)")
    f.add("final-header",f'''put(w, OUTPUT_N, {len(prefix)+len(middle)+len(suffix)} + get(w, DEST_N) + get(w, RECEIPT_N))
zero(w, WIRE, 128)
wire8(w, B_EVENT, 1, 2, 2, get(w, C_SEQUENCE) + 3, 0, 3, 0)
put(w, WIRE + 80, 1)
put(w, WIRE + 96, 128)
put(w, WIRE + 104, get(w, OUTPUT_N))
put(w, WIRE + 112, 128 + get(w, OUTPUT_N))
return copy(o, w, 2, WIRE, 10, 0, 128, @NEXT@)''')
    f.event("final-readonly","protect(o, w, 10, 1, @NEXT@)")
    f.add("final",'''put(w, C_OBSERVE, 128)
args(w, 2, 1, 10, 0, 128 + get(w, OUTPUT_N), 0, 0, 0, 0, 0, 0, 0)
return event(o, w, 18, @NEXT@)''')
    f.add("done","return refuse(w, 7409)")
    init=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 128 or word(s, 0) != B_INIT or word(s, 8) != 1 or word(s, 16) != 2 or word(s, 24) != 2:
            return refuse(w, 7410)
        if word(s, 48) != 12 or word(s, 64) != cap(w, 1) or word(s, 72) != cap(w, 4) or word(s, 80) != cap(w, 5):
            return refuse(w, 7411)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 56)
        put(w, C_LEASE, 2)
        put(w, C_PHASE, 1)
    elif acknowledge(s, w, 56) == 0:
        return refuse(w, 7412)
    while get(w, L_STATUS) == 1:
        result = fixture_step(o, w, get(w, C_PHASE))
        if result != 0:
            return result
    return ABI
'''
    return init+f.render()+"\n".join(literals)+F.COMMON,constants
