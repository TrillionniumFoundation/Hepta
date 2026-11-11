"""HIA-only private issuer for real A-service integration.
The issuer is a test owner; all program admission, projection and wire decisions
remain in their actual fixed native HIA images. No host services a pending event.
"""
import ast,struct
import cli_business_fixture_owners as fixture

def source(program,action,digits=4300):
    program=bytes(program)
    assert action in (6,7,8) and len(program)<26000
    argv=b"hia\0"+{6:b"verify",7:b"inspect",8:b"normalize"}[action]+b"\0input.hia\0"
    parser=bytearray(1536)
    struct.pack_into("<4Q",parser,1024,1,1,4,len({6:b"verify",7:b"inspect",8:b"normalize"}[action]))
    struct.pack_into("<4Q",parser,1056,1,1,len(argv)-10,9)
    if action==8:struct.pack_into("<4Q",parser,1088,1,0,0,0)
    payloads={4:program,5:argv,6:bytes(parser)}
    f=fixture.Flow()
    data_functions=[]
    cursor=20000
    for slot,raw in payloads.items():
        name="input_data_"+str(slot)
        # Bound each literal initializer independently of input content.
        # This changes no issued byte or service command. The original B3
        # per-block scalar limits still apply to every generated helper.
        pieces=[]
        for first in range(0,len(raw),128):
            helper=name+"_part_"+str(first//128);pieces.append(helper)
            lines=["def "+helper+"(w:mutbuf) -> u64:"]
            for at in range(first,min(first+128,len(raw)),8):
                part=raw[at:at+8]
                if len(part)==8:
                    lines.append("    put(w, "+str(cursor+at)+", "+str(int.from_bytes(part,"little"))+")")
                else:
                    lines.extend("    store(w, "+str(cursor+at+i)+", "+str(c)+")" for i,c in enumerate(part))
            lines.append("    return 0");data_functions.append("\n".join(lines)+"\n")
        lines=["def "+name+"(w:mutbuf) -> u64:"]
        lines.extend("    "+helper+"(w)" for helper in pieces)
        lines.append("    return 0");data_functions.append("\n".join(lines)+"\n")
        f.event("grow-"+str(slot),f"grow(o, w, {slot}, {max(1,len(raw))}, @NEXT@)")
        f.add("copy-"+str(slot),name+"(w)\n"+f"return copy(o, w, 2, {cursor}, {slot}, 0, {len(raw)}, @NEXT@)")
        f.event("protect-"+str(slot),f"protect(o, w, {slot}, 1, @NEXT@)")
        cursor+=len(raw)+8
    assert cursor<64000
    f.event("command-grow","grow(o, w, 13, 128, @NEXT@)")
    f.event("table-grow","grow(o, w, 14, 128, @NEXT@)")
    f.add("initial-table",f'''zero(w, WIRE, 128)
wire8(w, B_LEASES, 1, 3, 128, {4 if program else 0}, 0, {len(program)}, 1)
put(w, WIRE + 64, 5)
put(w, WIRE + 80, {len(argv)})
put(w, WIRE + 88, 4)
put(w, WIRE + 96, 6)
put(w, WIRE + 112, {len(parser)})
put(w, WIRE + 120, 5)
return copy(o, w, 2, WIRE, 14, 0, 128, @NEXT@)''')
    f.event("table-protect","protect(o, w, 14, 1, @NEXT@)")
    f.add("initial-command",f'''zero(w, WIRE, 128)
wire8(w, B_INIT, 1, 1, 2, 1, get(w, C_SEQUENCE) + 3, {action}, {digits})
put(w, WIRE + 64, {len(program)})
put(w, WIRE + 72, {len(argv)})
put(w, WIRE + 80, {len(parser)})
put(w, WIRE + 88, 16)
put(w, WIRE + 96, 1024)
put(w, WIRE + 104, 32)
return copy(o, w, 2, WIRE, 13, 0, 128, @NEXT@)''')
    f.event("command-protect","protect(o, w, 13, 1, @NEXT@)")
    f.add("begin",'''put(w, C_OBSERVE, 128)
args(w, 1, 1, 2, 13, 0, 128, 14, 0, 128, 15, 0, 0)
return event(o, w, 17, @NEXT@)''')
    f.add("begin-ack",'''if get(w, OBS) != B_ACK or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 1:
    return refuse(w, 2700)
if get(w, OBS + 24) != 2 or get(w, OBS + 32) != 2 or get(w, OBS + 40) == 0 or get(w, OBS + 48) != 56:
    return refuse(w, 2701)
if get(w, OBS + 56) != 1 or get(w, OBS + 64) != 15 or get(w, OBS + 72) <= 128 or get(w, OBS + 80) != 1:
    return refuse(w, 2702)
if get(w, OBS + 88) != get(w, C_SEQUENCE):
    return refuse(w, 2703)
at = 96
while at < 128:
    if get(w, OBS + at) != 0:
        return refuse(w, 2704)
    at = at + 8
put(w, CHILD_SEQ, get(w, OBS + 40))
put(w, CHILD_EXTENT, get(w, OBS + 72))
put(w, CAPS + 15 * 8, get(w, CHILD_EXTENT))
return view(o, w, 15, 0, 128, @NEXT@)''')
    f.add("result-header",'''if get(w, OBS) != B_EVENT or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 1 or get(w, OBS + 24) != 2:
    return refuse(w, 2705)
if get(w, OBS + 32) != get(w, CHILD_SEQ) or get(w, OBS + 40) != 0:
    return refuse(w, 2706)
if get(w, OBS + 48) != 3 and get(w, OBS + 48) != 4:
    return refuse(w, 2707)
if get(w, OBS + 72) != 0 or get(w, OBS + 88) != 0:
    return refuse(w, 2708)
if get(w, OBS + 96) != 128 or get(w, OBS + 104) != get(w, CHILD_EXTENT) - 128 or get(w, OBS + 112) != get(w, CHILD_EXTENT) or get(w, OBS + 120) != 0:
    return refuse(w, 2709)
put(w, C_OBSERVE, 0)
args(w, 3, 1, 2, 0, 0, 0, 0, 0, 0, 0, get(w, CHILD_SEQ), 0)
return event(o, w, 17, @NEXT@)''')
    # RETIRE must leave the parent's result as owned, readonly bytes.
    f.event("retired-result","view(o, w, 15, 0, 128, @NEXT@)")
    f.add("after-retire",'''if get(w, OBS) != B_EVENT or get(w, OBS + 32) != get(w, CHILD_SEQ) or get(w, OBS + 112) != get(w, CHILD_EXTENT):
    return refuse(w, 2710)
return protect(o, w, 4, 0, @NEXT@)''')
    f.event("unpin-input","release(o, w, 4, @NEXT@)")
    f.add("complete",'''zero(o, 0, 128)
put(o, 0, EVENT_MAGIC)
put(o, 8, 7)
put(o, 16, 1)
put(o, 24, get(w, C_SEQUENCE))
put(o, 40, 15)
put(o, 48, 0)
put(o, 56, get(w, CHILD_EXTENT))
return 128''')
    entry=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 65536 or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 64 or word(s, 0) != CLI_INIT or word(s, 8) != 1:
            return refuse(w, 2711)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 7)
        put(w, C_LEASE, 1)
        put(w, C_PHASE, 1)
        put(w, CAPS + 8, word(s, 16))
        put(w, CAPS + 16, 65536)
        put(w, CAPS + 24, 128)
    elif acknowledge(s, w, 7) == 0:
        return refuse(w, 2712)
    while get(w, L_STATUS) == 1:
        result = fixture_step(o, w, get(w, C_PHASE))
        if result != 0:
            return result
    return ABI
'''
    body=entry+f.render()+"".join(data_functions)+fixture.COMMON
    tree=ast.parse(body)
    for node in tree.body:
        if node.name!="entry" and node.returns.id=="u32":node.returns.id="u64"
    return ast.unparse(tree)+"\n",fixture.constants(0,1,65536),dict(action=action,digits=digits,
        program_bytes=len(program),argv_bytes=len(argv),parser_bytes=len(parser),
        private_HIA_issuer=True,actual_public_parser_claim=False)
