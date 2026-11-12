"""HIA reader/formatter for actual issued type-owner first-error context.

Inputs are two readonly leases: the actual 128 MiB type workspace and a fixed
128-byte command containing the actual 64-byte type result header. This is a
private continuation component, not authentication of arbitrary workspaces.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
from tools.cli_authoring import document,expanded
from tools.extend_native_type_context_r1 import (
 CONTEXT_MAGIC,CONTEXT_OFFSET,CONTEXT_BYTES,WHERE,NAME_CONTEXTS,SHAPE_CONTEXTS)

COMMAND=int.from_bytes(b"HIATDC01","little")
RESULT=int.from_bytes(b"HIATDE01","little")
TYPES=int.from_bytes(b"HIATYP01","little")
PARAMETERS=int.from_bytes(b"HIAPRM01","little")
ORIGINS=int.from_bytes(b"HIALOR01","little")
STATE=int.from_bytes(b"HIATYS01","little")
KEYS=("op","definitions","recursive_chain","partial_records","ref","base",
 "initialized","kind","name","params","fields","variants","state","result",
 "poll","cancel","type","args","partial","returns","return_loans","param",
 "task","functions")
S=96*1024*1024

def catalog():
    rows=[]
    for where in NAME_CONTEXTS:
        for code,suffix in ((5,"invalid/reserved ASCII identifier"),
                            (6,"identifier uses the elaborator namespace")):
            text=("E_HIA_NAME: "+WHERE[where]+": "+suffix).encode("ascii")
            rows.append(dict(code=code,where=where,mask=0,text=text))
    for where,shapes in SHAPE_CONTEXTS.items():
        for fields in shapes:
            assert len(set(fields))==len(fields)
            mask=sum(1<<KEYS.index(field) for field in fields)
            text=("E_HIA_FORMAT: "+WHERE[where]+": expected exactly "+", ".join(sorted(fields))).encode("ascii")
            rows.append(dict(code=1,where=where,mask=mask,text=text))
    rows.sort(key=lambda r:(r["code"],r["where"],r["mask"]))
    assert len(rows)==33
    assert len({(r["code"],r["where"],r["mask"]) for r in rows})==33
    return rows

BODY=r'''
def type_context(s:readbuf, r:readbuf, o:mutbuf) -> u32:
    if length(s) != WORK_BYTES or length(r) != 128 or length(o) < 128:
        return BAD
    if tc_word(r, 0) != CONTEXT_COMMAND or tc_word(r, 8) != 1:
        return BAD
    lease = tc_word(r, 16)
    sequence = tc_word(r, 24)
    request = tc_word(r, 32)
    operation = tc_word(r, 40)
    frame_bytes = tc_word(r, 48)
    if lease == 0 or sequence == 0 or request == 0 or operation < 1 or operation > 6 or tc_word(r, 56) != 0:
        return BAD
    if frame_bytes < 64 or frame_bytes > OUTPUT_BYTES or tc_word(r, 88) != frame_bytes - 64:
        return BAD
    frame_magic = TYPE_FRAME
    if operation == 2:
        frame_magic = PARAM_FRAME
    elif operation == 5:
        frame_magic = ORIGIN_FRAME
    if tc_word(r, 64) != frame_magic or tc_word(r, 80) != 0 or tc_word(r, 120) != 0:
        return BAD
    if tc_word(s, S) != TYPE_STATE:
        return BAD
    if operation == 1:
        if tc_word(s, S + 48) != 0:
            return BAD
    elif tc_word(s, S + 48) != 1:
        return BAD
    error = tc_word(s, S + 8)
    if error != 1 and error != 5 and error != 6:
        return BAD
    if tc_word(r, 72) != error:
        return BAD
    total = tc_word(s, S + 16)
    cached = tc_word(s, S + 24)
    steps = tc_word(s, S + 32)
    if total < 16 or cached > total - 16:
        return BAD
    if tc_word(r, 96) != cached or tc_word(r, 104) != total - 16 - cached or tc_word(r, 112) != steps:
        return BAD
    if tc_word(s, CONTEXT_AT) != CONTEXT_STATE or tc_word(s, CONTEXT_AT + 8) != 1 or tc_word(s, CONTEXT_AT + 16) != error:
        return BAD
    if tc_word(s, CONTEXT_AT + 48) != 0 or tc_word(s, CONTEXT_AT + 56) != 0:
        return BAD
    where = tc_word(s, CONTEXT_AT + 24)
    expected = tc_word(s, CONTEXT_AT + 32)
    node = tc_word(s, CONTEXT_AT + 40)
    if tc_node_bounded(node) == 0:
        return BAD
    if error != 1 and node == MAX:
        return BAD
    message = tc_select(error, where, expected)
    size = tc_size(message)
    if message == 0 or size == 0:
        return BAD
    needed = 128 + size
    tc_put(o, 0, CONTEXT_RESULT)
    tc_put(o, 8, 1)
    tc_put(o, 16, lease)
    tc_put(o, 24, sequence)
    tc_put(o, 32, request)
    tc_put(o, 40, operation)
    tc_put(o, 48, error)
    tc_put(o, 56, where)
    tc_put(o, 64, expected)
    tc_put(o, 72, node)
    tc_put(o, 80, size)
    tc_put(o, 88, needed)
    tc_put(o, 96, cached)
    tc_put(o, 104, total - 16 - cached)
    tc_put(o, 112, steps)
    tc_put(o, 120, 0)
    if length(o) < needed:
        return NEED
    tc_write(o, message)
    return needed

def tc_node_bounded(node:u64) -> u64:
    if node == MAX:
        return 1
    base = Q
    if node >= D:
        base = D
    if node < base + 64 or node > base + 33554432 - 56:
        return 0
    value = node - base - 64
    bits = 64
    remainder = 0
    while bits != 0:
        bits = bits - 1
        remainder = (remainder << 1) | ((value >> bits) & 1)
        if remainder >= 56:
            remainder = remainder - 56
    if remainder != 0:
        return 0
    return 1

def tc_word(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def tc_put(o:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, at + index, value & 255)
        value = value >> 8
        index = index + 1
    return 0
'''

def source():
    rows=catalog()
    functions=[]
    select=["def tc_select(code:u64, where:u64, mask:u64) -> u64:"]
    sizes=["def tc_size(message:u64) -> u64:"]
    write=["def tc_write(o:mutbuf, message:u64) -> u64:"]
    for index,row in enumerate(rows,1):
        select.extend([
            f'    if code == {row["code"]} and where == {row["where"]} and mask == {row["mask"]}:',
            f'        return {index}'])
        sizes.extend([f"    if message == {index}:",f'        return {len(row["text"])}'])
        write.extend([f"    if message == {index}:",f"        return tc_literal_{index}(o)"])
        lines=[f"def tc_literal_{index}(o:mutbuf) -> u64:"]
        data=row["text"];full=len(data)-(len(data)%8)
        for at in range(0,full,8):
            lines.append(f"    tc_put(o, {128+at}, {int.from_bytes(data[at:at+8],'little')})")
        for at in range(full,len(data)):lines.append(f"    store(o, {128+at}, {data[at]})")
        lines.append("    return 0");functions.append("\n".join(lines))
    select.append("    return 0");sizes.append("    return 0");write.append("    return 0")
    constants=dict(BAD=0xfffffffd,NEED=0xfffffffe,MAX=(1<<64)-1,
      WORK_BYTES=128*1024*1024,OUTPUT_BYTES=64*1024*1024,Q=32*1024*1024,D=64*1024*1024,S=S,
      CONTEXT_AT=CONTEXT_OFFSET,CONTEXT_STATE=CONTEXT_MAGIC,CONTEXT_COMMAND=COMMAND,
      CONTEXT_RESULT=RESULT,TYPE_STATE=STATE,TYPE_FRAME=TYPES,PARAM_FRAME=PARAMETERS,ORIGIN_FRAME=ORIGINS)
    text=BODY+"\n"+"\n\n".join(functions)+"\n"+"\n".join(select+sizes+write)+"\n"
    result=expanded(text,constants)
    return result,dict(schema="hia-native-type-context-reader-r1",
      rows=[{k:v for k,v in row.items() if k!="text"}|dict(
         text=row["text"].decode("ascii"),bytes=len(row["text"]),sha256=sha256(row["text"]).hexdigest())
         for row in rows],constants=constants,
      ABI="R/R/W actual type workspace / command plus actual native header / output",
      command_bytes=128,result_header_bytes=128,measurement_return=0xfffffffe,
      context_offset=CONTEXT_OFFSET,context_bytes=CONTEXT_BYTES,
      all_shapes_validated_before_output_capacity=True,
      same_actual_type_workspace_and_completed_command_required=True,
      arbitrary_external_workspaces_authenticated=False,
      first_error_only=True,semantic_errors=[1,5,6],whole_program_joined=False)

def generated_document():
    text,inventory=source()
    return document(text,"composite_type_context_reader_r1"),text,inventory
