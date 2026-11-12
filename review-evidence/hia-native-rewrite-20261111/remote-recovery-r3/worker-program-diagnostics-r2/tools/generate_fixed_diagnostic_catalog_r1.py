"""Native fixed diagnostic catalog from exact original refusal tables.

This file is development authoring only. The installed runtime receives a
native-issued terminal frame and emits its complete text in HIA. No Python
module, dictionary lookup or formatter participates in a native invocation.
Groups 6 and 9 remain excluded until their actual original routing is read.
"""
from __future__ import annotations
import ast,struct
from hashlib import sha256
from pathlib import Path
from tools.cli_authoring import document,expanded

TABLES=(
 (1,"hia_composite_constructor_errors.py","d19bd1da6a08a4e78994fb97005061279569c2bb865486f8707927b281a583db",14),
 (2,"hia_composite_types_native.py","3b40690bc0164a78b96b3a46729a59c0afae0172eeae5218d264e4b9dfc65ae3",50),
 (3,"hia_composite_functions_errors.py","64324171706dc1f8646b124653327bd2d84b6d1ba5f110e7f4d356993a05f604",113),
 (4,"hia_task_helpers_native.py","afc071582363f01f5a98f5c247101b9d4ddee4928361f60f5c5cc7adf12ae290",3),
)
OUTER=("hia_composite_outer_native.py","9947a9efce8e9bc95ff9b9328b1d30973557a40a5b22172e62d44166c6e3b594")
BAD=0xfffffffd
NEED=0xfffffffe
COMMAND=int.from_bytes(b"HIADGC01","little")
RESULT=int.from_bytes(b"HIADGT01","little")
EVENT=int.from_bytes(b"HIACDE01","little")

def literal_table(path,expected):
    raw=path.read_bytes()
    assert sha256(raw).hexdigest()==expected,(str(path),sha256(raw).hexdigest())
    tree=ast.parse(raw,filename=str(path))
    matches=[n.value for n in tree.body if isinstance(n,ast.Assign)
             and any(isinstance(t,ast.Name) and t.id=="ERRORS" for t in n.targets)]
    assert len(matches)==1,(str(path),len(matches))
    value=ast.literal_eval(matches[0])
    assert type(value) is dict
    for error,pair in value.items():
        assert type(error) is int and 0<error<1<<32 and error!=999
        assert type(pair) is tuple and len(pair)==2
        assert all(type(v) is str for v in pair)
        assert pair[0].startswith("E_HIA_") and "\x00" not in "".join(pair)
    return value,raw

def catalog(reference):
    reference=Path(reference)
    rows=[];pins=[]
    for group,name,expected,count in TABLES:
        table,raw=literal_table(reference/name,expected)
        assert len(table)==count,(name,len(table),count)
        pins.append(dict(path=str(reference/name),bytes=len(raw),sha256=expected))
        for error,(code,message) in sorted(table.items()):
            rows.append(dict(group=group,error=error,code=code,message=message,
                             text=(code+": "+message).encode("utf-8")))
    name,expected=OUTER
    raw=(reference/name).read_bytes()
    assert sha256(raw).hexdigest()==expected
    tree=ast.parse(raw,filename=name)
    required=("elaborated program exceeds core inventory budget","E_HIA_LIMIT")
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
           and isinstance(n.func,ast.Name) and n.func.id=="HIAProgramRejected"
           and len(n.args)==2 and all(isinstance(a,ast.Constant) for a in n.args)]
    assert any(tuple(a.value for a in n.args)==required for n in calls)
    rows.append(dict(group=5,error=1,code=required[1],message=required[0],
                     text=(required[1]+": "+required[0]).encode()))
    pins.append(dict(path=str(reference/name),bytes=len(raw),sha256=expected))
    rows.sort(key=lambda r:(r["group"],r["error"]))
    assert len(rows)==181 and len({(r["group"],r["error"]) for r in rows})==181
    text_at=16+len(rows)*16
    strings=bytearray();index=bytearray()
    for row in rows:
        raw=row["text"];offset=text_at+len(strings)
        assert 0<len(raw)<1<<32 and offset<1<<32
        index+=struct.pack("<QQ",(row["group"]<<32)|row["error"],(offset<<32)|len(raw))
        strings+=raw
    rom=struct.pack("<QQ",len(rows),text_at)+index+strings
    rom+=bytes((-len(rom))%8)
    assert len(rom)<=32768
    return rows,bytes(rom),pins

BODY=r'''
def fixed_diagnostic(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 192 or length(o) < 128 or length(w) < ROM_BYTES:
        return BAD
    if diag_word(s, 0) != DIAG_COMMAND or diag_word(s, 8) != 1:
        return BAD
    parent = diag_word(s, 16)
    sequence = diag_word(s, 24)
    child = diag_word(s, 32)
    child_sequence = diag_word(s, 40)
    if parent == 0 or parent > MAX - 3 or sequence == 0 or child != parent + 2 or child_sequence == 0:
        return BAD
    if diag_word(s, 48) != 46 or diag_word(s, 56) != 0:
        return BAD
    if diag_word(s, 64) != DIAG_EVENT or diag_word(s, 72) != 7:
        return BAD
    if diag_word(s, 80) != child or diag_word(s, 88) != child_sequence:
        return BAD
    group = diag_word(s, 96)
    error = diag_word(s, 104)
    if group < 1 or group > 5 or error == 0 or error > 4294967295 or error == 999:
        return BAD
    diag_initialize(w)
    found = diag_lookup(w, group, error)
    if found == 0:
        return BAD
    size = found & 4294967295
    offset = found >> 32
    if offset < TEXT_AT or offset > ROM_BYTES or size == 0 or size > ROM_BYTES - offset:
        return BAD
    needed = 128 + size
    diag_put(o, 0, DIAG_RESULT)
    diag_put(o, 8, 1)
    diag_put(o, 16, parent)
    diag_put(o, 24, sequence)
    diag_put(o, 32, child)
    diag_put(o, 40, child_sequence)
    diag_put(o, 48, group)
    diag_put(o, 56, error)
    diag_put(o, 64, diag_word(s, 112))
    diag_put(o, 72, size)
    diag_put(o, 80, needed)
    diag_put(o, 88, 0)
    at = 0
    while at < 32:
        store(o, 96 + at, byte(s, 160 + at))
        at = at + 1
    if length(o) < needed:
        return NEED
    at = 0
    while at < size:
        store(o, 128 + at, byte(w, offset + at))
        at = at + 1
    return needed

def diag_lookup(w:mutbuf, group:u64, error:u64) -> u64:
    key = (group << 32) | error
    low = 0
    high = CATALOG_COUNT
    found = 0
    while low < high:
        middle = (low + high) >> 1
        row = 16 + middle * 16
        value = diag_get(w, row)
        if value < key:
            low = middle + 1
        elif value > key:
            high = middle
        else:
            found = diag_get(w, row + 8)
            high = low
    return found

def diag_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def diag_get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def diag_put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''

def source_program(reference):
    rows,rom,pins=catalog(reference)
    functions=[]
    chunk=128*8
    for index,start in enumerate(range(0,len(rom),chunk)):
        lines=[f"def diag_initialize_{index}(w:mutbuf) -> u64:"]
        for at in range(start,min(start+chunk,len(rom)),8):
            lines.append(f"    diag_put(w, {at}, {int.from_bytes(rom[at:at+8],'little')})")
        lines.append("    return 0")
        functions.append("\n".join(lines))
    calls=["def diag_initialize(w:mutbuf) -> u64:"]
    calls.extend(f"    diag_initialize_{i}(w)" for i in range(len(functions)))
    calls.append("    return 0")
    constants=dict(BAD=BAD,NEED=NEED,DIAG_COMMAND=COMMAND,DIAG_RESULT=RESULT,
                   DIAG_EVENT=EVENT,MAX=(1<<64)-1,ROM_BYTES=len(rom),
                   CATALOG_COUNT=len(rows),TEXT_AT=16+len(rows)*16)
    text=expanded(BODY+"\n"+"\n\n".join(functions)+"\n"+"\n".join(calls)+"\n",constants)
    inventory=dict(schema="hia-fixed-diagnostic-source-catalog-v1",
      entries=[{k:v for k,v in row.items() if k!="text"}|
               dict(bytes=len(row["text"]),sha256=sha256(row["text"]).hexdigest())
               for row in rows],reference_pins=pins,
      ROM_bytes=len(rom),ROM_sha256=sha256(rom).hexdigest(),text_start=constants["TEXT_AT"],
      private_command_bytes=192,header_bytes=128,
      exact_native_terminal_bytes=128,groups=[1,2,3,4,5],
      delegated_error999_is_not_formatted=True,open_groups=[6,9],
      original_dynamic_Core_group8_unchanged=True,whole_public_diagnostics_closed=False)
    return text,inventory,rom

def generated_document(reference):
    text,inventory,rom=source_program(reference)
    return document(text,"fixed_public_diagnostic_catalog_r1"),text,inventory,rom
