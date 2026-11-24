"""Independent native assertions for current Core diagnostics and VM outcomes."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
ROOT=Path(__file__).resolve().parents[1]
PREFIX=b'{\n  "diagnostics": [\n    {\n      "code": "E_DRIVER",\n      "message": "'
SUFFIX=b'",\n      "phase": "driver"\n    }\n  ],\n  "ok": false,\n  "status": "error"\n}\n'
def equal(name,raw):
    text=f'\ndef {name}(s:readbuf, at:u64) -> bool:\n    if at > length(s) or {len(raw)} > length(s) - at:\n        return False\n'
    for i,value in enumerate(raw):text+=f'    if byte(s, at + {i}) != {value}:\n        return False\n'
    return text+'    return True\n'
SOURCE="""
def uint(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (8 * i))
        i = i + 1
    return value

def hex_digit(value:u64) -> bool:
    return (value >= 48 and value <= 57) or (value >= 65 and value <= 70) or (value >= 97 and value <= 102)

def outcome(status:u64, detail:u64) -> u64:
    if status >= 1 and status <= 4:
        if detail >= 12:
            return 255
        if status == 2:
            return 2
        return 1
    if status == 5:
        return 6
    if status == 6:
        return 7
    if status == 7:
        return 5
    if status == 8:
        return 1
    if status == 9:
        return 2
    if status == 10:
        return 3
    if status == 11:
        return 4
    if (status == 15 or status == 17) and detail == 1:
        return 4
    if status == 16 and (detail == 1 or detail == 2 or detail == 19):
        return 8
    if status == 18 and ((detail >= 1 and detail <= 11) or (detail >= 24 and detail <= 27)):
        return 3
    if status == 19 and (detail == 21 or detail == 22):
        return 3
    return 255

def vm(s:readbuf) -> bool:
    kind = uint(s, 16)
    wanted = uint(s, 24)
    budget = uint(s, 32)
    returns = uint(s, 40)
    snapshots = uint(s, 48)
    if kind > 2 or wanted > 8 or budget == 0 or budget == 18446744073709551615 or returns > 4096 or snapshots > 33554432:
        return False
    if length(s) != 208 + returns * 8 + snapshots or uint(s, 64) != 3549488768910182728:
        return False
    status = uint(s, 72)
    steps = uint(s, 80)
    detail = uint(s, 88)
    if steps > budget:
        if status != 5 or steps != budget + 1:
            return False
    if kind == 0:
        return status == 0 and wanted == 0
    if returns != 0:
        return False
    actual = outcome(status, detail)
    if actual != wanted or actual == 255:
        return False
    is_budget = status == 5 or status == 6 or status == 16
    return (kind == 2 and is_budget) or (kind == 1 and is_budget == False)

def diagnostic(s:readbuf) -> bool:
    code_size = uint(s, 16)
    report_size = uint(s, 24)
    if uint(s, 32) != 0 or uint(s, 40) != 0 or uint(s, 48) != 0:
        return False
    if code_size < 3 or code_size > 64 or report_size > 8388608 or length(s) != 64 + code_size + report_size:
        return False
    if byte(s, 64) != 69 or byte(s, 65) != 95:
        return False
    i = 0
    while i < code_size:
        value = byte(s, 64 + i)
        if value != 95 and (value < 65 or value > 90):
            return False
        i = i + 1
    start = 64 + code_size
    if prefix(s, start) == False:
        return False
    at = start + PREFIX_SIZE
    if length(s) - at < code_size + 2:
        return False
    i = 0
    while i < code_size:
        if byte(s, at + i) != byte(s, 64 + i):
            return False
        i = i + 1
    if byte(s, at + code_size) != 58:
        return False
    while at < length(s):
        value = byte(s, at)
        if value == 34:
            return length(s) - at == SUFFIX_SIZE and suffix(s, at)
        if value < 32:
            return False
        if value == 92:
            if length(s) - at < 2:
                return False
            escaped = byte(s, at + 1)
            if escaped == 117:
                if length(s) - at < 6:
                    return False
                i = 2
                while i < 6:
                    if hex_digit(byte(s, at + i)) == False:
                        return False
                    i = i + 1
                at = at + 6
            else:
                if escaped != 34 and escaped != 92 and escaped != 47 and escaped != 98 and escaped != 102 and escaped != 110 and escaped != 114 and escaped != 116:
                    return False
                at = at + 2
        else:
            if value < 128:
                at = at + 1
            else:
                width = 0
                if value >= 194 and value <= 223:
                    width = 2
                if value >= 224 and value <= 239:
                    width = 3
                if value >= 240 and value <= 244:
                    width = 4
                if width == 0 or width > length(s) - at:
                    return False
                second = byte(s, at + 1)
                if (value == 224 and second < 160) or (value == 237 and second >= 160) or (value == 240 and second < 144) or (value == 244 and second >= 144):
                    return False
                i = 1
                while i < width:
                    value = byte(s, at + i)
                    if value < 128 or value > 191:
                        return False
                    i = i + 1
                at = at + width
    return False

def gate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 8:
        return 4294967294
    if length(s) < 64 or uint(s, 0) != GATE_MAGIC or uint(s, 56) != 0:
        return 4294967295
    mode = uint(s, 8)
    accepted = False
    if mode == 0:
        accepted = vm(s)
    if mode == 1:
        accepted = diagnostic(s)
    if accepted == False:
        return 4294967295
    store(o, 0, 72)
    store(o, 1, 73)
    store(o, 2, 65)
    store(o, 3, 81)
    store(o, 4, 79)
    store(o, 5, 75)
    store(o, 6, 48)
    store(o, 7, 49)
    return 8
"""
def source_program():
    source=SOURCE.replace('GATE_MAGIC',str(int.from_bytes(b'HIAQCG01','little'))).replace('PREFIX_SIZE',str(len(PREFIX))).replace('SUFFIX_SIZE',str(len(SUFFIX)))
    source=source.replace('3549488768910182728',str(int.from_bytes(b'HIASPR01','little')))
    start=source.index('def gate(')
    source=source[start:]+source[:start]
    return source+equal('prefix',PREFIX)+equal('suffix',SUFFIX)
def main():
    doc=document(source_program(),'cold_cases_gate')
    path=ROOT/'examples/hia_bootstrap/cold_cases_gate.hepta'
    path.write_text(render_assembly(doc))
    print({'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),'ops':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])})
if __name__=='__main__':main()
