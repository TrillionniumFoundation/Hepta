"""Author the fixed HIA Cell flat-image to ET_REL packer.

The assembler and reference_object are independent qualification oracles only.
The installed packer writes every object byte itself from one bounded flat.
"""
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "examples/hia_cell_bridge/image_packer.hepta"
MAX_EXTENT = 65792
MAX_FLAT = (1 << 20) - 4096
MAGIC = int.from_bytes(b"HCLPACK1", "little")
BRIDGE = bytes.fromhex(
    '4881fe000101000f87940000004885f674154885ff0f84900000004989fa4901f20f828e0000004881f90001010077714885c9740d4885d274714989d34901cb72734981f90001010077564d85c9740d4d85c074564c89c04c01c872584885f674114885c9740c4939d276074939fb7602eb4c4885f674114d85c9740c4d39c276074839f87602eb364885c974114d85c9740c4d39c376074839d07602eb20eb28b80100000048c1e020c3b80200000048c1e020c3b80300000048c1e020c3b80400000048c1e020c3'
)
SECTIONS = b"\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0"


def fixed_parts():
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
        1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 7, 5,
    )
    symbols = (bytes(24) + struct.pack("<IBBHQQ", 0, 3, 0, 1, 0, 0)
               + struct.pack("<IBBHQQ", 1, 18, 0, 1, 0, 0))
    strings = b"\0cell_bridge_step\0"
    rows = [bytes(64)]
    for name, kind, flags, size, link, info, align, extent in (
        (".text", 1, 6, 0, 0, 0, 16, 0),
        (".rela.text", 4, 0, 0, 3, 1, 8, 24),
        (".symtab", 2, 0, len(symbols), 4, 2, 8, 24),
        (".strtab", 3, 0, len(strings), 0, 0, 1, 0),
        (".shstrtab", 3, 0, len(SECTIONS), 0, 0, 1, 0),
        (".note.GNU-stack", 1, 0, 0, 0, 0, 1, 0),
    ):
        rows.append(struct.pack(
            "<IIQQQQIIQQ", SECTIONS.index(name.encode() + b"\0"),
            kind, flags, 0, 0, size, link, info, align, extent,
        ))
    return header + BRIDGE, symbols, strings, b"".join(rows)


def reference_object(flat):
    """QA only: independently form the canonical fixed seven-section object."""
    if type(flat) is not bytes or not 0 < len(flat) <= MAX_FLAT:
        raise ValueError("one bounded nonempty Cell flat image is required")
    prefix, symbols, strings, sections = fixed_parts()
    raw = bytearray(prefix + flat)
    text_size = len(raw) - 64
    raw.extend(bytes((-len(raw)) % 8))
    symbol_at = len(raw)
    raw.extend(symbols)
    string_at = len(raw)
    raw.extend(strings)
    names_at = len(raw)
    raw.extend(SECTIONS)
    stack_at = len(raw)
    raw.extend(bytes((-len(raw)) % 8))
    section_at = len(raw)
    raw.extend(sections)
    struct.pack_into("<Q", raw, 40, section_at)
    struct.pack_into("<Q", raw, symbol_at + 64, text_size)
    struct.pack_into("<QQ", raw, section_at + 88, 64, text_size)
    for index, offset in enumerate(
        (symbol_at, symbol_at, string_at, names_at, stack_at), 2
    ):
        struct.pack_into("<Q", raw, section_at + 64 * index + 24, offset)
    return bytes(raw)


def emitters(name, raw):
    functions, calls = [], []
    for group, first in enumerate(range(0, len(raw), 384)):
        fn = "emit_" + name + "_" + str(group)
        calls.append(fn)
        lines = [f"def {fn}(o:mutbuf, base:u64) -> u64:"]
        for at in range(first, min(first + 384, len(raw)), 8):
            chunk = raw[at:at + 8]
            if any(chunk):
                lines.append(
                    f"    write(o, base + {at}, {int.from_bytes(chunk, 'little')}, {len(chunk)})"
                )
        lines.append("    return 0")
        functions.append("\n".join(lines))
    return calls, "\n\n".join(functions)


def source_program():
    prefix, symbols, strings, sections = fixed_parts()
    functions, calls = [], {}
    for name, raw in (
        ("prefix", prefix), ("tail", symbols + strings + SECTIONS),
        ("sections", sections),
    ):
        calls[name], text = emitters(name, raw)
        functions.append(text)
    program = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<32 or uint(s,0,8)!={MAGIC}:
        return 4294967295
    count=uint(s,8,8)
    if count==0 or count>{MAX_FLAT} or length(s)!=32+count:
        return 4294967295
    if uint(s,16,8)!={MAX_EXTENT} or uint(s,24,8)!=0:
        return 4294967295
    text_size={len(BRIDGE)}+count
    symbols=(64+text_size+7)&18446744073709551608
    strings=symbols+{len(symbols)}
    names=strings+{len(strings)}
    stack=names+{len(SECTIONS)}
    sections=(stack+7)&18446744073709551608
    size=sections+448
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for name, at in (("prefix", "0"), ("tail", "symbols"), ("sections", "sections")):
        for fn in calls[name]:
            program += f"    {fn}(o,{at})\n"
    program += f'''    write(o,40,sections,8)
    write(o,symbols+64,text_size,8)
    write(o,sections+88,64,8)
    write(o,sections+96,text_size,8)
    write(o,sections+152,symbols,8)
    write(o,sections+216,symbols,8)
    write(o,sections+280,strings,8)
    write(o,sections+344,names,8)
    write(o,sections+408,stack,8)
    i=0
    while i<count:
        store(o,{len(prefix)}+i,byte(s,32+i))
        i=i+1
    return size
'''
    return program + "\n\n" + "\n\n".join(functions) + HELPERS


HELPERS = '''
def uint(s:readbuf,at:u64,count:u64) -> u64:
    value=0
    i=0
    while i<count:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def write(o:mutbuf,at:u64,value:u64,count:u64) -> u64:
    i=0
    while i<count:
        store(o,at+i,(value>>(8*i))&255)
        i=i+1
    return 0
'''


def generated_source():
    return render_assembly(document(source_program(), "cell_bridge_image_packer")).encode()


def main():
    target = ROOT / SOURCE_PATH
    raw = generated_source()
    target.write_bytes(raw)
    print(target, len(raw))


if __name__ == "__main__":
    main()
