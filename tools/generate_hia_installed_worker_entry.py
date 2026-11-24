"""Author the installed MCP-compatible Worker argument admission and ELF packer."""
from pathlib import Path
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_filter import bind_adapter, source_program as packer_source, elf_header

SOURCE = 'examples/hia_bootstrap/installed_worker_entry.hepta'
PACKER = 'examples/hia_bootstrap/installed_worker_entry_packer.hepta'
ADAPTER = 'tools/hia_installed_worker_entry.S'
MAGIC = int.from_bytes(b'HIAWEP01', 'little')
CONFIG_MAGIC = int.from_bytes(b'HIAWEC01', 'little')
# The six-argument entry takes argv and the bound configuration in separate
# borrowed buffers. Only the caller-selected state root passes to the Worker.
POLICY = '''
def admit(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) == 16:
        return anchor_selector(s,o)
    if length(o) == 24:
        return anchor_metadata(s)
    if length(w) < 104 or length(s) < 10 or length(o) != 8:
        return 0
    if get(w,0) != CONFIG_MAGIC or get(w,8) != length(w):
        return 0
    slot = 16
    stop = 104
    while slot < 104:
        p = get(w,slot)
        if p != stop or p > length(w) or length(w)-p < 8:
            return 0
        n = get(w,p)
        if n > length(w)-p-8:
            return 0
        stop = p+8+n
        slot = slot+8
    if stop != length(w):
        return 0
    end = read_word(s,length(s)-8)
    if end >= length(s)-8 or byte(s,length(s)-9) != 0:
        return 0
    p = 0
    if match(s,w,0,72):
        p = get(w,get(w,72))
    if suffix(s,w,p,96,end) or bound_suffix(s,w,p,88,end):
        return 2
    if match(s,w,p,80) == False:
        return 0
    p = p+get(w,get(w,80))
    if p+1 >= end or byte(s,p) != 47 or byte(s,p+1) == 0:
        return 0
    root = p
    part = p+1
    p = p+1
    while p < end and p-root < 4096:
        c = byte(s,p)
        if c == 0 or c == 47:
            n = p-part
            if n == 0 or (n == 1 and byte(s,part) == 46) or (n == 2 and byte(s,part) == 46 and byte(s,part+1) == 46):
                return 0
            if c == 0:
                if bound_suffix(s,w,p+1,64,end) == False:
                    return 0
                put(o,0,root)
                return 1
            part = p+1
        p = p+1
    return 0

def suffix(s:readbuf,w:mutbuf,p:u64,slot:u64,end:u64) -> bool:
    return p <= end and get(w,get(w,slot)) == end-p and match(s,w,p,slot)

def bound_suffix(s:readbuf,w:mutbuf,p:u64,slot:u64,end:u64) -> bool:
    q = get(w,slot)
    z = get(w,q)
    if z < 8 or p > end:
        return False
    before = get(w,q+8)
    profile = length(s)-8-end
    if before > z-8 or z-8+profile != end-p:
        return False
    q = q+16
    i = 0
    while i < before:
        if byte(s,p+i) != byte(w,q+i):
            return False
        i = i+1
    p = p+before
    q = q+before
    i = 0
    while i < profile:
        if byte(s,p+i) != byte(s,end+i):
            return False
        i = i+1
    p = p+profile
    i = 0
    while i < z-8-before:
        if byte(s,p+i) != byte(w,q+i):
            return False
        i = i+1
    return True

def match(s:readbuf,w:mutbuf,p:u64,slot:u64) -> bool:
    q = get(w,slot)
    n = get(w,q)
    if p > length(s) or n > length(s)-p:
        return False
    i = 0
    while i < n:
        if byte(s,p+i) != byte(w,q+8+i):
            return False
        i = i+1
    return True
'''

POLICY += '\ndef anchor_selector(s:readbuf,o:mutbuf) -> u32:\n    if length(s) > 65536:\n        return 0\n    at = 0\n    index = 0\n    selected = 0\n    descriptor = 0\n    while at < length(s):\n        first = at\n        while at < length(s) and byte(s,at) != 0:\n            at = at+1\n        if at == length(s):\n            return 0\n        if anchor_prefix(s,first,at-first):\n            if selected != 0:\n                return 0\n            number = first+30\n            if number == at or at-number > 10:\n                return 0\n            while number < at:\n                digit = byte(s,number)\n                if digit < 48 or digit > 57:\n                    return 0\n                descriptor = descriptor*10+digit-48\n                if descriptor > 2147483647:\n                    return 0\n                number = number+1\n            if descriptor < 3:\n                return 0\n            selected = index+1\n        at = at+1\n        index = index+1\n    put(o,0,descriptor)\n    put(o,8,selected)\n    return 1\n\ndef anchor_metadata(s:readbuf) -> u32:\n    if length(s) != 168:\n        return 0\n    mode = read_word(s,24) & 4294967295\n    owner = read_word(s,28) & 4294967295\n    if mode & 61440 != 32768 or mode & 18 != 0 or read_word(s,16) != 1:\n        return 0\n    if owner != 0 and owner != read_word(s,144):\n        return 0\n    size = read_word(s,48)\n    if size < 104 or size > 1048576 or size != read_word(s,152) or read_word(s,160) & 3 != 0:\n        return 0\n    return 1\n\ndef anchor_prefix(s:readbuf,at:u64,size:u64) -> bool:\n    if size < 30:\n        return False\n    if byte(s,at+0) != 72:\n        return False\n    if byte(s,at+1) != 69:\n        return False\n    if byte(s,at+2) != 80:\n        return False\n    if byte(s,at+3) != 84:\n        return False\n    if byte(s,at+4) != 65:\n        return False\n    if byte(s,at+5) != 95:\n        return False\n    if byte(s,at+6) != 82:\n        return False\n    if byte(s,at+7) != 85:\n        return False\n    if byte(s,at+8) != 78:\n        return False\n    if byte(s,at+9) != 84:\n        return False\n    if byte(s,at+10) != 73:\n        return False\n    if byte(s,at+11) != 77:\n        return False\n    if byte(s,at+12) != 69:\n        return False\n    if byte(s,at+13) != 95:\n        return False\n    if byte(s,at+14) != 87:\n        return False\n    if byte(s,at+15) != 79:\n        return False\n    if byte(s,at+16) != 82:\n        return False\n    if byte(s,at+17) != 75:\n        return False\n    if byte(s,at+18) != 69:\n        return False\n    if byte(s,at+19) != 82:\n        return False\n    if byte(s,at+20) != 95:\n        return False\n    if byte(s,at+21) != 69:\n        return False\n    if byte(s,at+22) != 78:\n        return False\n    if byte(s,at+23) != 84:\n        return False\n    if byte(s,at+24) != 82:\n        return False\n    if byte(s,at+25) != 89:\n        return False\n    if byte(s,at+26) != 95:\n        return False\n    if byte(s,at+27) != 70:\n        return False\n    if byte(s,at+28) != 68:\n        return False\n    if byte(s,at+29) != 61:\n        return False\n    return True\n'

def source_document():
    from tools.generate_hia_worker_evaluate_case import source_program
    from tools.generate_hia_evaluate_settlement import function
    source = POLICY.replace('CONFIG_MAGIC', str(CONFIG_MAGIC))
    return document('\n'.join((source,*(function(source_program(),k) for k in ('get','put','read_word')))), 'installed_worker_entry')

def packer_document():
    raw = Path(ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-worker-entry-') as directory:
        adapter, loc, _ = adapter_layout(Path(directory), ADAPTER, raw, {'entry':'worker_entry_call_hole','anchor':'worker_entry_anchor_hole','metadata':'worker_entry_anchor_metadata_hole'})
    prefix = elf_header()
    holes = tuple(loc[key] for key in ('entry','anchor','metadata'))
    policy = packer_source(magic=MAGIC, image_template=(prefix+adapter, tuple(len(prefix)+hole for hole in holes)),
                           pack_limit=1 << 20)
    for extra in holes[1:]:
        write = f'    write(o, {len(prefix)+extra}, {len(adapter)-extra-4}, 4)\n'
        policy = policy.replace('    copy_bytes(s, o,', write+'    copy_bytes(s, o,', 1)
    return bind_adapter(document(policy, 'installed_worker_entry_packer'), raw, adapter, holes)

if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(source_document()))
    Path(PACKER).write_text(render_assembly(packer_document()))
