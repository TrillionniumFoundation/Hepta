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

def source_document():
    from tools.generate_hia_worker_evaluate_case import source_program
    from tools.generate_hia_evaluate_settlement import function
    source = POLICY.replace('CONFIG_MAGIC', str(CONFIG_MAGIC))
    return document('\n'.join((source,*(function(source_program(),k) for k in ('get','put','read_word')))), 'installed_worker_entry')

def packer_document():
    raw = Path(ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-worker-entry-') as directory:
        adapter, loc, _ = adapter_layout(Path(directory), ADAPTER, raw, {'entry':'worker_entry_call_hole'})
    prefix = elf_header()
    hole = loc['entry']
    policy = packer_source(magic=MAGIC, image_template=(prefix+adapter, (len(prefix)+hole,)),
                           pack_limit=1 << 20)
    return bind_adapter(document(policy, 'installed_worker_entry_packer'), raw, adapter, (hole,))

if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(source_document()))
    Path(PACKER).write_text(render_assembly(packer_document()))
