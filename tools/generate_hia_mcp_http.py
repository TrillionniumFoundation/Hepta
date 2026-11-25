"""HTTP owner native ELF composition. Initial argv is config, pin, manifest,
pin, loopback SocketAddr and private token path; syscall adaptation is mechanical.
"""
import argparse,importlib,struct,subprocess,tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document,COMPONENTS as MCP_COMPONENTS,PURE as MCP_PURE
from tools.generate_hia_mcp_service import COMPANIONS as MCP_COMPANIONS
from tools.generate_hia_native_filter import LINK_SOURCE
ROOT=Path(__file__).resolve().parents[1]
HTTP_COMPONENTS=('http_boot', 'http_io', 'http_post', 'http_response', 'http_registry', 'http_body', 'http_session', 'http_delivery', 'http_events', 'http_context', 'http_lifecycle')
HTTP_PURE=('http_headers', 'http_admission', 'http_bind', 'http_framing', 'http_json_error', 'http_metadata', 'http_chunk')
COMPONENTS=MCP_COMPONENTS+HTTP_COMPONENTS
PURE=MCP_PURE+HTTP_PURE
ROLES=COMPONENTS+PURE+('json','sha','bridge','audit')
COMPANIONS={**MCP_COMPANIONS,**{role:'examples/hia_bootstrap/mcp_'+role+'.hepta' for role in HTTP_PURE}}
COMPANIONS['http_chunk']='examples/hia_bootstrap/mcp_http_chunked.hepta'
COMPANIONS['session']='examples/hia_bootstrap/mcp_http_session_policy.hepta'
COMPANIONS['reply']='examples/hia_bootstrap/mcp_http_reply_policy.hepta'
COMPANIONS['catalog']='examples/hia_bootstrap/mcp_http_catalog_policy.hepta'

def template():
    with tempfile.TemporaryDirectory(prefix='hia-mcp-service-author-') as temp:
        obj = Path(temp) / 'adapter.o'
        raw = Path(temp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT / 'tools/hia_mcp_http_syscalls.S'), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('MCP service adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    holes = {name: 176 + symbols['mcp_service_' + name + '_hole'] for name in ROLES}
    holes['bridge_size'] = 176 + symbols['mcp_service_bridge_size_hole']
    holes['bridge_pin'] = 176 + symbols['mcp_service_bridge_pin']
    holes['audit_size'] = 176 + symbols['mcp_service_audit_size_hole']
    holes['audit_pin'] = 176 + symbols['mcp_service_audit_pin']
    return header + code, holes

def packer_source():
    prefix, holes = template()
    count = len(ROLES)
    head = 8 + count * 8 + 64
    code = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {head + count} or uint(s, 0, 8) != {int.from_bytes(b'HIAMHP01', 'little')}:
        return 4294967295
    size = {len(prefix)}
    index = 0
    while index < {count}:
        part = uint(s, 8 + index * 8, 8)
        maximum = choose(index >= {count - 2}, 16777216, 1048576)
        if part == 0 or part > maximum:
            return 4294967295
        size = size + part
        index = index + 1
    if length(s) != size - {len(prefix)} + {head}:
        return 4294967295
    if size > 67108864 or length(o) < size:
        return 4294967294
'''
    helpers = ''
    for bank, start in enumerate(range(0, len(prefix), 512)):
        code += f'    prefix_{bank}(o)\n'
        helpers += f'\ndef prefix_{bank}(o:mutbuf) -> u64:\n'
        for at in range(start, min(start + 512, len(prefix)), 8):
            chunk = prefix[at:at + 8]
            helpers += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
        helpers += '    return 0\n'
    code += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    code += f'    target = {len(prefix)}\n'
    for i, name in enumerate(ROLES):
        at = holes[name]
        code += f'    write(o, {at}, target - {at + 4}, 4)\n'
        code += f'    target = target + uint(s, {8 + i * 8}, 8)\n'
    code += f'    write(o, {holes["bridge_size"]}, uint(s, {8 + (count - 2) * 8}, 8), 4)\n'
    code += f'    copy_bytes(s, o, {8 + count * 8}, {holes["bridge_pin"]}, 32)\n'
    code += f'    write(o, {holes["audit_size"]}, uint(s, {8 + (count - 1) * 8}, 8), 4)\n'
    code += f'    copy_bytes(s, o, {40 + count * 8}, {holes["audit_pin"]}, 32)\n'
    code += f'    copy_bytes(s, o, {head}, {len(prefix)}, size - {len(prefix)})\n    return size\n'
    return code + helpers + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def component_source(name):
    if name=='dispatch':
        from tools.generate_hia_mcp_http_presentation import dispatch_source
        return dispatch_source()
    if name=='stream':
        from tools.generate_hia_mcp_http_child import stream_source
        return stream_source()
    if name=='scheduler':
        from tools.generate_hia_mcp_http_child import scheduler_source
        return scheduler_source()
    if name=='bootstrap':
        value=importlib.import_module('tools.generate_hia_mcp_service_bootstrap').source()
        needle='get(w, 112) != 4'
        assert value.count(needle)==1
        return value.replace(needle,'get(w, 112) != 6')
    if name=='setup':
        value=importlib.import_module('tools.generate_hia_mcp_service_setup').source()
        needle='return enter(w, 2, 0)'
        assert value.count(needle)==1
        return value.replace(needle,'return enter(w, 19, 100)')
    if name=='http_boot':
        return importlib.import_module('tools.generate_hia_mcp_http_bootstrap').source()
    if name.startswith('http_'):
        return importlib.import_module('tools.generate_hia_mcp_'+name).source()
    return importlib.import_module('tools.generate_hia_mcp_service_'+name).source()

def source_path(name):
    if name=='dispatch':return 'examples/hia_bootstrap/mcp_http_dispatch.hepta'
    if name=='reply':return 'examples/hia_bootstrap/mcp_http_reply_policy.hepta'
    if name=='catalog':return 'examples/hia_bootstrap/mcp_http_catalog_policy.hepta'
    if name=='session':return 'examples/hia_bootstrap/mcp_http_session_policy.hepta'
    if name=='bootstrap':return 'examples/hia_bootstrap/mcp_http_controller_bootstrap.hepta'
    if name=='setup':return 'examples/hia_bootstrap/mcp_http_setup.hepta'
    if name=='stream' or name=='scheduler':return 'examples/hia_bootstrap/mcp_http_'+name+'.hepta'
    if name=='http_boot':return 'examples/hia_bootstrap/mcp_http_bootstrap.hepta'
    if name.startswith('http_'):return 'examples/hia_bootstrap/mcp_'+name+'.hepta'
    return 'examples/hia_bootstrap/mcp_service_'+name+'.hepta'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('components',nargs='*')
    args=parser.parse_args()
    for name in args.components or COMPONENTS+('packer',):
        if name=='packer':
            src=packer_source();path=ROOT/'examples/hia_bootstrap/mcp_http_packer.hepta'
        else:
            if name not in COMPONENTS:raise ValueError(name)
            src=component_source(name);path=ROOT/source_path(name)
        value=render_assembly(document(src,'mcp_http_'+name))
        path.write_text(value);print(path.name,len(value.encode()))
if __name__=='__main__':main()
