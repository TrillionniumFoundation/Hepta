"""Author the standalone HIA MCP process owner and its native ELF packer.

This module is a development authoring tool. Installed service policy is HIA;
the Linux adapter only translates bounded memory offsets and native syscalls.
"""
from __future__ import annotations
import argparse
import ast
import importlib
import struct
import subprocess
import tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_json_decode import source_program as generic_json
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ('bootstrap', 'setup', 'stream', 'dispatch', 'transport', 'response',
              'scheduler', 'files', 'state', 'audit_transport')
PURE = ('session', 'reply', 'canonical', 'config', 'admission', 'catalog',
        'input_schema', 'controller_json', 'output_schema', 'sdk_request')
ROLES = COMPONENTS + PURE + ('json', 'sha', 'bridge', 'audit')
COMPANIONS = {
    'session': 'examples/hia_bootstrap/mcp_service_session.hepta',
    'reply': 'examples/hia_bootstrap/mcp_service_reply.hepta',
    'canonical': 'examples/hia_bootstrap/mcp_canonical.hepta',
    'config': 'examples/hia_bootstrap/mcp_service_config.hepta',
    'admission': 'examples/hia_bootstrap/mcp_service_admission.hepta',
    'catalog': 'examples/hia_bootstrap/mcp_catalog_wire.hepta',
    'input_schema': 'examples/hia_bootstrap/mcp_input_diagnostic.hepta',
    'sdk_request': 'examples/hia_bootstrap/mcp_sdk_request.hepta',
    'controller_json': 'examples/hia_bootstrap/worker_config_json.hepta',
    'output_schema': 'examples/hia_bootstrap/agent_response_schema.hepta',
    'sha': 'examples/hia_bootstrap/sha256_stream.hepta',
}


class ServiceBuilder(LinkerBuilder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'word_store':
            args = [self.expr(value) for value in node.args]
            return self.op('buffer.store.u64.le', [args[0], self.cast(args[1], 'usize'), self.cast(args[2], 'u64')])
        return super().expr(node)


def document(source, module):
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ServiceBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(a) for a in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9', 'module': module, 'functions': functions})


def template():
    with tempfile.TemporaryDirectory(prefix='hia-mcp-service-author-') as temp:
        obj = Path(temp) / 'adapter.o'
        raw = Path(temp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT / 'tools/hia_mcp_service_syscalls.S'), '-o', str(obj)],
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
    if length(s) < {head + count} or uint(s, 0, 8) != {int.from_bytes(b'HIAMSP03', 'little')}:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('components', nargs='*', choices=COMPONENTS + ('json', 'packer'))
    args = parser.parse_args()
    for name in args.components or COMPONENTS + ('json', 'packer'):
        if name == 'json':
            source = generic_json(wire_spans=True)
        elif name == 'packer':
            source = packer_source()
        else:
            source = importlib.import_module('tools.generate_hia_mcp_service_' + name).source()
        rendered = render_assembly(document(source, 'mcp_service_' + name))
        path = ROOT / ('examples/hia_bootstrap/mcp_service_' + name + '.hepta')
        path.write_text(rendered, encoding='utf-8')
        print(path.name, len(rendered.encode()))


if __name__ == '__main__':
    main()
