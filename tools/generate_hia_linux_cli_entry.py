"""HIA ELF layout for a process controller and three fixed CLI resident images.

The packer admits bounded component extents, writes their immutable placement,
publishes only three fixed call slots, and retains the existing kernel-startup
sealing protocol. No .S file, assembler, or opaque startup binary is consumed.
"""
from pathlib import Path
import ast
import copy
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_linux_process_entry as process
from tools.generate_hia_linux_stdio_entry import PackerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly

MAGIC = int.from_bytes(b'HCLIPAK1', 'little')
CALL_MAGIC = int.from_bytes(b'HCLICAP1', 'little')
IMAGE_AT = 1024
CAP = 0x600000
FRAME = 0x601000
OUTPUT = 0x701000
WORKSPACE = 0x801000
GUARD = 0x901000
STACK_TOP = 0x1102000

PACK = r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != MAGIC or uint(s, 8, 8) != 1 or uint(s, 48, 8) != 0 or uint(s, 56, 8) != 0:
        return 4294967295
    program = uint(s, 16, 8)
    control = uint(s, 24, 8)
    formatter = uint(s, 32, 8)
    discovery = uint(s, 40, 8)
    if program == 0 or control == 0 or formatter == 0 or discovery == 0:
        return 4294967295
    if program > 1047552 or control > 1047552 or formatter > 1047552 or discovery > 1047552:
        return 4294967295
    if length(s) != 64 + program + control + formatter + discovery:
        return 4294967295
    control_at = (1024 + program + 15) & 18446744073709551600
    format_at = (control_at + control + 15) & 18446744073709551600
    discovery_at = (format_at + formatter + 15) & 18446744073709551600
    file_size = (discovery_at + discovery + 4095) & 18446744073709547520
    if file_size > 1048576 or length(o) < file_size:
        return 4294967294
    fill_range(o, 0, file_size, 0)
    headers(o, file_size)
    end = startup(o, 232, 4194304 + control_at, 4194304 + format_at, 4194304 + discovery_at)
    if end > 1024:
        return 4294967295
    copy_exact(o, s, 1024, 64, program)
    copy_exact(o, s, control_at, 64 + program, control)
    copy_exact(o, s, format_at, 64 + program + control, formatter)
    copy_exact(o, s, discovery_at, 64 + program + control + formatter, discovery)
    return file_size
'''.replace('MAGIC', str(MAGIC))


def source_program():
    original = ast.parse(process.SOURCE)
    functions = {n.name: copy.deepcopy(n) for n in original.body}
    functions['pack'] = ast.parse(PACK).body[0]
    class DataExtent(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value == process.DATA_BYTES:
                return ast.copy_location(ast.Constant(STACK_TOP - CAP), node)
            return node
    functions['headers'] = DataExtent().visit(functions['headers'])
    startup = functions['startup']
    startup.args.args.extend(ast.arg(arg=n, annotation=ast.Name(id='u64', ctx=ast.Load()))
                             for n in ('control_address', 'format_address', 'discovery_address'))
    # Replace only the two fixed addresses in the existing startup template.
    replacements = {process.STACK_TOP: STACK_TOP, process.STACK_GUARD: GUARD}
    changes = []
    class StackAddresses(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value in replacements:
                changes.append(node.value)
                return ast.copy_location(ast.Constant(replacements[node.value]), node)
            return node
    startup = StackAddresses().visit(startup)
    assert sorted(changes) == sorted(replacements), changes
    original_registers = [(7, 4194304), (6, 0), (2, 6295552), (1, 1048576), (8, 7344128), (9, 1048576)]
    for i in range(len(startup.body) - 5):
        rows = startup.body[i:i + 6]
        signature = []
        for row in rows:
            if (isinstance(row, ast.Assign) and isinstance(row.value, ast.Call)
                    and isinstance(row.value.func, ast.Name) and row.value.func.id == 'register32'
                    and len(row.value.args) == 4 and all(isinstance(x, ast.Constant) for x in row.value.args[2:])):
                signature.append(tuple(x.value for x in row.value.args[2:]))
        if signature == original_registers:
            actual = [(7, FRAME), (6, 1048576), (2, OUTPUT), (1, 1048576), (8, WORKSPACE), (9, 1048576)]
            for row, (register, value) in zip(rows, actual):
                row.value.args[2:] = [ast.Constant(register), ast.Constant(value)]
            break
    else:
        raise AssertionError('exact six-register startup preimage is absent')
    insertion = None
    for i, row in enumerate(startup.body):
        if (isinstance(row, ast.Expr) and isinstance(row.value, ast.Call)
                and isinstance(row.value.func, ast.Name) and row.value.func.id == 'write'
                and isinstance(row.value.args[2], ast.Constant) and row.value.args[2].value == process.CAP_MAGIC):
            assert ast.unparse(startup.body[i - 1]) == 'at = instruction(o, at, 47176, 2)'
            insertion = i - 1
            break
    assert insertion is not None
    added = ast.parse(f'''
at = instruction(o, at, 47176, 2)
write(o, at, {CALL_MAGIC}, 8)
at = at + 8
at = instruction(o, at, 944081225, 4)
at = register32(o, at, 0, control_address)
at = instruction(o, at, 1078298953, 4)
at = register32(o, at, 0, format_address)
at = instruction(o, at, 1212516681, 4)
at = register32(o, at, 0, discovery_address)
at = instruction(o, at, 1346734409, 4)
''').body
    # 49 89 45 disp8: stores RAX into capability offsets56/64/72/80.
    assert [int.from_bytes(bytes([0x49, 0x89, 0x45, n]), 'little') for n in (56,64,72,80)] == [944081225,1078298953,1212516681,1346734409]
    startup.body[insertion:insertion] = added
    functions['startup'] = startup
    module = ast.Module(body=[functions[n.name] for n in original.body], type_ignores=[])
    ast.fix_missing_locations(module)
    return ast.unparse(module) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = PackerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'linux_cli_entry_packer', 'functions': functions})


def frame(images):
    if type(images) is not tuple or len(images) != 4 or any(type(raw) is not bytes for raw in images):
        raise TypeError('exact controller/control/format/discovery image tuple required')
    return struct.pack('<8Q', MAGIC, 1, *(len(raw) for raw in images), 0, 0) + b''.join(images)


def generated():
    return render_assembly(document())


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Generate fixed resident CLI ELF packer')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    raw = generated().encode()
    target = ROOT / 'examples/hia_bootstrap/linux_cli_entry_packer.hepta'
    if args.check:
        if target.read_bytes() != raw: raise SystemExit('CLI entry HIA source differs')
    else:
        target.write_bytes(raw)
    print(json.dumps({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'native_executed': False, 'matching_cold': False, 'whole': False}, sort_keys=True))


if __name__ == '__main__':
    main()
