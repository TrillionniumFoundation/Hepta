"""Pure HIA ELF packer for file/render controller and two immutable residents.

The 8 MiB+1 file borrow is independent of the 1 MiB assembly, compiler workspace
and aggregate RX image limits. All addresses are fixed by this entry; no public
operand becomes a function pointer or descriptor. The file capability closes
before any component runs, and a normal return with a live descriptor traps.
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
from tools import generate_hia_linux_file_entry as file
from tools.generate_hia_linux_stdio_entry import PackerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_selfhost_linux_file_render import FILE_MAGIC, CALL_MAGIC
from hepta.hia_agent_assembly import render_assembly

MAGIC = int.from_bytes(b'HFLRPAK1', 'little')
CAP, STATE, FILE_BUFFER = file.CAP, file.STATE, file.RESULT
OUTPUT, WORKSPACE, GUARD, STACK_TOP = 0xe03000, 0xf03000, 0x1003000, 0x1804000
IMAGE_AT = 1024

PACK = r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 48 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != MAGIC or uint(s, 8, 8) != 1 or uint(s, 40, 8) != 0:
        return 4294967295
    program = uint(s, 16, 8)
    frontend = uint(s, 24, 8)
    compiler = uint(s, 32, 8)
    if program == 0 or frontend == 0 or compiler == 0:
        return 4294967295
    if program > 1047552 or frontend > 1047552 or compiler > 1047552:
        return 4294967295
    if length(s) != 48 + program + frontend + compiler:
        return 4294967295
    frontend_at = (1024 + program + 15) & 18446744073709551600
    compiler_at = (frontend_at + frontend + 15) & 18446744073709551600
    file_size = (compiler_at + compiler + 4095) & 18446744073709547520
    if file_size > 1048576 or length(o) < file_size:
        return 4294967294
    fill_range(o, 0, file_size, 0)
    headers(o, file_size)
    end = startup(o, 232, 4194304 + frontend_at, 4194304 + compiler_at)
    if end > 1024:
        return 4294967295
    copy_exact(o, s, 1024, 48, program)
    copy_exact(o, s, frontend_at, 48 + program, frontend)
    copy_exact(o, s, compiler_at, 48 + program + frontend, compiler)
    return file_size
'''.replace('MAGIC', str(MAGIC))


def source_program():
    original = ast.parse(file.source_program())
    functions = {node.name: copy.deepcopy(node) for node in original.body}
    functions['pack'] = ast.parse(PACK).body[0]

    class DataExtent(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value == file.STACK_TOP - file.CAP:
                return ast.copy_location(ast.Constant(STACK_TOP - CAP), node)
            return node

    functions['headers'] = DataExtent().visit(functions['headers'])
    startup = functions['startup']
    startup.args.args.extend(ast.arg(arg=name, annotation=ast.Name(id='u64', ctx=ast.Load()))
                             for name in ('frontend_address', 'compiler_address'))
    replacements = {file.STACK_TOP: STACK_TOP, file.GUARD: GUARD, file.FILE_MAGIC: FILE_MAGIC}
    changes = []

    class StartupConstants(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value in replacements:
                changes.append(node.value)
                return ast.copy_location(ast.Constant(replacements[node.value]), node)
            return node

    startup = StartupConstants().visit(startup)
    assert sorted(changes) == sorted(replacements), changes
    expected = [(7, 4194304), (6, 0), (2, file.RESULT), (1, file.FILE_LIMIT), (8, file.WORKSPACE), (9, 1048576)]
    matches = 0
    for i in range(len(startup.body) - 5):
        rows = startup.body[i:i + 6]
        signature = []
        for row in rows:
            if (isinstance(row, ast.Assign) and isinstance(row.value, ast.Call)
                    and isinstance(row.value.func, ast.Name) and row.value.func.id == 'register32'
                    and len(row.value.args) == 4 and all(isinstance(x, ast.Constant) for x in row.value.args[2:])):
                signature.append(tuple(x.value for x in row.value.args[2:]))
        if signature == expected:
            actual = [(7, FILE_BUFFER), (6, file.FILE_LIMIT), (2, OUTPUT), (1, 1048576), (8, WORKSPACE), (9, 1048576)]
            for row, (register, value) in zip(rows, actual):
                row.value.args[2:] = [ast.Constant(register), ast.Constant(value)]
            matches += 1
    assert matches == 1, matches
    insertion = None
    for i, row in enumerate(startup.body):
        if ast.unparse(row) == 'at = register32(o, at, 7, 6291456)':
            assert insertion is None
            insertion = i
    assert insertion is not None
    added = ast.parse(f'''
at = register32(o, at, 0, frontend_address)
at = instruction(o, at, {int.from_bytes(bytes([0x49,0x89,0x45,64]),'little')}, 4)
at = register32(o, at, 0, compiler_address)
at = instruction(o, at, {int.from_bytes(bytes([0x49,0x89,0x45,72]),'little')}, 4)
at = instruction(o, at, 47176, 2)
write(o, at, {CALL_MAGIC}, 8)
at = at + 8
at = instruction(o, at, {int.from_bytes(bytes([0x49,0x89,0x45,80]),'little')}, 4)
''').body
    startup.body[insertion:insertion] = added
    functions['startup'] = startup
    module = ast.Module(body=[functions[node.name] for node in original.body], type_ignores=[])
    ast.fix_missing_locations(module)
    return ast.unparse(module) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = PackerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'linux_file_render_entry_packer', 'functions': functions})


def frame(images):
    if type(images) is not tuple or len(images) != 3 or any(type(raw) is not bytes for raw in images):
        raise TypeError('exact controller/frontend/ordinary-compiler image tuple required')
    return struct.pack('<6Q', MAGIC, 1, *(len(raw) for raw in images), 0) + b''.join(images)


def generated():
    return render_assembly(document())


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    raw = generated().encode()
    target = ROOT / 'examples/hia_bootstrap/linux_file_render_entry_packer.hepta'
    if args.check:
        if target.read_bytes() != raw:
            raise SystemExit('file/render entry source differs')
    else:
        target.write_bytes(raw)
    print(json.dumps({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'native_executed': False, 'matching_cold': False, 'whole': False}, sort_keys=True))


if __name__ == '__main__':
    main()
