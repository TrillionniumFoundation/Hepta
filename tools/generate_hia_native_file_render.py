"""Version-aware HIA file-to-assembly pipeline with fixed residents.

This v3 executable preserves primitive v6/v7/v8 presentation and explicit empty
exports. An exact reversible private view is checked by a separate HIA
semantic resident; ordinary B3 remains unchanged. This finite policy is not
the complete old CLI or an independent canonical-roundtrip verifier.
"""
from pathlib import Path
import ast
import hashlib
import inspect
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_native_file_read as reader
from tools.generate_hia_selfhost import total_scalar_functions, compact_authoring_cfg, TYPES
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_linux_file_render import PROFILE, MODULE

RUN = r'''
def run(f:mutbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(f) != 8388609 or length(o) != 1048576 or length(w) != 1048576:
        return 126
    if argc() != 3:
        return refuse(w, 64, 1, 0)
    if arglen(1) != 15:
        return refuse(w, 64, 1, 0)
    copied = argcopy(w, 0, 1, 0, 15)
    if copied != 15 or uint(w, 0, 8) != COMMAND_FIRST or uint(w, 8, 7) != COMMAND_LAST:
        return refuse(w, 64, 1, 0)
    raw_size = arglen(2)
    if raw_size > 524287:
        return refuse(w, 65, 1, raw_size)
    got = argcopy(w, 524288, 2, 0, raw_size)
    if got != raw_size:
        return 126
    path_size = path(w, 524288, raw_size, 256)
    if path_size > 262143:
        return refuse(w, 65, 1, path_size)
    fill_range(w, 0, 128, 0)
    write(w, 64, path_size, 8)
    status = bounded_read(f, w, 8388608)
    if status != 0:
        return refuse(w, 66, status, uint(w, 16, 8))
    wire_size = uint(w, 24, 8)
    # The original file capability has now closed. The two residents receive
    # disjoint spans, never a filename, descriptor, or host callback.
    fill_range(w, 0, 1048576, 0)
    write(w, 48, 262144, 8)
    write(w, 56, 64, 8)
    rendered = raw_word(frontend(f, 0, wire_size, o, 0, 1048576, w, 0, 1048576))
    if rendered == 0 or rendered > 1048576:
        return refuse(w, 67, 2, rendered)
    # The exact resident already retained the original schema and exports.
    # Normalize only an internal verification view, preserving a reversible
    # description in scalar locals; never alter user output on success.
    if rendered < 33:
        return refuse(w, 67, 2, rendered)
    schema_version = uint(o, 30, 1)
    if schema_version != 54 and schema_version != 55 and schema_version != 56:
        return refuse(w, 67, 2, schema_version)
    write(o, 30, 56, 1)
    fill_range(w, 0, 1048576, 0)
    checked = raw_word(compiler(o, 0, rendered, f, 0, 1048576, w, 0, 1048576))
    # Restore even a rejected verification view before selecting the failure
    # path. Only the presentation below can reach stdout; code is never run.
    write(o, 30, schema_version, 1)
    if checked != 0:
        return refuse(w, 68, 3, uint(w, 40, 8))
    # No user machine image is produced or executed. This is a semantic gate;
    # successful output is the already bounded assembly representation.
    sent = send(o, 0, rendered, 1)
    if sent != 0:
        return 120
    return 0

def refuse(w:mutbuf, status:u32, phase:u64, detail:u64) -> u32:
    write(w, 0, RESULT_MAGIC, 8)
    write(w, 8, raw_word(status), 8)
    write(w, 16, phase, 8)
    write(w, 24, detail, 8)
    sent = send(w, 0, 32, 2)
    if sent != 0:
        return 121
    return status
'''.replace('COMMAND_FIRST', str(int.from_bytes(b'render-a', 'little'))).replace(
    'COMMAND_LAST', str(int.from_bytes(b'ssembly', 'little'))).replace(
    'RESULT_MAGIC', str(int.from_bytes(b'HRENDR1\x00', 'little')))


def author_source():
    retained = []
    for node in ast.parse(reader.author_source()).body:
        if node.name != 'run':
            retained.append(ast.unparse(node))
    return RUN + '\n\n' + '\n\n'.join(retained) + '\n'


class FileRenderBuilder(reader.FileBuilder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('frontend', 'compiler'):
            assert len(node.args) == 9 and not node.keywords
            args = [self.expr(value) for value in node.args]
            args = [value if i in (0, 3, 6) else self.cast(value, 'usize') for i, value in enumerate(args)]
            return self.op('linux.render.' + node.func.id, args, 'u32')
        return super().expr(node)


def document():
    nodes = ast.parse(author_source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = FileRenderBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap', 'linux_io', 'linux_startup', 'linux_file', 'linux_render'],
            'entry': 'b0', 'blocks': builder.blocks})
    doc = {'schema': 'hepta.hia.program.v8', 'module': MODULE, 'functions': functions}
    tree = ast.parse(inspect.getsource(compact_authoring_cfg))
    changes = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == 'hepta.hia_program':
            assert [(value.name, value.asname) for value in node.names] == [('verify_program', None)]
            node.module = 'hepta.hia_linux_file_render'
            node.names = [ast.alias(name='verify_linux_file_render_program', asname='verify_program')]
            changes += 1
    assert changes == 1
    ast.fix_missing_locations(tree)
    namespace = {'TYPES': TYPES}
    exec(compile(tree, '<reviewed-file-render-author-CFG>', 'exec'), namespace)
    result = namespace['compact_authoring_cfg'](doc)
    for before, after in zip(doc['functions'], result['functions'], strict=True):
        assert [op for block in before['blocks'] for op in block['ops']] == [op for block in after['blocks'] for op in block['ops']]
    return result


def generated():
    return render_assembly(document(), profile=PROFILE)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    doc = document()
    raw = render_assembly(doc, profile=PROFILE).encode()
    target = ROOT / 'examples/hia_bootstrap/native_file_render.hepta'
    if args.check:
        if target.read_bytes() != raw:
            raise SystemExit('native file/render source differs')
    else:
        target.write_bytes(raw)
    print(json.dumps({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'functions': len(doc['functions']), 'blocks': sum(len(fn['blocks']) for fn in doc['functions']),
        'operations': sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']),
        'matching_cold': False, 'whole': False}, sort_keys=True))


if __name__ == '__main__':
    main()
