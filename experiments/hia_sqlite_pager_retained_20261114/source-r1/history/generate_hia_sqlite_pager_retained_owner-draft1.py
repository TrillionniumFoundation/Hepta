"""Author the fixed Linux read-only Pager request owner in existing HIA.

Static authoring only. No generation or execution was performed when this file
was written. The independent assembly transport is an explicit bootstrap
dependency. It is not a Core opcode, generic FFI, Python page provider, or proof
of a complete SQLite implementation.
"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.pager_owner_lock_source_r3 import SOURCE as LOCK_SOURCE
from tools.pager_owner_page_source import SOURCE as PAGE_SOURCE
from tools.pager_owner_common_source_r2 import SOURCE as COMMON_SOURCE

RETAINED_PATH = Path(__file__).with_name('sqlite_pager_retained_owner.hia')
RETAINED_BYTES = RETAINED_PATH.read_bytes()
if hashlib.sha256(RETAINED_BYTES).hexdigest() != '573b4fae906e9f648d4632c94bacda3b89e148bae53e327d563e1dc4646e9a0a':
    raise ValueError('frozen retained HIA source differs')
RETAINED_SOURCE = RETAINED_BYTES.decode('utf-8', errors='strict')
# Preserve the old lock source except the private workspace extent in this
# separate extended component. The original R3 component remains unchanged.
_LOCK_EDITS = (
    ('length(w) != 73728', 'length(w) != 147456'),
    ('while index < 73728:', 'while index < 147456:'),
)
EXTENDED_LOCK_SOURCE = LOCK_SOURCE
for before, after in _LOCK_EDITS:
    if EXTENDED_LOCK_SOURCE.count(before) != 1 or after in EXTENDED_LOCK_SOURCE:
        raise ValueError('exact original lock extent admission')
    EXTENDED_LOCK_SOURCE = EXTENDED_LOCK_SOURCE.replace(before, after)
SOURCE = RETAINED_SOURCE + EXTENDED_LOCK_SOURCE + PAGE_SOURCE + COMMON_SOURCE
CONSTANTS = {
    'ABI': 4294967293,
    'RETAINED_MAGIC': int.from_bytes(b'HIARPGL1', 'little'),
    'EINTR': 18446744073709551612,
    'STATE_MAGIC': int.from_bytes(b'HIAPGST2', 'little'),
    'REQUEST_MAGIC': int.from_bytes(b'HIAPGOS2', 'little'),
    'EVENT_MAGIC': int.from_bytes(b'HIAPGEV2', 'little'),
    'OUTPUT_MAGIC': int.from_bytes(b'HIAPGOT2', 'little'),
    'DB_MAGIC0': int.from_bytes(b'SQLite f', 'big'),
    'DB_MAGIC1': int.from_bytes(b'ormat 3\0', 'big'),
}

def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(SOURCE)))) + '\n'

class PagerBuilder(Builder):
    """Select the existing checked copy opcode; no host file/lock computation."""
    def expr(self, expression):
        if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                and expression.func.id == 'copy_range'):
            if expression.keywords or len(expression.args) != 5:
                raise ValueError('copy_range requires five positional operands')
            values = [self.expr(value) for value in expression.args]
            if values[0][1] != 'mutbuf' or values[1][1] != 'readbuf':
                raise ValueError('copy_range requires distinct mutable/read owners')
            self.op('buffer.copy_range', values[:2] +
                    [self.cast(value, 'usize') for value in values[2:]])
            return self.c(0)
        return super().expr(expression)

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate Pager source function')
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                             node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = PagerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns],
            'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks,
        })
    return compact_authoring_cfg({
        'schema': 'hepta.hia.program.v8', 'module': 'sqlite_pager_retained_read_owner',
        'functions': functions,
    })

def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(render_assembly(document()))

if __name__ == '__main__':
    main()
