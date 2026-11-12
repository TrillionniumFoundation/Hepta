"""Finite byte-wrapper authoring; nested load closes over two explicit handles.

Existing 18 packet opcodes, four bound arguments and all compiler caps stay
unchanged. Unsupported imports, closure bodies and control syntax fail closed.
"""
from __future__ import annotations

import ast
import copy

from tools.hia_core_lowering_ir import Function, Literals, Raw, link_functions

IMPORTS = {
    ('hia_program', ('SCALARS',)),
    ('hia_program_native', ('IMPORTS', '_LOADER_HOOKS', '_reject')),
    ('hia_program_native', ('MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue', '_reject')),
}


class ByteFunction(Function):
    def __init__(self, *args):
        super().__init__(*args)
        self.continue_labels = []

    def statements(self, nodes):
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                names = tuple(alias.name for alias in node.names)
                if node.level != 1 or (node.module, names) not in IMPORTS:
                    raise ValueError('byte-wrapper import requires explicit review')
                bridge = self.expression(ast.Name(id='_hia_byte_import_members', ctx=ast.Load()))
                packed = self.effect('PACK', (Raw(2), Raw(len(names))),
                    vector=tuple(self.constant(name) for name in names))
                empty = self.constant(None)
                observed = self.effect('CALL', (bridge, Raw(2), self.constant(node.module),
                    packed, empty, empty, empty, empty))
                for index, alias in enumerate(node.names):
                    value = self.effect('ITEM', (observed, self.constant(index)))
                    self.move(self.local(alias.asname or alias.name), value)
            elif isinstance(node, ast.FunctionDef):
                if self.name != 'emit_wrapper' or ast.dump(node) != ast.dump(_load_node()):
                    raise ValueError('byte-wrapper closure requires exact reviewed load body')
                bridge = self.expression(ast.Name(id='_hia_byte_closure', ctx=ast.Load()))
                captures = self.effect('PACK', (Raw(2), Raw(2)),
                    vector=(self.variable('c'), self.variable('input_slot')))
                empty = self.constant(None)
                value = self.effect('CALL', (bridge, Raw(2), self.constant('emit_wrapper.load'),
                    captures, empty, empty, empty, empty))
                self.move(self.local('load'), value)
            elif isinstance(node, ast.For):
                iterator = self.effect('ITER', (self.expression(node.iter),))
                head, found, done = self.label(), self.label(), self.label()
                self.mark(head)
                value = self.effect('NEXT', (iterator,))
                self.instructions.append(dict(kind='flag', yes=found, no=done))
                self.mark(found)
                self.assign(node.target, value)
                self.continue_labels.append(head)
                self.statements(node.body)
                self.continue_labels.pop()
                self.jump(head)
                self.mark(done)
                self.statements(node.orelse)
            elif isinstance(node, ast.Continue):
                if not self.continue_labels:
                    raise ValueError('continue outside reviewed byte-wrapper loop')
                self.jump(self.continue_labels[-1])
            else:
                super().statements([node])


def _load_node():
    return ast.parse('''def load(word, register):
    c.load(register, "rbp", input_slot + word * 8)
''').body[0]


def compile_policy(source):
    declarations = [n for n in ast.parse(source).body if not (isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Constant) and type(n.value.value) is str)]
    if tuple(getattr(n, 'name', None) for n in declarations) != ('normalize_exports', 'emit_wrapper'):
        raise ValueError('byte-wrapper complete function inventory differs')
    nested = [n for node in declarations for n in ast.walk(node)
              if isinstance(n, ast.FunctionDef) and n not in declarations]
    if len(nested) != 1 or ast.dump(nested[0]) != ast.dump(_load_node()):
        raise ValueError('byte-wrapper exact closure inventory differs')
    closure = copy.deepcopy(nested[0])
    closure.args.args = [ast.arg(arg='c'), ast.arg(arg='input_slot'), *closure.args.args]
    literals = Literals()
    functions = [ByteFunction(node.name, node, literals).compile() for node in declarations]
    functions.append(ByteFunction('emit_wrapper.load', closure, literals).compile())
    return link_functions(literals, functions)
