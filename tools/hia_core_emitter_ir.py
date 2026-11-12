"""Finite Emitter authoring adapter to the existing 18-primitive HIA ABI.

No packet, slot or source cap is enlarged. The original five constructor
arguments are transported as one exact tuple. The only extra grammar forms
are one **mapping call and four-value unpacking, both mechanical operations.
"""
from __future__ import annotations

import ast
import copy

from tools.hia_core_lowering_ir import Function, Literals, Raw, link_functions


class EmitterFunction(Function):
    def statements(self, nodes):
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                allowed = {('hia_machine_plan', 'code_options'),
                           ('hia_native_byte_abi', 'emit_wrapper')}
                if (node.level != 1 or len(node.names) != 1
                        or (node.module, node.names[0].name) not in allowed):
                    raise ValueError('Emitter import requires explicit review')
                bridge = self.expression(ast.Name(id='_hia_emitter_import_member', ctx=ast.Load()))
                empty = self.constant(None)
                result = self.effect('CALL', (bridge, Raw(2), self.constant(node.module),
                    self.constant(node.names[0].name), empty, empty, empty, empty))
                self.move(self.local(node.names[0].asname or node.names[0].name), result)
            else:
                super().statements([node])

    def expression(self, node):
        if isinstance(node, ast.GeneratorExp):
            # Only the original lazy item projection passed to list.extend.
            # Materializing a comprehension would change partial writes on an
            # exception, so retain a lazy, generic object-runtime projection.
            if (len(node.generators) != 1 or node.generators[0].is_async
                    or node.generators[0].ifs
                    or not isinstance(node.generators[0].target, ast.Name)
                    or not isinstance(node.elt, ast.Subscript)
                    or not isinstance(node.elt.value, ast.Name)
                    or node.elt.value.id != node.generators[0].target.id
                    or not isinstance(node.elt.slice, ast.Constant)):
                raise ValueError('Emitter admits only a lazy item projection')
            bridge = self.expression(ast.Name(id='_hia_emitter_project_items', ctx=ast.Load()))
            iterable = self.expression(node.generators[0].iter)
            key = self.expression(node.elt.slice)
            empty = self.constant(None)
            return self.effect('CALL', (bridge, Raw(2), iterable, key, empty, empty, empty, empty))
        if isinstance(node, ast.Call) and any(k.arg is None for k in node.keywords):
            if node.args or len(node.keywords) != 1 or node.keywords[0].arg is not None:
                raise ValueError('Emitter admits only a sole keyword mapping')
            callee = self.expression(node.func)
            bridge = super().expression(ast.Name(id='_hia_emitter_call_keywords', ctx=ast.Load()))
            mapping = self.expression(node.keywords[0].value)
            empty = self.constant(None)
            return self.effect('CALL', (bridge, Raw(2), callee, mapping, empty, empty, empty, empty))
        return super().expression(node)

    def assign(self, target, value):
        if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 4:
            bridge = self.expression(ast.Name(id='_hia_emitter_unpack_four', ctx=ast.Load()))
            empty = self.constant(None)
            packed = self.effect('CALL', (bridge, Raw(1), value, empty, empty, empty, empty, empty))
            # Unpacking completes before any target is assigned, as in Python.
            for index, element in enumerate(target.elts):
                item = self.effect('ITEM', (packed, self.constant(index)))
                super().assign(element, item)
            return
        return super().assign(target, value)


def transported_constructor(node):
    node = copy.deepcopy(node)
    wanted = ['self', 'document', 'allowed_exports', 'block_order',
              'foreign_buffer_exports', 'machine_plan']
    if [a.arg for a in node.args.args] != wanted:
        raise ValueError('Emitter constructor signature requires explicit review')
    transport = '_hia_emitter_args'
    if any(isinstance(n, ast.Name) and n.id == transport for n in ast.walk(node)):
        raise ValueError('Emitter transport name collision')
    prefix = [ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())],
                         value=ast.Subscript(value=ast.Name(id=transport, ctx=ast.Load()),
                                             slice=ast.Constant(index), ctx=ast.Load()))
              for index, name in enumerate(wanted[1:])]
    node.args = ast.arguments(posonlyargs=[], args=[ast.arg(arg='self'), ast.arg(arg=transport)],
                              kwonlyargs=[], kw_defaults=[], defaults=[])
    node.body = prefix + node.body
    return ast.fix_missing_locations(node)


def compile_policy(source):
    tree = ast.parse(source)
    declarations = [n for n in tree.body if not (isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Constant) and type(n.value.value) is str)]
    if len(declarations) != 1 or not isinstance(declarations[0], ast.ClassDef):
        raise ValueError('Emitter policy must contain exactly one class')
    cls = declarations[0]
    expected = ('__init__', 'ordered_blocks', 'label', 'function_symbol', 'wrapper', 'render')
    if cls.name != '_Emitter' or tuple(getattr(n, 'name', None) for n in cls.body) != expected:
        raise ValueError('Emitter complete method inventory differs')
    literals, functions = Literals(), []
    for node in cls.body:
        if node.name == '__init__':
            node = transported_constructor(node)
        functions.append(EmitterFunction('_Emitter.' + node.name, node, literals).compile())
    return link_functions(literals, functions)
