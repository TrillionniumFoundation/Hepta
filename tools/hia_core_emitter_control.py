"""Compile the six exact original Core emitter methods into HIA control.

The shared continuation compiler owns branches, local lifetimes, generators,
and error paths. This reviewed profile adds only the original single mapping
expansion call and its two fixed imports to the Core object primitives.
"""
from __future__ import annotations

import ast

from tools.hia_core_lowering_control import Compiler as _Compiler
from tools.hia_core_lowering_control import Function as _Function
from tools.hia_core_lowering_control import OPS
from tools.hia_machine_plan_control import COMPARE

METHODS = ('__init__', 'ordered_blocks', 'label', 'function_symbol', 'wrapper', 'render')
IMPORTS = {'hia_machine_plan': 'code_options', 'hia_native_byte_abi': 'emit_wrapper'}
MAPPING_PREPARE = 254
MAPPING_CALL = 255


class Compiler(_Compiler):
    def __init__(self, source):
        self.source = source
        self.tree = ast.parse(source)
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        for node in self.tree.body:
            if isinstance(node, ast.ClassDef) and node.name == '_Emitter':
                if (node.bases or node.keywords or node.decorator_list
                        or tuple(getattr(child, 'name', None) for child in node.body) != METHODS):
                    raise ValueError('complete original emitter class inventory differs')
                selected = tuple(('_Emitter.' + method.name, method) for method in node.body)
            elif isinstance(node, ast.FunctionDef) and node.name == '_native_globals':
                selected = ((node.name, node),)
            elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                  and type(node.value.value) is str):
                continue
            else:
                raise ValueError('unreviewed Core emitter top-level statement')
            for name, method in selected:
                function = Function(self, name, method)
                self.functions.append(function)
                self.by_name[name] = function
        if tuple(self.by_name) != tuple('_Emitter.' + name for name in METHODS) + ('_native_globals',):
            raise ValueError('complete Core emitter entry inventory differs')
        index = 0
        while index < len(self.functions):
            self.functions[index].compile()
            index += 1
        for mode, function in enumerate(self.functions, 1):
            function.mode = mode
        for function in self.functions:
            function.resolve()

    def nested(self, parent, node, kind):
        name = parent.name + ':' + kind + ':' + str(len(self.functions))
        function = Function(self, name, node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


class Function(_Function):
    def condition(self, node, yes, no):
        if isinstance(node, ast.Compare) and len(node.ops) > 1:
            left = self.expression(node.left)
            for index, (operation, expression) in enumerate(zip(node.ops, node.comparators)):
                right = self.expression(expression)
                last = index == len(node.ops) - 1
                value = self.effect('COMPARE', (left, right),
                    raw=(COMPARE[type(operation).__name__],),
                    consume=(left, right) if last else (left,))
                if last:
                    self.truth(value, yes, no)
                else:
                    onward, failed = self.label(), self.label()
                    self.truth(value, onward, failed)
                    self.mark(failed)
                    self.release((right,))
                    self.jump(no)
                    self.mark(onward)
                    left = right
            return
        return super().condition(node, yes, no)

    def expression(self, node):
        if isinstance(node, ast.Call) and any(keyword.arg is None for keyword in node.keywords):
            if node.args or len(node.keywords) != 1 or node.keywords[0].arg is not None:
                raise ValueError('unreviewed Core emitter mapping-call shape')
            callee = self.expression(node.func)
            mapping = self.expression(node.keywords[0].value)
            prepared = self.effect('CALL', (callee, mapping), raw=(0, MAPPING_PREPARE),
                                   consume=(mapping,))
            return self.effect('CALL', (callee, prepared), raw=(0, MAPPING_CALL),
                               consume=(callee, prepared))
        return super().expression(node)

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                if (node.level != 1 or node.module not in IMPORTS or len(node.names) != 1
                        or node.names[0].name != IMPORTS[node.module]):
                    raise ValueError('unreviewed Core emitter import')
                name = node.names[0].name
                value = self.effect('IMPORT', raw=(self.compiler.literal(name),))
                self.assign(ast.Name(id=node.names[0].asname or name, ctx=ast.Store()), value)
            else:
                super().statements((node,))


def compile_policy(source):
    return Compiler(source)
