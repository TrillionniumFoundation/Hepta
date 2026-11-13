"""Compile the retained complete Core lowering policy into native control.

The business-policy input is the exact peer `_Function` and five-helper AST.
The shared finite continuation compiler owns lazy generators, closure cells,
expression retirement and original error paths. Runtime never imports either
authoring policy or compiler. Attribute stores and the one original register
import are additional fixed object primitives, not hosted lowering decisions.
"""
from __future__ import annotations

import ast

from tools.hia_machine_plan_control import Compiler as _Compiler
from tools.hia_machine_plan_control import Function as _Function
from tools.hia_machine_plan_control import BINARY, OPS


HELPERS = ('_reject', '_words', '_bounds', '_normalize', '_prologue')


class Compiler(_Compiler):
    def __init__(self, source):
        self.source = source
        self.tree = ast.parse(source)
        self.literals = []
        self.literal_indices = {}
        self.functions = []
        self.by_name = {}
        for node in self.tree.body:
            if isinstance(node, ast.FunctionDef):
                selected = ((node.name, node),)
            elif isinstance(node, ast.ClassDef) and node.name == '_Function':
                selected = tuple(('_Function.' + method.name, method) for method in node.body
                                 if isinstance(method, ast.FunctionDef))
                if len(selected) != len(node.body):
                    raise ValueError('unreviewed Core lowering class body')
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
                continue
            else:
                raise ValueError('unreviewed Core lowering top-level statement')
            for name, method in selected:
                function = Function(self, name, method)
                self.functions.append(function)
                self.by_name[name] = function
        if tuple(self.by_name)[:5] != HELPERS or len(self.by_name) != 28 or '_native_globals' not in self.by_name:
            raise ValueError('complete original Core lowering entry inventory differs')
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
    def assign(self, target, value):
        if isinstance(target, ast.Attribute):
            receiver = self.expression(target.value)
            # SET_ITEM's explicit tagged representation also carries the one
            # fixed attribute-store primitive. HIA selects its exact operands.
            self.effect('SET_ITEM', (receiver, value),
                        raw=(1, self.compiler.literal(target.attr)), count=0,
                        consume=(value, receiver))
        else:
            super().assign(target, value)

    def statements(self, statements):
        for node in statements:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], (ast.Tuple, ast.List))
                    and isinstance(node.value, ast.Tuple)
                    and len(node.targets[0].elts) == len(node.value.elts)
                    and not any(isinstance(value, ast.Starred) for value in node.value.elts)):
                # These fixed tuple displays are unpacked by the original
                # bytecode without creating an intermediate tuple object.
                values = [self.expression(value) for value in node.value.elts]
                for target, value in zip(node.targets[0].elts, values):
                    self.assign(target, value)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute):
                receiver = self.expression(node.target.value)
                left = self.effect('ATTR', (receiver,),
                                   raw=(self.compiler.literal(node.target.attr),))
                right = self.expression(node.value)
                value = self.effect('BINARY', (left, right),
                                    raw=(128 + BINARY[type(node.op).__name__],),
                                    consume=(left, right))
                self.effect('SET_ITEM', (receiver, value),
                            raw=(1, self.compiler.literal(node.target.attr)), count=0,
                            consume=(value, receiver))
            elif isinstance(node, ast.While):
                head, body, done = self.label(), self.label(), self.label()
                self.mark(head)
                self.condition(node.test, body, done)
                self.mark(body)
                self.loop_stack.append((head, done))
                self.statements(node.body)
                self.loop_stack.pop()
                self.jump(head)
                self.mark(done)
                self.statements(node.orelse)
            elif isinstance(node, ast.ImportFrom):
                if (node.level != 1 or node.module != 'hia_machine_plan' or len(node.names) != 1
                        or node.names[0].name != 'VALUE_REGISTERS'):
                    raise ValueError('unreviewed Core lowering import')
                name = node.names[0].name
                value = self.effect('IMPORT', raw=(self.compiler.literal(name),))
                self.assign(ast.Name(id=node.names[0].asname or name, ctx=ast.Store()), value)
            else:
                super().statements((node,))


def compile_policy(source):
    return Compiler(source)
