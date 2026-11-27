"""Offline lowering of the eight exact proof-contract bodies to HIA control.

All proof decisions, lazy obligations, operation order and lifetime permission
are emitted into the HIA image. The runtime never reads this policy or its AST.
Imports use one original IMPORT_NAME followed by its ordered IMPORT_FROM ports.
"""
from __future__ import annotations

import ast
from types import CodeType

from tools.hia_machine_plan_control import Compiler as _Compiler, OPS, COMPARE
from tools.hia_service_verification_control import Function as _Function

ENTRIES = ('_item', '_require', '_safe_core_method', 'proof_subject', '_method',
           'proof_result', 'assumptions_document', 'proof_contract_description')
IMPORT_GROUPS = (
    ('ARTIFACT_PROFILE', 'ARTIFACT_PROPERTY', 'ARTIFACT_OBLIGATIONS', 'SCHEMA',
     'CLAIMS', 'ASSUMPTIONS', 'LIMITS', 'UNPROVED_OBLIGATIONS',
     '_checker_source_identity', '_solver_identity'),
    ('ASSUMPTIONS',),
)


class Compiler(_Compiler):
    def __init__(self, source):
        self.source, self.tree = source, ast.parse(source)
        self.lexical_codes = {}
        def remember(code):
            for child in code.co_consts:
                if isinstance(child, CodeType):
                    key = (child.co_firstlineno, child.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous proof-contract lexical frame')
                    self.lexical_codes[key] = child
                    remember(child)
        # The unexecuted code observes only the original physical local/cell
        # order during generation. No code object reaches the runtime image.
        remember(compile(source, '<proof-contract-lexical-layout>', 'exec'))
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        nodes = [node for node in self.tree.body if isinstance(node, ast.FunctionDef)]
        if tuple(node.name for node in nodes) != ENTRIES:
            raise ValueError('complete proof-contract entry inventory differs')
        if any(not isinstance(node, ast.FunctionDef) and not (
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and type(node.value.value) is str) for node in self.tree.body):
            raise ValueError('unreviewed proof-contract top-level statement')
        for node in nodes:
            if node.decorator_list:
                raise ValueError('unreviewed proof-contract decorator')
            function = Function(self, node.name, node)
            self.functions.append(function)
            self.by_name[node.name] = function
        index = 0
        while index < len(self.functions):
            self.functions[index].compile()
            index += 1
        if len(self.functions) != 16:
            raise ValueError('complete proof-contract eight lazy frames differ')
        for mode, function in enumerate(self.functions, 1):
            function.mode = mode
        for function in self.functions:
            function.resolve()

    def nested(self, parent, node, kind):
        if kind != 'generator':
            raise ValueError('proof-contract closure is not an original lazy generator')
        function = Function(self, parent.name + ':generator:' + str(len(self.functions)),
                            node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


class Function(_Function):
    def expression(self, node):
        if isinstance(node, ast.JoinedStr):
            values = []
            for part in node.values:
                if isinstance(part, ast.Constant) and type(part.value) is str:
                    values.append(self.constant(part.value))
                elif isinstance(part, ast.FormattedValue) and part.conversion == -1:
                    if part.format_spec is None:
                        format_mode = 0
                    elif (isinstance(part.format_spec, ast.JoinedStr)
                          and len(part.format_spec.values) == 1
                          and isinstance(part.format_spec.values[0], ast.Constant)
                          and part.format_spec.values[0].value == '02d'):
                        format_mode = 1
                    else:
                        raise ValueError('proof-contract fixed format differs')
                    value = self.expression(part.value)
                    values.append(self.effect('CALL', (value,), raw=(format_mode, 252),
                                              consume=(value,)))
                else:
                    raise ValueError('proof-contract formatted part differs')
            if len(values) != 4:
                raise ValueError('proof-contract original BUILD_STRING extent differs')
            return self.effect('CALL', values, raw=(4, 251), consume=values)
        if isinstance(node, ast.Compare) and len(node.ops) > 1:
            result, done = self.slot(), self.label()
            left = self.expression(node.left)
            for index, (operation, expression) in enumerate(zip(node.ops, node.comparators)):
                right = self.expression(expression)
                last = index == len(node.ops) - 1
                value = self.effect('COMPARE', (left, right),
                    raw=(COMPARE[type(operation).__name__],),
                    consume=(left, right) if last else (left,))
                self.store(result, value)
                if not last:
                    onward, failed = self.label(), self.label()
                    self.truth(self.copy(result), onward, failed)
                    self.mark(failed)
                    self.release((right,))
                    self.jump(done)
                    self.mark(onward)
                    self.release((result,))
                    left = right
            self.mark(done)
            return result
        return super().expression(node)

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                names = tuple(alias.name for alias in node.names)
                if node.level != 1 or node.module != 'hia_safe_core' or names not in IMPORT_GROUPS:
                    raise ValueError('proof-contract import group differs')
                module = self.effect('IMPORT', raw=(0, IMPORT_GROUPS.index(names)))
                for alias in node.names:
                    value = self.effect('IMPORT', (module,),
                        raw=(1, self.compiler.literal(alias.name)))
                    self.assign(ast.Name(id=alias.asname or alias.name, ctx=ast.Store()), value)
                self.release((module,))
            elif isinstance(node, ast.Import):
                if len(node.names) != 1 or node.names[0].name != 'importlib' or node.names[0].asname:
                    raise ValueError('proof-contract plain import differs')
                value = self.effect('IMPORT', raw=(2,))
                self.assign(ast.Name(id='importlib', ctx=ast.Store()), value)
            else:
                super().statements((node,))


def compile_policy(source):
    return Compiler(source)
