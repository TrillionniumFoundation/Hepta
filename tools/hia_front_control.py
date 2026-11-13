"""Offline authoring of complete public assembly and verify routing.

The runtime receives only a HIA-emitted control table. The source's branches,
loops, local/cell layout, exception regions and one-use foreign permissions
are emitted as HIA. JSON, regex and existing semantic providers are explicit
dependencies; no original assembly/verify-routing body is a foreign port.
"""
from __future__ import annotations

import ast
from types import CodeType

from tools.hia_machine_plan_control import Compiler as _Compiler, OPS, BINARY
from tools.hia_native_build_control import Function as _Function

FORMAT_VALUE = 240
BUILD_STRING = 241


class Compiler(_Compiler):
    def __init__(self, source, entries, imports):
        self.source, self.tree = source, ast.parse(source)
        self.entry_names = tuple(entries)
        self.lexical_codes = {}
        def remember(code):
            for child in code.co_consts:
                if isinstance(child, CodeType):
                    key = (child.co_firstlineno, child.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous public-front lexical frame')
                    self.lexical_codes[key] = child
                    remember(child)
        remember(compile(source, '<public-front-lexical-layout>', 'exec'))
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        self.imports = {name: set(values) for name, values in imports.items()}
        nodes = []
        for node in self.tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
                continue
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                raise ValueError('unreviewed public-front policy declaration')
            nodes.append(node)
        if tuple(node.name for node in nodes) != self.entry_names:
            raise ValueError('complete public-front original entry inventory differs')
        for node in nodes:
            function = Function(self, node.name, node)
            self.functions.append(function)
            self.by_name[node.name] = function
        index = 0
        while index < len(self.functions):
            self.functions[index].compile()
            index += 1
        for mode, function in enumerate(self.functions, 1):
            function.mode = mode
        for function in self.functions:
            function.resolve()
        self._validate_calls()

    def nested(self, parent, node, kind):
        if kind not in ('generator', 'lambda'):
            raise ValueError('public-front has no unreviewed named/with region')
        function = Function(self, parent.name + ':' + kind + ':' + str(len(self.functions)),
                            node, parent=parent, kind=kind)
        self.functions.append(function)
        return function

    def _validate_calls(self):
        self.call_shapes, self.string_shapes = set(), set()
        for function in self.functions:
            for instruction in function.instructions:
                if instruction['kind'] != 'effect' or instruction['opcode'] != OPS['CALL']:
                    continue
                raw, args = instruction['raw'], instruction['arguments']
                if len(raw) == 2 and raw[1] in (FORMAT_VALUE, BUILD_STRING):
                    if raw[1] == FORMAT_VALUE:
                        if raw[0] != 0 or len(args) != 1:
                            raise ValueError('public-front format shape differs')
                    else:
                        if raw[0] != len(args) or len(args) < 2:
                            raise ValueError('public-front BUILD_STRING shape differs')
                        self.string_shapes.add(len(args))
                else:
                    if (len(raw) < 2 or len(raw) != 2 + raw[1]
                            or len(args) != 1 + raw[0] + raw[1]):
                        raise ValueError('public-front CALL shape differs')
                    self.call_shapes.add((raw[0], tuple(self.literals[i] for i in raw[2:])))
                if (len({r.slot for r in args}) != len(args)
                        or set(instruction['consume']) != set(args)
                        or any(not r.temporary or r.slot in function.cell_slots for r in args)):
                    raise ValueError('public-front CALL lacks unique consumed operands')


class Function(_Function):
    def __init__(self, compiler, name, node, *, parent=None, kind='function'):
        self.namespace = parent.namespace if parent is not None else 0
        super().__init__(compiler, name, node, parent=parent, kind=kind)

    def effect(self, operation, arguments=(), **keywords):
        if operation == 'GLOBAL':
            raw = keywords.get('raw', ())
            if len(raw) != 1:
                raise ValueError('public-front global representation differs')
            keywords['raw'] = (*raw, self.namespace)
        return super().effect(operation, arguments, **keywords)

    def expression(self, node):
        if isinstance(node, ast.NamedExpr):
            if not isinstance(node.target, ast.Name):
                raise ValueError('public-front walrus target differs')
            value = self.expression(node.value)
            self.store(self.variable(node.target.id), value, consume=False)
            return value
        if isinstance(node, ast.JoinedStr):
            values = []
            for part in node.values:
                if isinstance(part, ast.Constant) and type(part.value) is str:
                    values.append(self.constant(part.value))
                elif isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None:
                    value = self.expression(part.value)
                    values.append(self.effect('CALL', (value,), raw=(0, FORMAT_VALUE),
                                              consume=(value,)))
                else:
                    raise ValueError('unreviewed public-front string format')
            if not values:
                return self.constant('')
            if len(values) == 1:
                return values[0]
            return self.effect('CALL', values, raw=(len(values), BUILD_STRING),
                               consume=reversed(values))
        return super().expression(node)

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.Assign) and len(node.targets) > 1:
                value = self.expression(node.value)
                for target in node.targets[:-1]:
                    self.assign(target, self.copy(value))
                self.assign(node.targets[-1], value)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Subscript):
                owner, key = self.expression(node.target.value), self.expression(node.target.slice)
                left = self.effect('ITEM', (owner, key))
                right = self.expression(node.value)
                value = self.effect('BINARY', (left, right),
                    raw=(128 + BINARY[type(node.op).__name__],), consume=(left, right))
                self.effect('SET_ITEM', (owner, key, value), count=0,
                            consume=(value, owner, key))
            else:
                super().statements((node,))


def compile_policy(source, entries, imports):
    return Compiler(source, entries, imports)
