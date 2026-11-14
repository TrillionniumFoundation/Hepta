"""Offline authoring of the seven original verification coordinator bodies.

The runtime never imports this module or the retained policy. Every branch,
loop, construction order, foreign permission and retirement becomes ordinary
HIA control. This finite syntax profile adds the exact original call/import/
dictionary forms to the already reviewed Plan continuation representation.
"""
from __future__ import annotations

import ast
from types import CodeType

from tools.hia_machine_plan_control import Compiler as _Compiler
from tools.hia_machine_plan_control import Function as _Function, OPS, PACK

ENTRIES = ('_subject', '_hia_verify', '_verification', '_replay_verification',
           '_required_claims', '_check_native_refinement_evidence',
           '_native_refinement_binding')
IMPORTS = {
    'hia_program_native': ('validate_block_layout_plan', 'emit_program_machine'),
    'hia_checker_identity': ('checker_native_selection',),
    'hia_machine_plan': ('preservation_checks',),
    'hia_safe_core_elf': ('bind_final_artifact',),
}
DICT_UPDATE = 253
MAPPING_PREPARE = 254
MAPPING_CALL = 255


class Compiler(_Compiler):
    def __init__(self, source):
        self.source, self.tree = source, ast.parse(source)
        self.lexical_codes = {}
        def remember(code):
            for child in code.co_consts:
                if isinstance(child, CodeType):
                    key = (child.co_firstlineno, child.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous verification lexical frame')
                    self.lexical_codes[key] = child
                    remember(child)
        # This observes unexecuted lexical layout during source generation.
        # No code object, source or AST is given to the runtime continuation.
        remember(compile(source, '<verification-lexical-layout>', 'exec'))
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        classes = [n for n in self.tree.body if isinstance(n, ast.ClassDef)]
        if len(classes) != 1 or classes[0].name != 'HIAAgentService':
            raise ValueError('verification policy class inventory differs')
        methods = classes[0].body
        if tuple(getattr(n, 'name', None) for n in methods) != ENTRIES:
            raise ValueError('complete verification policy method inventory differs')
        for node in methods:
            decorators = [ast.unparse(d) for d in node.decorator_list]
            if decorators != (['staticmethod'] if node.name == '_native_refinement_binding' else []):
                raise ValueError('verification method decorator differs')
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

    def nested(self, parent, node, kind):
        if kind != 'generator':
            raise ValueError('verification only uses its exact lazy generator closure')
        function = Function(self, parent.name + ':generator:' + str(len(self.functions)),
                            node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


class Function(_Function):
    def __init__(self, compiler, name, node, *, parent=None, kind='function'):
        super().__init__(compiler, name, node, parent=parent, kind=kind)
        lexical_name = '<genexpr>' if kind == 'generator' else node.name
        first = min([node.lineno] + [d.lineno for d in getattr(node, 'decorator_list', ())])
        code = compiler.lexical_codes[(first, lexical_name)]
        names = tuple(dict.fromkeys((*code.co_varnames, *code.co_cellvars)))
        if names[:len(self.parameters)] != tuple(self.parameters):
            raise ValueError('verification physical argument order differs')
        self.locals, self.next_slot = {}, 0
        self.temporary_slots, self.cell_slots = set(), set()
        handler_names = {n.name for n in ast.walk(node)
                         if isinstance(n, ast.ExceptHandler) and n.name}
        for local_name in names:
            value = self.local(local_name)
            if local_name in handler_names:
                # A bound except variable is cleared on handler exit, including
                # the path that raises another exception. It is not retained
                # as an ordinary original local in that later traceback.
                self.temporary_slots.add(value.slot)
        for local_name in code.co_cellvars:
            self.cell_slots.add(self.locals[local_name].slot)
        for free_name in code.co_freevars:
            if parent is None:
                raise ValueError('verification top-level method has a free cell')
            outer = parent.variable(free_name)
            if outer is None:
                raise ValueError('verification capture has no enclosing owner')
            parent.cell_slots.add(outer.slot)
            self.captures[free_name] = (self.slot(False), outer)
        self.lexical_names, self.lexical_cells = names, code.co_cellvars
        self.lexical_freevars = code.co_freevars

    def comp_scope(self, generators, *, generator=False):
        if generator:
            names = {n.id for item in generators for n in ast.walk(item.target)
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            return {name: self.local(name) for name in sorted(names)}
        return super().comp_scope(generators, generator=generator)

    def expression(self, node):
        if isinstance(node, ast.BoolOp):
            result, done = self.slot(), self.label()
            for index, child in enumerate(node.values):
                self.store(result, self.expression(child))
                if index != len(node.values) - 1:
                    onward = self.label()
                    self.truth(self.copy(result),
                               onward if isinstance(node.op, ast.And) else done,
                               done if isinstance(node.op, ast.And) else onward)
                    self.mark(onward)
                    # JUMP_IF_*_OR_POP discards the first value before the
                    # next expression. Keep it only on the short-circuit edge,
                    # where the caller may truth-test that same object again.
                    self.release((result,))
            self.mark(done)
            return result
        if isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args):
                raise ValueError('verification policy has no starred positional call')
            mappings = [i for i, keyword in enumerate(node.keywords) if keyword.arg is None]
            callee = self.expression(node.func)
            arguments = [self.expression(arg) for arg in node.args]
            if mappings:
                if mappings != [len(node.keywords)-1] or len(mappings) != 1:
                    raise ValueError('verification mapping must be the one final expansion')
                explicit = node.keywords[:-1]
                if tuple(k.arg for k in explicit) not in ((), ('kind',)):
                    raise ValueError('verification explicit mapping-keyword shape differs')
                # CALL_FUNCTION_EX constructs the positional tuple before
                # evaluating the keyword mapping. Its objects then outlive
                # the original operand temporaries under that same tuple.
                positional = self.effect('PACK', raw=(PACK['Tuple'],),
                                         vector=arguments, consume=reversed(arguments))
                values = [self.expression(k.value) for k in explicit]
                mapping = self.expression(node.keywords[-1].value)
                prepared = self.effect('CALL', (callee, positional, *values, mapping),
                    raw=(len(explicit), MAPPING_PREPARE),
                    consume=(*reversed(values), mapping))
                return self.effect('CALL', (callee, positional, prepared),
                                   raw=(0, MAPPING_CALL), consume=(callee, positional, prepared))
            keys = [self.compiler.literal(k.arg) for k in node.keywords]
            values = [self.expression(k.value) for k in node.keywords]
            if len(arguments) > 5 or len(keys) > 8:
                raise ValueError('verification fixed call extent differs')
            return self.effect('CALL', (callee, *arguments, *values),
                               raw=(len(arguments), len(keys), *keys),
                               consume=(callee, *arguments, *values))
        if isinstance(node, ast.Dict) and any(key is None for key in node.keys):
            result = self.effect('PACK', raw=(PACK['Dict'],), vector=())
            pending_keys, pending_values = [], []
            def flush():
                if pending_keys:
                    block = super(Function, self).expression(ast.Dict(
                        keys=list(pending_keys), values=list(pending_values)))
                    self.effect('CALL', (result, block), raw=(0, DICT_UPDATE),
                                destination=result, consume=(block,))
                    pending_keys.clear(); pending_values.clear()
            for key, value in zip(node.keys, node.values):
                if key is None:
                    flush()
                    mapping = self.expression(value)
                    self.effect('CALL', (result, mapping), raw=(0, DICT_UPDATE),
                                destination=result, consume=(mapping,))
                else:
                    if not isinstance(key, ast.Constant) or type(key.value) is not str:
                        raise ValueError('verification expanded dictionary key shape differs')
                    pending_keys.append(key); pending_values.append(value)
            flush()
            return result
        return super().expression(node)

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                if (node.level != 1 or node.module not in IMPORTS
                        or any(alias.name not in IMPORTS[node.module] for alias in node.names)):
                    raise ValueError('verification import is outside the original fixed inventory')
                for alias in node.names:
                    value = self.effect('IMPORT', raw=(self.compiler.literal(node.module),
                                                       self.compiler.literal(alias.name)))
                    self.assign(ast.Name(id=alias.asname or alias.name, ctx=ast.Store()), value)
            elif isinstance(node, ast.Continue):
                if not self.loop_stack:
                    raise ValueError('verification continue has no loop')
                self.jump(self.loop_stack[-1][0])
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], (ast.Tuple, ast.List))
                    and isinstance(node.value, ast.Tuple)
                    and len(node.targets[0].elts) == len(node.value.elts)
                    and not any(isinstance(value, ast.Starred) for value in node.value.elts)):
                # Original tuple assignment is parallel and does not create
                # an extra tuple holder for these literal display forms.
                values = [self.expression(value) for value in node.value.elts]
                for target, value in zip(node.targets[0].elts, values):
                    self.assign(target, value)
            else:
                super().statements((node,))


def compile_policy(source):
    return Compiler(source)
