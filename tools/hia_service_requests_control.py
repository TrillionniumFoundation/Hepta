"""Complete eight-body service-requests continuation authoring.

Uses the reviewed Build lexical cell/named-function mechanism and the reviewed
Verification DICT_MERGE/DICT_UPDATE policy. The runtime receives no AST.
"""
from __future__ import annotations
import ast
import struct
from types import CodeType
from tools.hia_native_build_control import Compiler as BuildCompiler, Function as BuildFunction
from tools.hia_machine_plan_control import OPS, PACK, COMPARE

METHODS = ('_profiles', '_examples', '_error', '_hia_describe', '_hia_artifact', '_hia_read', '_hia_inspect', '_hia_candidate')
ENTRIES = METHODS
DICT_UPDATE = 253
MAPPING_PREPARE = 254
MAPPING_CALL = 255


class Compiler(BuildCompiler):
    def __init__(self, source):
        self.source, self.tree = source, ast.parse(source)
        # Handler routing is encoded per effect instruction. A loop jump out
        # of a try BODY needs no dynamic pop; it has never entered HANDLED.
        # The retained page loops only break from successful try bodies.
        # A jump/return out of an except or a finally region would need a
        # separate cleanup protocol and remains explicitly unreviewed.
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.AsyncWith, ast.TryStar)):
                raise ValueError('request policy has an unreviewed cleanup region')
            if isinstance(node, ast.Try):
                if (len(node.handlers) != 1 or node.orelse or node.finalbody
                        or node.handlers[0].type is None):
                    raise ValueError('request policy has an unreviewed exception region')
                if any(isinstance(child, (ast.Break, ast.Continue, ast.Return))
                       for statement in node.handlers[0].body for child in ast.walk(statement)):
                    raise ValueError('request policy has an unreviewed handled-exception exit')
        self.lexical_codes = {}
        def remember(code):
            for child in code.co_consts:
                if isinstance(child, CodeType):
                    key = (child.co_firstlineno, child.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous requests lexical frame')
                    self.lexical_codes[key] = child
                    remember(child)
        remember(compile(source, '<requests-lexical-layout>', 'exec'))
        self.imports = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                if node.level != 1:
                    raise ValueError('requests import must be package-relative')
                self.imports.setdefault(node.module, set()).update(alias.name for alias in node.names)
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        classes = [node for node in self.tree.body if isinstance(node, ast.ClassDef)]
        if (len(classes) != 1 or classes[0].name != 'HIAAgentService'
                or tuple(getattr(node, 'name', None) for node in classes[0].body) != METHODS
                or any(isinstance(node, ast.FunctionDef) for node in self.tree.body)):
            raise ValueError('complete request policy inventory differs')
        for node in classes[0].body:
            expected = [ast.Name(id='staticmethod', ctx=ast.Load())] if node.name == '_examples' else []
            if (not isinstance(node, ast.FunctionDef)
                    or [ast.dump(d) for d in node.decorator_list] != [ast.dump(d) for d in expected]):
                raise ValueError('request policy declaration differs')
            if node.decorator_list:
                # co_firstlineno includes the exact staticmethod decorator.
                # Preserve that original physical layout while providing the
                # source-def lookup expected by the shared lexical author.
                original = self.lexical_codes[(node.decorator_list[0].lineno, node.name)]
                if (node.lineno, node.name) in self.lexical_codes:
                    raise ValueError('request staticmethod lexical layout is ambiguous')
                self.lexical_codes[(node.lineno, node.name)] = original
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

    def literal(self, value):
        if type(value) is float:
            # Distinct IEEE payloads, especially +0 and -0, must not collapse
            # under Python's value equality. Each emitted index is boxed once.
            key = (float, struct.pack('<d', value))
            if key not in self.literal_indices:
                self.literal_indices[key] = len(self.literals)
                self.literals.append(value)
            return self.literal_indices[key]
        return super().literal(value)

    def nested(self, parent, node, kind):
        if kind not in ('function', 'generator', 'lambda'):
            raise ValueError('requests lexical child kind differs')
        function = Function(self, parent.name + ':' + kind + ':' + str(len(self.functions)),
                            node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


    def region(self, parent, node):
        function = Function(self, parent.name+':with:'+str(len(self.functions)),
                            node, parent=parent, kind='with_region')
        self.functions.append(function)
        return function


class Function(BuildFunction):
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
                raise ValueError('requests policy has no starred positional call')
            mappings = [i for i, keyword in enumerate(node.keywords) if keyword.arg is None]
            callee = self.expression(node.func)
            arguments = [self.expression(arg) for arg in node.args]
            if mappings:
                if mappings != [len(node.keywords)-1] or len(mappings) != 1:
                    raise ValueError('requests mapping must be the one final expansion')
                explicit = node.keywords[:-1]
                if tuple(k.arg for k in explicit) not in ((), ('kind',)):
                    raise ValueError('requests explicit mapping-keyword shape differs')
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
                raise ValueError('requests fixed call extent differs')
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
                        raise ValueError('requests expanded dictionary key shape differs')
                    pending_keys.append(key); pending_values.append(value)
            flush()
            return result
        return super().expression(node)


    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.For):
                iterable = self.expression(node.iter)
                iterator = self.effect('ITER', (iterable,), consume=(iterable,))
                head, found, exhausted, broken, done = (self.label() for _ in range(5))
                self.mark(head)
                value = self.effect('NEXT', (iterator,))
                self.emit('flag', yes=found, no=exhausted)
                self.mark(found)
                self.assign(node.target, value)
                # Continue resumes the same iterator. Break owns only the
                # nearest loop exit; it retires that iterator before the
                # following statement and bypasses the normal else body.
                self.loop_stack.append((head, broken))
                self.statements(node.body)
                self.loop_stack.pop()
                self.jump(head)
                self.mark(exhausted)
                self.release((value, iterator))
                self.statements(node.orelse)
                self.jump(done)
                self.mark(broken)
                self.release((value, iterator))
                self.mark(done)
            elif isinstance(node, ast.While):
                if node.orelse:
                    raise ValueError('request while-else has no reviewed cleanup contract')
                super().statements((node,))
            elif isinstance(node, ast.Break):
                if not self.loop_stack:
                    raise ValueError('requests break has no owning loop')
                self.jump(self.loop_stack[-1][1])
            else:
                super().statements((node,))



def compile_policy(source):
    return Compiler(source)
