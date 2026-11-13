"""Finite original ELF-policy authoring on the unchanged 18-primitive ABI.

Lazy generators and sort keys dispatch their predicates/projections to HIA.
The hosted iterator/call transport does not reproduce a product predicate or
substitute a sorting algorithm. Existing compiler and packet caps stay fixed.
"""
from __future__ import annotations

import ast
import copy

from tools.hia_core_lowering_ir import Function, Literals, Raw, link_functions


class ObjectFunction(Function):
    def __init__(self, name, node, literals, callbacks, helpers):
        super().__init__(name, node, literals)
        self.callbacks = callbacks
        self.helpers = helpers
        self.inline_returns = []

    def statements(self, nodes):
        for node in nodes:
            if isinstance(node, ast.Return) and self.inline_returns:
                result, done = self.inline_returns[-1]
                self.move(result, self.expression(node.value) if node.value else self.constant(None))
                self.jump(done)
            else:
                super().statements([node])

    def call(self, target, arguments, key=None, value=None):
        if len(arguments) > 4:
            raise ValueError('mechanical bridge exceeds original four bound arguments')
        empty = self.constant(None)
        return self.effect('CALL', (target, Raw(len(arguments)),
            *arguments, *([empty] * (4 - len(arguments))),
            empty if key is None else key, empty if value is None else value))

    def bridge(self, name, arguments):
        target = super().expression(ast.Name(id=name, ctx=ast.Load()))
        return self.call(target, arguments)

    def expression(self, node):
        if isinstance(node, ast.Constant) and type(node.value) is bytes:
            return self.bridge('_hia_object_literal_bytes', (self.constant(node.value.hex()),))
        if isinstance(node, ast.Compare) and len(node.ops) > 1:
            result, done = self.temporary(), self.label()
            left = self.expression(node.left)
            for index, (operator, comparator) in enumerate(zip(node.ops, node.comparators)):
                right = self.expression(comparator)
                self.move(result, self.compare(operator, left, right))
                if index < len(node.ops) - 1:
                    onward = self.label()
                    self.truth(result, onward, done)
                    self.mark(onward)
                left = right
            self.mark(done)
            return result
        if isinstance(node, (ast.Lambda, ast.GeneratorExp)):
            key = ast.dump(node, include_attributes=False)
            if key not in self.callbacks:
                raise ValueError('unreviewed ELF callback')
            mode = self.constant(self.callbacks[key])
            if isinstance(node, ast.Lambda):
                return self.bridge('_hia_object_callback', (mode,))
            generator = node.generators[0]
            # GET_ITER is eager at generator construction; the hosted iterator
            # continuation uses NEXT directly and must not repeat __iter__.
            iterable = self.expression(generator.iter)
            iterator = self.effect('ITER', (iterable,))
            return self.bridge('_hia_object_generator', (mode, iterator))
        if isinstance(node, ast.Call):
            # Keep original global lookup/callee/argument/keyword order, also
            # for any(generator). No compiler reduction bypasses that lookup.
            target = self.expression(node.func)
            if any(isinstance(n, ast.Starred) for n in node.args):
                raise ValueError('expanded ELF argument requires review')
            if len(node.keywords) > 1 or any(n.arg is None for n in node.keywords):
                raise ValueError('expanded ELF keywords require review')
            arguments = tuple(self.expression(n) for n in node.args)
            if isinstance(node.func, ast.Name) and node.func.id in self.helpers:
                helper = self.helpers[node.func.id]
                parameters = [n.arg for n in helper.args.args]
                if node.keywords or len(arguments) != len(parameters):
                    raise ValueError('ELF internal helper binding differs')
                # These exact HIA-owned helper bodies have no assignment or
                # recursion. Preserve callee and argument observation order,
                # then lower the body in fresh slots rather than allocate a
                # second hosted continuation. No retained helper is called.
                bound = {}
                for name, argument in zip(parameters, arguments):
                    slot = self.temporary()
                    self.move(slot, argument)
                    bound[name] = slot
                result, done = self.temporary(), self.label()
                self.comp_scopes.append(bound)
                self.inline_returns.append((result, done))
                self.statements(helper.body)
                self.inline_returns.pop()
                self.comp_scopes.pop()
                self.mark(done)
                return result
            keyword = node.keywords[0] if node.keywords else None
            name = self.constant(keyword.arg) if keyword else self.constant(None)
            value = self.expression(keyword.value) if keyword else self.constant(None)
            if len(arguments) <= 4:
                return self.call(target, arguments, name, value)
            if keyword:
                raise ValueError('long ELF call with keyword requires review')
            packed = self.effect('PACK', (Raw(2), Raw(len(arguments))), vector=arguments)
            return self.bridge('_hia_object_call_arguments', (target, packed))
        return super().expression(node)

    def assign(self, target, value):
        if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 8:
            unpacked = self.bridge('_hia_object_unpack_eight', (value,))
            for index, element in enumerate(target.elts):
                item = self.effect('ITEM', (unpacked, self.constant(index)))
                super().assign(element, item)
            return
        return super().assign(target, value)


def function(name, parameters, body):
    return ast.FunctionDef(name=name, args=ast.arguments(posonlyargs=[],
        args=[ast.arg(arg=n) for n in parameters], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=body, decorator_list=[])


def compile_policy(source):
    declarations = [n for n in ast.parse(source).body if not (isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Constant) and type(n.value.value) is str)]
    if tuple(getattr(n, 'name', None) for n in declarations) != ('_name', '_exact_int', 'write_elf_object'):
        raise ValueError('complete ELF function inventory differs')
    callbacks, extras = {}, []
    for node in ast.walk(ast.Module(body=declarations, type_ignores=[])):
        if not isinstance(node, (ast.Lambda, ast.GeneratorExp)):
            continue
        key = ast.dump(node, include_attributes=False)
        if key in callbacks:
            continue
        mode = 'elf.callback.' + str(len(callbacks))
        callbacks[key] = mode
        if isinstance(node, ast.Lambda):
            if len(node.args.args) != 1 or node.args.defaults or node.args.kwonlyargs:
                raise ValueError('ELF sort key signature requires review')
            parameters = [n.arg for n in node.args.args]
            bound = set(parameters)
            body = [ast.Return(value=copy.deepcopy(node.body))]
            expression_nodes = [node.body]
        else:
            if len(node.generators) != 1 or node.generators[0].is_async:
                raise ValueError('ELF generator signature requires review')
            generator = node.generators[0]
            bound = {n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name)}
            parameters = ['_hia_object_item']
            body = [ast.Assign(targets=[copy.deepcopy(generator.target)],
                               value=ast.Name(id=parameters[0], ctx=ast.Load()))]
            for condition in generator.ifs:
                body.append(ast.If(test=ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(condition)),
                    body=[ast.Return(value=ast.Tuple(elts=[ast.Constant(False), ast.Constant(None)], ctx=ast.Load()))],
                    orelse=[]))
            body.append(ast.Return(value=ast.Tuple(elts=[ast.Constant(True), copy.deepcopy(node.elt)], ctx=ast.Load())))
            expression_nodes = [node.elt, *generator.ifs]
        free = {n.id for e in expression_nodes for n in ast.walk(e)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} - bound
        if free:
            raise ValueError('ELF callback captures require explicit transport: ' + repr(free))
        extras.append(function(mode, parameters, body))
    writer = copy.deepcopy(declarations[-1])
    if ([n.arg for n in writer.args.kwonlyargs] != ['text_alignment']
            or [ast.dump(n) for n in writer.args.kw_defaults] != [ast.dump(ast.Constant(16))]):
        raise ValueError('ELF keyword binding differs')
    writer.args.args += writer.args.kwonlyargs
    writer.args.kwonlyargs, writer.args.kw_defaults = [], []
    declarations = [*declarations[:-1], writer, *extras]
    literals = Literals()
    helpers = {n.name:n for n in declarations[:2]}
    functions = [ObjectFunction(n.name, n, literals, callbacks, helpers).compile() for n in declarations]
    return link_functions(literals, functions)
