"""Finite source compiler for the four machine-plan APIs and their helpers.

This is an authoring tool.  Its output is ordinary HIA control flow.  Runtime
never imports this module or executes a retained Python policy function.
Object operations remain individually visible foreign requests; their result
does not choose the next operation until the HIA continuation acknowledges it.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


OPS = {name: i + 1 for i, name in enumerate((
    'CONST', 'GLOBAL', 'ATTR', 'ITEM', 'BINARY', 'COMPARE', 'UNARY', 'TRUTH',
    'CALL', 'PACK', 'ITER', 'NEXT', 'UNPACK', 'SET_ITEM', 'STORE', 'RELEASE',
    'SLICE', 'FUNCTION', 'IMPORT', 'RAISE', 'EXCEPTION_MATCH', 'ERROR',
    'APPEND', 'EXTEND', 'SET_ADD', 'HANDLED', 'CLEAR_HANDLED', 'DROP_SLOT'))}
BINARY = {name: i + 1 for i, name in enumerate((
    'Add', 'Sub', 'Mult', 'FloorDiv', 'Div', 'Mod', 'Pow', 'LShift',
    'RShift', 'BitOr', 'BitXor', 'BitAnd'))}
COMPARE = {name: i + 1 for i, name in enumerate((
    'Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'In', 'NotIn', 'Is', 'IsNot'))}
UNARY = {'UAdd': 1, 'USub': 2, 'Invert': 3, 'Not': 4}
PACK = {'List': 1, 'Tuple': 2, 'Set': 3, 'Dict': 4}
PUBLIC = ('validate_plan', 'register_assignment_witness', 'code_options',
          'preservation_checks')
HELPERS = ('_require', '_permutation', '_terminal_arguments')


@dataclass(frozen=True)
class Ref:
    slot: int
    temporary: bool = True


class Compiler:
    def __init__(self, source):
        self.source = source
        self.tree = ast.parse(source)
        self.literals = []
        self.literal_indices = {}
        self.functions = []
        self.by_name = {}
        for name in (*PUBLIC, *HELPERS):
            node = next(n for n in self.tree.body
                        if isinstance(n, ast.FunctionDef) and n.name in
                        (name, '_reference_' + name))
            function = Function(self, name, node)
            self.functions.append(function)
            self.by_name[name] = function
        index = 0
        while index < len(self.functions):
            self.functions[index].compile()
            index += 1
        for mode, function in enumerate(self.functions, 1):
            function.mode = mode
        for function in self.functions:
            function.resolve()

    def literal(self, value):
        if type(value) not in (type(None), bool, int, str, tuple, frozenset):
            raise ValueError('unreviewed machine-plan literal ' + repr(value))
        key = (type(value), value)
        if key not in self.literal_indices:
            self.literal_indices[key] = len(self.literals)
            self.literals.append(value)
        return self.literal_indices[key]

    def nested(self, parent, node, kind):
        name = parent.name + ':' + kind + ':' + str(len(self.functions))
        function = Function(self, name, node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


class Function:
    def __init__(self, compiler, name, node, *, parent=None, kind='function'):
        self.compiler, self.name, self.node = compiler, name, node
        self.parent, self.kind = parent, kind
        self.instructions, self.locals, self.captures = [], {}, {}
        self.scopes = []
        self.temporary_slots = set()
        self.cell_slots = set()
        self.next_slot = 0
        self.next_label = 0
        self.handlers = []
        self.loop_stack = []
        if kind == 'generator':
            self.parameters = ['.0']
        else:
            args = node.args
            if args.posonlyargs or args.vararg or args.kwarg:
                raise ValueError('unsupported finite policy signature')
            self.parameters = [a.arg for a in args.args + args.kwonlyargs]
        for name in self.parameters:
            self.local(name)
        if kind == 'function':
            # Comprehension bindings have separate inline scopes.  They must
            # neither overwrite nor retain an unrelated outer local.
            def stores(value):
                if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp,
                                      ast.GeneratorExp, ast.Lambda)):
                    return
                if isinstance(value, ast.Name) and isinstance(value.ctx, ast.Store):
                    self.local(value.id)
                if isinstance(value, ast.ImportFrom):
                    for alias in value.names:
                        self.local(alias.asname or alias.name)
                if isinstance(value, ast.ExceptHandler) and value.name:
                    # CPython deletes the except binding even when its body
                    # raises. It is not a traceback-retained function local.
                    if value.name not in self.locals:
                        self.locals[value.name] = self.slot()
                for child in ast.iter_child_nodes(value):
                    stores(child)
            for statement in node.body:
                stores(statement)

    def slot(self, temporary=True):
        value = Ref(self.next_slot, temporary)
        self.next_slot += 1
        if temporary:
            self.temporary_slots.add(value.slot)
        return value

    def local(self, name):
        if name not in self.locals:
            self.locals[name] = self.slot(False)
        return self.locals[name]

    def variable(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        if name in self.locals:
            return self.locals[name]
        if name in self.captures:
            return self.captures[name][0]
        if self.parent is not None:
            outer = self.parent.variable(name)
            if outer is not None:
                self.parent.cell_slots.add(outer.slot)
                own = self.slot(False)
                self.captures[name] = (own, outer)
                return own
        return None

    def label(self):
        value = 'L' + str(self.next_label)
        self.next_label += 1
        return value

    def mark(self, label):
        self.instructions.append({'kind': 'label', 'label': label})

    def emit(self, kind, **fields):
        self.instructions.append({'kind': kind, **fields})

    def jump(self, label):
        self.emit('jump', target=label)

    def effect(self, operation, arguments=(), *, raw=(), vector=(), count=1,
               consume=(), destination=None):
        destinations = ([destination] if destination is not None else
                        [self.slot() for _ in range(count)])
        retired = []
        for ref in consume:
            if ref is not None and ref.temporary and ref not in retired:
                retired.append(ref)
        self.emit('effect', opcode=OPS[operation], arguments=list(arguments),
                  raw=list(raw), vector=list(vector), destinations=destinations,
                  consume=retired,
                  handler=self.handlers[-1] if self.handlers else None)
        return destinations[0] if len(destinations) == 1 else tuple(destinations)

    def release(self, refs):
        values = []
        seen = set()
        for ref in refs:
            if ref is not None and ref.temporary and ref.slot not in seen:
                seen.add(ref.slot)
                values.append(ref)
        if values:
            self.emit('effect', opcode=OPS['RELEASE'], arguments=[], raw=[],
                      vector=values, destinations=[], consume=[], handler=None)

    def constant(self, value):
        return self.effect('CONST', raw=(self.compiler.literal(value),))

    def copy(self, value):
        return self.effect('STORE', (value,))

    def store(self, destination, value, *, consume=True):
        self.effect('STORE', (value,), destination=destination,
                    consume=(value,) if consume else ())

    def truth(self, value, yes, no):
        self.effect('TRUTH', (value,), count=0, consume=(value,))
        self.emit('flag', yes=yes, no=no)

    def condition(self, node, yes, no):
        if isinstance(node, ast.BoolOp):
            for child in node.values[:-1]:
                onward = self.label()
                self.condition(child, onward if isinstance(node.op, ast.And) else yes,
                               no if isinstance(node.op, ast.And) else onward)
                self.mark(onward)
            self.condition(node.values[-1], yes, no)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            self.condition(node.operand, no, yes)
        else:
            self.truth(self.expression(node), yes, no)

    def expression(self, node):
        if isinstance(node, ast.Constant):
            return self.constant(node.value)
        if isinstance(node, ast.Name):
            value = self.variable(node.id)
            return self.copy(value) if value is not None else self.effect(
                'GLOBAL', raw=(self.compiler.literal(node.id),))
        if isinstance(node, ast.Attribute):
            owner = self.expression(node.value)
            return self.effect('ATTR', (owner,), raw=(self.compiler.literal(node.attr),),
                               consume=(owner,))
        if isinstance(node, ast.Subscript):
            owner, key = self.expression(node.value), self.expression(node.slice)
            return self.effect('ITEM', (owner, key), consume=(owner, key))
        if isinstance(node, ast.Slice):
            values = [self.expression(v) if v is not None else self.constant(None)
                      for v in (node.lower, node.upper, node.step)]
            return self.effect('SLICE', values, consume=values)
        if isinstance(node, ast.BinOp):
            left, right = self.expression(node.left), self.expression(node.right)
            return self.effect('BINARY', (left, right), raw=(BINARY[type(node.op).__name__],),
                               consume=(left, right))
        if isinstance(node, ast.UnaryOp):
            value = self.expression(node.operand)
            return self.effect('UNARY', (value,), raw=(UNARY[type(node.op).__name__],),
                               consume=(value,))
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1:
                raise ValueError('unreviewed chained comparison')
            left, right = self.expression(node.left), self.expression(node.comparators[0])
            return self.effect('COMPARE', (left, right), raw=(COMPARE[type(node.ops[0]).__name__],),
                               consume=(left, right))
        if isinstance(node, ast.BoolOp):
            result, done = self.slot(), self.label()
            for index, child in enumerate(node.values):
                value = self.expression(child)
                self.store(result, value)
                if index != len(node.values) - 1:
                    onward = self.label()
                    self.truth(self.copy(result), onward if isinstance(node.op, ast.And) else done,
                               done if isinstance(node.op, ast.And) else onward)
                    self.mark(onward)
            self.mark(done)
            return result
        if isinstance(node, ast.IfExp):
            result, yes, no, done = self.slot(), self.label(), self.label(), self.label()
            self.condition(node.test, yes, no)
            self.mark(yes); self.store(result, self.expression(node.body)); self.jump(done)
            self.mark(no); self.store(result, self.expression(node.orelse)); self.mark(done)
            return result
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            kind = PACK[type(node).__name__]
            if isinstance(node, ast.Dict):
                if any(key is None for key in node.keys):
                    raise ValueError('unreviewed dictionary expansion')
                children = [value for pair in zip(node.keys, node.values) for value in pair]
            else:
                children = node.elts
            if any(isinstance(child, ast.Starred) for child in children):
                if kind != PACK['List']:
                    raise ValueError('unreviewed starred pack')
                result = self.effect('PACK', raw=(kind,), vector=())
                for child in children:
                    value = self.expression(child.value if isinstance(child, ast.Starred) else child)
                    self.effect('EXTEND' if isinstance(child, ast.Starred) else 'APPEND',
                                (result, value), count=0, consume=(value,))
                return result
            values = [self.expression(child) for child in children]
            return self.effect('PACK', raw=(kind,), vector=values, consume=reversed(values))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            return self.comprehension(node)
        if isinstance(node, ast.GeneratorExp):
            iterator_value = self.expression(node.generators[0].iter)
            iterator = self.effect('ITER', (iterator_value,), consume=(iterator_value,))
            nested = self.compiler.nested(self, node, 'generator')
            # Compile now so closure cells are fixed before the request which
            # creates this generator.  Later outer assignments update cells.
            nested.compile()
            return self.effect('FUNCTION', (iterator,), raw=(nested, 1),
                               vector=[pair[1] for pair in nested.captures.values()],
                               consume=(iterator,))
        if isinstance(node, ast.Lambda):
            nested = self.compiler.nested(self, node, 'lambda')
            nested.compile()
            return self.effect('FUNCTION', raw=(nested, 0),
                               vector=[pair[1] for pair in nested.captures.values()])
        if isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args) or len(node.args) > 4:
                raise ValueError('unreviewed call extent')
            if any(keyword.arg is None for keyword in node.keywords) or len(node.keywords) > 2:
                raise ValueError('unreviewed call keywords')
            callee = self.expression(node.func)
            args = [self.expression(arg) for arg in node.args]
            keys = [self.compiler.literal(keyword.arg) for keyword in node.keywords]
            values = [self.expression(keyword.value) for keyword in node.keywords]
            return self.effect('CALL', [callee, *args, *values],
                               raw=(len(args), len(keys), *keys),
                               consume=(callee, *args, *values))
        if isinstance(node, ast.JoinedStr):
            values = []
            for child in node.values:
                if isinstance(child, ast.Constant):
                    values.append(self.constant(child.value))
                elif isinstance(child, ast.FormattedValue):
                    if child.conversion != -1 or child.format_spec is not None:
                        raise ValueError('unreviewed f-string format')
                    callee = self.effect('GLOBAL', raw=(self.compiler.literal('format'),))
                    value = self.expression(child.value)
                    values.append(self.effect('CALL', (callee, value), raw=(1, 0),
                                              consume=(callee, value)))
                else:
                    raise ValueError('unreviewed f-string')
            result = self.constant('')
            for value in values:
                result = self.effect('BINARY', (result, value), raw=(BINARY['Add'],),
                                     consume=(result, value))
            return result
        raise ValueError('unreviewed expression: ' + ast.dump(node))

    def assign(self, target, value):
        if isinstance(target, ast.Name):
            destination = self.variable(target.id)
            if destination is None:
                destination = self.local(target.id)
            self.store(destination, value)
        elif isinstance(target, ast.Subscript):
            owner, key = self.expression(target.value), self.expression(target.slice)
            self.effect('SET_ITEM', (owner, key, value), count=0,
                        consume=(value, owner, key))
        elif isinstance(target, (ast.Tuple, ast.List)):
            pieces = self.effect('UNPACK', (value,), raw=(len(target.elts),),
                                 count=len(target.elts), consume=(value,))
            if len(target.elts) == 1:
                pieces = (pieces,)
            for child, piece in zip(target.elts, pieces):
                self.assign(child, piece)
        else:
            raise ValueError('unreviewed assignment: ' + ast.dump(target))

    def iterate(self, generators, body, *, first=None):
        if not generators:
            body(); return
        generator = generators[0]
        if generator.is_async:
            raise ValueError('asynchronous policy is not admitted')
        if first is None:
            iterable = self.expression(generator.iter)
            iterator = self.effect('ITER', (iterable,), consume=(iterable,))
        else:
            iterator = first
        head, found, done = self.label(), self.label(), self.label()
        self.mark(head)
        value = self.effect('NEXT', (iterator,))
        self.emit('flag', yes=found, no=done)
        self.mark(found); self.assign(generator.target, value)
        for condition in generator.ifs:
            onward = self.label()
            self.condition(condition, onward, head)
            self.mark(onward)
        self.iterate(generators[1:], body)
        self.jump(head); self.mark(done)
        self.release((value, iterator))

    def comp_scope(self, generators, *, generator=False):
        names = {n.id for generator in generators for n in ast.walk(generator.target)
                 if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        return {name: self.slot(not generator) for name in sorted(names)}

    def comprehension(self, node):
        iterable = self.expression(node.generators[0].iter)
        first = self.effect('ITER', (iterable,), consume=(iterable,))
        kind = ('Dict' if isinstance(node, ast.DictComp) else
                'Set' if isinstance(node, ast.SetComp) else 'List')
        result = self.effect('PACK', raw=(PACK[kind],), vector=())
        scope = self.comp_scope(node.generators)
        self.scopes.append(scope)
        def body():
            if kind == 'Dict':
                key, value = self.expression(node.key), self.expression(node.value)
                self.effect('SET_ITEM', (result, key, value), count=0,
                            consume=(value, key))
            else:
                value = self.expression(node.elt)
                self.effect('SET_ADD' if kind == 'Set' else 'APPEND',
                            (result, value), count=0, consume=(value,))
        self.iterate(node.generators, body, first=first)
        self.scopes.pop()
        self.release(reversed(tuple(scope.values())))
        return result

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant):
                    self.release((self.expression(node.value),))
            elif isinstance(node, ast.Assign):
                value = self.expression(node.value)
                if len(node.targets) != 1:
                    raise ValueError('unreviewed chained assignment')
                self.assign(node.targets[0], value)
            elif isinstance(node, ast.AugAssign):
                if not isinstance(node.target, ast.Name):
                    raise ValueError('unreviewed augmented target')
                left = self.expression(ast.Name(id=node.target.id, ctx=ast.Load()))
                right = self.expression(node.value)
                value = self.effect('BINARY', (left, right),
                                    raw=(128 + BINARY[type(node.op).__name__],),
                                    consume=(left, right))
                self.assign(node.target, value)
            elif isinstance(node, ast.If):
                yes, no, done = self.label(), self.label(), self.label()
                self.condition(node.test, yes, no)
                self.mark(yes); self.statements(node.body); self.jump(done)
                self.mark(no); self.statements(node.orelse); self.mark(done)
            elif isinstance(node, ast.For):
                iterable = self.expression(node.iter)
                iterator = self.effect('ITER', (iterable,), consume=(iterable,))
                head, found, done = self.label(), self.label(), self.label()
                self.mark(head)
                value = self.effect('NEXT', (iterator,))
                self.emit('flag', yes=found, no=done)
                self.mark(found); self.assign(node.target, value)
                self.loop_stack.append((head, done))
                self.statements(node.body)
                self.loop_stack.pop()
                self.jump(head); self.mark(done)
                self.release((value, iterator)); self.statements(node.orelse)
            elif isinstance(node, ast.Return):
                value = self.expression(node.value) if node.value else self.constant(None)
                self.emit('return', value=value)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 1 or node.module != 'hia_program':
                    raise ValueError('unreviewed import')
                for alias in node.names:
                    value = self.effect('IMPORT', raw=(self.compiler.literal(alias.name),))
                    self.assign(ast.Name(id=alias.asname or alias.name, ctx=ast.Store()), value)
            elif isinstance(node, ast.Raise):
                if node.exc is None:
                    raise ValueError('bare re-raise is not used by this policy')
                value = self.expression(node.exc)
                cause = self.expression(node.cause) if node.cause else self.constant(None)
                self.effect('RAISE', (value, cause), raw=(int(node.cause is not None),), count=0)
            elif isinstance(node, ast.Try):
                if len(node.handlers) != 1 or node.orelse or node.finalbody:
                    raise ValueError('unreviewed exception control')
                handler = node.handlers[0]
                if handler.type is None:
                    raise ValueError('unreviewed bare handler')
                caught, matched, not_matched, done = (self.label() for _ in range(4))
                self.handlers.append(caught)
                self.statements(node.body)
                self.handlers.pop(); self.jump(done); self.mark(caught)
                typ = self.expression(handler.type)
                self.effect('EXCEPTION_MATCH', (typ,), count=0, consume=(typ,))
                self.emit('flag', yes=matched, no=not_matched)
                self.mark(not_matched); self.emit('error_return')
                self.mark(matched)
                if handler.name:
                    error = self.effect('ERROR')
                    self.assign(ast.Name(id=handler.name, ctx=ast.Store()), error)
                self.effect('HANDLED', count=0)
                self.statements(handler.body)
                self.effect('CLEAR_HANDLED', count=0)
                if handler.name:
                    self.store(self.local(handler.name), self.constant(None))
                self.mark(done)
            elif isinstance(node, ast.Pass):
                pass
            else:
                raise ValueError('unreviewed statement: ' + ast.dump(node))

    def compile(self):
        if getattr(self, '_compiled', False):
            return
        self._compiled = True
        if self.kind == 'generator':
            # Unlike inlined comprehension bindings, a generator's targets
            # remain locals in a retained exception traceback.
            scope = self.comp_scope(self.node.generators, generator=True)
            self.scopes.append(scope)
            def body():
                value = self.expression(self.node.elt)
                self.emit('yield', value=value)
                self.release((value,))
            self.iterate(self.node.generators, body,
                         first=self.copy(self.local('.0')))
            self.scopes.pop(); self.release(reversed(tuple(scope.values())))
        elif self.kind == 'lambda':
            self.emit('return', value=self.expression(self.node.body))
        else:
            self.statements(self.node.body)
        self.emit('return', value=self.constant(None))

    def resolve(self):
        labels, final = {}, []
        for instruction in self.instructions:
            if instruction['kind'] == 'label':
                labels[instruction['label']] = len(final) + 1
            else:
                final.append(dict(instruction, pc=len(final) + 1))
        for instruction in final:
            for key in ('target', 'yes', 'no', 'handler'):
                if key in instruction and instruction[key] is not None:
                    instruction[key] = labels[instruction[key]]
            if instruction['kind'] == 'effect':
                instruction['raw'] = [value.mode if isinstance(value, Function) else value
                                      for value in instruction['raw']]
        self.instructions = final


def compile_policy(source):
    return Compiler(source)
