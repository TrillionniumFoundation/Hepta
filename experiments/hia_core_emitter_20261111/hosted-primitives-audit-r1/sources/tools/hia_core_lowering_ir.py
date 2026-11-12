"""Finite authoring compiler for the complete, explicitly checked lowering policy.

This module is never imported by the runtime. Its instructions are control
blocks subsequently rendered as HIA; they are not precomputed lowering results.
Unsupported Python syntax fails generation instead of falling back to Python.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


OPS = {
    'GLOBAL': 1, 'ATTR': 2, 'SET_ATTR': 3, 'ITEM': 4, 'SET_ITEM': 5,
    'CALL': 6, 'PACK': 7, 'ITER': 8, 'NEXT': 9, 'TRUTH': 10,
    'BINARY': 11, 'UNARY': 12, 'COMPARE': 13, 'UNPACK': 14,
    'SLICE': 15, 'APPEND': 16, 'IMPORT': 17, 'RAISE': 18,
    'GENERATOR': 19,
}
BINARY = {name: i for i, name in enumerate((
    'Add', 'Sub', 'Mult', 'FloorDiv', 'Div', 'Mod', 'Pow',
    'LShift', 'RShift', 'BitOr', 'BitXor', 'BitAnd'), 1)}
COMPARE = {name: i for i, name in enumerate((
    'Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'In', 'NotIn'), 1)}
UNARY = {'UAdd': 1, 'USub': 2, 'Invert': 3}
PACK = {'List': 1, 'Tuple': 2, 'Set': 3, 'Dict': 4}


@dataclass(frozen=True)
class Ref:
    kind: str
    index: int


@dataclass(frozen=True)
class Raw:
    value: int


class Literals:
    def __init__(self):
        self.values = []
        self.indices = {}
        for value in (None, False, True):
            self.get(value)

    def get(self, value):
        if type(value) not in (type(None), bool, int, str):
            raise ValueError('unsupported literal type: ' + type(value).__name__)
        if type(value) is int and not 0 <= value < 1 << 64:
            raise ValueError('integer literal must use explicit unary/arithmetic construction')
        key = (type(value), value)
        if key not in self.indices:
            self.indices[key] = len(self.values)
            self.values.append(value)
        return Ref('constant', self.indices[key])


class Function:
    def __init__(self, name, node, literals, generator_plans):
        self.name, self.node, self.literals = name, node, literals
        self.generator_plans = generator_plans
        self.instructions = []
        self.locals = {}
        self.slot_count = 0
        self.labels = 0
        self.comp_scopes = []
        self.parameters = [a.arg for a in node.args.args]
        if node.args.posonlyargs or node.args.vararg or node.args.kwonlyargs or node.args.kwarg:
            raise ValueError('unsupported policy signature: ' + name)
        if len(self.parameters) > 6:
            raise ValueError('policy ABI v2 accepts at most six bound arguments')
        for parameter in self.parameters:
            self.local(parameter)
        # Assignment establishes a Python local even before its first value.
        for value in ast.walk(node):
            if isinstance(value, ast.Name) and isinstance(value.ctx, ast.Store):
                self.local(value.id)
            elif isinstance(value, ast.ImportFrom):
                for alias in value.names:
                    self.local(alias.asname or alias.name)

    def temporary(self):
        result = Ref('slot', self.slot_count)
        self.slot_count += 1
        return result

    def local(self, name):
        if name not in self.locals:
            self.locals[name] = self.temporary()
        return self.locals[name]

    def variable(self, name):
        for scope in reversed(self.comp_scopes):
            if name in scope:
                return scope[name]
        return self.locals.get(name)

    def constant(self, value):
        return self.literals.get(value)

    def label(self):
        result = self.name + ':L' + str(self.labels)
        self.labels += 1
        return result

    def mark(self, label):
        self.instructions.append({'kind': 'mark', 'label': label})

    def move(self, destination, value):
        assert destination.kind == 'slot'
        self.instructions.append({'kind': 'move', 'destination': destination, 'value': value})

    def jump(self, label):
        self.instructions.append({'kind': 'jump', 'target': label})

    def effect(self, opcode, arguments, count=1, **extra):
        if len(arguments) > 8 or not 0 <= count <= 4:
            raise ValueError('foreign primitive exceeds the fixed HIA packet ABI')
        destinations = tuple(self.temporary() for _ in range(count))
        self.instructions.append({'kind': 'effect', 'opcode': OPS[opcode],
                                  'arguments': tuple(arguments), 'destinations': destinations, **extra})
        return destinations[0] if count == 1 else destinations

    def truth(self, value, yes, no):
        if value.kind == 'constant':
            literal = self.literals.values[value.index]
            # Literal truth is a static language operation, without foreign hooks.
            self.jump(yes if literal else no)
            return
        self.effect('TRUTH', (value,), count=0)
        self.instructions.append({'kind': 'flag', 'yes': yes, 'no': no})

    def condition(self, node, yes, no):
        if isinstance(node, ast.BoolOp):
            for value in node.values[:-1]:
                onward = self.label()
                self.condition(value, onward if isinstance(node.op, ast.And) else yes,
                               no if isinstance(node.op, ast.And) else onward)
                self.mark(onward)
            self.condition(node.values[-1], yes, no)
            return
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            self.condition(node.operand, no, yes)
            return
        if isinstance(node, ast.Compare) and len(node.ops) > 1:
            left = self.expression(node.left)
            for index, (operator, comparator) in enumerate(zip(node.ops, node.comparators)):
                right = self.expression(comparator)
                result = self.compare(operator, left, right)
                onward = yes if index == len(node.ops) - 1 else self.label()
                self.truth(result, onward, no)
                if index != len(node.ops) - 1:
                    self.mark(onward)
                left = right
            return
        self.truth(self.expression(node), yes, no)

    def compare(self, operator, left, right):
        if isinstance(operator, (ast.Is, ast.IsNot)):
            result = self.temporary()
            self.instructions.append({'kind': 'identity', 'destination': result,
                'left': left, 'right': right, 'negate': isinstance(operator, ast.IsNot),
                'true': self.constant(True), 'false': self.constant(False)})
            return result
        return self.effect('COMPARE', (Raw(COMPARE[type(operator).__name__]), left, right))

    def expression(self, node):
        if isinstance(node, ast.Constant):
            return self.constant(node.value)
        if isinstance(node, ast.Name):
            local = self.variable(node.id)
            return local if local is not None else self.effect('GLOBAL', (self.constant(node.id),))
        if isinstance(node, ast.Attribute):
            return self.effect('ATTR', (self.expression(node.value), self.constant(node.attr)))
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value)
            return self.effect('ITEM', (value, self.expression(node.slice)))
        if isinstance(node, ast.Slice):
            return self.effect('SLICE', tuple(self.expression(v) if v is not None else self.constant(None)
                                              for v in (node.lower, node.upper, node.step)))
        if isinstance(node, ast.BinOp):
            return self.effect('BINARY', (Raw(BINARY[type(node.op).__name__]),
                                          self.expression(node.left), self.expression(node.right)))
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                result, yes, no, done = self.temporary(), self.label(), self.label(), self.label()
                self.condition(node.operand, no, yes)
                self.mark(yes); self.move(result, self.constant(True)); self.jump(done)
                self.mark(no); self.move(result, self.constant(False)); self.mark(done)
                return result
            return self.effect('UNARY', (Raw(UNARY[type(node.op).__name__]), self.expression(node.operand)))
        if isinstance(node, ast.BoolOp):
            result, done = self.temporary(), self.label()
            for index, value in enumerate(node.values):
                observed = self.expression(value); self.move(result, observed)
                if index != len(node.values) - 1:
                    onward = self.label()
                    self.truth(observed, onward if isinstance(node.op, ast.And) else done,
                               done if isinstance(node.op, ast.And) else onward)
                    self.mark(onward)
            self.mark(done)
            return result
        if isinstance(node, ast.IfExp):
            result, yes, no, done = self.temporary(), self.label(), self.label(), self.label()
            self.condition(node.test, yes, no)
            self.mark(yes); self.move(result, self.expression(node.body)); self.jump(done)
            self.mark(no); self.move(result, self.expression(node.orelse)); self.mark(done)
            return result
        if isinstance(node, ast.Compare):
            if len(node.ops) == 1:
                return self.compare(node.ops[0], self.expression(node.left), self.expression(node.comparators[0]))
            raise ValueError('value-context chained comparisons are outside this finite policy grammar')
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            if isinstance(node, ast.Dict):
                if any(k is None for k in node.keys): raise ValueError('dict expansion is not admitted')
                values = tuple(v for pair in zip(node.keys, node.values) for v in pair)
            else:
                values = node.elts
            observed = tuple(self.expression(v) for v in values)
            return self.effect('PACK', (Raw(PACK[type(node).__name__]), Raw(len(observed))),
                               vector=observed)
        if isinstance(node, (ast.ListComp, ast.DictComp)):
            return self.comprehension(node)
        if isinstance(node, ast.GeneratorExp):
            return self.generator_expression(node)
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Name) and node.func.id in ('sum', 'max', 'any')
                    and len(node.args) == 1 and isinstance(node.args[0], ast.GeneratorExp)):
                return self.reduction(node)
            callee = self.expression(node.func)
            if any(isinstance(v, ast.Starred) for v in node.args) or len(node.args) > 4:
                raise ValueError('expanded or long call is outside the finite policy grammar')
            arguments = [self.expression(v) for v in node.args]
            if len(node.keywords) > 1:
                raise ValueError('multiple keyword entries are outside the finite policy grammar')
            key, value = self.constant(None), self.constant(None)
            if node.keywords:
                # Raw handle zero is a protocol tag for one **mapping expansion.
                # HIA still selects the original callee and evaluates the mapping
                # at the original argument point; CPython performs only CALL_EX.
                key = Raw(0) if node.keywords[0].arg is None else self.constant(node.keywords[0].arg)
                value = self.expression(node.keywords[0].value)
            arguments += [self.constant(None)] * (4 - len(arguments))
            return self.effect('CALL', (callee, Raw(len(node.args)), *arguments, key, value))
        raise ValueError('unsupported policy expression: ' + ast.dump(node))

    def generator_expression(self, node):
        # The current complete emitter has exactly the two p["type"] extension
        # generators. Refuse unreviewed captures rather than eagerly listing.
        if len(node.generators) != 1:
            raise ValueError('only the reviewed single-iterator generator is admitted')
        loop = node.generators[0]
        element = node.elt
        if (loop.is_async or loop.ifs or not isinstance(loop.target, ast.Name)
                or not isinstance(element, ast.Subscript)
                or not isinstance(element.value, ast.Name)
                or element.value.id != loop.target.id
                or not isinstance(element.slice, ast.Constant)
                or type(element.slice.value) is not str or element.slice.value != 'type'):
            raise ValueError('generator body has unreviewed captures or operations')
        # Generator expression creation evaluates its outer iter() immediately.
        # Its HIA NEXT and ITEM body remain suspended until Python asks next().
        iterator = self.effect('ITER', (self.expression(loop.iter),))
        name = '_native_generator_' + str(len(self.generator_plans))
        self.generator_plans.append({'name': name, 'target': loop.target, 'element': element})
        return self.effect('GENERATOR', (self.constant(name), iterator))

    def assign(self, target, value):
        if isinstance(target, ast.Name):
            local = self.variable(target.id)
            if local is None: local = self.local(target.id)
            self.move(local, value)
        elif isinstance(target, ast.Attribute):
            self.effect('SET_ATTR', (self.expression(target.value), self.constant(target.attr), value), count=0)
        elif isinstance(target, ast.Subscript):
            self.effect('SET_ITEM', (self.expression(target.value), self.expression(target.slice), value), count=0)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if not 1 <= len(target.elts) <= 4: raise ValueError('unpack arity outside packet profile')
            pieces = self.effect('UNPACK', (value, Raw(len(target.elts))), count=len(target.elts))
            if len(target.elts) == 1: pieces = (pieces,)
            for child, piece in zip(target.elts, pieces): self.assign(child, piece)
        else:
            raise ValueError('unsupported assignment target: ' + ast.dump(target))

    def iterate(self, generators, body, *, first_iterator=None):
        if not generators:
            body(); return
        generator = generators[0]
        if generator.is_async: raise ValueError('async comprehension is not supported')
        iterator = first_iterator or self.effect('ITER', (self.expression(generator.iter),))
        head, found, done = self.label(), self.label(), self.label()
        self.mark(head); value = self.effect('NEXT', (iterator,))
        self.instructions.append({'kind': 'flag', 'yes': found, 'no': done})
        self.mark(found); self.assign(generator.target, value)
        for condition in generator.ifs:
            onward = self.label(); self.condition(condition, onward, head); self.mark(onward)
        self.iterate(generators[1:], body)
        self.jump(head); self.mark(done)

    def scope_for(self, generators):
        names = {v.id for g in generators for v in ast.walk(g.target)
                 if isinstance(v, ast.Name) and isinstance(v.ctx, ast.Store)}
        return {name: self.temporary() for name in sorted(names)}

    def comprehension(self, node):
        # The outer iterable is bound before the comprehension's own locals.
        first = self.effect('ITER', (self.expression(node.generators[0].iter),))
        result = self.effect('PACK', (Raw(PACK['Dict' if isinstance(node, ast.DictComp) else 'List']), Raw(0)), vector=())
        self.comp_scopes.append(self.scope_for(node.generators))
        def body():
            if isinstance(node, ast.DictComp):
                key, value = self.expression(node.key), self.expression(node.value)
                self.effect('SET_ITEM', (result, key, value), count=0)
            else:
                self.effect('APPEND', (result, self.expression(node.elt)), count=0)
        self.iterate(node.generators, body, first_iterator=first)
        self.comp_scopes.pop()
        return result

    def reduction(self, node):
        name, generator = node.func.id, node.args[0]
        if any(k.arg != 'default' for k in node.keywords) or len(node.keywords) > 1:
            raise ValueError('unsupported generator reduction keyword')
        if name != 'max' and node.keywords: raise ValueError('unexpected reduction keyword')
        if name == 'max' and not node.keywords:
            raise ValueError('the finite max-generator profile requires an explicit default')
        # These are explicit HIA loops; a hosted Python generator is never built.
        first = self.effect('ITER', (self.expression(generator.generators[0].iter),))
        result, seen, done = self.temporary(), self.temporary(), self.label()
        default = self.expression(node.keywords[0].value) if node.keywords else self.constant(False if name == 'any' else 0)
        self.move(result, default); self.move(seen, self.constant(False))
        self.comp_scopes.append(self.scope_for(generator.generators))
        def body():
            value = self.expression(generator.elt)
            if name == 'sum':
                self.move(result, self.effect('BINARY', (Raw(BINARY['Add']), result, value)))
            elif name == 'any':
                yes, no = self.label(), self.label()
                self.truth(value, yes, no); self.mark(yes)
                self.move(result, self.constant(True)); self.jump(done); self.mark(no)
            else:
                compare, take, onward = self.label(), self.label(), self.label()
                self.truth(seen, compare, take); self.mark(compare)
                self.truth(self.compare(ast.Gt(), value, result), take, onward)
                self.mark(take); self.move(result, value); self.move(seen, self.constant(True))
                self.mark(onward)
        self.iterate(generator.generators, body, first_iterator=first)
        self.comp_scopes.pop(); self.mark(done)
        return result

    def statements(self, nodes):
        for node in nodes:
            if isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant): self.expression(node.value)
            elif isinstance(node, ast.Assign):
                value = self.expression(node.value)
                for target in node.targets: self.assign(target, value)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    old = self.variable(node.target.id); receiver = None
                elif isinstance(node.target, ast.Attribute):
                    receiver = self.expression(node.target.value)
                    old = self.effect('ATTR', (receiver, self.constant(node.target.attr)))
                else:
                    raise ValueError('unsupported augmented assignment target')
                value = self.effect('BINARY', (Raw(128 + BINARY[type(node.op).__name__]), old, self.expression(node.value)))
                if receiver is None: self.assign(node.target, value)
                else: self.effect('SET_ATTR', (receiver, self.constant(node.target.attr), value), count=0)
            elif isinstance(node, ast.If):
                yes, no, done = self.label(), self.label(), self.label()
                self.condition(node.test, yes, no); self.mark(yes)
                self.statements(node.body); self.jump(done); self.mark(no)
                self.statements(node.orelse); self.mark(done)
            elif isinstance(node, ast.For):
                iterator = self.effect('ITER', (self.expression(node.iter),))
                head, found, done = self.label(), self.label(), self.label()
                self.mark(head); value = self.effect('NEXT', (iterator,))
                self.instructions.append({'kind':'flag','yes':found,'no':done})
                self.mark(found); self.assign(node.target, value); self.statements(node.body)
                self.jump(head); self.mark(done); self.statements(node.orelse)
            elif isinstance(node, ast.While):
                head, body, done = self.label(), self.label(), self.label()
                self.mark(head); self.condition(node.test, body, done); self.mark(body)
                self.statements(node.body); self.jump(head); self.mark(done); self.statements(node.orelse)
            elif isinstance(node, ast.Return):
                self.instructions.append({'kind':'return','value':self.expression(node.value) if node.value is not None else self.constant(None)})
            elif isinstance(node, ast.ImportFrom):
                imports = {('hia_machine_plan', 'VALUE_REGISTERS'): 1,
                           ('hia_machine_plan', 'code_options'): 2,
                           ('hia_native_byte_abi', 'emit_wrapper'): 3}
                if node.level != 1 or len(node.names) != 1 or (node.module, node.names[0].name) not in imports:
                    raise ValueError('only the three original explicit imports are admitted')
                value = self.effect('IMPORT', (Raw(imports[(node.module, node.names[0].name)]),))
                self.move(self.local(node.names[0].asname or node.names[0].name), value)
            elif isinstance(node, ast.Raise):
                if node.cause is not None or node.exc is None: raise ValueError('unsupported raise form')
                self.effect('RAISE', (self.expression(node.exc),), count=0)
            elif isinstance(node, ast.Pass):
                pass
            else:
                raise ValueError('unsupported policy statement: ' + ast.dump(node))

    def compile(self):
        self.statements(self.node.body)
        self.instructions.append({'kind':'return','value':self.constant(None)})
        return self


class GeneratorFunction(Function):
    """One HIA-controlled lazy generator; the first iterator is already bound."""

    is_generator = True

    def __init__(self, plan, literals, generator_plans):
        node = ast.parse('def ' + plan['name'] + '(iterator):\n    pass\n').body[0]
        super().__init__(plan['name'], node, literals, generator_plans)
        self.plan = plan

    def compile(self):
        head, found, done = self.label(), self.label(), self.label()
        self.mark(head)
        value = self.effect('NEXT', (self.locals['iterator'],))
        self.instructions.append({'kind': 'flag', 'yes': found, 'no': done})
        self.mark(found)
        self.assign(self.plan['target'], value)
        self.instructions.append({'kind': 'yield', 'value': self.expression(self.plan['element'])})
        self.jump(head)
        self.mark(done)
        self.instructions.append({'kind': 'return', 'value': self.constant(None)})
        return self


def compile_policy(source):
    tree = ast.parse(source)
    literals, functions, generator_plans = Literals(), [], []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            functions.append(Function(node.name, node, literals, generator_plans).compile())
        elif isinstance(node, ast.ClassDef) and node.name in ('_Function', '_Emitter'):
            for method in node.body:
                if not isinstance(method, ast.FunctionDef): raise ValueError('unsupported lowering class body')
                functions.append(Function(node.name + '.' + method.name, method, literals, generator_plans).compile())
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            pass
        else:
            raise ValueError('policy contains an unreviewed top-level declaration')
    for plan in generator_plans:
        functions.append(GeneratorFunction(plan, literals, generator_plans).compile())
    instructions, entries, labels = [], {}, {}
    for mode, function in enumerate(functions, 1):
        entries[function.name] = {'mode':mode,'pc':len(instructions)+1,'parameters':function.parameters,
                                  'slots':function.slot_count, 'generator':getattr(function, 'is_generator', False)}
        for instruction in function.instructions:
            if instruction['kind'] == 'mark': labels[instruction['label']] = len(instructions)+1
            else: instructions.append(dict(instruction, function=function.name, pc=len(instructions)+1))
    for instruction in instructions:
        for field in ('target','yes','no'):
            if field in instruction: instruction[field] = labels[instruction[field]]
    return literals, functions, entries, instructions
