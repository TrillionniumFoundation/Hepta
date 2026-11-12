"""Author the complete borrowed-byte policy as HIA object continuations.

The ordinary source bodies remain independent reference inputs. This private
authoring extension adds the three constructs actually present in those bodies:
conditional chained comparisons, a named closure, and loop continue. Runtime
imports neither this compiler nor its policy input.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from types import CodeType

from tools.hia_core_lowering_control import Function as _Function
from tools.hia_machine_plan_control import Compiler as _Compiler, COMPARE, OPS

ENTRIES = ('normalize_exports', 'emit_wrapper', '_reject', '_normalize', '_prologue')
IMPORTS = {
    'hia_program': frozenset(('SCALARS',)),
    'hia_program_native': frozenset(('IMPORTS', '_LOADER_HOOKS', '_reject',
                                   'MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue')),
}


def _validate_call_operands(function):
    """Bind the fixed move port to the exact HIA table's owning temporaries."""
    for instruction in function.instructions:
        if instruction['kind'] != 'effect' or instruction['opcode'] != OPS['CALL']:
            continue
        raw, arguments = instruction['raw'], instruction['arguments']
        if (len(raw) != 2 or raw[1] != 0 or not 0 <= raw[0] <= 4
                or len(arguments) != raw[0] + 1
                or len({ref.slot for ref in arguments}) != len(arguments)
                or instruction['consume'] != arguments
                or any(not ref.temporary or ref.slot not in function.temporary_slots
                       or ref.slot in function.cell_slots for ref in arguments)):
            raise ValueError('byte ABI CALL does not own its complete temporary operands')


class Compiler(_Compiler):
    def __init__(self, source):
        self.source = source
        self.tree = ast.parse(source)
        # Compilation observes lexical layout only; no Python policy body is
        # executed. The generated HIA table owns the physical retirement.
        self.lexical_codes = {}
        def codes(value):
            for item in value.co_consts:
                if isinstance(item, CodeType):
                    key = (item.co_firstlineno, item.co_name)
                    if key in self.lexical_codes:
                        raise ValueError('ambiguous byte ABI lexical frame')
                    self.lexical_codes[key] = item
                    codes(item)
        codes(compile(source, '<byte-abi-lexical-layout>', 'exec'))
        self.literals, self.literal_indices = [], {}
        self.functions, self.by_name = [], {}
        for node in self.tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
                continue
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                raise ValueError('unreviewed byte ABI top-level policy')
            function = Function(self, node.name, node)
            self.functions.append(function)
            self.by_name[node.name] = function
        if tuple(self.by_name) != ENTRIES:
            raise ValueError('complete byte ABI function inventory differs')
        index = 0
        while index < len(self.functions):
            self.functions[index].compile()
            index += 1
        for mode, function in enumerate(self.functions, 1):
            function.mode = mode
        for function in self.functions:
            function.resolve()
            _validate_call_operands(function)

    def nested(self, parent, node, kind):
        name = parent.name + ':' + kind + ':' + str(len(self.functions))
        function = Function(self, name, node, parent=parent, kind=kind)
        self.functions.append(function)
        return function


class Function(_Function):
    def __init__(self, compiler, name, node, *, parent=None, kind='function'):
        # A nested function owns its own locals. The outer frame owns only
        # its function binding and any actual cells captured by that closure.
        # The shared constructor's lexical scan predates named declarations.
        scanned = deepcopy(node)
        class ScopeScan(ast.NodeTransformer):
            def visit_FunctionDef(self, value):
                if value is scanned:
                    return self.generic_visit(value)
                return ast.copy_location(ast.Assign(
                    targets=[ast.Name(id=value.name, ctx=ast.Store())],
                    value=ast.Constant(None)), value)
        if kind == 'function':
            scanned = ast.fix_missing_locations(ScopeScan().visit(scanned))
        super().__init__(compiler, name, scanned, parent=parent, kind=kind)
        self.node = node
        lexical_name = '<genexpr>' if kind == 'generator' else node.name
        code = compiler.lexical_codes[(node.lineno, lexical_name)]
        # CPython places ordinary fast locals before non-argument cells, then
        # free cells. A named closure therefore changes the containing frame's
        # retirement order even though its lexical assignment order is stable.
        # Inline-comprehension names reserve their physical slots but their
        # live shadow values still belong to the existing temporary scope.
        names = tuple(dict.fromkeys((*code.co_varnames, *code.co_cellvars)))
        if names[:len(self.parameters)] != tuple(self.parameters):
            raise ValueError('byte ABI lexical parameter order differs')
        self.locals, self.next_slot = {}, 0
        self.temporary_slots, self.cell_slots = set(), set()
        for local_name in names:
            self.local(local_name)
        for local_name in code.co_cellvars:
            self.cell_slots.add(self.locals[local_name].slot)
        for free_name in code.co_freevars:
            if parent is None:
                raise ValueError('byte ABI top-level function has a free cell')
            outer = parent.variable(free_name)
            if outer is None:
                raise ValueError('byte ABI lexical capture has no enclosing owner')
            parent.cell_slots.add(outer.slot)
            self.captures[free_name] = (self.slot(False), outer)
        self.lexical_names = names
        self.lexical_cells = code.co_cellvars
        self.lexical_freevars = code.co_freevars

    def comp_scope(self, generators, *, generator=False):
        if generator:
            names = {n.id for value in generators for n in ast.walk(value.target)
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            return {name: self.local(name) for name in sorted(names)}
        return super().comp_scope(generators, generator=generator)

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

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                if (node.level != 1 or node.module not in IMPORTS
                        or any(alias.name not in IMPORTS[node.module] for alias in node.names)):
                    raise ValueError('unreviewed byte ABI import')
                for alias in node.names:
                    value = self.effect('IMPORT', raw=(self.compiler.literal(node.module),
                                                       self.compiler.literal(alias.name)))
                    self.assign(ast.Name(id=alias.asname or alias.name, ctx=ast.Store()), value)
            elif isinstance(node, ast.FunctionDef):
                if (node.decorator_list or node.args.defaults or node.args.kw_defaults
                        or node.args.posonlyargs or node.args.vararg or node.args.kwarg
                        or node.args.kwonlyargs or node.returns):
                    raise ValueError('unreviewed byte ABI closure declaration')
                nested = self.compiler.nested(self, node, 'function')
                nested.compile()
                value = self.effect('FUNCTION', raw=(nested, 0),
                    vector=[pair[1] for pair in nested.captures.values()])
                self.assign(ast.Name(id=node.name, ctx=ast.Store()), value)
            elif isinstance(node, ast.Continue):
                if not self.loop_stack:
                    raise ValueError('byte ABI continue has no loop')
                self.jump(self.loop_stack[-1][0])
            else:
                super().statements((node,))


def compile_policy(source):
    return Compiler(source)
