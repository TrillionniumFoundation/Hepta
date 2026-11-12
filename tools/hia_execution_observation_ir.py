"""Lower the retained execution-ledger validator, not a reduced predicate list.

The public keyword frame is transported as one tuple. All original decisions
and their ordering remain in the HIA body; the nested need() becomes its own
HIA entry and the generator remains lazy with eager GET_ITER.
"""
from __future__ import annotations

import ast
import copy

from tools.hia_core_lowering_ir import Literals, link_functions
from tools.hia_machine_object_ir import ObjectFunction, function


def compile_policy(source):
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError('exact observation policy declaration required')
    original = tree.body[0]
    if original.name != 'validate_execution_observation':
        raise ValueError('execution observation entry differs')
    owner = copy.deepcopy(original)
    if ([p.arg for p in owner.args.args] != ['status', 'ledger']
            or [p.arg for p in owner.args.kwonlyargs] != [
                'steps', 'max_steps', 'max_heap_bytes', 'error_code',
                'with_chains', 'allow_host_memory', 'live_external_roots']):
        raise ValueError('execution observation signature differs')
    helpers = [n for n in owner.body if isinstance(n, ast.FunctionDef)]
    if len(helpers) != 1 or helpers[0].name != 'need':
        raise ValueError('exact observation need helper required')
    need = helpers[0]
    owner.body.remove(need)
    names = [p.arg for p in owner.args.kwonlyargs]
    owner.args.args.append(ast.arg(arg='_hia_observation_options'))
    owner.args.kwonlyargs, owner.args.kw_defaults = [], []
    # Seven keyword values are a private mechanical tuple, not seven native
    # call parameters. This preserves the existing four-bound-argument limit.
    binding = ast.Assign(targets=[ast.Tuple(elts=[ast.Name(id=n, ctx=ast.Store())
        for n in names], ctx=ast.Store())],
        value=ast.Name(id='_hia_observation_options', ctx=ast.Load()))
    owner.body.insert(0, binding)
    callbacks, extras = {}, []
    for node in ast.walk(owner):
        if not isinstance(node, ast.GeneratorExp):
            continue
        if len(node.generators) != 1 or node.generators[0].is_async:
            raise ValueError('unreviewed observation generator')
        gen = node.generators[0]
        bound = {n.id for n in ast.walk(gen.target) if isinstance(n, ast.Name)}
        free = {n.id for e in [node.elt, *gen.ifs] for n in ast.walk(e)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} - bound
        if free - {'type', 'int'}:
            raise ValueError('observation callback captures require review: ' + repr(free))
        key = ast.dump(node, include_attributes=False)
        if key in callbacks:
            continue
        mode = 'observation.callback.' + str(len(callbacks))
        callbacks[key] = mode
        body = [ast.Assign(targets=[copy.deepcopy(gen.target)],
                           value=ast.Name(id='_hia_object_item', ctx=ast.Load()))]
        for condition in gen.ifs:
            body.append(ast.If(test=ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(condition)),
                body=[ast.Return(value=ast.Tuple(elts=[ast.Constant(False), ast.Constant(None)], ctx=ast.Load()))], orelse=[]))
        body.append(ast.Return(value=ast.Tuple(elts=[ast.Constant(True), copy.deepcopy(node.elt)], ctx=ast.Load())))
        extras.append(function(mode, ['_hia_object_item'], body))

    class ObservationFunction(ObjectFunction):
        def assign(self, target, value):
            if isinstance(target, ast.Tuple) and len(target.elts) == 7:
                unpacked = self.bridge('_hia_observation_unpack_seven', (value,))
                for index, element in enumerate(target.elts):
                    item = self.effect('ITEM', (unpacked, self.constant(index)))
                    super().assign(element, item)
                return
            return super().assign(target, value)

    literals = Literals()
    functions = [ObservationFunction(n.name, n, literals, callbacks, {}).compile()
                 for n in [owner, need, *extras]]
    return link_functions(literals, functions)
