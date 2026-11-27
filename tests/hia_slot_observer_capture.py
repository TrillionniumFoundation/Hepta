"""Explicit revision of the Slot observer's two JSON snapshot boundaries.

Original product calls, releases, cases, providers and explicit collections
retain their order and GC state. Snapshot construction alone defers automatic
cyclic GC. The final snapshot establishes its seal in the same critical section.
The consumer snapshot is retained as canonical immutable bytes until that final
section: constructing its decoded object graph earlier would itself schedule
cyclic collection between product releases. Final observation fields are exact
decoded values. Original fixture bytes and original-v1 remain available.
"""
from __future__ import annotations

import ast
import gc

VERSION = 'deferred-json-snapshots-v3'
SNAPSHOTS = {
    'consumer_snapshot': """copy_json({"events": self.events, "alive": self.alive(), "outcome": outcome})""",
    'record': """copy_json({
        "id": self.case["id"], "template": self.case["template"], "method": self.case["method"],
        "outer_exception": self.case["outer_exception"], "outcome": outcome,
        "events": self.events, "consumer_snapshot": consumer_snapshot, "alive_at_seal": self.alive(),
        "fake_sql_effects": self.effects, "sql_prefix_length": self.sql_at,
        "complete_request_packets": self.requests, "fault_hits": self.fault_hits,
        "unraisable": self.unraisable,
    })""",
}
SEAL = ("self.phase = 'case-sealed'", "self.sealed_event_count = len(self.events)")


def rewrite_snapshot_calls(module):
    """Admit exact expressions and move only the two seal bookkeeping lines."""
    worlds = [node for node in module.body
              if isinstance(node, ast.ClassDef) and node.name == 'World']
    if len(worlds) != 1:
        raise ValueError('snapshot revision requires exactly one original World')
    methods = [node for node in worlds[0].body
               if isinstance(node, ast.FunctionDef) and node.name == 'observe']
    if len(methods) != 1:
        raise ValueError('snapshot revision requires exactly one original observer')
    method = methods[0]
    selected, seal = {}, []
    for index, node in enumerate(method.body):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in SNAPSHOTS:
            name = target.id
            expected = ast.parse(SNAPSHOTS[name], mode='eval').body
            if name in selected or ast.dump(node.value) != ast.dump(expected):
                raise ValueError('original snapshot expression differs')
            selected[name] = node
        elif (isinstance(target, ast.Attribute)
              and isinstance(target.value, ast.Name) and target.value.id == 'self'
              and (target.attr == 'sealed_event_count'
                   or (target.attr == 'phase' and isinstance(node.value, ast.Constant)
                       and node.value.value == 'case-sealed'))):
            seal.append((index, node))
    if set(selected) != set(SNAPSHOTS):
        raise ValueError('both original snapshots must be present')
    expected_seal = [ast.dump(ast.parse(line).body[0]) for line in SEAL]
    if (len(seal) != 2 or seal[1][0] != seal[0][0] + 1
            or [ast.dump(node) for _, node in seal] != expected_seal
            or not (method.body.index(selected['consumer_snapshot']) < seal[0][0]
                    < seal[1][0] < method.body.index(selected['record']))):
        raise ValueError('original seal statements differ')
    replacements = {
        'consumer_snapshot': '_HIA_OBSERVER_CAPTURE_CONSUMER(self, outcome)',
        'record': '_HIA_OBSERVER_CAPTURE_FINAL(self, outcome, consumer_snapshot)',
    }
    for name, node in selected.items():
        node.value = ast.copy_location(ast.parse(replacements[name], mode='eval').body,
                                       node.value)
    for index, _ in reversed(seal):
        del method.body[index]
    ast.fix_missing_locations(module)
    return {'version': VERSION, 'changed_snapshot_expressions': 2,
            'changed_seal_statements': 2, 'changed_product_expressions': 0,
            'changed_case_inputs': 0,
            'consumer_representation': 'canonical-json-bytes'}


def bind_snapshot_functions(namespace):
    copier = namespace['copy_json']
    encoder = namespace['canonical']
    decoder = namespace['json'].loads

    def consumer(world, outcome):
        enabled = gc.isenabled()
        gc.disable()
        try:
            return encoder({'events': world.events, 'alive': world.alive(),
                            'outcome': outcome})
        finally:
            if enabled:
                gc.enable()

    def final(world, outcome, consumer_snapshot):
        enabled = gc.isenabled()
        gc.disable()
        try:
            world.phase = 'case-sealed'
            world.sealed_event_count = len(world.events)
            consumer_record = decoder(consumer_snapshot)
            return copier({
                'id': world.case['id'], 'template': world.case['template'],
                'method': world.case['method'],
                'outer_exception': world.case['outer_exception'],
                'outcome': outcome, 'events': world.events,
                'consumer_snapshot': consumer_record,
                'alive_at_seal': world.alive(), 'fake_sql_effects': world.effects,
                'sql_prefix_length': world.sql_at,
                'complete_request_packets': world.requests,
                'fault_hits': world.fault_hits, 'unraisable': world.unraisable,
            })
        finally:
            if enabled:
                gc.enable()

    namespace['_HIA_OBSERVER_CAPTURE_CONSUMER'] = consumer
    namespace['_HIA_OBSERVER_CAPTURE_FINAL'] = final
