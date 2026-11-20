"""Temporary receiver observations from the exact frozen original methods.

The R2 oracle supplies every fake provider and both complete original bodies.
Only consumer ownership changes: service/arguments are popped into actual
call arguments, with no extra receiver reference retained by this observer.
No product import, HIA policy or expected outcome is defined here.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / 'tests/hia_service_inspection_oracle.py'
ORACLE_SHA256 = 'a0cb85c6a2d103ccb0fb53b6240d024ef46721bbdc33dab41dd7c99a86cd2055'
_original_module = None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def original_module():
    global _original_module
    if _original_module is None:
        raw = ORACLE.read_bytes()
        if sha256(raw).hexdigest() != ORACLE_SHA256:
            raise ValueError('inherited original oracle differs')
        spec = importlib.util.spec_from_file_location('_inspection_lifetime_original', ORACLE)
        module = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(ORACLE), 'exec'), module.__dict__)
        if ORACLE.read_bytes() != raw:
            raise ValueError('inherited original oracle changed during import')
        _original_module = module
    return _original_module


def observe(case, owner=None):
    """owner(mode, make_service, make_arguments, namespace, original_method).

The factories contain only a transfer dictionary; after argument evaluation it
has no remaining strong service/arguments reference. Original code is fresh
per case, as in R2. No invocation occurs at import.
"""
    oracle = original_module()
    fixture = oracle.Fixture(case)
    world = fixture.world
    original = fixture.original()
    transfer = {'service': fixture.__dict__.pop('service'),
                'arguments': fixture.__dict__.pop('arguments')}
    result = error = None
    outer = RuntimeError('outer-active-exception') if case.get('outer') else None
    raw_traceback = None
    outcome = body_live = after_live = None
    body_end = consumer_end = None

    def active():
        value = sys.exception()
        if value is None:
            return None
        if value is outer:
            return 'outer'
        if value is world.fault:
            return 'injected'
        return type(value).__name__

    def live():
        values = []
        for reference in world.weak_objects:
            item = reference()
            if item is not None:
                values.append(object.__getattribute__(item, '_token'))
            item = None
        return sorted(values)

    def make_service():
        return transfer.pop('service')

    def make_arguments():
        return transfer.pop('arguments')

    def invoke():
        if owner is None:
            return original(make_service(), make_arguments())
        return owner(case['mode'], make_service, make_arguments,
                     fixture.namespace, original)

    def consume():
        nonlocal result, error, raw_traceback, outcome, body_live, after_live, body_end, consumer_end
        try:
            result = invoke()
        except BaseException as caught:
            error = caught
            raw_traceback = ''.join(traceback.format_exception(
                type(caught), caught, caught.__traceback__))
        world.events.append({'operation': 'lifetime.body-return', 'active_exception': active()})
        body_end = len(world.events)
        error_view = oracle.error_snapshot(error, world.fault)
        if error_view is not None:
            error_view['context_is_outer'] = error.__context__ is outer
        outcome = {'result': oracle.snapshot(result), 'error': error_view}
        body_live = live()
        world.events.append({'operation': 'lifetime.consumer-release.begin',
                             'active_exception': active()})
        result = None
        world.escaped.clear()
        # Consumer reference release only: no TB clearing, field edits or GC.
        world.fault = None
        error = None
        world.events.append({'operation': 'lifetime.consumer-release.end',
                             'active_exception': active()})
        consumer_end = len(world.events)
        after_live = live()

    with fixture.providers():
        if outer is None:
            consume()
        else:
            try:
                raise outer
            except RuntimeError:
                consume()
                world.events.append({'operation': 'lifetime.outer-restored',
                                     'identity': sys.exception() is outer})
    if transfer:
        raise AssertionError('receiver transfer was not completely consumed')
    observation = {
        'case_id': case['id'], 'mode': case['mode'], 'outcome': outcome,
        'trace': world.events, 'body_trace_end': body_end,
        'consumer_release_trace_end': consumer_end,
        'objects_live_at_body_return': body_live,
        'objects_live_after_consumer_release': after_live,
        'fault_hits': world.fault_hits, 'fault_required': case.get('fault') is not None,
        'fixture_keeps_service_and_arguments_through_consumer': False,
        'fresh_original_function_code': True,
        'traceback_cleared_or_error_fields_changed': False,
        'forced_gc_or_heat_reset': False,
        'actual_SQL_filesystem_or_compiler_provider_called': False,
    }
    # No later finalizer can mutate this declared semantic endpoint.
    return json.loads(canonical(observation)), raw_traceback
