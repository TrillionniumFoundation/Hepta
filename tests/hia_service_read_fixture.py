"""Admission and invocation glue for the independently frozen read oracle.

The complete original body produces expectations. This module neither repeats
the pagination algorithm nor derives expected effects from the HIA port graph.
The finite comparison declares fresh provider code for both sides; normal
public callers, packet controls and installed workers use ordinary code.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import types
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_service_read_original_91bbd077'
IDENTITY_SHA256 = 'f15fb8a12a16701f77e0654d994c0ed3b89b7095b6d67c745cbdc7c2b432a2cb'
ORACLE_MODULE = 'independent_original_read_oracle'
BASE_COUNT, FAULT_COUNT = 86, 6286
GLOBAL_PROVIDERS = ('UnicodeDecodeError', 'int', 'len', 'max', 'wire', 'digest',
                    'reject', 'base64')


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def original_inputs():
    identity_raw = (ORIGINAL / 'source-identity.json').read_bytes()
    if sha256(identity_raw).hexdigest() != IDENTITY_SHA256:
        raise ValueError('independent read source identity changed')
    identity = json.loads(identity_raw)
    captured = {name: (ORIGINAL / name).read_bytes() for name in identity['file_pins']}
    for name, raw in captured.items():
        record = identity['file_pins'][name]
        if len(raw) != record['bytes'] or sha256(raw).hexdigest() != record['sha256']:
            raise ValueError('independent read fixture changed: ' + name)
    base_document = json.loads(captured['base-inputs.json'])
    fault_document = json.loads(captured['fault-inputs-FROZEN-before-execution.json'])
    base, faults = base_document['base_cases'], fault_document['cases']
    if (len(base) != BASE_COUNT or len(faults) != FAULT_COUNT
            or len({case['id'] for case in (*base, *faults)}) != BASE_COUNT + FAULT_COUNT
            or len(base_document['fault_matrix']['basis_case_ids']) != 9
            or len(base_document['fault_matrix']['exception_kinds']) != 7
            or fault_document['candidate_consulted'] is not False
            or fault_document['fault_cases_executed_at_freeze'] != 0
            or identity['source_pin_count'] != 76):
        raise ValueError('independent complete read input scope changed')
    if ((ORIGINAL / 'source-identity.json').read_bytes() != identity_raw
            or any((ORIGINAL / name).read_bytes() != raw for name, raw in captured.items())):
        raise ValueError('independent read input changed during admission')
    return identity, base, faults


def load_oracle():
    original_inputs()
    path = ORIGINAL / 'original_read_oracle.py'
    existing = sys.modules.get(ORACLE_MODULE)
    if existing is not None:
        if getattr(existing, '__file__', None) != str(path):
            raise ValueError('independent read oracle module identity differs')
        return existing
    spec = importlib.util.spec_from_file_location(ORACLE_MODULE, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[ORACLE_MODULE] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(ORACLE_MODULE, None)
        raise
    return module


def originals():
    oracle = load_oracle()
    return oracle, oracle.load_originals(ORIGINAL)


@contextmanager
def fresh_foreign_code(native):
    """Give this finite input fresh code, without changing product defaults.

    The independent observer compiles its complete original anew per input.
    Clone the exact candidate linear-provider and effect code for the same
    declared fresh start. This does not equate every instruction history, and
    is never used by the complete ordinary caller or installed-worker gates.
    """
    with ExitStack() as stack:
        functions = [(name, value) for name, value in vars(native).items()
                     if name.startswith('_literal_') and type(value) is types.FunctionType]
        for name, function in functions:
            copied = types.FunctionType(function.__code__.replace(), function.__globals__,
                function.__name__, function.__defaults__, function.__closure__)
            copied.__kwdefaults__ = function.__kwdefaults__
            stack.enter_context(patch.object(native, name, copied))
        function = native.ServiceReadFrame.effect
        copied = types.FunctionType(function.__code__.replace(), function.__globals__,
            function.__name__, function.__defaults__, function.__closure__)
        copied.__kwdefaults__ = function.__kwdefaults__
        stack.enter_context(patch.object(native.ServiceReadFrame, 'effect', copied))
        yield


def observe_original(case, oracle=None, bodies=None):
    if oracle is None or bodies is None:
        oracle, bodies = originals()
    fixture = oracle.Fixture(case, bodies)
    observation = fixture.run_original()
    return observation, fixture.traceback_diagnostics


def observe_candidate(case, image, *, oracle=None, bodies=None, fresh=True, public=False):
    from hepta import hia_agent_service as api
    from hepta import hia_service_read_native as native
    if oracle is None or bodies is None:
        oracle, bodies = originals()
    fixture = oracle.Fixture(case, bodies)

    def forbidden(*arguments, **keywords):
        raise AssertionError('selected read route called a retained Python body')

    def selected(service, arguments):
        if public:
            return api.HIAAgentService._hia_read(service, arguments)
        return native.ServiceReadFrame(image, service, arguments,
                                       namespace=fixture.namespace).finish()

    fixture.original_read = selected
    fixture.namespace['_hia_read'] = forbidden
    with ExitStack() as stack:
        stack.enter_context(patch.object(api, '_SERVICE_READ_REFERENCE', forbidden))
        stack.enter_context(patch.object(api.HIAAgentService, '_hia_read_reference', forbidden))
        if fresh:
            stack.enter_context(fresh_foreign_code(native))
        if public:
            for name in GLOBAL_PROVIDERS:
                stack.enter_context(patch.object(api, name, fixture.namespace[name], create=True))
        observation = fixture.run_original()
    return observation, fixture.traceback_diagnostics
