"""Current service-controller observations with actual admitted Core inputs.

The old opaque-provider 185-case domain remains unchanged in its fixed historical
source view. These independently named cases compare the current host methods
with the current HIA graph and never label the old corpus as current execution.
"""
from __future__ import annotations
from hashlib import sha256
import json
import types
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_behavior_inputs
from hepta import hia_program
from hepta import hia_service_verification_native as native
from tests import hia_service_verification_oracle as original

_OriginalWorld = original.World
_REFERENCES = tuple(getattr(api, '_SERVICE_VERIFICATION_REFERENCE_' + str(i))
                    for i in range(1, 10))
_SCENARIOS = (
    ('behavior', 'finite'), ('subject', 'core'), ('verify', 'behavior'),
    ('verification', 'valid'), ('replay', 'valid'), ('binding', 'basic'),
    ('refinement', 'proved'), ('check', 'valid'), ('claims', 'behavior'),
)


def real_program(tag):
    return hia_program.verify_program({
        'schema': 'hepta.hia.program.v1', 'module': 'current_' + tag,
        'functions': [{
            'name': 'entry', 'params': [], 'returns': ['u8'], 'effects': [],
            'entry': 'entry', 'blocks': [{
                'id': 'entry', 'params': [], 'ops': [{
                    'op': 'const', 'args': [], 'out': [{'name': 'answer', 'type': 'u8'}],
                    'attrs': {'value': 7}}],
                'term': {'op': 'ret', 'values': ['answer']}}]}]})


class CurrentWorld(_OriginalWorld):
    def _install(self):
        super()._install()
        self.namespace.update({
            '_signatures': api._signatures,
            '_vm_observation': api._vm_observation,
            '_REFERENCE_VM_OBSERVATION': api._REFERENCE_VM_OBSERVATION,
            '_behavior_source_snapshot': api._behavior_source_snapshot,
            '_behavior_source_bound_result': api._behavior_source_bound_result,
        })

    def importer(self, name, globals=None, locals=None, fromlist=(), level=0):
        if name.rsplit('.', 1)[-1] == 'hia_behavior_inputs':
            self.event('import.' + name, {'fromlist': list(fromlist), 'level': level,
                'globals_same': globals is self.namespace,
                'locals': None if locals is None else sorted(locals)})
            return hia_behavior_inputs
        return super().importer(name, globals, locals, fromlist, level)

    def program(self, tag):
        return real_program(tag)

    def raw_binding(self, subject, built, tag='candidate'):
        result = super().raw_binding(subject, built, tag)
        current = real_program(tag)
        result['candidate_core_sha256'] = current.sha256
        result['input_sha256'] = current.input_sha256
        return result

    def receipt(self):
        result = super().receipt()
        scenario = self.case['scenario']
        if scenario != 'core':
            result['candidate_core_sha256'] = real_program('candidate').sha256
        if scenario not in ('base', 'baseline'):
            result['base_core_sha256'] = real_program('base').sha256
        return result

    def arguments(self):
        result = super().arguments()
        if self.case['mode'] == 'claims':
            return (*result[:-1], real_program('base').sha256)
        return result


def cases():
    rows = json.loads((original.ORIGINALS / 'cases.json').read_bytes())['base_cases']
    selected = []
    for mode, scenario in _SCENARIOS:
        prior = next(row for row in rows
                     if row['id'] == mode + '.' + scenario + '.outer0')
        selected.append({**prior, 'id': 'current-real-core.' + mode + '.' + scenario})
    return selected


def host_factory(world, mode, arguments):
    number = original.MODES.index(mode)
    old = _REFERENCES[number]
    function = types.FunctionType(old.__code__, world.namespace, old.__name__,
                                  old.__defaults__)
    return function(*arguments)


def native_factory(image):
    def invoke(world, mode, arguments):
        number = original.MODES.index(mode) + 1
        frame = native.ServiceVerificationFrame(image, number,
            dict(zip(native.PUBLIC_ARGUMENTS[number - 1], arguments)),
            namespace=world.namespace)
        result = frame.finish()
        if not frame.finished or frame.native_failed:
            raise AssertionError('current business method did not reach a known terminal')
        return result
    return invoke


def observe(case, factory):
    with patch.object(original, 'World', CurrentWorld):
        return original.observe_case(case, factory)


def current_input_identities():
    return {tag: {'canonical_bytes': len((p := real_program(tag)).canonical_bytes),
                  'canonical_sha256': sha256(p.canonical_bytes).hexdigest(),
                  'structured_bytes': None if p.structured_bytes is None else len(p.structured_bytes),
                  'structured_sha256': None if p.structured_bytes is None else sha256(p.structured_bytes).hexdigest()}
            for tag in ('base', 'candidate')}
