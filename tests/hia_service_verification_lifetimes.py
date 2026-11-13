"""Object lifetimes through original bodies and actual HIA/public facades.

No GC is invoked. Error tracebacks remain live through the first observation;
the second deliberately detaches each route's traceback at the same boundary.
"""
from contextlib import ExitStack
import json
import sys
from unittest.mock import patch
from hepta import hia_agent_service as api
from hepta import hia_checker_identity as checker
from hepta.hia_service_verification_native import NativeVerificationService
from tests.hia_service_verification_fixtures import REFERENCE
original_verify=REFERENCE['_hia_verify']
original_subject=REFERENCE['_subject']

def exception_shape(error):
    if error is None:
        return None
    return {'type': type(error).__name__, 'message': str(error),
            'cause': exception_shape(error.__cause__),
            'context': None if error.__context__ is error else exception_shape(error.__context__),
            'suppress': error.__suppress_context__, 'notes': getattr(error, '__notes__', None)}

def captured(call):
    try:
        return call(), None
    except BaseException as error:
        return None, error

def observation(case, native, outer, image=None, *, route='direct'):
    if native and image is None:raise ValueError('actual verification image required')
    events = []
    def event(*parts):
        events.append(list(parts))
    def ambient():
        current = sys.exception()
        return None if current is None else type(current).__name__ + ':' + str(current)
    class Name(str):
        def __del__(self):
            event('name-del', str(self), ambient())
    class Context(dict):
        def __del__(self):
            event('context-del', ambient())
    class Program:
        sha256 = 'candidate-sha'
        input_sha256 = 'input-sha'
        canonical_bytes = b'core'
        def __del__(self):
            event('program-del', ambient())
    class Ignored:
        def __del__(self):
            event('ignored-profile-result-del', ambient())
    class Receiver:
        def profile(self, name, kind, **kwargs):
            event('profile-body', str(name), kind, sorted(kwargs), ambient())
            if case in ('profile-error', 'profile-stop'):
                if case == 'profile-stop':
                    raise StopIteration('original profile stop')
                raise ValueError('original profile error')
            return Ignored()
        def __del__(self):
            event('receiver-del', ambient())
    class Args(dict):
        seen_validation = False
        def __getitem__(self, key):
            value = super().__getitem__(key)
            if key == 'validation_profile' and not self.seen_validation:
                self.seen_validation = True
                return Name(value)
            return value
    class Store:
        def json(self, value, kind):
            event('publish', kind, ambient())
            if case == 'publish-error' and kind == 'verification-evidence':
                raise KeyError('original publication error')
            return 'artifact-' + kind
    class Service:
        identities = {'installed': 'same'}
        store = Store()
        def _held_checker_owners(self):
            event('held', ambient()); return ()
        def _context(self, value):
            event('context', str(value), ambient())
            return Context(target_profile='target', foreign_buffer_exports=[])
        @property
        def _profile(self):
            event('profile-receiver', ambient())
            return Receiver().profile
        def _program(self, value):
            event('program', str(value), ambient()); return Program()
        def _subject(self, args, program, *, _connection=None):
            # This second actual original/native method is selected separately;
            # neither route uses the other route as its nested oracle.
            if native:
                frame = image.prepare('_subject', (self, args, program, _connection))
                self = args = program = _connection = None
                return image.finish(frame)
            return original_subject(self, args, program, _connection=_connection)
        def _remaining_ms(self, context):
            return 100
    service = Service()
    if route == 'public':
        service._native_verification = NativeVerificationService(image) if native else None
        service._hia_verify_reference = REFERENCE['_hia_verify'].__get__(service)
        service._subject_reference = REFERENCE['_subject'].__get__(service)
        service._subject = api.HIAAgentService._subject.__get__(service)
    args = Args(subject={'kind': 'core'}, context='ctx', candidate='candidate',
                base_program=None, validation_profile='vp', claims=['core_admission'])
    def proof_subject(binding, target):
        event('proof-subject', ambient())
        if case == 'subject-error':
            raise RuntimeError('original subject error')
        return {'target': target}
    def proof_result(**values):
        event('proof-result', ambient())
        return {key: values[key] for key in ('claim', 'status', 'domain', 'subject', 'profile')}
    def call():
        if route == 'public':
            return api.HIAAgentService._hia_verify(service, args)
        if native:
            return image.run('_hia_verify', service, args)
        return original_verify(service, args)
    def run():
        with ExitStack() as stack:
            for target, name, value in ((api, 'proof_subject', proof_subject),
                    (api, 'proof_result', proof_result),
                    (api, 'assumptions_document', lambda value: {'scope': value}),
                    (checker, 'checker_native_selection', lambda **kw: {})):
                stack.enter_context(patch.object(target, name, value))
            value, error = captured(call)
            held = list(events)
            shape = exception_shape(error)
            public = value
            value = None
            # The result is normalized before dropping it; it contains no
            # foreign fixtures. The original exception object/traceback is
            # deliberately retained until this exact observation boundary.
            wire = json.dumps(public, sort_keys=True)
            public = None
            if error is not None:
                error.__traceback__ = None
            error = None
            released = list(events)
            return {'wire': wire, 'error': shape, 'held': held, 'released': released}
    if outer:
        try:
            raise LookupError('outer')
        except LookupError:
            return run()
    return run()
