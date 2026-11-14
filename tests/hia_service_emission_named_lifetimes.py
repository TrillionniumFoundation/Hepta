"""Additional original/native named-local observations; not part of old45/48.

The selected HIA executes every policy step. Deterministic foreign providers
return actual objects with finalizers, and the original three Python bodies
remain the independent reference. No GC or manual traceback edits are used.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys
import weakref
from unittest.mock import patch


def observe(implementation, operation, failure, outer, image, *, public_default=False):
    from hepta import hia_agent_service as api
    from hepta import hia_program_native as provider
    from hepta import hia_service_emission_native as native
    from tests.hia_service_emission_fixtures import REFERENCE
    trace, references, faults = [], [], []

    def ambient():
        error = sys.exception()
        return None if error is None else [type(error).__name__, str(error)]

    def created(label, value):
        trace.append(['new', label, ambient()])
        try:
            references.append((label, weakref.ref(value)))
        except TypeError:
            # Exact bytes cannot carry a Python finalizer; the accepted read
            # result may be a bytes subclass and is observed by __del__ below.
            pass

    def dropped(label):
        trace.append(['del', label, ambient()])

    class ForeignFailure(Exception):
        pass

    def failure_value(label):
        error = ForeignFailure(label)
        faults.append(weakref.ref(error))
        return error

    class Program:
        sha256 = 'a' * 64
        scalar_entrypoints = set()
        def __init__(self): created('program', self)
        def as_dict(self):
            trace.append(['as_dict', ambient()])
            if failure == 'signatures': raise failure_value('signatures')
            return {'functions': []}
        def __del__(self): dropped('program')

    class Image:
        object_bytes = b'OBJ'
        def __init__(self): created('image', self)
        def __del__(self): dropped('image')

    class Data(bytes):
        def __new__(cls):
            value = super().__new__(cls, b'OBJ')
            created('data', value)
            return value
        def __del__(self): dropped('data')

    class BuildResult(dict):
        def __init__(self, **values):
            super().__init__(values)
            created('build-result', self)
        def __del__(self): dropped('build-result')

    class Context(dict):
        def __init__(self):
            super().__init__(target_profile='target')
            created('context', self)
        def __del__(self): dropped('context')

    class Directory(str):
        def __new__(cls):
            value = super().__new__(cls, '/controlled-emission')
            created('directory', value)
            return value
        def __del__(self): dropped('directory')

    class Output:
        def __init__(self): created('output', self)
        def read_bytes(self):
            trace.append(['read_bytes', ambient()])
            if failure == 'read': raise failure_value('read')
            return Data()
        def __del__(self): dropped('output')

    class PathValue:
        def __init__(self, directory):
            trace.append(['Path', str(directory), ambient()])
            created('path-left', self)
        def __truediv__(self, name):
            trace.append(['path-divide', name, ambient()])
            return Output()
        def __del__(self): dropped('path-left')

    class Manager:
        def __init__(self, **values):
            trace.append(['temporary-directory', values['prefix'], str(values['dir']), ambient()])
            created('manager', self)
        def __enter__(self):
            trace.append(['enter', ambient()])
            return Directory()
        def __exit__(self, typ, value, tb):
            trace.append(['exit', None if value is None else type(value).__name__, ambient()])
            return False
        def __del__(self): dropped('manager')

    class Store:
        root = '/controlled-store'
        def put(self, data, kind, metadata):
            trace.append(['put', kind, bytes(data).hex(), ambient()])
            if failure == 'store' and kind == 'build-object': raise failure_value('store')
            if failure == 'native' and kind == 'native': raise failure_value('native')
            return kind + '-ref'
        def json(self, document, kind):
            trace.append(['json', kind, ambient()])
            if failure == 'receipt': raise failure_value('receipt')
            return 'receipt-ref'

    class Service:
        identities = {}
        def __init__(self): self.store = Store()
        def _profile(self, *values): trace.append(['profile', *values, ambient()])
        def _context(self, *values): return Context()
        def _program(self, *values): return Program()
        def _remaining_ms(self, context): return 1000
        def _verification(self, *values): raise AssertionError('no verification expected')
        _compile = REFERENCE['_compile']

    def emit(program, **values):
        trace.append(['emit-machine', ambient()])
        return Image()

    def link(image, *, program, output, **values):
        trace.append(['compile-machine', values['kind'], values['timeout_seconds'], ambient()])
        return BuildResult(output=output, object_sha256=sha256(b'OBJ').hexdigest(),
            core_sha256=program.sha256, artifact_sha256=sha256(b'OBJ').hexdigest(),
            machine_plan_sha256='b' * 64)

    service = Service()
    owner = native.NativeEmissionService(service, image) if implementation == 'native' else None
    if owner is not None: service._compile = owner.compile
    if public_default:
        if owner is not None: raise AssertionError('default route must have no selected emission owner')
        service._native_emission = None
        Service._compile = api.HIAAgentService._compile
        Service._compile_reference = api.HIAAgentService._compile_reference
        Service._hia_emit_reference = api.HIAAgentService._hia_emit_reference
    args = {'backend_profile': 'backend', 'context': 'context', 'candidate': 'candidate',
        'verification_receipts': [], 'output_kind': 'object',
        'codegen': {'kind': 'canonical', 'lowering_profile': 'lowering'}}

    def call():
        if public_default:
            if operation == 'compile':
                return api.HIAAgentService._compile(service, Program(), 'object', None, 1000)
            return api.HIAAgentService._hia_emit(service, args)
        if operation == 'compile':
            if owner is None:
                return REFERENCE['_compile'](service, Program(), 'object', None, 1000)
            return owner.compile(Program(), 'object', None, 1000)
        if owner is None: return REFERENCE['_hia_emit'](service, args)
        return owner.emit(args)

    def alive():
        return [[label, reference() is not None] for label, reference in references]

    def run():
        result = held = None
        try:
            result = call()
        except BaseException as error:
            held = error
        if held is None:
            outcome = {'returned': ([result[0].hex(), dict(result[1])] if operation == 'compile' else result)}
        else:
            outcome = {'raised': type(held).__name__, 'message': str(held),
                'original_foreign_error': any(reference() is held for reference in faults),
                'cause': None if held.__cause__ is None else [type(held.__cause__).__name__, str(held.__cause__)],
                'context': None if held.__context__ is None else [type(held.__context__).__name__, str(held.__context__)]}
        after_call = {'trace': list(trace), 'alive': alive()}
        result = None
        after_return_release = {'trace': list(trace), 'alive': alive()}
        held = None
        after_error_release = {'trace': list(trace), 'alive': alive()}
        return {'outcome': outcome, 'after_call': after_call,
            'after_return_release': after_return_release, 'after_error_release': after_error_release}

    def poisoned(*args, **kwargs):
        raise AssertionError('native route called the retained signature policy')

    with ExitStack() as stack:
        stack.enter_context(patch.object(provider, 'emit_program_machine', emit))
        stack.enter_context(patch.object(provider, 'compile_program_machine', link))
        stack.enter_context(patch.object(api.tempfile, 'TemporaryDirectory', Manager))
        stack.enter_context(patch.object(api, 'Path', PathValue))
        stack.enter_context(patch.object(api.time, 'monotonic', lambda: 1.0))
        stack.enter_context(patch.object(api, '_signatures', REFERENCE['_signatures'] if owner is None else poisoned))
        if outer:
            try: raise ArithmeticError('outer-handled')
            except ArithmeticError: observation = run()
        else: observation = run()
    observation['known_outcome_has_no_unconfirmed_state'] = owner is None or not (owner.active or owner.unknown)
    return observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--route', choices=('direct-native', 'public-default'), default='direct-native')
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    output = args.output.absolute(); output.mkdir(mode=0o700, exist_ok=False)
    sys.path.insert(0, str(root))
    from hepta import hia_service_emission_native as native
    manifest = args.manifest.resolve(strict=True)
    value = json.loads(manifest.read_bytes())
    paths = (manifest, manifest.parent / value['image_path'], native.SOURCE,
        root / 'hepta/hia_service_emission_native.py', root / 'hepta/hia_agent_service.py',
        root / 'tests/hia_service_emission_fixtures.py',
        root / 'tests/fixtures/hia_service_emission_original_v76.json', Path(__file__).resolve())
    before = {str(path): sha256(path.read_bytes()).hexdigest() for path in paths}
    image = native.installed_emission(manifest)
    rows = []
    for operation, cases in [('compile', ('success', 'read', 'store')),
                             ('emit', ('success', 'read', 'signatures', 'native', 'receipt'))]:
        for failure in cases:
            for outer in (False, True):
                expected = observe('reference', operation, failure, outer, image)
                actual = observe('reference' if args.route == 'public-default' else 'native',
                    operation, failure, outer, image, public_default=args.route == 'public-default')
                row = {'operation': operation, 'failure': failure, 'outer': outer,
                    'expected': expected, 'actual': actual, 'equal': expected == actual}
                rows.append(row)
                print(json.dumps({key: row[key] for key in ('operation', 'failure', 'outer', 'equal')}), flush=True)
    after = {str(path): sha256(path.read_bytes()).hexdigest() for path in paths}
    report = {'schema': 'hia.emission.named-local-lifetimes.v77.r2', 'python': sys.version, 'route': args.route,
        'observations': rows, 'matches': sum(row['equal'] for row in rows), 'total': len(rows),
        'inputs_before': before, 'inputs_after': after, 'inputs_unchanged': before == after,
        'no_manual_traceback_clear': True, 'no_gc': True,
        'provider_scope': 'Controlled foreign compiler/path/store ports; actual selected HIA policy',
        'object_bytes_scope': 'Accepted object_bytes must be exact bytes; no subtype finalizer is admitted',
        'current_source_cold': False, 'whole_native': False}
    report['status'] = 'PASS' if report['matches'] == report['total'] and before == after else 'FAIL'
    (output / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
