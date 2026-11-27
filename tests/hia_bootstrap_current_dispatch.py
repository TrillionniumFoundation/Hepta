"""Actual current public dispatch controls, separate from the R12 domain."""
from __future__ import annotations
from hashlib import sha256
import itertools
import json
from pathlib import Path
import types
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tools import hia_bootstrap_source_history as history

OPTIONS = ('native_store', 'native_edit_query', 'native_candidate_import')
PROGRAM_CASES = (
    'native-success', 'native-refusal-valid', 'native-refusal-invalid',
    'native-throws', 'store-throws', 'native-getter-order',
    'none-reference-override', 'native-reference-throws',
    'none-admission-override', 'native-admission-override',
    'none-reference-default', 'none-reference-invalid',
)
REFUSAL = 'native Agent retained-program refusal disagrees with hosted admission'

def _reference(backend, mode):
    function = backend.api._SERVICE_BOOTSTRAP_REFERENCES[mode]
    result = types.FunctionType(function.__code__, backend.namespace, function.__name__,
                                function.__defaults__, function.__closure__)
    result.__kwdefaults__ = None if function.__kwdefaults__ is None else dict(function.__kwdefaults__)
    return result

def _entries(lane, number):
    if type(number) is not int or (number != 0 if lane == 'unselected' else number <= 0):
        raise AssertionError('current public dispatch did not use its declared entry lane')

def init_controls(backend, lane):
    api = backend.api
    original_import = backend.captured_builtins['__import__']
    active = {}
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'hia_candidate_budget_native':
            return types.SimpleNamespace(selected_candidate_budget=active['candidate'],
                                         NativeCandidateBudgetStore=active['budget_type'])
        if level == 1 and name == 'hia_slot_ledger_native':
            return types.SimpleNamespace(selected_slot_ledger=active['slot'],
                                         NativeSlotLedgerStore=active['ledger_type'])
        return original_import(name, globals, locals, fromlist, level)
    backend.captured_builtins['__import__'] = importer
    rows = []
    try:
        for bits in itertools.product((False, True), repeat=3):
            options = {name: object() if selected else None for name, selected in zip(OPTIONS, bits)}
            state_root = object()
            identities, digest = object(), object()
            first = {'name': 'second'}; second = {'name': 'first'}
            replacement = {'name': 'second', 'revision': 2}
            catalog = {'tools': [first, second, replacement]}
            states = []
            for reference in (True, False):
                events = []
                stores = []
                def candidate():
                    events.append('selected_candidate_budget'); return None
                def slot():
                    events.append('selected_slot_ledger'); return None
                def forbidden(*args, **kwargs):
                    raise AssertionError('unselected budget or ledger constructor was entered')
                active.update(candidate=candidate, slot=slot, budget_type=forbidden, ledger_type=forbidden)
                class Store:
                    def __init__(self, *args, **kwargs):
                        events.append('AgentStore')
                        if (len(args) != 1 or args[0] is not state_root
                                or set(kwargs) != {'native_store'}
                                or kwargs['native_store'] is not options['native_store']):
                            raise AssertionError('current Store arguments lost an explicit option')
                        stores.append(self)
                    def close(self):
                        events.append('Store.close')
                class Service(api.HIAAgentService):
                    def _profiles(self):
                        events.append('profiles')
                def read_catalog():
                    events.append('catalog'); return catalog, digest
                def read_identities():
                    events.append('installation_manifest'); return identities
                backend.namespace.update(catalog=read_catalog, installation_manifest=read_identities,
                                         AgentStore=Store)
                service = object.__new__(Service)
                entry_start = backend.image._entry.calls
                frame_start = len(backend.frame_arguments)
                function = _reference(backend, 1) if reference else backend.functions['__init__']
                result = function(service, state_root, artifact_roots=(), **options)
                entries = backend.image._entry.calls - entry_start
                if reference:
                    if entries != 0: raise AssertionError('current independent reference entered the candidate')
                else:
                    _entries(lane, entries)
                option_identity = (service._native_edit_query is options['native_edit_query']
                                   and service._native_candidate_import is options['native_candidate_import'])
                exact_state = (service.catalog is catalog and service.catalog_sha256 is digest
                               and service.identities is identities and len(stores) == 1
                               and service.store is stores[0] and result is None
                               and service._candidate_budget is None and service._slot_ledger is None
                               and service.artifact_roots == ())
                tools_identity = (list(service.tools) == ['second', 'first']
                                  and service.tools['second'] is replacement and service.tools['first'] is second
                                  and service._tool_roles == {'second': 1, 'first': 2})
                if not (option_identity and exact_state and tools_identity):
                    raise AssertionError('current init options, identities or tool roles differ')
                frame_rows = backend.frame_arguments[frame_start:]
                if not reference and lane != 'unselected':
                    if (len(frame_rows) != 1 or frame_rows[0]['mode'] != 1
                            or set(frame_rows[0]['service_options']) != set(OPTIONS)
                            or any(frame_rows[0]['service_options'][name] is not options[name] for name in OPTIONS)):
                        raise AssertionError('public constructor did not forward the exact three options')
                elif frame_rows:
                    raise AssertionError('unselected or reference init constructed a native frame')
                states.append({'events': events, 'entries': entries,
                    'opaque_option_identity': option_identity, 'complete_state_identity': exact_state,
                    'tool_role_and_item_identity': tools_identity, 'profile_calls': events.count('profiles'),
                    'explicit_store_keyword_preserved': True,
                    'frame_options_forwarded': not reference and lane != 'unselected'})
            if states[0]['events'] != states[1]['events']:
                raise AssertionError('current constructor effect order differs')
            rows.append({'options': list(bits), 'reference': states[0], 'current': states[1],
                         'actual_service_subclass': True})
    finally:
        backend.captured_builtins['__import__'] = original_import
    return rows

def program_controls(backend, lane):
    api = backend.api
    backend.namespace.update(verify_program=api.verify_program, decode_json=api.decode_json)
    valid = json.dumps({'schema': 'hepta.hia.program.v6', 'module': 'identity', 'functions': [{
        'name': 'identity', 'params': [{'name': 'value', 'type': 'u8'}], 'returns': ['u8'],
        'effects': [], 'entry': 'entry', 'blocks': [{'id': 'entry',
        'params': [{'name': 'value', 'type': 'u8'}], 'ops': [],
        'term': {'op': 'ret', 'values': ['value']}}]}]}, separators=(',', ':')).encode()
    rows = []
    for case in PROGRAM_CASES:
        states = []
        for reference in (True, False):
            events = []
            token, ref = object(), object()
            failure = LookupError('opaque-provider-failure')
            raw = b'not JSON' if case in ('native-refusal-invalid', 'none-reference-invalid') else valid
            class Provider:
                def retained_program(self, data):
                    events.append('native.retained_program')
                    if data is not raw: raise AssertionError('native admission lost opaque source bytes')
                    if case == 'native-throws': raise failure
                    if case in ('native-refusal-valid', 'native-refusal-invalid', 'native-reference-throws'):
                        return None
                    return token
            class Store:
                def get(self, value):
                    events.append('store.get')
                    if value is not ref: raise AssertionError('current program lost opaque reference')
                    if case == 'store-throws': raise failure
                    return raw, object()
            class Service(api.HIAAgentService):
                def __getattribute__(self, name):
                    if name == '_native_candidate_import' and case == 'native-getter-order':
                        events.append('native.getter')
                    return super().__getattribute__(name)
                @staticmethod
                def _reference_import(data, source_format):
                    events.append('reference_import')
                    if data is not raw or source_format != 'core-json':
                        raise AssertionError('current reference-import arguments differ')
                    if case == 'native-reference-throws': raise failure
                    if case == 'none-reference-override': return token
                    return api.HIAAgentService._reference_import(data, source_format)
            if case in ('none-admission-override', 'native-admission-override'):
                def admit(self, data):
                    events.append('admission-override')
                    if data is not raw: raise AssertionError('current admission override source differs')
                    return token
                Service._admit_retained_program = admit
            service = object.__new__(Service)
            service.store = Store()
            service._native_candidate_import = None if case.startswith('none-') else Provider()
            start = backend.image._entry.calls
            function = _reference(backend, 5) if reference else backend.functions['_program']
            try:
                value = function(service, ref)
                outcome = {'kind': 'return', 'type': type(value).__name__, 'opaque_identity': value is token}
                if case == 'none-reference-default':
                    expected = api.HIAAgentService._reference_import(raw, 'core-json')
                    same_program = (type(value) is type(expected)
                                    and value.canonical_bytes == expected.canonical_bytes
                                    and value.structured_bytes == expected.structured_bytes)
                    if not same_program: raise AssertionError('current default reference program changed')
                    outcome['default_program_exact'] = True
                elif value is not token:
                    raise AssertionError('current native or override return lost its opaque identity')
            except BaseException as error:
                if isinstance(error, AssertionError): raise
                outcome = {'kind': 'raise', 'type': type(error).__name__, 'message': str(error),
                           'supplied_exception_identity': error is failure}
                if case in ('native-throws', 'store-throws', 'native-reference-throws') and error is not failure:
                    raise AssertionError('current program replaced an opaque provider exception')
                if case == 'native-refusal-valid' and (type(error) is not ValueError or str(error) != REFUSAL):
                    raise AssertionError('current native-refusal diagnostic differs')
                if case in ('native-refusal-invalid', 'none-reference-invalid') and type(error).__name__ != 'HIAEditRejected':
                    raise AssertionError('current reference invalid-source diagnostic differs')
            entries = backend.image._entry.calls - start
            if reference:
                if entries != 0: raise AssertionError('current reference program entered the candidate')
            else:
                _entries(lane, entries)
            states.append({'events': events, 'outcome': outcome, 'entries': entries})
        if ({k:v for k,v in states[0].items() if k != 'entries'}
                != {k:v for k,v in states[1].items() if k != 'entries'}):
            raise AssertionError('current program actual reference and dispatch observations differ: ' + case)
        if case == 'native-getter-order' and states[1]['events'].count('native.getter') != 2:
            raise AssertionError('current native-provider getter count changed')
        rows.append({'case': case, 'reference': states[0], 'current': states[1],
                     'actual_service_subclass': True})
    return rows

def current_dispatch_controls(backend, lane):
    root = Path(__file__).resolve().parents[1]
    _historical, _proof, saved = history.capture(root)
    physical = saved[history.SOURCE]
    code = history.code_bindings(physical)
    if backend.public_code != code['public']:
        raise ValueError('current dispatcher does not execute its actual public source code')
    def actual_complete():
        return {
            'public': {name: history.complete_code_digest(backend.functions[name].__code__)
                       for name in history.METHODS},
            'retained': {name: history.complete_code_digest(
                backend.api._SERVICE_BOOTSTRAP_REFERENCES[mode].__code__)
                for mode, name in enumerate(history.METHODS, 1)},
        }
    complete = actual_complete()
    if complete != {'public': code['public_complete'], 'retained': code['retained_complete']}:
        raise ValueError('current dispatcher complete code differs from physical source')
    for mode, method in enumerate(history.METHODS, 1):
        if sha256(backend.api._SERVICE_BOOTSTRAP_REFERENCES[mode].__code__.co_code).hexdigest() != code['retained'][method]:
            raise ValueError('current retained reference does not match its physical source')
    init = init_controls(backend, lane)
    program = program_controls(backend, lane)
    history.unchanged(root, saved)
    if actual_complete() != complete or backend.poison_calls:
        raise ValueError('current code changed or selected dispatch reached a retained complete body')
    return {'schema': 'hepta.hia.bootstrap-current-dispatch-controls.v3',
            'status': 'PASS_CURRENT_INIT_AND_PROGRAM_ONLY',
            'domain': 'CURRENT_PHYSICAL_PUBLIC_DISPATCH', 'lane': lane,
            'physical_source': {'path': history.SOURCE, **history.identity(physical)},
            'actual_public_code': dict(backend.public_code), 'current_reference_code': code['retained'],
            'actual_public_complete_code': complete['public'],
            'current_reference_complete_code': complete['retained'],
            'option_names': list(OPTIONS), 'init_cases': 8, 'init_rows': init,
            'program_cases': len(PROGRAM_CASES), 'program_rows': program,
            'current_source_unchanged': True, 'retained_poison_calls': [],
            'complete_current_semantics_qualified': False, 'whole_native_stack_qualified': False}


def main(argv=None):
    """Observe the current public domain in its own fresh owned process."""
    import argparse
    from tests import hia_service_bootstrap_support as support
    from tests.hia_service_bootstrap_observer import Backend, UnselectedBackend

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=('unselected', 'vm', 'native'), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if (args.lane == 'native') != (args.manifest is not None):
        parser.error('only the native lane requires its actual admitted manifest')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_before = support.source_snapshot()
    manifest_raw = None
    manifest_pin = None
    if args.manifest is not None:
        manifest_raw, manifest_value, manifest_pin = support.capture_json(args.manifest)
        image_path = args.manifest.parent / manifest_value['image_path']
        if support.file_pin(image_path)['sha256'] != manifest_value['image_sha256']:
            raise ValueError('current dispatcher image differs from its actual manifest')
    backend = UnselectedBackend() if args.lane == 'unselected' else Backend(args.lane, args.manifest)
    proof = current_dispatch_controls(backend, args.lane)
    source_after = support.source_snapshot()
    if source_before != source_after:
        raise ValueError('current dispatcher component source changed')
    if manifest_raw is not None:
        support.exact_reread(args.manifest, manifest_raw)
    report = {
        'schema': 'hepta.hia.bootstrap-current-dispatch-process.v1',
        'status': 'PASS_CURRENT_INIT_AND_PROGRAM_PROCESS_ONLY',
        **support.child_identity(), 'lane': args.lane,
        'source_before': source_before, 'source_after': source_after,
        'manifest': manifest_pin, 'current_dispatch': proof,
        'whole_native_stack_qualified': False,
    }
    support.write_json(args.output / 'report.json', report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
