"""Compare original mutable foreign lookups without executing any policy image."""
from pathlib import Path
import argparse
import importlib
import json
import os
import sys
import types
from hashlib import sha256

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--role', choices=('before', 'after'), required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
sys.dont_write_bytecode = True
sys.path.insert(0, str(args.source.resolve(strict=True)))
for key in tuple(os.environ):
    if key.startswith('HEPTA_'):
        del os.environ[key]
stems = ('hia_native_build', 'hia_service_verification', 'hia_proof_contract', 'hia_native_byte_abi')
foreign_names = {'hepta.' + stem + '_foreign' for stem in stems}
profiles = []
def profiler(frame, event, result):
    if (event == 'call' and frame.f_code.co_name == '_profile'
            and frame.f_globals.get('__name__') in foreign_names):
        profiles.append(frame.f_globals['__name__'])
sys.setprofile(profiler)
modules = {stem: importlib.import_module('hepta.' + stem + '_native') for stem in stems}
sys.setprofile(None)
initial_ports = sorted(foreign_names.intersection(sys.modules))
initial_profiles = list(profiles)
if args.role == 'after':
    assert not initial_ports and not profiles, (initial_ports, profiles)
    for module in modules.values():
        assert module.foreign is module._FOREIGN_NOT_LOADED
        module._load_foreign_ports()
        actual = sys.modules[module.__name__.removesuffix('_native') + '_foreign']
        assert module.foreign is actual
        module._load_foreign_ports()
        assert module.foreign is actual

rows = []
for stem, module in modules.items():
    real_foreign = module.foreign
    for phase in ('before_first_load', 'after_first_load'):
        for state in ('real', 'replacement', 'none', 'missing'):
            for outer in (False, True):
                events = []
                class Calls:
                    def get(self, key):
                        events.append(('calls-get', key))
                        def primitive(frame, slots):
                            events.append(('replacement-call', tuple(slots)))
                            return 'replacement-result'
                        return primitive
                class Provider:
                    def __getattribute__(self, name):
                        events.append(('provider-attribute', name))
                        if name == 'CALLS':
                            return Calls()
                        if name == 'import_ports':
                            def port(namespace):
                                events.append(('replacement-import-ports', namespace['__name__']))
                                return {}, {}
                            return port
                        raise AttributeError(name)
                replacement = Provider()
                if args.role == 'after':
                    module.foreign = module._FOREIGN_NOT_LOADED if phase == 'before_first_load' else real_foreign
                    if phase == 'after_first_load':
                        module._load_foreign_ports()
                else:
                    module.foreign = real_foreign
                if state == 'real':
                    module.foreign = real_foreign
                elif state == 'replacement':
                    module.foreign = replacement
                elif state == 'none':
                    module.foreign = None
                else:
                    del module.foreign
                before_binding = vars(module).get('foreign', 'ABSENT')
                if args.role == 'after':
                    module._load_foreign_ports()
                    assert vars(module).get('foreign', 'ABSENT') is before_binding
                class Frame:
                    image = types.SimpleNamespace(literal=lambda index: index)
                    def _move(self, slot):
                        events.append(('move', slot))
                        return lambda: 'original-callee-result'
                    def _get(self, slot):
                        return self._move(slot)
                    def _move_call_operand(self, slot):
                        return self._move(slot)
                def invoke():
                    if stem == 'hia_native_byte_abi':
                        api = importlib.import_module('hepta.hia_native_byte_abi')
                        arities = list(module.ARITIES.values())
                        owner = types.SimpleNamespace(function=lambda n: (0, 0, arities[n - 1]))
                        return module.NativeByteABI._bind_namespace(owner, vars(api))
                    frame = Frame()
                    cls = getattr(module, {'hia_native_build': 'NativeBuildFrame',
                           'hia_service_verification': 'VerificationFrame',
                           'hia_proof_contract': 'ProofContractFrame'}[stem])
                    return cls._call(frame, (0,), (0, 0))
                def capture(handled):
                    try:
                        return {'kind': 'value', 'value': invoke()}
                    except BaseException as error:
                        return {'kind': 'error', 'type': type(error).__name__, 'args': list(error.args),
                            'name': getattr(error, 'name', None),
                            'context_type': type(error.__context__).__name__ if error.__context__ else None,
                            'context_is_outer': error.__context__ is handled,
                            'cause_type': type(error.__cause__).__name__ if error.__cause__ else None}
                if outer:
                    try:
                        raise LookupError('outer-binding-control')
                    except LookupError as handled:
                        result = capture(handled)
                else:
                    result = capture(None)
                rows.append({'owner': stem, 'phase': phase, 'binding': state, 'outer': outer,
                             'outcome': result, 'events': events})
                module.foreign = real_foreign
report = {'schema': 'hia.foreign-global-binding.controlled-observations.v1',
    'role': args.role, 'python': sys.version, 'source': str(args.source),
    'initial_foreign_modules': initial_ports, 'initial_profile_calls': initial_profiles,
    'rows': rows, 'observations': len(rows), 'actual_native_entries': 0,
    'scope': 'CONTROLLED_FIXED_PORT_AND_GLOBAL_LOOKUP_ONLY_NOT_NATIVE_POLICY_QUALIFICATION',
    'source_identities': {stem: {'path': module.__file__,
        'sha256': sha256(Path(module.__file__).read_bytes()).hexdigest()} for stem, module in modules.items()},
    'current_cold': False, 'default_activated': False, 'whole_normalization': False}
args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'role': args.role, 'observations': len(rows),
    'initial_foreign_modules': initial_ports, 'initial_profile_calls': len(initial_profiles)}))
