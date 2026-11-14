"""Default checker roles and explicit application-provider bindings."""
import ast
from contextlib import nullcontext
import copy
import importlib
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta import hia_agent_assembly as assembly
from hepta import hia_checker_identity as identity
from hepta import hia_program_tools as application
from hepta import hia_linux_file_roundtrip as roundtrip
from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
from tools import generate_hia_checker_inventory as inventory


ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'hepta.hia.linux-file-roundtrip.v2'
ENTRIES = (
    ('assemble_program', '_roundtrip_assembly_provider', 'assemble_linux_file_roundtrip'),
    ('render_assembly', '_roundtrip_render_provider', 'render_linux_file_roundtrip'),
)


class ExplicitProfileProviderSourceTests(unittest.TestCase):
    def test_exact_profile_metadata_is_consumed_by_the_full_physical_inventory(self):
        actual = inventory.check(ROOT)
        bindings = actual['explicit_profile_providers']
        self.assertEqual(bindings, identity.CHECKER_EXPLICIT_PROFILE_PROVIDER_BINDINGS)
        self.assertEqual(bindings['schema'], 'hepta.hia.checker-explicit-profile-providers.v1')
        self.assertEqual(set(bindings['profiles']), set(OPTIONAL_PROFILE_FILES))
        self.assertEqual((len(identity.SEMANTIC_CORE_SOURCE_FILES),
                          len(identity.CHECKER_MECHANISM_SOURCE_FILES)), (54, 54))
        self.assertEqual(identity.CHECKER_MECHANISM_EXTERNAL_PROVIDERS['hia_agent_assembly.py'],
                         ('hia_program_tools.py',))
        for profile, record in bindings['profiles'].items():
            with self.subTest(profile=profile):
                self.assertEqual(record['source_files'], OPTIONAL_PROFILE_FILES[profile])
                self.assertEqual(record['providers'], identity.EXPLICIT_PROFILE_PROVIDER_FILES[profile])
                for name in record['providers']:
                    self.assertIn(name, actual['names'])
                    self.assertIn(name, actual['sources'])
                    self.assertEqual(actual['roles'][name], ('custody-dependency',))
                    self.assertNotIn(name, identity.MECHANISM_SOURCE_FILES)
        for entry, factory, target in ENTRIES:
            self.assertIs(application._ROUNDTRIP_PROFILE_PROVIDERS[entry],
                          vars(application)[factory])
            self.assertIn(('hia_agent_assembly.py', entry, 1, 'hia_program_tools',
                           ('_ROUNDTRIP_PROFILE_PROVIDERS',), 'hia_program_tools.py', 'custody'),
                          actual['edges'])
            self.assertIn(('hia_program_tools.py', factory, 1, 'hia_linux_file_roundtrip',
                           (target,), 'hia_linux_file_roundtrip.py', 'custody'), actual['edges'])

    def test_each_explicit_call_uses_the_current_target_once_after_its_factory_returns(self):
        for entry, factory, target in ENTRIES:
            public = getattr(assembly, entry)
            argument = object()
            events = []
            for turn in (1, 2):
                result = object()
                def selected(value, turn=turn, result=result):
                    events.append((turn, value))
                    return result
                with self.subTest(entry=entry, turn=turn), patch.object(roundtrip, target, selected), \
                        patch.object(application, factory, side_effect=AssertionError('late factory replacement')), \
                        patch.object(assembly, '_native_assembly_front_scope',
                                     side_effect=AssertionError('default owner entered')):
                    self.assertIs(public(argument, profile=PROFILE), result)
            self.assertEqual(events, [(1, argument), (2, argument)])
            error = ValueError('same explicit target error')
            def rejected(value):
                self.assertIs(value, argument)
                events.append(('error', value))
                raise error
            with patch.object(roundtrip, target, rejected):
                try:
                    public(argument, profile=PROFILE)
                except ValueError as observed:
                    self.assertIs(observed, error)
                    names = []
                    trace = observed.__traceback__
                    while trace is not None:
                        names.append(trace.tb_frame.f_code.co_name)
                        trace = trace.tb_next
                    self.assertEqual(names[-1], 'rejected')
                    self.assertEqual(names.count(entry), 1)
                    self.assertNotIn('_roundtrip_assembly_provider', names)
                    self.assertNotIn('_roundtrip_render_provider', names)
                    self.assertIsNone(observed.__cause__)
                else:
                    self.fail('explicit target exception was not propagated')
            self.assertEqual(events, [(1, argument), (2, argument), ('error', argument)])

    def test_default_and_all_previous_profiles_do_not_resolve_the_new_factories(self):
        previous = (
            ('hepta.hia.linux-file-render.v3', 'hia_linux_file_render', 'linux_file_render'),
            ('hepta.hia.linux-file.v1', 'hia_linux_file', 'linux_file'),
            ('hepta.hia.linux-cli-process.v1', 'hia_linux_cli_process', 'linux_cli_process'),
            ('hepta.hia.linux-process.v1', 'hia_linux_process', 'linux_process'),
            ('hepta.hia.linux-stdio.v1', 'hia_linux_stdio', 'linux_stdio'),
        )
        def forbidden():
            raise AssertionError('unselected explicit profile factory was entered')
        with patch.dict(application._ROUNDTRIP_PROFILE_PROVIDERS,
                        {entry: forbidden for entry, _factory, _target in ENTRIES}, clear=True):
            for entry, _factory, _target in ENTRIES:
                public = getattr(assembly, entry)
                argument, result = object(), object()
                calls = []
                def selected(value):
                    calls.append(value)
                    return result
                reference = '_assembly_front_reference' + entry
                with self.subTest(entry=entry, profile=None), patch.object(assembly, reference, selected), \
                        patch.object(assembly, '_native_assembly_front_scope',
                                     side_effect=lambda: nullcontext(None)):
                    self.assertIs(public(argument), result)
                self.assertEqual(calls, [argument])
                for profile, module_name, suffix in previous:
                    module = importlib.import_module('hepta.' + module_name)
                    target = ('assemble_' if entry == 'assemble_program' else 'render_') + suffix
                    calls.clear()
                    with self.subTest(entry=entry, profile=profile), patch.object(module, target, selected), \
                            patch.object(assembly, '_native_assembly_front_scope',
                                         side_effect=AssertionError('default owner entered')):
                        self.assertIs(public(argument, profile=profile), result)
                    self.assertEqual(calls, [argument])

    def test_generator_rejects_registry_factory_anchor_and_callsite_drift(self):
        declarations = inventory._literal_assignments(ast.parse((ROOT / 'hepta/hia_checker_identity.py').read_bytes()))
        mechanisms = declarations['MECHANISM_SOURCE_FILES']
        expected = inventory.explicit_profile_bindings(ROOT, declarations, mechanisms)
        self.assertEqual(expected['application_bridges'], identity.EXPLICIT_PROFILE_APPLICATION_BRIDGES)
        changed = copy.deepcopy(declarations)
        changed['EXPLICIT_PROFILE_PROVIDER_SCHEMA'] += '.unknown'
        with self.assertRaisesRegex(ValueError, 'profile provider schema'):
            inventory.explicit_profile_bindings(ROOT, changed, mechanisms)
        changed = copy.deepcopy(declarations)
        del changed['EXPLICIT_PROFILE_PROVIDER_FILES'][PROFILE]
        with self.assertRaisesRegex(ValueError, 'real resource registry'):
            inventory.explicit_profile_bindings(ROOT, changed, mechanisms)
        mutations = (
            ('hepta/hia_linux_file_roundtrip.py',
             b'PROFILE = "hepta.hia.linux-file-roundtrip.v2"',
             b'PROFILE = "hepta.hia.linux-file-roundtrip.unknown"'),
            ('hepta/hia_program_tools.py',
             b"'assemble_program': _roundtrip_assembly_provider",
             b"'assemble_program': _roundtrip_render_provider"),
            ('hepta/hia_program_tools.py',
             b'from .hia_linux_file_roundtrip import assemble_linux_file_roundtrip',
             b'from .hia_linux_file_roundtrip import render_linux_file_roundtrip'),
            ('hepta/hia_agent_assembly.py',
             b"assemble_linux_file_roundtrip = _ROUNDTRIP_PROFILE_PROVIDERS['assemble_program']()",
             b"assemble_linux_file_roundtrip = _ROUNDTRIP_PROFILE_PROVIDERS['render_assembly']()"),
        )
        original = Path.read_bytes
        for relative, old, new in mutations:
            target = ROOT / relative
            raw = original(target)
            self.assertEqual(raw.count(old), 1)
            replacement = raw.replace(old, new, 1)
            def read(path):
                return replacement if path == target else original(path)
            with self.subTest(source=relative, before=old), patch.object(Path, 'read_bytes', read):
                with self.assertRaises(ValueError):
                    inventory.explicit_profile_bindings(ROOT, declarations, mechanisms)


if __name__ == '__main__':
    unittest.main()
