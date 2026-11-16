"""Ordinary CLI discovery selection, exact bytes, and fail-closed routing."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import cli
from hepta import hia_cli_discovery_selection as selection

CLI_FIXTURE = 'HEPTA_HIA_CLI_DISCOVERY_CALLERS_CLI_MANIFEST'
CLI_DEVELOPMENT_COMPILER = 'HEPTA_HIA_CLI_DISCOVERY_CALLERS_DEVELOPMENT_COMPILER'


def outcome(argv, values=None):
    output, errors = io.StringIO(), io.StringIO()
    env = {key: value for key, value in os.environ.items()
           if key not in (selection.SELECTOR, 'HEPTA_HIA_CLI_MANIFEST')}
    env.update(values or {})
    with patch.dict(os.environ, env, clear=True), redirect_stdout(output), redirect_stderr(errors):
        try:
            result = ('return', cli.hia_main(argv))
        except SystemExit as error:
            result = ('exit', error.code)
    return result, output.getvalue(), errors.getvalue()


class CliDiscoverySelectionSourceTests(unittest.TestCase):
    def test_worker_scope_refuses_unregistered_image_before_mapping(self):
        from hepta import hia_native_helpers
        from hepta import hia_cli_discovery_json_native as runtime
        env = {key: value for key, value in os.environ.items()
               if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with patch.dict(os.environ, env, clear=True):
            with hia_native_helpers.native_helpers_scope():
                with patch.object(runtime, '_captured', side_effect=AssertionError('unbound mapping entered')):
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        runtime.installed_cli_discovery_json('/missing/unbound/manifest.json')
                with patch.dict(os.environ, {selection.SELECTOR: '/missing/unbound/manifest.json'}):
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        selection.selected_json(1)
        self.assertNotIn(selection.SELECTOR, hia_native_helpers.HELPERS)

    def test_absent_selection_retains_dynamic_dictionary_apis(self):
        from hepta import hia_opcodes
        value = {'custom': ['value', 7]}
        with patch.object(cli, 'agent_capabilities', return_value=value) as capabilities:
            result = outcome(['capabilities'])
        capabilities.assert_called_once_with()
        self.assertEqual(result, (('return', 0), json.dumps(value, indent=2, sort_keys=True) + '\n', ''))
        with patch.object(hia_opcodes, 'opcode_catalog', return_value=value) as catalog:
            result = outcome(['catalog', '--schema', 'hepta.hia.program.v2'])
        catalog.assert_called_once_with('hepta.hia.program.v2')
        self.assertEqual(json.loads(result[1]), value)

    def test_present_empty_selection_fails_before_retained_semantics(self):
        from hepta import hia_opcodes
        with patch.object(cli, 'agent_capabilities', side_effect=AssertionError('retained capabilities')):
            observed = outcome(['capabilities'], {selection.SELECTOR: ''})
        self.assertEqual(observed[0], ('return', 2))
        self.assertIn('selected CLI discovery JSON manifest must not be empty', observed[1])
        with patch.object(hia_opcodes, 'opcode_catalog', side_effect=AssertionError('retained catalog')):
            observed = outcome(['catalog'], {selection.SELECTOR: ''})
        self.assertEqual(observed[0], ('return', 2))
        for values in ({CLI_FIXTURE: ''},
                       {CLI_FIXTURE: 'companion', CLI_DEVELOPMENT_COMPILER: 'compiler'}):
            with patch.dict(os.environ, values, clear=True), self.assertRaises(ValueError):
                CliDiscoverySelectionNativeTests.setUpClass()

    def test_parser_admission_precedes_discovery_selection(self):
        from hepta import hia_cli_discovery_json_native as runtime
        cases = (['--help'], ['--version'], ['catalog', '--schema', 'unknown'],
                 ['catalog', '--schema'], ['capabilities', '--unexpected'])
        expected = [outcome(argv) for argv in cases]
        with patch.object(runtime, 'installed_cli_discovery_json', side_effect=AssertionError('image entered')):
            actual = [outcome(argv, {selection.SELECTOR: '/missing/operator/manifest'}) for argv in cases]
        self.assertEqual(actual, expected)

    def test_completed_byte_carrier_preserves_original_stream_writes(self):
        # This is a transport unit control, not native execution evidence.
        class Stream:
            def __init__(self):
                self.writes = []
            def write(self, text):
                self.writes.append(text)
        stream = Stream()
        with patch.object(json, 'dumps', side_effect=AssertionError('host JSON constructor entered')):
            with redirect_stdout(stream):
                cli.output_json(selection.DiscoveryJsonBytes(b'{"key":"value"}\n'))
        self.assertEqual(stream.writes, ['{"key":"value"}', '\n'])
        for invalid in ('{}\n', b'{}', bytearray(b'{}\n')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                selection.DiscoveryJsonBytes(invalid)

    def test_native_catalog_effect_observes_namespace_field_once(self):
        from hepta import hia_opcodes
        from hepta.hia_cli_native import CliSession
        observed, registered = [], []
        def field(a, b):
            observed.append((a, b))
            return 'hepta.hia.program.v1'
        def register(value):
            registered.append(value)
            return len(registered)
        fake = SimpleNamespace(value=None, register=register, field=field, cli=cli)
        env = {key: value for key, value in os.environ.items() if key != selection.SELECTOR}
        sentinel = {'custom': True}
        with patch.dict(os.environ, env, clear=True), patch.object(hia_opcodes, 'opcode_catalog', return_value=sentinel):
            self.assertEqual(CliSession._effect(fake, 2, 17, 3, 0, 0), (1, 0, 0))
        self.assertEqual(observed, [(17, 3)])
        self.assertEqual(registered, [sentinel])


class CliDiscoverySelectionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_cli_discovery_json import CliDiscoveryJsonNativeTests
        if CLI_FIXTURE in os.environ and (not os.environ[CLI_FIXTURE]
                                         or CLI_DEVELOPMENT_COMPILER in os.environ):
            raise ValueError('one nonempty explicit CLI companion selection is required')
        # The original fixture enforces cold/development separation, actual
        # owner bindings and source stability, without removing any old case.
        cls.fixture = type('CliDiscoverySelectionFixture', (CliDiscoveryJsonNativeTests,), {})
        cls.fixture.setUpClass()
        if CLI_FIXTURE in os.environ:
            selected = os.environ[CLI_FIXTURE]
            if not selected:
                raise ValueError('selected CLI companion manifest must not be empty')
            cls.cli_manifest = Path(selected).resolve(strict=True)
        elif cls.fixture.cold:
            if CLI_DEVELOPMENT_COMPILER in os.environ:
                raise ValueError('development CLI compiler cannot replace matching cold authority')
            from tools import qualify_hia_cli_discovery_json as qualifier
            from tools.build_hia_cli_native import build, SOURCES
            from tools.hia_cli_discovery_custody import admit_compilation
            selected = qualifier.admit_fixture(cls.fixture.cold)
            authority = selected['authority']
            cls.cli_manifest = build(cls.fixture.folder / 'cli-companion',
                Path(authority['compiler']), Path(authority['cold_report']))
            root = Path(__file__).resolve().parents[1]
            for name, source_name in SOURCES.items():
                directory = cls.cli_manifest.parent / name
                admit_compilation(directory, 'cli-' + name, authority['compiler'],
                    (root / source_name).read_bytes(), directory / ('cli-' + name + '.image.bin'))
        else:
            from hashlib import sha256
            from tools.build_hia_cli_native import build_development
            selected = os.environ.get(CLI_DEVELOPMENT_COMPILER)
            if not selected:
                raise ValueError('explicit development CLI compiler or companion manifest is required')
            compiler = Path(selected).resolve(strict=True)
            manifest = json.loads(cls.fixture.manifest.read_bytes())
            if sha256(compiler.read_bytes()).hexdigest() != manifest['compiler_sha256']:
                raise ValueError('development CLI and discovery compiler identities differ')
            cls.cli_manifest = build_development(cls.fixture.folder / 'cli-companion', compiler)
        from hepta.hia_cli_native import installed_cli
        cls.cli_owner = installed_cli(cls.cli_manifest)
        from tools.hia_cli_discovery_custody import binding
        cls.cli_bindings = [binding(path) for path in cls.cli_manifest.parent.rglob('*') if path.is_file()]

    def tearDown(self):
        self.fixture.guard()
        from tools.hia_cli_discovery_custody import check_bindings
        check_bindings(self.cli_bindings)

    def modes(self):
        return ({selection.SELECTOR: str(self.fixture.manifest)},
                {selection.SELECTOR: str(self.fixture.manifest),
                 'HEPTA_HIA_CLI_MANIFEST': str(self.cli_manifest)})

    def test_01_all_original_outputs_through_both_ordinary_cli_routes(self):
        from hepta import hia_opcodes
        from hepta.hia_cli_discovery_json_native import NativeCliDiscoveryJson
        from tools.hia_cli_discovery_controls import original_oracles, save
        cases = original_oracles()
        calls, records = [], []
        original_observe = NativeCliDiscoveryJson.observe
        def observe(owner, wire, **kwargs):
            self.assertEqual(owner.image_sha256, self.fixture.owner.image_sha256)
            calls.append(wire)
            return original_observe(owner, wire, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, 'agent_capabilities', side_effect=AssertionError('retained capabilities entered')))
            stack.enter_context(patch.object(hia_opcodes, 'opcode_catalog', side_effect=AssertionError('retained catalog entered')))
            stack.enter_context(patch.object(json, 'dumps', side_effect=AssertionError('host JSON constructor entered')))
            stack.enter_context(patch.object(NativeCliDiscoveryJson, 'observe', observe))
            for mode in self.modes():
                for label, _wire, expected in cases:
                    argv = ['capabilities'] if label == 'capabilities' else ['catalog']
                    if label.startswith('catalog-v'):
                        argv += ['--schema', 'hepta.hia.program.' + label.removeprefix('catalog-')]
                    with self.subTest(mode=sorted(mode), label=label):
                        actual = outcome(argv, mode)
                        self.assertEqual(actual, (('return', 0), expected.decode('utf-8'), ''))
                        records.append({'mode': sorted(mode), 'label': label, 'output_bytes': len(expected)})
        self.assertEqual(len(calls), 20)
        save(self.fixture.folder / 'ORDINARY_CLI.json', {'status': 'PASS', 'scope': self.fixture.scope,
            'observations': records, 'actual_native_json_calls': len(calls),
            'retained_semantic_calls': 0, 'host_json_constructor_calls': 0,
            'ordinary_cli_explicit_selection': True, 'whole_native_delivery_qualified': False})

    def test_02_parser_errors_and_help_remain_exact_under_both_routes(self):
        from hepta import hia_cli_discovery_json_native as runtime
        cases = (['--help'], ['--version'], ['catalog', '--schema', 'unknown'],
                 ['catalog', '--schema'], ['capabilities', '--unexpected'])
        expected = [outcome(argv) for argv in cases]
        with patch.object(runtime, 'installed_cli_discovery_json', side_effect=AssertionError('discovery entered before parser admission')):
            for mode in self.modes():
                self.assertEqual([outcome(argv, mode) for argv in cases], expected)

    def test_03_selected_missing_or_empty_manifest_never_falls_back(self):
        from hepta import hia_opcodes
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / 'missing.json')
            for mode in self.modes():
                for selected in ('', missing):
                    for argv in (['capabilities'], ['catalog']):
                        with self.subTest(mode=sorted(mode), selected=selected, argv=argv):
                            with patch.object(cli, 'agent_capabilities', side_effect=AssertionError('retained capabilities entered')):
                                with patch.object(hia_opcodes, 'opcode_catalog', side_effect=AssertionError('retained catalog entered')):
                                    observed = outcome(argv, {**mode, selection.SELECTOR: selected})
                            self.assertEqual(observed[0], ('return', 2))
                            self.assertEqual(observed[2], '')
                            self.assertIn('E_DRIVER', observed[1])


if __name__ == '__main__':
    unittest.main()
