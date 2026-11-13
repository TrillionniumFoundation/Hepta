"""Ordinary bounded-wire/Agent entry controls for the explicit HIA product profile."""
from contextlib import contextmanager
from hashlib import sha256
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta import hia_agent_store as store
from hepta import hia_json_wire_native as native
from hepta import hia_program_tools as program_tools
from tests import test_hia_json_wire_native as wire_tests

FIXTURE_EVIDENCE = 'HEPTA_HIA_JSON_WIRE_ENTRY_FIXTURE_EVIDENCE'
FORMAT_SELECTOR = 'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST'


def outcome(operation):
    try:
        return 'ok', operation()
    except Exception as exc:
        return type(exc).__name__, str(exc)


class EntryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the strict current-cold/development fixture builder, but give
        # this complete module its own create-only evidence tree.
        evidence = os.environ.get(FIXTURE_EVIDENCE, '')
        with patch.dict(os.environ, {wire_tests.FIXTURE_EVIDENCE: evidence}):
            wire_tests.WireNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        wire_tests.WireNativeTests.tearDownClass.__func__(cls)

    @contextmanager
    def selected(self, *, formatter=''):
        with (patch.dict(os.environ, {native.SELECTOR: str(self.manifest), FORMAT_SELECTOR: formatter}),
              patch.object(program_tools, '_reference_bounded_json_wire',
                           side_effect=AssertionError('retained bounded-wire owner entered')),
              patch.object(json.JSONEncoder, 'iterencode',
                           side_effect=AssertionError('host JSON encoder entered'))):
            yield

    def test_ordinary_bytes_errors_and_immutable_builtin_flag_truth(self):
        values = [None, True, -0.0, 5e-324, 1.7976931348623157e308,
                  {'z': ['雪', 1.25], 'a': (False, 10 ** 100)},
                  {1: 0, '1': 1}, {'x': float('nan')}, '\ud800', object()]
        for value in values:
            for maximum in (0, 1, 3, 32, 4096):
                expected = outcome(lambda: program_tools._reference_bounded_json_wire(value, maximum))
                with self.selected():
                    actual = outcome(lambda: program_tools.bounded_json_wire(value, maximum))
                self.assertEqual(actual, expected)
        flags = [None, False, True, 0, -1, 1 << 100, 0., -0., float('nan'), float('inf'),
                 '', 'yes', b'', b'\xff', (), (object(),), frozenset(), frozenset({1})]
        value = {'z': '雪\x7f', 'a': 1.25}
        for flag in flags:
            for option in ('ensure_ascii', 'sort_keys'):
                options = {'ensure_ascii': False, 'sort_keys': True, option: flag}
                expected = program_tools._reference_bounded_json_wire(value, 4096, **options)
                with self.selected():
                    self.assertEqual(program_tools.bounded_json_wire(value, 4096, **options), expected)

    def test_budget_precedes_foreign_flags_and_unclosed_profiles_fail_closed(self):
        class Flag:
            def __bool__(self):
                raise AssertionError('foreign truthiness hook entered')
        class Integer(int):
            def __bool__(self):
                raise AssertionError('integer subclass truthiness hook entered')
        for maximum in (None, True, -1, native.MAXIMUM + 1, 1 << 100):
            with self.selected(), self.assertRaisesRegex(program_tools.HIAEditRejected, 'invalid JSON output byte budget'):
                program_tools.bounded_json_wire(None, maximum, ensure_ascii=Flag(), sort_keys=Flag())
        for value in (Flag(), Integer(1), [], {}, set()):
            for option in ('ensure_ascii', 'sort_keys'):
                with self.selected(), self.assertRaisesRegex(program_tools.HIAEditRejected, 'immutable builtin ' + option):
                    program_tools.bounded_json_wire(None, 128, **{option: value})
        callback = lambda number: (_ for _ in ()).throw(AssertionError('unadmitted renderer entered'))
        with self.selected(), self.assertRaisesRegex(program_tools.HIAEditRejected, 'admitted HIA binary64 renderer'):
            program_tools.bounded_json_wire(1.25, 128, float_renderer=callback)
        with self.selected(), self.assertRaisesRegex(program_tools.HIAEditRejected, 'invalid JSON output byte budget'):
            program_tools.bounded_json_wire(1.25, -1, float_renderer=callback)

    def test_Agent_wire_digest_and_selected_HIA_formatter_preserve_selection_order(self):
        from hepta.hia_agent_binary64_format_native import NativeAgentBinary64Format
        values = [{'z': -0.0, 'a': [1.25, 5e-324, 1.7976931348623157e308, '雪']},
                  {1.25: 'numeric', -2.: 'second'}, {'integer': 10 ** 100}]
        expected = [program_tools._reference_bounded_json_wire(value, native.MAXIMUM,
                    ensure_ascii=False, sort_keys=True) for value in values]
        calls = []
        original = NativeAgentBinary64Format.render
        def render(image, number):
            calls.append(struct.pack('<d', number))
            return original(image, number)
        with patch.object(NativeAgentBinary64Format, 'render', render):
            for formatter in ('', str(self.folder / 'format/manifest.json')):
                with self.selected(formatter=formatter):
                    for value, wanted in zip(values, expected):
                        self.assertEqual(store.wire(value), wanted)
                        self.assertEqual(store.digest(value), sha256(wanted).hexdigest())
        self.assertIn(struct.pack('<d', -0.0), calls)
        self.assertIn(struct.pack('<d', 5e-324), calls)
        with self.selected(formatter=str(self.folder / 'missing-formatter')):
            with patch.object(native, 'installed_json_wire', side_effect=AssertionError('wire admitted before formatter')):
                with self.assertRaises(FileNotFoundError):
                    store.wire(object())

    def test_initial_packet_option_facts_and_old_protocol_refuse_before_output(self):
        changes = [('old-length', None, None), ('unknown-kind', 64, 6), ('none-value', 72, 1),
                   ('boolean-value', 88, 2), ('renderer-profile', 96, 3)]
        for label, offset, value in changes:
            observer = native.ForeignGraphObserver()
            session = native.WireSession(self.image, observer, observer.register(None), 16,
                                         ensure_ascii=None, sort_keys=True)
            raw = ctypes.create_string_buffer(48)
            ctypes.memset(raw, 0xA5, 48)
            session.output = ctypes.cast(ctypes.byref(raw, 16), ctypes.POINTER(ctypes.c_char))
            packet = bytearray(session.packet)
            if offset is None:
                packet = packet[:88]
            else:
                struct.pack_into('<Q', packet, offset, value)
            with self.subTest(case=label):
                self.assertEqual(session.step(bytes(packet)), 199)
                self.assertEqual(raw.raw, b'\xa5' * 48)

    def test_selected_manifest_source_and_new_image_path_refuse_without_fallback(self):
        directory = self.folder / 'ordinary-binding'; directory.mkdir()
        bad = directory / 'bad.json'; bad.write_text('{}')
        with self.selected(), patch.dict(os.environ, {native.SELECTOR: str(bad)}):
            with self.assertRaises(ValueError): program_tools.bounded_json_wire(None, 128)
        source = directory / 'source.hepta'; source.write_bytes(native.SOURCE.read_bytes() + b'\n')
        with self.selected(), patch.object(native, 'SOURCE', source):
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                program_tools.bounded_json_wire(None, 128)
        manifest = json.loads(self.manifest.read_bytes())
        corrupt = directory / 'corrupt.image.bin'
        image = (self.manifest.parent / manifest['image_path']).resolve()
        corrupt.write_bytes(image.read_bytes() + b'!')
        manifest['image_path'] = str(corrupt)
        wrong = directory / 'new-path.json'; wrong.write_text(json.dumps(manifest))
        with self.selected(), patch.dict(os.environ, {native.SELECTOR: str(wrong)}):
            with self.assertRaisesRegex(ValueError, 'executable identity mismatch'):
                program_tools.bounded_json_wire(None, 128)

    def test_installed_wheel_ordinary_entry_forbids_retained_owner_and_authoring(self):
        wire_tests.WireNativeTests.test_installed_wheel_resource_identity_and_no_retained_encoder(self)
        installed, = self.folder.glob('installed-*/installed')
        script = r'''
import builtins,json,os,pathlib,sys
from hashlib import sha256
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from hepta import hia_program_tools as tools
from hepta import hia_agent_store as store
from hepta.hia_json_wire_native import SOURCE,SELECTOR
assert pathlib.Path(tools.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
assert '_data' in SOURCE.parts
os.environ[SELECTOR]=sys.argv[2]
os.environ['HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST']=sys.argv[3]
real_import=builtins.__import__
def no_authoring(name,*a,**kw):
 if name=='tools' or name.startswith('tools.'):raise AssertionError('installed entry imported authoring')
 return real_import(name,*a,**kw)
with patch('builtins.__import__',no_authoring),patch.object(tools,'_reference_bounded_json_wire',side_effect=AssertionError('retained')),patch('json.JSONEncoder.iterencode',side_effect=AssertionError('host encoder')):
 expected=b'{"a":1.25,"z":"\xe9\x9b\xaa"}'
 assert store.wire({'z':'雪','a':1.25})==expected
 assert store.digest({'z':'雪','a':1.25})==sha256(expected).hexdigest()
 assert tools.bounded_json_wire({'z':'雪','a':1.25},128,ensure_ascii=False)==expected
print('INSTALLED_ORDINARY_NATIVE_WIRE_PASS')
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, str(installed), str(self.manifest),
                                 str(self.folder / 'format/manifest.json')], cwd=self.folder,
                                env={'PATH': '', 'LANG': 'C.UTF-8'}, capture_output=True, timeout=30)
        (self.folder / 'installed-ordinary.stdout.log').write_bytes(result.stdout)
        (self.folder / 'installed-ordinary.stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, b'INSTALLED_ORDINARY_NATIVE_WIRE_PASS\n')
