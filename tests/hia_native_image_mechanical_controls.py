"""Development-only mechanical controls plus the unchanged full packet method.

This does not qualify the public route, full146 observer or installed worker.
The method below is compiled from a sealed complete old file without edits.
"""
from pathlib import Path
import ast
import ctypes
import gc
from hashlib import sha256
import importlib.util
import json
import os
import struct
import sys
import sysconfig
import types
import unittest
import weakref

if len(sys.argv) != 4:
    raise SystemExit('usage: hia_native_image_mechanical_controls.py SOURCE MANIFEST OUTPUT')
ROOT = Path(sys.argv[1]).resolve(strict=True)
MANIFEST = Path(sys.argv[2]).resolve(strict=True)
HERE = Path(sys.argv[3]).resolve()
if HERE.is_relative_to(ROOT):
    raise ValueError('mechanical observations must be outside the source tree')
HERE.mkdir(mode=0o700)
INSTALLED = ROOT
MANIFEST_RAW = MANIFEST.read_bytes()
MANIFEST_VALUE = json.loads(MANIFEST_RAW)
IMAGE = MANIFEST.parent / MANIFEST_VALUE['image_path']
sys.path.insert(0, str(INSTALLED))
from hepta import hia_service_artifact_native as native
from hepta.hia_agent_assembly import assemble_program

LIBRARY = ROOT / 'hepta' / ('_hia_native_image' + sysconfig.get_config_var('EXT_SUFFIX'))
spec = importlib.util.spec_from_file_location('_hia_native_image', LIBRARY)
carrier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(carrier)
RAW_IMAGE = IMAGE.read_bytes()
assert sha256(RAW_IMAGE).hexdigest() == MANIFEST_VALUE['image_sha256']
assert sha256(native.SOURCE.read_bytes()).hexdigest() == MANIFEST_VALUE['source_sha256']
assert sha256(RAW_IMAGE).hexdigest() == 'e2229fceca81cc1fd92596c1cd79b784b28df737dd9b3423938d87e772a8f126'
assert sha256(native.SOURCE.read_bytes()).hexdigest() == 'cce535c67f4b0c2ce806864142497a7ae018bc611d8c885e39ae1ec9f7374ff5'
OUTPUTS = {}


def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate((raw, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
        [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('independent VM changed immutable request')
    return code, bytes(owners[1].data), bytes(owners[2].data)


class MechanicalControls(unittest.TestCase):
    def test_heap_type_module_instance_cycles_are_visible_to_gc(self):
        def isolated_graph(kind):
            selected = importlib.util.spec_from_file_location('_hia_native_image', LIBRARY)
            module = importlib.util.module_from_spec(selected)
            selected.loader.exec_module(module)
            value = module.Buffer(8) if kind == 'buffer' else module.Image(RAW_IMAGE)
            module.instance = value
            self.assertTrue(gc.is_tracked(value))
            self.assertIn(type(value), gc.get_referents(value))
            self.assertFalse(any(ref is RAW_IMAGE for ref in gc.get_referents(value)))
            return [weakref.ref(module), weakref.ref(type(value)), weakref.ref(value)]
        for kind in ('buffer', 'image'):
            observed = isolated_graph(kind)
            self.assertTrue(all(reference() is not None for reference in observed))
            gc.collect()
            self.assertTrue(all(reference() is None for reference in observed))

    def test_real_export_callbacks_release_in_reverse_and_keep_the_image_alive(self):
        if sys.version_info < (3, 12):
            self.skipTest('Python-level buffer exports start in CPython 3.12')
        image = carrier.Image(RAW_IMAGE)
        observed = weakref.ref(image)
        events = []
        owners = [carrier.Buffer(struct.pack('<10Q', native.REQUEST_MAGIC,
                   0, 0, 0, 0, 1, 11, 17, 0, 0), 80), carrier.Buffer(96), carrier.Buffer(128)]
        class Exporter:
            def __init__(self, index): self.index = index
            def __buffer__(self, flags):
                events.append(('acquire', self.index, observed() is image))
                return memoryview(owners[self.index])
            def __release_buffer__(self, view):
                events.append(('release', self.index, observed() is image))
        self.assertEqual(image(Exporter(0), 80, Exporter(1), 96, Exporter(2), 128), 96)
        self.assertEqual(events, [('acquire', 0, True), ('acquire', 1, True),
            ('acquire', 2, True), ('release', 2, True), ('release', 1, True), ('release', 0, True)])
        events.clear()
        with self.assertRaises(TypeError): image(Exporter(0), 80, Exporter(1), 96, object(), 128)
        self.assertEqual(events, [('acquire', 0, True), ('acquire', 1, True),
            ('release', 1, True), ('release', 0, True)])

    def test_buffers_are_real_exports_and_retain_their_own_lifetime(self):
        for size in (0, 1, 80, 96, 128, 144, 65536):
            value = carrier.Buffer(size)
            self.assertEqual(value.raw, bytes(size))
            self.assertEqual(len(value), size)
            self.assertEqual(ctypes.string_at(value, size), bytes(size))
            view = memoryview(value)
            self.assertFalse(view.readonly)
            self.assertEqual(view.nbytes, size)
            if size:
                view[-1] = 179
                self.assertEqual(value.raw[-1], 179)
                ctypes.memmove(value, b'Q', 1)
                self.assertEqual(view[0], ord('Q'))
            observed = weakref.ref(value)
            del value
            self.assertIsNotNone(observed())
            view.release()
            self.assertIsNone(observed())
        self.assertEqual(carrier.Buffer(b'ab', 5).raw, b'ab\0\0\0')
        self.assertEqual(carrier.Buffer(b'ab').raw, b'ab\0')
        for values in ((-1,), (b'ab', 1), (b'ab', -1)):
            with self.assertRaises(ValueError): carrier.Buffer(*values)
        for values in ((True,), (bytearray(1),), (b'ab', True), (1, 2)):
            with self.assertRaises(TypeError): carrier.Buffer(*values)

    def test_bounded_exports_and_entry_buffer_compatibility(self):
        image = carrier.Image(RAW_IMAGE)
        raw = struct.pack('<10Q', native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 11, 17, 0, 0)
        source = carrier.Buffer(raw + b'\xc9' * 16, 96)
        output = carrier.Buffer(b'\xa5' * 96 + b'\xa7' * 16, 112)
        state = carrier.Buffer(bytes(128) + b'\xb7' * 16, 144)
        self.assertEqual(image(source, 80, output, 96, state, 128), 96)
        self.assertEqual(source.raw, raw + b'\xc9' * 16)
        self.assertEqual(output.raw[96:], b'\xa7' * 16)
        self.assertEqual(state.raw[128:], b'\xb7' * 16)
        for index in (1, 3, 5):
            for wrong in (True, -1, 1 << 64, 1000):
                args = [source, 80, output, 96, state, 128]
                args[index] = wrong
                sealed = (source.raw, output.raw, state.raw)
                with self.assertRaises((TypeError, ValueError, OverflowError)):
                    image(*args)
                self.assertEqual((source.raw, output.raw, state.raw), sealed)
        for index in (0, 2, 4):
            args = [source, 80, output, 96, state, 128]
            args[index] = bytes(args[index].raw)
            with self.assertRaises(BufferError): image(*args)
            args[index] = memoryview(bytearray(300))[::2]
            with self.assertRaises(BufferError): image(*args)
        # Failed later exports do not leave a stale export on earlier owners.
        mutable = bytearray(raw)
        with self.assertRaises(TypeError): image(mutable, 80, object(), 96, state, 128)
        mutable.extend(b'!')
        observed = weakref.ref(image)
        del image
        self.assertIsNone(observed())
        for invalid in (b'', b'x' * ((1 << 20) + 1), bytearray(1)):
            with self.assertRaises(ValueError): carrier.Image(invalid)


SOURCE_PATH = ROOT / 'tests/test_hia_service_artifact_native.py'
SOURCE_RAW = SOURCE_PATH.read_bytes()
tree = ast.parse(SOURCE_RAW)
method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
              and node.name == 'test_native_complete_packets_buffers_and_protocol_rejections')
method_raw = b''.join(SOURCE_RAW.splitlines(keepends=True)[method.lineno - 1:method.end_lineno])
assert len(method_raw) == 5634 and sha256(method_raw).hexdigest() == '0153afa9f52002e5a2bc691859c410191625117de49ddf260c22cdc66c0012a6'
module = ast.Module(body=[method], type_ignores=[])
namespace = dict(globals())
exec(compile(ast.fix_missing_locations(module), str(SOURCE_PATH), 'exec'), namespace)


class UnchangedPacketMethod(unittest.TestCase):
    def setUp(self):
        self.image = types.SimpleNamespace(_entry=carrier.Image(RAW_IMAGE))

    def write(self, name, records):
        OUTPUTS[name] = records
        (HERE / name).write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')


setattr(UnchangedPacketMethod, method.name, namespace[method.name])


if __name__ == '__main__':
    before = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in (SOURCE_PATH, LIBRARY, IMAGE, MANIFEST, native.SOURCE)}
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(MechanicalControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(UnchangedPacketMethod)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in before}
    report = {'schema': 'hepta.development.three-buffer-carrier.v1',
        'scope': 'MECHANICAL_CONTROLS_AND_UNCHANGED_COMPLETE_PACKET_METHOD',
        'status': 'PASS' if result.wasSuccessful() and before == after else 'FAIL',
        'runtime': sys.version, 'tests': result.testsRun, 'skips': len(result.skipped), 'before': before, 'after': after,
        'original_packet_method': {'bytes': len(method_raw), 'sha256': sha256(method_raw).hexdigest()},
        'actual_packet_records': len(OUTPUTS.get('complete-packets-and-buffers.json', ())),
        'complete146_or_public_or_installed_qualification': False}
    (HERE / 'development.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    raise SystemExit(0 if report['status'] == 'PASS' else 1)
