"""Strict cold/admission controls; simulated transport is never native qualification."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tools import build_hia_store_lifecycle as builder
from hepta import hia_store_lifecycle_native as native

@contextmanager
def controlled_build():
    with tempfile.TemporaryDirectory(prefix='hia-store-build-control-') as folder:
        root = Path(folder)
        for name in builder.DEVELOPMENT_INPUT_NAMES:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('controlled input: ' + name).encode())
        compiler, cold = root / 'compiler', root / 'cold.json'
        compiler.write_bytes(b'controlled compiler, not executable')
        cold.write_text(json.dumps({'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3}))
        sources = {name: sha256((root / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES}
        output = root / 'output'
        calls = []
        def compile_stage(out, label, consumed_compiler, source):
            calls.append((out, label, consumed_compiler, source))
            image = out / (label + '.image.bin'); image.write_bytes(b'x')
            c, s, i = (sha256(raw).hexdigest() for raw in (compiler.read_bytes(), source, b'x'))
            receipt = {'status': 'returned', 'format': 'flat-x86-64',
                'return_encoding': 'zero-extended-u32', 'artifact_sha256': c, 'image_sha256': c,
                'input_sha256': s, 'source_sha256': s, 'produced_sha256': i,
                'input_bytes': len(source), 'produced_bytes': 1, 'result_u64': 1, 'core_u32': 1,
                'abi_status': 0, 'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'case': label, 'produced_image': str(image)}
            (out / (label + '.receipt.json')).write_text(json.dumps(receipt))
            return image, receipt
        with patch.object(builder, 'ROOT', root), patch.object(builder, 'admit_cold_build', return_value=sources), patch.object(builder, 'current_sources', return_value=sources):
            yield SimpleNamespace(root=root, compiler=compiler, cold=cold, sources=sources,
                                  output=output, calls=calls, compile_stage=compile_stage)


class StoreLifecycleAdapterTests(unittest.TestCase):
    def test_invalid_actual_cold_receipt_refuses_before_output_or_compile(self):
        with tempfile.TemporaryDirectory(prefix='store-invalid-cold-') as directory:
            root = Path(directory); compiler = root / 'compiler'; cold = root / 'cold'
            compiler.write_bytes(b'not an actual qualified compiler'); cold.write_bytes(b'{}')
            with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaises(ValueError):
                    builder.build(root / 'output', compiler, cold)
            self.assertFalse((root / 'output').exists())

    def test_all_required_source_paths_and_full_current_map_precede_output(self):
        for name in builder.REQUIRED_SOURCE_NAMES:
            with self.subTest(name=name), controlled_build() as case:
                case.sources.pop(name)
                with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                    with self.assertRaises(ValueError):
                        builder.build(case.output, case.compiler, case.cold)
                self.assertFalse(case.output.exists())
        with controlled_build() as case, patch.object(builder, 'current_sources', return_value={}):
            with self.assertRaises(ValueError):
                builder.build(case.output, case.compiler, case.cold)
            self.assertFalse(case.output.exists())

    def test_cold_limits_keep_exact_integer_180_and_3(self):
        for key, value in (('qualification_wall_limit_seconds', 180.0), ('qualification_wall_limit_seconds', 181),
                           ('cleanup_wall_limit_seconds', 3.0), ('cleanup_wall_limit_seconds', True),
                           ('cleanup_wall_limit_seconds', 4)):
            with self.subTest(key=key, value=value), controlled_build() as case:
                record = json.loads(case.cold.read_bytes()); record[key] = value
                case.cold.write_text(json.dumps(record))
                with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                    with self.assertRaises(ValueError):
                        builder.build(case.output, case.compiler, case.cold)
                self.assertFalse(case.output.exists())

    def test_returned_and_disk_receipts_must_match_exact_invocation(self):
        for disk_only in (False, True):
            for key, value in (('abi_status', False), ('result_u64', True), ('core_u32', 1.0),
                               ('source_unchanged', 1), ('produced_sha256', '0' * 64), ('case', 'other')):
                with self.subTest(disk_only=disk_only, key=key), controlled_build() as case:
                    def changed(*args):
                        image, receipt = case.compile_stage(*args)
                        altered = dict(receipt); altered[key] = value
                        (case.output / 'store-lifecycle.receipt.json').write_text(json.dumps(altered))
                        return image, receipt if disk_only else altered
                    with patch.object(builder, 'compile_stage', side_effect=changed):
                        with self.assertRaises(ValueError):
                            builder.build(case.output, case.compiler, case.cold)
                    self.assertFalse((case.output / 'manifest.json').exists())

    def test_admission_and_receipts_are_fresh_after_compile(self):
        for name in ('compiler', 'cold', *builder.REQUIRED_SOURCE_NAMES):
            with self.subTest(name=name), controlled_build() as case:
                def changed(*args):
                    result = case.compile_stage(*args)
                    path = case.compiler if name == 'compiler' else case.cold if name == 'cold' else case.root / name
                    path.write_bytes(path.read_bytes() + b'changed')
                    return result
                with patch.object(builder, 'compile_stage', side_effect=changed):
                    with self.assertRaises(ValueError):
                        builder.build(case.output, case.compiler, case.cold)
                self.assertFalse((case.output / 'manifest.json').exists())

    def test_manifest_refuses_duplicate_unknown_or_mismatched_source_before_mapping(self):
        with tempfile.TemporaryDirectory(prefix='store-manifest-refusal-') as directory:
            root = Path(directory); path = root / 'manifest.json'; image = root / 'image.bin'
            image.write_bytes(b'not executable')
            record = {'schema': native.SCHEMA, 'source_sha256': sha256(native.SOURCE.read_bytes()).hexdigest(),
                      'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(), 'compiler_sha256': '1' * 64}
            variants = [json.dumps({**record, 'extra': 0}), json.dumps({**record, 'image_path': '../image.bin'}),
                        json.dumps({**record, 'source_sha256': '0' * 64}),
                        json.dumps({**record, 'image_sha256': '0' * 64}),
                        json.dumps(record)[:-1] + ',"schema":"duplicate"}']
            for raw in variants:
                path.write_text(raw)
                with self.subTest(raw=raw), patch.object(native, '_mapped_store_lifecycle', side_effect=AssertionError('mapping entered')):
                    with self.assertRaises(ValueError):
                        native.installed_store_lifecycle(path, capture_identity=True)

