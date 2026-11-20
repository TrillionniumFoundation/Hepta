"""Adversarial loaded-code/source controls, including actual proof consumers."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOLVER_ROOT = Path(importlib.util.find_spec("z3").origin).resolve().parent.parent
PROBE = '''from .hia_loaded_source import loaded_source_identity, register_loaded_module
VALUE = 41
def nested():
    return 41
def slicing(value):
    return value[:6]
def identity():
    return loaded_source_identity(__name__, ('probe.py',))
register_loaded_module(__name__)
'''
PRELUDE = '''
import hashlib, importlib, json, os, py_compile, struct, sys, types
from pathlib import Path
from unittest.mock import patch
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
sys.path.insert(1, sys.argv[2])
'''
PROOF = '''
import subprocess
from hepta.hia_verified_simd import simd_kernel_program, emit_verified_simd
from hepta.hia_verified_scalar import emit_verified_scalar
from hepta.hia_program import verify_program
from hepta.hia_loaded_source import VerifiedSourceRejected
import hepta.hia_verified_simd_check as simd
import hepta.hia_safe_core as scalar
import hepta.hia_verified_kernel_load as loader
if KIND == 'simd':
    core = simd_kernel_program('sum_u8')
    image = emit_verified_simd(core, unroll=1)
    check = simd.validate_verified_simd_artifact
    options = {}
else:
    core = verify_program(json.loads((root / 'multiply_add.hepta').read_bytes()))
    image = emit_verified_scalar(core)
    check = scalar.validate_safe_core_artifact
    options = {'profile_version': 2}
obj, elf = root / 'probe.o', root / 'probe.so'
obj.write_bytes(image.object_bytes)
subprocess.run(['ld', '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
    '-z', 'relro', '-z', 'now', '--hash-style=both', '--build-id=none',
    str(obj), '-lc', '-o', str(elf)], check=True, capture_output=True)
final = elf.read_bytes()
baseline = check(core, image.object_bytes, final, **options)
assert baseline['ok'] and baseline['complete']
assert 'hia_loaded_source.py' in baseline['checker']['source_identity']
'''


class VerifiedSourceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-loaded-source-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        shutil.copytree(ROOT / 'hepta', cls.root / 'hepta',
                        ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT / 'examples/hia_verified_kernels/multiply_add.hepta',
                        cls.root / 'multiply_add.hepta')

    def child(self, source, *, probe=False):
        if probe:
            package = self.root / 'binding_probe'
            if package.exists():
                shutil.rmtree(package)
            package.mkdir()
            (package / '__init__.py').write_text('')
            shutil.copyfile(ROOT / 'hepta/hia_loaded_source.py', package / 'hia_loaded_source.py')
            (package / 'probe.py').write_text(PROBE)
        completed = subprocess.run([sys.executable, '-I', '-B', '-c',
                                    textwrap.dedent(PRELUDE) + textwrap.dedent(source),
                                    str(self.root), str(SOLVER_ROOT)],
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_fresh_module_reports_executed_source_and_binding_implementation(self):
        self.child('''
            from binding_probe import probe
            evidence = probe.identity()
            for filename, digest in evidence.items():
                assert digest == hashlib.sha256((root / 'binding_probe' / filename).read_bytes()).hexdigest()
            assert set(evidence) == {'probe.py', 'hia_loaded_source.py'}
            assert probe.VALUE == probe.nested() == 41
            assert probe.slicing('0123456789') == '012345'
        ''', probe=True)

    def test_slice_constants_keep_all_components_and_exact_types(self):
        from hepta.hia_loaded_source import _constant_shape
        values = (slice(None), slice(None, 0), slice(0, None),
                  slice(None, None, 0), slice(None, None, 1),
                  slice(None, None, -1), slice(False, None),
                  slice(None, False), slice(None, None, False),
                  slice(1, 6, 2), slice(1, 7, 2), slice(1, 6, 3),
                  slice(-1, 6, 2), slice(None, 6, 2))
        shapes = [_constant_shape(value) for value in values]
        self.assertEqual(len(set(shapes)), len(values))
        self.assertEqual(_constant_shape(slice(None, 6, -1)),
                         ('slice', ('NoneType', None), ('int', 6), ('int', -1)))

    def test_slice_constants_in_nested_code_and_collections_remain_distinct(self):
        from hepta.hia_loaded_source import _code_shape, _constant_shape
        code = compile('value = None', '<slice-constant>', 'exec')
        nested = code.replace(co_consts=(slice(None, 6, None),))
        unchanged = code.replace(co_consts=(slice(None, 6, None),))
        changed = code.replace(co_consts=(slice(None, 7, None),))
        wrap = lambda item: code.replace(co_consts=(item, (slice(1, None, 2),),
                                                   slice(frozenset({1, 2}), None, -1)))
        self.assertEqual(_code_shape(wrap(nested)), _code_shape(wrap(unchanged)))
        self.assertNotEqual(_code_shape(wrap(nested)), _code_shape(wrap(changed)))
        self.assertNotEqual(_constant_shape(slice(slice(None), None)),
                            _constant_shape(slice(slice(0, None), None)))

    def test_unreviewed_slice_components_do_not_invoke_equality_or_repr(self):
        from hepta.hia_loaded_source import _constant_shape, VerifiedSourceRejected
        class Forbidden:
            def __eq__(self, other):
                raise AssertionError('constant equality hook entered')
            def __repr__(self):
                raise AssertionError('constant repr hook entered')
        value = Forbidden()
        for candidate in (slice(value, None), slice(None, value), slice(None, None, value)):
            with self.assertRaisesRegex(VerifiedSourceRejected, 'unreviewed Python code constant'):
                _constant_shape(candidate)

    def test_ordinary_object_emission_does_not_run_source_proof_comparison(self):
        self.child('''
            sys.path.insert(0, REPOSITORY)
            import hepta.hia_loaded_source as binding
            with patch.object(binding, '_code_shape', side_effect=AssertionError('proof comparison on ordinary route')):
                from hepta.hia_program import verify_program
                from hepta.hia_program_native import emit_program_machine
                core = verify_program(json.loads((root / 'multiply_add.hepta').read_bytes()))
                assert emit_program_machine(core).object_bytes.startswith(b'\\x7fELF')
            assert not any(name.startswith('hepta.hia_verified_') for name in sys.modules)
            assert 'z3' not in sys.modules
        '''.replace('REPOSITORY', repr(str(ROOT))))

    def test_matching_timestamp_pyc_remains_accepted(self):
        self.child('''
            path = root / 'binding_probe/probe.py'
            py_compile.compile(str(path), doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            from binding_probe import probe
            assert probe.VALUE == 41 and probe.identity()
        ''', probe=True)

    def test_stale_timestamp_pyc_cannot_bind_changed_top_level_or_nested_code(self):
        for before, after in (('VALUE = 41', 'VALUE = 42'), ('return 41', 'return 42'),
                              ('return value[:6]', 'return value[:7]')):
            with self.subTest(changed=before):
                self.child('''
                    path = root / 'binding_probe/probe.py'
                    original = path.read_text()
                    before, after = CHANGE
                    old_stat = path.stat()
                    cached = Path(py_compile.compile(str(path), doraise=True,
                        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
                    path.write_text(original.replace(before, after))
                    os.utime(path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
                    header = cached.read_bytes()[:16]
                    assert struct.unpack('<III', header[4:]) == (0, int(old_stat.st_mtime), old_stat.st_size)
                    from binding_probe.hia_loaded_source import VerifiedSourceRejected
                    try:
                        importlib.import_module('binding_probe.probe').identity()
                    except VerifiedSourceRejected as exc:
                        assert 'stale bytecode' in str(exc)
                    else:
                        raise AssertionError('timestamp-valid stale code was attributed to current source')
                '''.replace('CHANGE', repr((before, after))), probe=True)

    def test_post_import_source_change_is_not_relabelled_as_current_execution(self):
        self.child('''
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            path = root / 'binding_probe/probe.py'
            path.write_text(path.read_text().replace('return 41', 'return 42'))
            assert probe.nested() == 41
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'source changed' in str(exc)
            else:
                raise AssertionError('old execution acquired the new source identity')
        ''', probe=True)

    def test_same_path_module_substitution_rejects_cached_original_alias(self):
        self.child('''
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            replacement = types.ModuleType(probe.__name__)
            replacement.__dict__.update(probe.__dict__)
            sys.modules[probe.__name__] = replacement
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'module object' in str(exc)
            else:
                raise AssertionError('replacement module authorized a cached original alias')
        ''', probe=True)

    def test_reload_taints_binding_even_when_source_bytes_are_unchanged(self):
        self.child('''
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            try:
                importlib.reload(probe)
            except VerifiedSourceRejected as exc:
                assert 'reload' in str(exc)
            else:
                raise AssertionError('reload preserved an old executing-module binding')
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'reloaded module' in str(exc)
            else:
                raise AssertionError('failed reload left an authoritative binding')
        ''', probe=True)

    def test_unregistered_legacy_module_cannot_acquire_a_binding_later(self):
        self.child('''
            path = root / 'binding_probe/probe.py'
            path.write_text(path.read_text().replace('register_loaded_module(__name__)', ''))
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'no executed-source binding' in str(exc)
            else:
                raise AssertionError('unregistered code received a source hash')
        ''', probe=True)

    def test_binding_implementation_itself_must_still_match_loaded_source(self):
        self.child('''
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            path = root / 'binding_probe/hia_loaded_source.py'
            path.write_text(path.read_text() + '\\n# changed binding implementation\\n')
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'source changed' in str(exc)
            else:
                raise AssertionError('source-binding code drift was ignored')
        ''', probe=True)

    def test_missing_registered_source_fails_closed(self):
        self.child('''
            from binding_probe import probe
            from binding_probe.hia_loaded_source import VerifiedSourceRejected
            (root / 'binding_probe/probe.py').unlink()
            try:
                probe.identity()
            except VerifiedSourceRejected as exc:
                assert 'unavailable' in str(exc)
            else:
                raise AssertionError('missing executed source was admitted')
        ''', probe=True)

    def test_actual_scalar_proof_rejects_checker_change_after_import(self):
        self._actual_changed_checker('scalar')

    def test_actual_simd_proof_rejects_checker_change_after_import(self):
        self._actual_changed_checker('simd')

    def _actual_changed_checker(self, kind):
        self.child('KIND = ' + repr(kind) + '\n' + PROOF + '''
module = simd if KIND == 'simd' else scalar
path = Path(module.__file__)
raw = path.read_text()
marker = '    checked = verify_program(document)' if KIND == 'scalar' else "    require(type(object_bytes) is bytes and type(final_bytes) is bytes,'immutable ELF bytes required')"
assert marker in raw
path.write_text(raw.replace(marker, '    raise RuntimeError("new source cannot complete a proof")\\n' + marker))
try:
    try:
        check(core, image.object_bytes, final, **options)
    except VerifiedSourceRejected as exc:
        assert 'source changed' in str(exc)
    else:
        raise AssertionError('a successful proof was attributed to unexecuted checker source')
finally:
    path.write_text(raw)
''')

    def test_actual_simd_consumer_rejects_replaced_dependency_module(self):
        self.child("KIND = 'simd'\n" + PROOF + '''
import hepta.hia_verified_simd_wide_x64 as decoder
replacement = types.ModuleType(decoder.__name__)
replacement.__dict__.update(decoder.__dict__)
sys.modules[decoder.__name__] = replacement
try:
    check(core, image.object_bytes, final)
except VerifiedSourceRejected as exc:
    assert 'module object' in str(exc)
else:
    raise AssertionError('replaced decoder module was admitted by a cached validator')
''')

    def test_actual_loader_rejects_source_drift_before_any_mapping(self):
        self.child("KIND = 'simd'\n" + PROOF + '''
path = Path(loader.__file__)
raw = path.read_text()
path.write_text(raw + '\\n# changed after import\\n')
try:
    with patch('os.memfd_create', side_effect=AssertionError('mapping before source admission')) as mapping:
        try:
            loader.load_verified_simd_kernel(core, image.object_bytes, final)
        except VerifiedSourceRejected as exc:
            assert 'source changed' in str(exc)
        else:
            raise AssertionError('stale loader source reached a native mapping')
        assert mapping.call_count == 0
finally:
    path.write_text(raw)
''')

    def test_actual_producer_rejects_source_drift_before_linkage(self):
        self.child('''
            from hepta.hia_verified_simd import simd_kernel_program
            from hepta.hia_loaded_source import VerifiedSourceRejected
            import hepta.hia_verified_kernel as builder
            core = simd_kernel_program('sum_u8')
            path = Path(builder.__file__)
            raw = path.read_text()
            path.write_text(raw + '\\n# changed producer after import\\n')
            try:
                with patch.object(builder, 'run_bounded', side_effect=AssertionError('link before source admission')) as linking:
                    try:
                        builder.build_verified_kernel(core, root / 'must-not-exist.so', simd_isa='sse2')
                    except VerifiedSourceRejected as exc:
                        assert 'source changed' in str(exc)
                    else:
                        raise AssertionError('stale producer source reached a linker')
                    assert linking.call_count == 0
                    assert not (root / 'must-not-exist.so').exists()
            finally:
                path.write_text(raw)
        ''')

    def test_actual_cpu_admission_rejects_drift_before_probe_subprocess(self):
        self.child('''
            import hepta.hia_verified_cpu as cpu
            from hepta.hia_loaded_source import VerifiedSourceRejected
            path = Path(cpu.__file__)
            raw = path.read_text()
            path.write_text(raw + '\\n# changed CPU admission after import\\n')
            try:
                with patch('hepta.clang_capture.run_bounded', side_effect=AssertionError('probe before source admission')) as running:
                    try:
                        cpu.probe_host_isa()
                    except VerifiedSourceRejected as exc:
                        assert 'source changed' in str(exc)
                    else:
                        raise AssertionError('stale CPU module reached probe execution')
                    assert running.call_count == 0
            finally:
                path.write_text(raw)
        ''')
