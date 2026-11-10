"""Cross-component grammar and fail-closed custody of the actual native bundle.

These integration controls compile genuine successors and component images.
They do not manufacture a passing cold qualification or activate production.
"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import importlib
import itertools
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.parser import Parser, parse
from hepta import hia_source_frontend_native as frontend
from hepta.hia_source_frontend_native import (
    INDIVIDUAL_SELECTORS, MANIFESTS, SCHEMA, installed_source_frontend, read_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SELECTORS = {name: '' for name in (*INDIVIDUAL_SELECTORS, 'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST')}
REFERENCE_METHODS = ('_reference_path', '_reference_type_params', '_reference_function_type_params',
                     '_reference_effects', '_reference_resources', '_reference_type', '_reference_expr', '_prefix')

CASES = (
    "module alpha::beta; import pkg::lib as p; struct Pair<'a,T>{x:read 'a T,n:[u8;0x10]} "
    "fn f<'a,T:Copy>(x:read 'a T,y:u64)->read 'a T from x effects{io,unsafe} "
    "resources{fuel=4096;ratio=1.25;enabled=true;} {let a:X<Y<u8>>=p::make::<X<Y<u8>>>(y >> 1); return x;}",
    'fn f(x:u64)->u64 effects{} {let a:X<u8>=x; let b:X<Y<u8>>=x; return x>=0;}',
    'fn f(x:u64)->u64 effects{} {let a=x as X<Y<u8>> >> 2; return a>=0;}',
    'import p; fn f(x:u64)->u64 effects{} {let a=p::f::<X<Y<u8>>>(x); return a;}',
    'enum E<T>{V(T),None} fn f(e:E<u8>)->u8 effects{} {match e {E::V(v)=>{return v;},E::None=>{return 0;}}}',
    'struct Pair<T:Owned,T:Copy>{x:T} fn f<T:Owned,T:Copy>(x:T)->T effects{} {return x;}',
    'fn f(x:u64)->u64 effects{} {if x>=1 {let a=[x,2][0];} while x<2 {x=x+1;} for i in 0..3 {x=x+i;} return x;}',
    '/* π🙂 */\r\nmodule demo; import p; fn f<T>(x:T)->T effects{io,unsafe,} resources{n=0xff;r=5e-324;} {return p::f::<T>(x);}',
    'fn f<T>=x',
    'fn f<T>>() -> u8 effects{} {return 0;}',
    'enum E<T>=x',
    'struct Pair<T:Owned>{x:T}',
    "fn f<'a,T:Owned,'a,T:Copy>()->u8 effects{io,io} resources{bad=-1;} {return 1;}",
    'fn f<T:>()->u8 effects{} {return 0;}',
    'module a::; import b; fn f()->u8 effects{} {return 0;}',
    'fn f()->u8 effects{} resources{a=1;a=2;bad=-1;} {return 1;}',
    'fn f(x:u8)->u8 effects{} {x as X<u8>=0; return x;}',
    'fn f(x:u8)->u8 effects{} {return missing::f::<X<X<u8>>>(x);}',
    'fn f()->u8 effects{io,io} resources{a=-1;} {return 0;} #',
    'fn f(x:u8)->u8 effects{} {return ' + '(' * 94 + 'x' + ')' * 94 + ';}',
    'fn f(x:u8)->u8 effects{} {return x as ' + '[' * 94 + 'u8' + ']' * 94 + ';}',
)


def outcome(source, selectors=None, *, forbid_reference=False, path='integration.hepta'):
    with ExitStack() as stack:
        stack.enter_context(patch.dict('os.environ', {**SELECTORS, **(selectors or {})}))
        if forbid_reference:
            for method in REFERENCE_METHODS:
                stack.enter_context(patch.object(Parser, method, side_effect=AssertionError('foreign ' + method)))
            stack.enter_context(patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')))
        try:
            parser = Parser(source, path)
            result = parser.parse()
            return ('tree', result, parser.position, parser.tokens, parser.current,
                    parser.previous, parser.qualified_expressions, parser.depth)
        except HeptaError as error:
            return ('error', error.diagnostic.to_dict())


class SourceFrontendCustodyTests(unittest.TestCase):
    """Tiny opaque images exercise custody only; no native code is executed.

    These fixtures are never compiler qualifications or build evidence. The
    real native compilation and grammar observations remain in the next class.
    """
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-frontend-custody-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.bundle = self.folder / 'bundle'
        self.bundle.mkdir()
        self.image = bytes.fromhex('31c0c3')
        self.image_sha = sha256(self.image).hexdigest()
        projection = {
            'names/manifest.json': 'names', 'names/source-lexer/manifest.json': 'lexer',
            'clauses/manifest.json': 'clauses', 'clauses/source-lexer/manifest.json': 'lexer',
            'expressions/manifest.json': 'expressions', 'expressions/source-types/manifest.json': 'types',
            'expressions/source-types/source-lexer/manifest.json': 'lexer',
        }
        for relative, part in projection.items():
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            module = importlib.import_module('hepta.hia_source_' + part + '_native')
            (path.parent / 'image.bin').write_bytes(self.image)
            path.write_text(json.dumps({'schema': module.SCHEMA,
                'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
                'image_path': 'image.bin', 'image_sha256': self.image_sha,
                'compiler_sha256': '1' * 64}))
        self.manifest = self.bundle / 'manifest.json'
        self.bind()

    def bind(self):
        self.manifest.write_text(json.dumps({'schema': SCHEMA, 'compiler_sha256': '1' * 64,
            'manifests': {name: sha256((self.bundle / name).read_bytes()).hexdigest() for name in MANIFESTS}}))

    def test_absolute_image_path_outside_bundle_is_refused(self):
        external = self.folder / 'external.bin'
        external.write_bytes(self.image)
        child = self.bundle / 'names/manifest.json'
        value = json.loads(child.read_bytes())
        value['image_path'] = str(external)
        child.write_text(json.dumps(value))
        self.bind()
        for operation in (read_manifest, installed_source_frontend):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(ValueError, 'image escapes its bundle'):
                    operation(self.manifest)

    def test_image_symlink_outside_bundle_is_refused(self):
        external = self.folder / 'external.bin'
        external.write_bytes(self.image)
        target = self.bundle / 'names/image.bin'
        target.unlink()
        target.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'image escapes its bundle'):
            installed_source_frontend(self.manifest)

    def test_image_reference_inside_bundle_may_cross_directories(self):
        shared = self.bundle / 'shared/image.bin'
        shared.parent.mkdir()
        shared.write_bytes(self.image)
        child = self.bundle / 'names/manifest.json'
        value = json.loads(child.read_bytes())
        value['image_path'] = '../shared/image.bin'
        child.write_text(json.dumps(value))
        self.bind()
        selected, manifest = read_manifest(self.manifest)
        self.assertEqual(selected, self.manifest)
        self.assertEqual(manifest['schema'], SCHEMA)
        self.assertTrue(all(image.image_sha256 == self.image_sha
                            for image in installed_source_frontend(self.manifest)))

    def test_manifest_and_image_aba_cannot_replace_any_captured_component(self):
        original_load = frontend._load_snapshot
        alternate = bytes.fromhex('b801000000c3')
        for relative in MANIFESTS:
            with self.subTest(component=relative):
                child = self.bundle / relative
                image_path = child.parent / 'image.bin'
                original = child.read_bytes()
                loaded = []

                def replace_after_snapshot(snapshot):
                    changed = json.loads(original)
                    changed['compiler_sha256'] = '2' * 64
                    changed['image_sha256'] = sha256(alternate).hexdigest()
                    child.write_text(json.dumps(changed))
                    image_path.write_bytes(alternate)
                    try:
                        # Any reopen here would reintroduce a lookup between
                        # authenticated admission and executable mapping.
                        with patch.object(Path, 'open', side_effect=AssertionError('admitted input reopened')):
                            images = original_load(snapshot)
                        self.assertEqual(set(images), set(MANIFESTS))
                        self.assertTrue(all(image.image_sha256 == self.image_sha for image in images.values()))
                        loaded.append(images)
                        return images
                    finally:
                        child.write_bytes(original)
                        image_path.write_bytes(self.image)

                with patch.object(frontend, '_load_snapshot', side_effect=replace_after_snapshot):
                    installed_source_frontend(self.manifest)
                self.assertEqual(len(loaded), 1)
                self.assertEqual(child.read_bytes(), original)
                read_manifest(self.manifest)

    def builder_inputs(self):
        # Deliberately non-executable, non-qualification bytes. Only rejected
        # calls below may use these fixtures; no passing evidence is emitted.
        compiler = self.folder / 'synthetic-compiler.bin'
        compiler.write_bytes(b'synthetic rejection-only compiler\n')
        cold = self.folder / 'synthetic-cold.json'
        cold.write_bytes(b'{"status":"SYNTHETIC_REJECTION_ONLY"}\n')
        checks = ('export_manifest_matches_qualification', 'isolated_python_without_site',
            'nested_full_qualification_pass', 'nested_process_exit_zero',
            'no_ancestor_git_identity', 'no_bytecode_cache_created',
            'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
            'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
            'source_export_hashes_preserved')
        # Mock only the earlier admission gate in memory to reach the later
        # receipt boundary. This object is never saved or cited as evidence.
        gate = {'schema': 'hepta.hia.selfhost-cold-replay.v1',
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'checks': dict.fromkeys(checks, True),
            'generation_sha256': [sha256(compiler.read_bytes()).hexdigest()] * 3}
        return compiler, cold, gate

    def test_compile_receipt_accepts_only_exact_captured_identities(self):
        from tools.build_hia_source_lexer import _checked_compile_receipt
        compiler, source, image = b'compiler fixture', b'source fixture', b'image fixture'
        expected = {'compiler_sha256': sha256(compiler).hexdigest(),
                    'source_sha256': sha256(source).hexdigest(),
                    'image_sha256': sha256(image).hexdigest()}
        receipt = {'artifact_sha256': expected['compiler_sha256'],
                   'input_sha256': expected['source_sha256'],
                   'source_sha256': expected['source_sha256'],
                   'produced_sha256': expected['image_sha256']}
        self.assertEqual(_checked_compile_receipt(receipt, compiler, source, image), expected)
        for changed in (None, {}, {**receipt, 'source_sha256': '0' * 64}):
            with self.subTest(receipt=changed):
                with self.assertRaisesRegex(ValueError, 'receipt identity mismatch'):
                    _checked_compile_receipt(changed, compiler, source, image)

    def test_every_builder_refuses_compiler_aba_and_wrong_source_or_image_receipts(self):
        compiler, cold, gate = self.builder_inputs()
        compiler_bytes = compiler.read_bytes()
        root = self.folder / 'synthetic-source-root'
        (root / 'examples/hia_bootstrap').mkdir(parents=True)
        variants = ('compiler-aba', 'input-hash', 'source-hash', 'image-drift', 'missing-produced-hash')
        for part in ('lexer', 'types', 'names', 'clauses', 'expressions'):
            module = importlib.import_module('tools.build_hia_source_' + part)
            source_path = root / ('examples/hia_bootstrap/source_' + part + '.hiaasm')
            source_path.write_bytes(b'synthetic rejection-only source\n')
            for variant in variants:
                with self.subTest(component=part, change=variant):
                    destination = self.folder / ('rejected-' + part + '-' + variant)

                    def reject_stage(output, label, selected_compiler, source):
                        image_path = output / 'synthetic-refusal-image.bin'
                        image = b'synthetic rejection-only output\n'
                        image_path.write_bytes(image)
                        receipt = {'artifact_sha256': sha256(compiler_bytes).hexdigest(),
                            'input_sha256': sha256(source).hexdigest(),
                            'produced_sha256': sha256(image).hexdigest()}
                        if variant == 'compiler-aba':
                            selected_compiler.write_bytes(b'temporary different compiler\n')
                            try:
                                receipt['artifact_sha256'] = sha256(selected_compiler.read_bytes()).hexdigest()
                            finally:
                                selected_compiler.write_bytes(compiler_bytes)
                        elif variant == 'input-hash':
                            receipt['input_sha256'] = sha256(source + b'changed').hexdigest()
                        elif variant == 'source-hash':
                            receipt['source_sha256'] = sha256(source + b'changed').hexdigest()
                        elif variant == 'image-drift':
                            image_path.write_bytes(image + b'changed')
                        else:
                            del receipt['produced_sha256']
                        return image_path, receipt

                    with ExitStack() as stack:
                        stack.enter_context(patch.object(module, 'ROOT', root))
                        stack.enter_context(patch('tools.build_hia_source_lexer.json.loads', return_value=gate))
                        if part == 'names':
                            stack.enter_context(patch('hepta.hia_source_names_native.SOURCE', source_path))
                        if part != 'lexer':
                            child = 'types' if part == 'expressions' else 'lexer'
                            stack.enter_context(patch('tools.build_hia_source_' + child + '.build',
                                side_effect=lambda output, *args: output / 'manifest.json'))
                        compile_mock = stack.enter_context(patch('tools.qualify_hia_selfhost.compile_stage',
                            side_effect=reject_stage))
                        with self.assertRaisesRegex(ValueError, 'receipt identity mismatch'):
                            module.build(destination, compiler, cold)
                        compile_mock.assert_called_once()
                    self.assertEqual(compiler.read_bytes(), compiler_bytes)
                    self.assertFalse((destination / 'manifest.json').exists())
                    self.assertFalse((destination / 'build.json').exists())

    def test_lexer_builder_refuses_cold_report_drift_before_publication(self):
        from tools import build_hia_source_lexer as module
        compiler, cold, gate = self.builder_inputs()
        destination = self.folder / 'rejected-cold-drift'

        def drift_after_compile(output, label, selected_compiler, source):
            image_path = output / 'synthetic-refusal-image.bin'
            image = b'synthetic rejection-only output\n'
            image_path.write_bytes(image)
            cold.write_bytes(b'{"status":"CHANGED_SYNTHETIC_REJECTION_ONLY"}\n')
            return image_path, {'artifact_sha256': sha256(selected_compiler.read_bytes()).hexdigest(),
                'input_sha256': sha256(source).hexdigest(), 'produced_sha256': sha256(image).hexdigest()}

        with patch.object(module.json, 'loads', return_value=gate), patch(
                'tools.qualify_hia_selfhost.compile_stage', side_effect=drift_after_compile):
            with self.assertRaisesRegex(ValueError, 'build inputs changed'):
                module.build(destination, compiler, cold)
        self.assertFalse((destination / 'manifest.json').exists())
        self.assertFalse((destination / 'build.json').exists())


class SourceFrontendNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # All baseline observations precede B0; the cross-component oracle is
        # the independent existing parser, never the candidate's own arena.
        cls.expected = [outcome(source) for source in CASES]
        corpus = sorted(path for directory in ('examples', 'tests')
                        for path in (ROOT / directory).rglob('*.hepta') if path.is_file())
        if not corpus:
            raise AssertionError('the repository source corpus must not be empty')
        cls.corpus = []
        for path in corpus:
            name, source = path.relative_to(ROOT).as_posix(), path.read_text()
            cls.corpus.append((name, source, outcome(source, path=name)))
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-frontend-integration-')
        cls.folder = Path(cls.temporary.name)
        cls.bundle = cls.folder / 'bundle'
        cls.bundle.mkdir()
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        seed, _ = build_seed(cls.folder)
        compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler_source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler_source)
        assert first.read_bytes() == second.read_bytes()
        cls.compiler = second
        cls.compiler_sha = sha256(second.read_bytes()).hexdigest()
        modules, images = {}, {}
        cls.receipts = {}
        for part in ('lexer', 'types', 'names', 'clauses', 'expressions'):
            module = importlib.import_module('hepta.hia_source_' + part + '_native')
            modules[part] = module
            image, receipt = compile_stage(cls.folder, part, second, module.SOURCE.read_bytes())
            images[part] = image
            cls.receipts[part] = receipt
        projection = {
            'names/manifest.json': 'names', 'names/source-lexer/manifest.json': 'lexer',
            'clauses/manifest.json': 'clauses', 'clauses/source-lexer/manifest.json': 'lexer',
            'expressions/manifest.json': 'expressions', 'expressions/source-types/manifest.json': 'types',
            'expressions/source-types/source-lexer/manifest.json': 'lexer',
        }
        for relative, part in projection.items():
            path = cls.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw_image = images[part].read_bytes()
            (path.parent / 'image.bin').write_bytes(raw_image)
            path.write_text(json.dumps({'schema': modules[part].SCHEMA,
                'source_sha256': sha256(modules[part].SOURCE.read_bytes()).hexdigest(),
                'image_path': 'image.bin', 'image_sha256': sha256(raw_image).hexdigest(),
                'compiler_sha256': cls.compiler_sha}, sort_keys=True) + '\n')
        cls.manifest = cls.bundle / 'manifest.json'
        cls.write_root(cls.bundle)
        cls.individual = {
            'HEPTA_HIA_SOURCE_NAMES_MANIFEST': str(cls.bundle / 'names/manifest.json'),
            'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': str(cls.bundle / 'clauses/manifest.json'),
            'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST': str(cls.bundle / 'expressions/manifest.json'),
            'HEPTA_HIA_SOURCE_TYPES_MANIFEST': str(cls.bundle / 'expressions/source-types/manifest.json'),
        }

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def write_root(cls, folder):
        value = {'schema': SCHEMA, 'compiler_sha256': cls.compiler_sha,
                 'manifests': {relative: sha256((folder / relative).read_bytes()).hexdigest() for relative in MANIFESTS}}
        (folder / 'manifest.json').write_text(json.dumps(value, sort_keys=True) + '\n')

    def copy_bundle(self, name):
        destination = self.folder / name
        shutil.copytree(self.bundle, destination)
        return destination

    def rejected_parser(self, folder, expected=ValueError):
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST': str(folder / 'manifest.json')}):
            with self.assertRaises(expected):
                Parser('fn f()->u8 effects{} {return 0;}')

    def test_all_sixteen_individual_grammar_combinations_preserve_cross_boundaries(self):
        names = tuple(self.individual)
        observations = 0
        for active in itertools.product((False, True), repeat=len(names)):
            selection = {name: self.individual[name] for name, used in zip(names, active) if used}
            for source, expected in zip(CASES, self.expected):
                with self.subTest(active=active, source=source[:80]):
                    self.assertEqual(outcome(source, selection), expected)
                observations += 1
        print(f'HIA frontend mixed selectors: {observations} exact Parser observations', flush=True)

    def test_single_bundle_actual_parser_rejects_all_reference_grammar(self):
        selected = {'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST': str(self.manifest)}
        for source, expected in zip(CASES, self.expected):
            with self.subTest(source=source[:100]):
                self.assertEqual(outcome(source, selected, forbid_reference=True), expected)
        names, clauses, expressions, types, lexer = installed_source_frontend(str(self.manifest))
        self.assertEqual(len({obj.image_sha256 for obj in (names, clauses, expressions, types, lexer)}), 5)
        self.assertTrue(all(not receipt['forbidden_compiler_modules_loaded'] for receipt in self.receipts.values()))

    def test_single_bundle_matches_complete_repository_source_corpus(self):
        selected = {'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST': str(self.manifest)}
        self.assertTrue(self.corpus)
        for name, source, expected in self.corpus:
            with self.subTest(path=name):
                self.assertEqual(outcome(source, selected, forbid_reference=True, path=name), expected)
        print(f'HIA frontend unified bundle: {len(self.corpus)} exact repository Parser observations', flush=True)

    def test_every_explicit_selector_must_be_loaded_even_when_another_is_present(self):
        for selector in self.individual:
            selected = {**self.individual, selector: str(self.folder / ('missing-' + selector + '.json'))}
            with self.subTest(selector=selector), patch.dict('os.environ', {**SELECTORS, **selected}):
                with self.assertRaises(FileNotFoundError):
                    Parser('fn f()->u8 effects{} {return 0;}')
        for grammar in self.individual:
            selected = {grammar: self.individual[grammar], 'HEPTA_HIA_SOURCE_LEXER_MANIFEST': str(self.folder / 'absent-lexer.json')}
            with self.subTest(grammar=grammar), patch.dict('os.environ', {**SELECTORS, **selected}):
                with self.assertRaises(FileNotFoundError):
                    Parser('fn f()->u8 effects{} {return 0;}')

    def test_bundle_refuses_mixed_individual_selection_before_any_grammar_call(self):
        for name in INDIVIDUAL_SELECTORS:
            with self.subTest(selector=name), patch.dict('os.environ', {**SELECTORS,
                    'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST': str(self.manifest), name: 'selected-but-conflicting.json'}):
                with self.assertRaises(ValueError):
                    Parser('fn f()->u8 effects{} {return 0;}')

    def test_partial_missing_corrupt_and_duplicate_field_bundle_fail_closed(self):
        partial = self.copy_bundle('partial')
        value = json.loads((partial / 'manifest.json').read_text())
        del value['manifests'][MANIFESTS[-1]]
        (partial / 'manifest.json').write_text(json.dumps(value))
        self.rejected_parser(partial)
        missing = self.copy_bundle('missing')
        (missing / MANIFESTS[2]).unlink()
        self.rejected_parser(missing, FileNotFoundError)
        drift = self.copy_bundle('drift')
        (drift / MANIFESTS[0]).write_text((drift / MANIFESTS[0]).read_text() + ' ')
        self.rejected_parser(drift)
        malformed = self.copy_bundle('malformed')
        (malformed / MANIFESTS[0]).write_text('{"schema":1,"schema":2}')
        self.write_root(malformed)
        self.rejected_parser(malformed)
        root_duplicate = self.copy_bundle('root-duplicate')
        raw = (root_duplicate / 'manifest.json').read_text()
        (root_duplicate / 'manifest.json').write_text('{"schema":"duplicate",' + raw[1:])
        self.rejected_parser(root_duplicate)

    def test_byte_consistent_but_mixed_compiler_or_lexer_identity_is_rejected(self):
        mixed = self.copy_bundle('mixed-compiler')
        child = mixed / 'clauses/manifest.json'
        value = json.loads(child.read_text())
        value['compiler_sha256'] = '0' * 64
        child.write_text(json.dumps(value))
        self.write_root(mixed)
        self.rejected_parser(mixed)
        lexer = self.copy_bundle('mixed-lexer')
        child = lexer / 'clauses/source-lexer/manifest.json'
        value = json.loads(child.read_text())
        value['source_sha256'] = '0' * 64
        child.write_text(json.dumps(value))
        self.write_root(lexer)
        self.rejected_parser(lexer)

    def test_new_path_image_corruption_missing_image_and_escaping_component_refused(self):
        corrupt = self.copy_bundle('corrupt-image')
        target = corrupt / 'names/image.bin'
        image = bytearray(target.read_bytes())
        image[0] ^= 1
        target.write_bytes(image)
        self.rejected_parser(corrupt)
        missing = self.copy_bundle('missing-image')
        (missing / 'expressions/source-types/image.bin').unlink()
        self.rejected_parser(missing, FileNotFoundError)
        escape = self.copy_bundle('escaping-component')
        target = escape / MANIFESTS[0]
        raw = target.read_bytes()
        external = self.folder / 'external-manifest.json'
        external.write_bytes(raw)
        target.unlink()
        target.symlink_to(external)
        self.rejected_parser(escape)

    def test_failed_cold_build_never_publishes_final_bundle(self):
        from tools.build_hia_source_frontend import build
        rejected = self.folder / 'failed-cold.json'
        rejected.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'FAIL', 'returncode': 1}))
        destination = self.folder / 'failed-build'
        with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compilation after failed cold evidence')):
            with self.assertRaises(ValueError):
                build(destination, self.compiler, rejected)
        self.assertFalse((destination / 'manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
