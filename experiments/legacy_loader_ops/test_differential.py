import ast
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules as original_modules, packages as original_packages
from hepta.ast import HeptaError
from hepta.lexer import Lexer
from .candidate import modules, packages, source
from .ops import LegacyLoaderOps


class RecordingOps(LegacyLoaderOps):
    def __init__(self):
        self.events = []

    def read(self, path, role):
        self.events.append(('read', str(path), role))
        return super().read(path, role)

    def inventory(self, root):
        self.events.append(('inventory', str(root)))
        return super().inventory(root)

    def json(self, data, path):
        self.events.append(('json', str(path)))
        return super().json(data, path)

    def toml(self, data, path):
        self.events.append(('toml', str(path)))
        return super().toml(data, path)

    def tokenize(self, text, path):
        self.events.append(('tokenize', str(path)))
        return super().tokenize(text, path)

    def parse(self, text, path):
        self.events.append(('parse', str(path)))
        return super().parse(text, path)


def outcome(load, entry, **kwargs):
    try:
        project = load(entry, **kwargs)
        return {'report': project.report(), 'program': asdict(project.program),
                'bytes': project.source_bytes, 'unchanged': project.unchanged()}
    except HeptaError as error:
        return {'diagnostic': error.diagnostic.to_dict()}
    except (OSError, UnicodeError, ValueError) as error:
        return {'exception': type(error).__name__, 'message': str(error)}


class DifferentialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.main = self.put('main.hepta', 'fn main() -> i32 effects {} { return 1; }')

    def put(self, path, text):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def package(self):
        self.put('hepta.toml', '[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def parity(self, entry=None, **kwargs):
        entry = self.main if entry is None else entry
        left = outcome(original_modules.load_project, entry, **kwargs)
        right = outcome(modules.load_project, entry, **kwargs)
        self.assertEqual(left, right)
        return right

    def test_real_example_graphs(self):
        from experiments.loader_api.measure import CASES
        repo = Path(__file__).resolve().parents[2]
        for path in CASES:
            with self.subTest(path=path):
                self.assertIn('report', self.parity(repo / path))

    def test_complete_repository_example_corpus(self):
        from collections import Counter
        repo = Path(__file__).resolve().parents[2]
        paths = sorted((repo / 'examples').rglob('*.hepta'))
        self.assertEqual(len(paths), 80)
        outcomes = Counter()
        for path in paths:
            with self.subTest(path=str(path.relative_to(repo))):
                result = self.parity(path)
                outcomes['success' if 'report' in result else result['diagnostic']['code']] += 1
        # Missing imported/generated sources are visible negative cases, not
        # silently excluded examples or evidence that all examples compile.
        self.assertEqual(outcomes, {'success': 68, 'E_MODULE_READ': 12})

    def test_read_order_and_duplicate_lexing_are_unchanged(self):
        self.package()
        original = Path.read_bytes
        lex = Lexer.tokenize
        evidence = []
        for loader in (original_modules.load_project, modules.load_project):
            reads, lexing = [], []
            def read(path):
                reads.append(str(path)); return original(path)
            def tokenize(lexer):
                lexing.append(lexer.source); return lex(lexer)
            with patch.object(Path, 'read_bytes', read), patch.object(Lexer, 'tokenize', tokenize):
                result = outcome(loader, self.main)
            evidence.append((reads, lexing, result))
        self.assertEqual(evidence[0], evidence[1])
        self.assertEqual(len(evidence[0][1]), 2)

    def test_empty_and_unused_overrides(self):
        for overrides in (None, {}, {'unused.hepta': 'not valid syntax'}):
            with self.subTest(overrides=overrides):
                self.assertIn('report', self.parity(source_overrides=overrides))

    def test_used_and_alias_overrides_preserve_last_wins(self):
        for overrides in ({str(self.main): 'fn main() -> i32 effects {} { return 2; }'},
                          {str(self.main): 'bad', str(self.root / 'sub' / '..' / 'main.hepta'):
                           'fn main() -> i32 effects {} { return 3; }'}):
            result = self.parity(source_overrides=overrides)
            self.assertIn('report', result)
            self.assertFalse(result['unchanged'])

    def test_malformed_source(self):
        self.main.write_text('not valid syntax')
        self.assertIn('diagnostic', self.parity())

    def test_invalid_utf8_source(self):
        self.main.write_bytes(b'\xff')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_MODULE_READ')

    def test_missing_source(self):
        self.assertEqual(self.parity(self.root / 'absent.hepta')['diagnostic']['code'], 'E_MODULE_READ')

    def test_invalid_manifest(self):
        self.put('hepta.toml', '[package')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_PACKAGE_MANIFEST')

    def test_invalid_manifest_utf8(self):
        self.put('hepta.toml', '').write_bytes(b'\xff')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_PACKAGE_MANIFEST')

    def test_missing_and_invalid_and_stale_lock(self):
        self.package()
        self.assertEqual(self.parity(locked=True)['diagnostic']['code'], 'E_LOCK_MISSING')
        self.put('Hepta.lock', '{')
        self.assertEqual(self.parity(locked=True)['diagnostic']['code'], 'E_LOCK_INVALID')
        original_packages.write_lock(self.root)
        self.assertIn('report', self.parity(locked=True))
        self.main.write_text(self.main.read_text() + '\n')
        self.assertEqual(self.parity(locked=True)['diagnostic']['code'], 'E_LOCK_STALE')

    def test_locked_override_keeps_disk_lock_semantics(self):
        self.package(); original_packages.write_lock(self.root)
        result = self.parity(locked=True, source_overrides={str(self.main): 'fn main() -> i32 effects {} { return 3; }'})
        self.assertTrue(result['report']['locked'])
        self.assertFalse(result['unchanged'])

    def test_module_diamond_and_private_diagnostic(self):
        self.put('leaf.hepta', 'pub fn answer() -> i32 effects {} { return 2; }')
        self.put('left.hepta', 'import leaf; pub fn left() -> i32 effects {} { return leaf::answer(); }')
        self.put('right.hepta', 'import leaf; pub fn right() -> i32 effects {} { return leaf::answer(); }')
        self.main.write_text('import left; import right; fn main() -> i32 effects {} { return left::left(); }')
        self.assertEqual(len(self.parity()['report']['sources']), 4)
        self.put('leaf.hepta', 'fn answer() -> i32 effects {} { return 2; }')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_MODULE_PRIVATE')

    def test_module_cycle(self):
        self.main.write_text('import main as again; fn main() -> i32 effects {} { return 1; }')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_MODULE_CYCLE')

    def test_source_file_symlink_and_directory_alias(self):
        alias = self.root / 'alias.hepta'; alias.symlink_to(self.main)
        self.assertIn('report', self.parity(alias))
        self.package(); (self.root / 'directory_alias').symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_PACKAGE_SOURCE_LINK')

    def test_c_import_sidecar_identity_and_header_reads(self):
        text = '// hepta:c-import:v1\nfn main() -> i32 effects {} { return 1; }'
        self.main.write_text(text)
        header = self.put('api.h', '/* test */')
        metadata = {'schema': 'hepta.c-import.v1', 'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
                    'header': str(header), 'header_sha256': hashlib.sha256(header.read_bytes()).hexdigest(),
                    'target': 'test', 'host': {'system': platform.system(), 'machine': platform.machine(),
                                              'pointer_bits': struct.calcsize('P') * 8}}
        self.put('main.hepta.imports.json', json.dumps(metadata))
        self.assertIn('report', self.parity())
        header.write_text('changed')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_C_IMPORT_IDENTITY')

    def test_c_import_invalid_sidecar(self):
        self.main.write_text('// hepta:c-import:v1\nfn main()->Unit effects {} {}')
        self.put('main.hepta.imports.json', '{')
        self.assertEqual(self.parity()['diagnostic']['code'], 'E_C_IMPORT_MANIFEST')

    def test_ops_owner_is_preserved_through_revalidation_and_lock_write(self):
        self.package(); ops = RecordingOps()
        result = packages.write_lock(self.root, ops=ops)
        self.assertTrue(result['ok'])
        self.assertGreater(sum(e[0] == 'toml' for e in ops.events), 1)
        project = modules.load_project(self.main, locked=True, ops=ops)
        before = len(ops.events)
        self.assertIs(project._ops, ops)
        self.assertTrue(project.unchanged())
        self.assertGreater(len(ops.events), before)
        for operation in ('read', 'inventory', 'json', 'toml', 'tokenize', 'parse'):
            self.assertTrue(any(e[0] == operation for e in ops.events), operation)

    def test_budget_like_runtime_error_is_not_stale_or_parse_error(self):
        class Refusal(RuntimeError):
            pass
        class Deny(RecordingOps):
            def read(self, path, role):
                if getattr(self, 'deny', False):
                    raise Refusal('test admission failure')
                return super().read(path, role)
        ops = Deny(); project = modules.load_project(self.main, ops=ops)
        ops.deny = True
        with self.assertRaises(Refusal):
            project.unchanged()
        with self.assertRaises(Refusal):
            modules.load_project(self.main, ops=ops)

    def test_write_lock_matches_bytes_and_leaves_no_staging_files(self):
        self.package()
        left = original_packages.write_lock(self.root)
        data = (self.root / 'Hepta.lock').read_bytes()
        right = packages.write_lock(self.root)
        self.assertEqual(left, right)
        self.assertEqual(data, (self.root / 'Hepta.lock').read_bytes())
        self.assertEqual(list(self.root.glob('.hepta-lock-*')), [])

    def test_postload_mutation_and_except_paths(self):
        first = original_modules.load_project(self.main)
        second = modules.load_project(self.main)
        self.main.write_text('changed')
        self.assertEqual(first.unchanged(), second.unchanged())
        self.assertFalse(second.unchanged())
        self.assertEqual(first.unchanged(except_paths=[self.main]), second.unchanged(except_paths=[self.main]))

    def test_load_race_diagnostic_and_read_order_match(self):
        original_read = Path.read_bytes
        results = []
        initial = 'fn main() -> i32 effects {} { return 1; }'
        for loader in (original_modules.load_project, modules.load_project):
            self.main.write_text(initial)
            reads = []
            def read(path):
                reads.append(str(path))
                if path == self.main and reads.count(str(path)) == 2:
                    path.write_text(initial + '\n')
                return original_read(path)
            with patch.object(Path, 'read_bytes', read):
                result = outcome(loader, self.main)
            results.append((result, reads))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0]['diagnostic']['code'], 'E_MODULE_RACE')

    def test_lock_race_preserves_destination_and_removes_stage(self):
        self.package()
        original_read = Path.read_bytes
        results = []
        for writer in (original_packages.write_lock, packages.write_lock):
            self.main.write_text('fn main() -> i32 effects {} { return 1; }')
            lock = self.put('Hepta.lock', 'previous output\n')
            reads = []
            def read(path):
                reads.append(str(path))
                if path == self.main and reads.count(str(path)) == 2:
                    path.write_text('fn main() -> i32 effects {} { return 2; }')
                return original_read(path)
            with patch.object(Path, 'read_bytes', read), self.assertRaises(HeptaError) as error:
                writer(self.root)
            self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_RACE')
            self.assertEqual(lock.read_text(), 'previous output\n')
            self.assertEqual(list(self.root.glob('.hepta-lock-*')), [])
            results.append((error.exception.diagnostic.to_dict(), reads))
        self.assertEqual(results[0], results[1])

    def test_falsey_ops_are_not_replaced_by_default(self):
        class Falsey(RecordingOps):
            def __bool__(self):
                return False
        ops = Falsey()
        project = modules.load_project(self.main, ops=ops)
        self.assertIs(project._ops, ops)
        self.assertTrue(ops.events)

    def test_source_pin_refuses_drift_instead_of_fuzzy_rewrite(self):
        original_read = Path.read_bytes
        def changed(path):
            data = original_read(path)
            return data + b'\n' if path.name == 'modules.py' else data
        with patch.object(Path, 'read_bytes', changed), self.assertRaisesRegex(RuntimeError, 'upstream drift'):
            source('modules')

    def test_recipe_has_no_direct_domain_reads_or_parsers_left(self):
        for name in ('modules', 'packages'):
            candidate = source(name)
            self.assertNotIn('.read_bytes(', candidate)
            self.assertNotIn('.rglob(', candidate)
            self.assertNotIn('json.loads(', candidate)
            self.assertNotIn('tomllib.loads(', candidate)
            direct_parsers = [node.func.id for node in ast.walk(ast.parse(candidate))
                              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                              and node.func.id in {'parse', 'tokenize'}]
            self.assertEqual(direct_parsers, [])
        self.assertIsNot(original_modules, modules)
        self.assertEqual(original_modules.__name__, 'hepta.modules')


if __name__ == '__main__':
    unittest.main()
