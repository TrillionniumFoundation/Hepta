import ast
from dataclasses import asdict, fields
import hashlib
import inspect
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hepta import modules, packages
from hepta.ast import HeptaError
from hepta._loader_ops import LegacyLoaderOps
from . import baseline


def outcome(loader, entry, **kwargs):
    try:
        graph = loader(entry, **kwargs)
        return ('graph', graph.report(), asdict(graph.program), graph.source_bytes, graph.unchanged())
    except HeptaError as error:
        return ('diagnostic', error.diagnostic.to_dict())
    except (OSError, ValueError, RuntimeError) as error:
        return ('exception', type(error).__name__, str(error))


class HookTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.main = self.root / 'main.hepta'
        self.main.write_text('fn main() -> i32 effects {} { return 1; }')

    def package(self, dependencies=False):
        text = '[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n'
        if dependencies:
            dep = self.root / 'dep'; dep.mkdir(exist_ok=True)
            (dep / 'lib.hepta').write_text('pub fn answer() -> i32 effects {} { return 3; }')
            (dep / 'hepta.toml').write_text('[package]\nname="dep"\nversion="1.0.0"\nkind="lib"\nsource_root="."\nentry="lib.hepta"\n')
            text += '[dependencies]\ndep={path="dep"}\n'
        (self.root / 'hepta.toml').write_text(text)

    def test_frozen_raw_oracle_matches_corpus_full_outcomes(self):
        from collections import Counter
        root = Path(__file__).resolve().parents[2]
        counts = Counter()
        paths = sorted((root / 'examples').rglob('*.hepta'))
        self.assertEqual(len(paths), 80)
        for path in paths:
            with self.subTest(path=path):
                old = outcome(baseline.modules.load_project, path)
                self.assertEqual(old, outcome(modules.load_project, path))
                counts[old[0] if old[0] == 'graph' else old[1]['code']] += 1
        self.assertEqual(counts, {'graph': 68, 'E_MODULE_READ': 12})

    def test_public_signatures_annotations_and_dataclass_shapes_match_baseline(self):
        for left, right in ((baseline.modules, modules), (baseline.packages, packages)):
            names = ('LoadedProject', 'load_project') if right is modules else ('Package', 'load_package', 'package_snapshot', 'verify_lock', 'write_lock')
            for name in names:
                self.assertEqual(str(inspect.signature(getattr(left, name))), str(inspect.signature(getattr(right, name))))
            cls = 'LoadedProject' if right is modules else 'Package'
            self.assertEqual([(f.name, f.type, f.init, f.repr, f.compare) for f in fields(getattr(left, cls))],
                             [(f.name, f.type, f.init, f.repr, f.compare) for f in fields(getattr(right, cls))])
        graph = modules.load_project(self.main)
        self.assertIs(type(graph), modules.LoadedProject)
        self.assertEqual(type(graph).__module__, 'hepta.modules')
        self.package()
        self.assertIs(type(modules.load_project(self.main).package), packages.Package)

    def test_module_parse_and_tokenize_replacements_are_exact(self):
        evidence = []
        for api in (baseline.modules, modules):
            calls = []
            parse, tokenize = api.parse, api.tokenize
            def p(*args, **kwargs):
                calls.append(('parse', args, kwargs)); return parse(*args, **kwargs)
            def t(*args, **kwargs):
                calls.append(('tokenize', args, kwargs)); return tokenize(*args, **kwargs)
            with patch.object(api, 'parse', p), patch.object(api, 'tokenize', t):
                result = outcome(api.load_project, self.main)
            evidence.append((calls, result))
        self.assertEqual(evidence[0], evidence[1])
        self.assertEqual([x[0] for x in evidence[0][0]], ['tokenize', 'parse'])

    def test_package_namespace_rebinding_json_toml_is_preserved(self):
        self.package(); packages.write_lock(self.root)
        for name in ('json', 'tomllib'):
            outcomes = []
            for api in (baseline.packages, packages):
                original = getattr(api, name)
                spy = Mock(wraps=original.loads)
                # Keep serialization helpers when the entire module is rebound.
                replacement = SimpleNamespace(loads=spy, dumps=getattr(original, 'dumps', None))
                with patch.object(api, name, replacement):
                    package = api.load_package(self.root)
                    result = api.verify_lock(package)
                outcomes.append((result, spy.call_args_list))
            self.assertEqual(outcomes[0], outcomes[1])
            self.assertGreater(len(outcomes[0][1]), 0)

    def test_json_callable_is_looked_up_before_lock_read(self):
        self.package(); packages.write_lock(self.root)
        for api in (baseline.packages, packages):
            original_read = Path.read_bytes
            loads = api.json.loads
            first, replacement = Mock(wraps=loads), Mock(side_effect=AssertionError('late lookup'))
            namespace = SimpleNamespace(loads=first, dumps=api.json.dumps)
            def read(path):
                if path.name == 'Hepta.lock': namespace.loads = replacement
                return original_read(path)
            with patch.object(api, 'json', namespace), patch.object(Path, 'read_bytes', read):
                api.verify_lock(api.load_package(self.root))
            self.assertEqual(first.call_count, 1)
            replacement.assert_not_called()

    def test_modules_alias_and_packages_recursive_hook_stay_distinct(self):
        self.package(dependencies=True)
        evidence = []
        for mod, pkg in ((baseline.modules, baseline.packages), (modules, packages)):
            calls = []
            root_hook, recursive_hook = mod.load_package, pkg.load_package
            def root(*args, **kwargs):
                calls.append(('module', len(args), sorted(kwargs))); return root_hook(*args, **kwargs)
            def recursive(*args, **kwargs):
                calls.append(('package', len(args), sorted(kwargs))); return recursive_hook(*args, **kwargs)
            with patch.object(mod, 'load_package', root), patch.object(pkg, 'load_package', recursive):
                result = outcome(mod.load_project, self.main)
            evidence.append((result, calls))
        self.assertEqual(evidence[0], evidence[1])
        self.assertIn(('package', 3, []), evidence[0][1])
        self.assertIn(('module', 1, []), evidence[0][1])

    def test_packages_patch_does_not_rebind_existing_modules_alias(self):
        self.package()
        for mod, pkg in ((baseline.modules, baseline.packages), (modules, packages)):
            with patch.object(pkg, 'load_package', side_effect=AssertionError('wrong namespace')):
                self.assertEqual(outcome(mod.load_project, self.main)[0], 'graph')

    def test_snapshot_and_verify_alias_hooks_match(self):
        self.package(); packages.write_lock(self.root)
        evidence = []
        for mod, pkg in ((baseline.modules, baseline.packages), (modules, packages)):
            events = []
            originals = {(scope, name): getattr(api, name) for scope, api in (('module', mod), ('package', pkg))
                         for name in ('package_snapshot', 'verify_lock')}
            from contextlib import ExitStack
            with ExitStack() as stack:
                for scope, api in (('module', mod), ('package', pkg)):
                    for name in ('package_snapshot', 'verify_lock'):
                        original = originals[(scope, name)]
                        def hook(*args, _scope=scope, _name=name, _original=original, **kwargs):
                            events.append((_scope, _name, len(args), sorted(kwargs)))
                            return _original(*args, **kwargs)
                        stack.enter_context(patch.object(api, name, hook))
                result = outcome(mod.load_project, self.main, locked=True)
            evidence.append((events, result))
        self.assertEqual(evidence[0], evidence[1])
        self.assertIn(('module', 'verify_lock', 1, []), evidence[0][0])
        self.assertIn(('package', 'package_snapshot', 1, []), evidence[0][0])

    def test_replacement_helper_exceptions_keep_original_boundary(self):
        self.package()
        for api in (baseline.modules, modules):
            with patch.object(api, 'load_package', side_effect=RuntimeError('hook')):
                self.assertEqual(outcome(api.load_project, self.main), ('exception', 'RuntimeError', 'hook'))

    def test_mock_wraps_is_not_unwrapped_or_compared_by_equality(self):
        self.package()
        for api in (baseline.modules, modules):
            original = api.load_package
            spy = Mock(wraps=original)
            with patch.object(api, 'load_package', spy):
                api.load_project(self.main)
            self.assertEqual(spy.call_count, 2)
            self.assertTrue(all(not c.kwargs for c in spy.call_args_list))

    def test_changed_helper_during_load_is_observed_next_time(self):
        self.package()
        for api in (baseline.modules, modules):
            original = api.load_package
            later = Mock(side_effect=RuntimeError('later hook'))
            def root(*args, **kwargs):
                result = original(*args, **kwargs)
                api.load_package = later
                return result
            with patch.object(api, 'load_package', root):
                self.assertEqual(outcome(api.load_project, self.main), ('exception', 'RuntimeError', 'later hook'))
            self.assertEqual(later.call_count, 1)

    def test_final_unchanged_method_hook_is_not_bypassed(self):
        for api in (baseline.modules, modules):
            with patch.object(api.LoadedProject, 'unchanged', return_value=False) as spy:
                result = outcome(api.load_project, self.main)
            self.assertEqual(result[0], 'diagnostic')
            self.assertEqual(result[1]['code'], 'E_MODULE_RACE')
            spy.assert_called_once_with(except_paths={})
            with patch.object(api.LoadedProject, 'unchanged', side_effect=RuntimeError('method hook')):
                self.assertEqual(outcome(api.load_project, self.main), ('exception', 'RuntimeError', 'method hook'))

    def test_fake_func_attribute_does_not_bypass_unchanged_hook(self):
        class Hook:
            __func__ = modules._LEGACY_UNCHANGED
            def __call__(self, **kwargs): return False
        with patch.object(modules.LoadedProject, 'unchanged', Hook()):
            result = outcome(modules.load_project, self.main)
        self.assertEqual(result[1]['code'], 'E_MODULE_RACE')

    def test_rebound_original_method_keeps_its_bound_receiver(self):
        graph = modules.load_project(self.main)
        graph.bindings = {'missing': 'different'}
        with patch.object(modules.LoadedProject, 'unchanged', graph.unchanged):
            result = outcome(modules.load_project, self.main)
        self.assertEqual(result[1]['code'], 'E_MODULE_RACE')

    def test_unmodified_private_path_shares_ops_without_public_graph_owner(self):
        self.package(dependencies=True); packages.write_lock(self.root)
        class Recorder(LegacyLoaderOps):
            def __init__(self): self.events = []
            def read(self, path, role):
                self.events.append((path.name, role)); return super().read(path, role)
        ops = Recorder()
        with patch.object(modules, '_LegacyLoaderOps', side_effect=AssertionError('new owner')), \
             patch.object(packages, '_LegacyLoaderOps', side_effect=AssertionError('new owner')):
            graph = modules._load_project(self.main, locked=True, ops=ops)
            packages._write_lock(self.root, ops=ops)
        self.assertNotIn('_ops', vars(graph))
        self.assertTrue(any(role == 'revalidation' for _, role in ops.events))
        self.assertGreater(sum(name == 'hepta.toml' for name, _ in ops.events), 4)
        self.assertTrue(graph.unchanged())

    def test_forwarding_hook_starts_fresh_legacy_owner_explicitly(self):
        self.package()
        original = modules.load_package
        with patch.object(modules, 'load_package', wraps=original), \
             patch.object(packages, '_LegacyLoaderOps', wraps=LegacyLoaderOps) as factory:
            modules._load_project(self.main, ops=LegacyLoaderOps())
        self.assertEqual(factory.call_count, 2)

    def test_patch_before_modules_import_is_not_treated_as_original(self):
        script = '''from unittest.mock import Mock
from hepta import packages
hook = Mock(side_effect=RuntimeError("preimport hook"))
packages.load_package = hook
from hepta import modules
try:
    modules.load_project(__import__('sys').argv[1])
except RuntimeError as error:
    assert str(error) == "preimport hook"
else:
    raise AssertionError("hook bypassed")
assert hook.call_count == 1
assert not hook.call_args.kwargs
'''
        self.package()
        result = subprocess.run([sys.executable, '-c', script, str(self.main)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_production_extraction_has_no_runtime_rewriting_or_new_dataclass_owner(self):
        root = Path(__file__).resolve().parents[2]
        for name in ('_loader_ops', 'packages', 'modules'):
            tree = ast.parse((root / 'hepta' / (name + '.py')).read_text())
            forbidden = [n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Name) and n.func.id in {'exec', 'eval', 'compile'}]
            self.assertEqual(forbidden, [])
            if name != '_loader_ops':
                direct = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                          and ((isinstance(n.func, ast.Attribute) and n.func.attr in {'read_bytes', 'rglob', 'loads'})
                               or (isinstance(n.func, ast.Name) and n.func.id in {'parse', 'tokenize'}))]
                self.assertEqual(direct, [])
        self.assertEqual(len(fields(modules.LoadedProject)), 11)

    def test_lock_fsync_replace_errors_keep_destination_and_cleanup_stage(self):
        self.package()
        for api in (baseline.packages, packages):
            for target in ('fsync', 'replace'):
                with self.subTest(api=api.__name__, target=target):
                    lock = self.root / 'Hepta.lock'; lock.write_bytes(b'old lock')
                    with patch.object(api.os, target, side_effect=OSError('injected ' + target)):
                        with self.assertRaisesRegex(OSError, 'injected ' + target):
                            api.write_lock(self.root)
                    self.assertEqual(lock.read_bytes(), b'old lock')
                    self.assertFalse(list(self.root.glob('.hepta-lock-*')))

    def test_final_lock_snapshot_callable_is_captured_before_nested_load(self):
        self.package()
        for api in (baseline.packages, packages):
            load, snapshot = api.load_package, api.package_snapshot
            events, count = [], [0]
            def first(package):
                events.append('first'); return snapshot(package)
            def replacement(package):
                raise AssertionError('outer snapshot resolved too late')
            def hook(*args):
                count[0] += 1
                if count[0] == 2: api.package_snapshot = replacement
                return load(*args)
            with patch.object(api, 'load_package', hook), patch.object(api, 'package_snapshot', first):
                api.write_lock(self.root)
            self.assertEqual(events, ['first', 'first'])

    def test_toml_callable_is_captured_before_decode(self):
        self.package()
        for api in (baseline.packages, packages):
            original_read, original_loads = Path.read_bytes, api.tomllib.loads
            calls = []
            def loads(source):
                calls.append('original'); return original_loads(source)
            namespace = SimpleNamespace(loads=loads)
            class Data(bytes):
                def decode(self, *args):
                    namespace.loads = Mock(side_effect=AssertionError('late decoder'))
                    return super().decode(*args)
            def read(path):
                data = original_read(path)
                return Data(data) if path.name == 'hepta.toml' else data
            with patch.object(api, 'tomllib', namespace), patch.object(Path, 'read_bytes', read):
                api.load_package(self.root)
            self.assertEqual(calls, ['original'])
            namespace.loads.assert_not_called()

    def test_unchanged_descriptor_is_evaluated_once(self):
        for api in (baseline.modules, modules):
            receivers = []
            class Descriptor:
                def __get__(self, instance, owner):
                    receivers.append(instance)
                    return lambda **kwargs: True
            with patch.object(api.LoadedProject, 'unchanged', Descriptor()):
                graph = api.load_project(self.main)
            self.assertEqual(len(receivers), 1)
            self.assertIs(receivers[0], graph)

    def test_pre_extraction_pickle_loads_as_current_public_types(self):
        import pickle
        self.package(dependencies=True)
        historical = baseline.modules.load_project(self.main)
        # Serialize the immutable historical shapes under their original public
        # names, then restore real production bindings before deserializing.
        with patch.object(baseline.modules.LoadedProject, '__module__', 'hepta.modules'), \
             patch.object(baseline.packages.Package, '__module__', 'hepta.packages'), \
             patch.object(modules, 'LoadedProject', baseline.modules.LoadedProject), \
             patch.object(packages, 'Package', baseline.packages.Package):
            data = pickle.dumps(historical)
        current = pickle.loads(data)
        self.assertIs(type(current), modules.LoadedProject)
        self.assertIs(type(current.package), packages.Package)
        self.assertTrue(all(type(p) is packages.Package for p in current.package.dependencies.values()))
        self.assertEqual(current.report(), historical.report())
        self.assertTrue(current.unchanged())
