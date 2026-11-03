"""Compatibility evidence and explicit counterexamples, not production promotion."""
import copy
from dataclasses import asdict, fields, replace
import inspect
import json
from pathlib import Path
import pickle
import tempfile
import unittest

from hepta import modules, packages, pipeline
from hepta.ast import HeptaError
from experiments.legacy_loader_ops import candidate
from .inventory import ROOT, inspect_source, inventory


class ConsumerContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text('fn main() -> i32 effects {} { return 1; }')

    def package(self):
        (self.root / 'hepta.toml').write_text(
            '[package]\nname="audit"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def pair(self, **kwargs):
        return modules.load_project(self.entry, **kwargs), candidate.modules.load_project(self.entry, **kwargs)

    def test_inventory_is_reproducible_and_pins_all_production_sources(self):
        saved = json.loads((Path(__file__).with_name('inventory.json')).read_text())
        self.assertEqual(saved, inventory())
        self.assertEqual(len(saved['source_sha256']), 179)
        self.assertEqual(len(saved['references']), 26)
        self.assertEqual(sum(map(len, saved['references'].values())), 202)

    def test_inventory_tracks_import_aliases_and_nested_project_attributes(self):
        rows = inspect_source('from hepta.modules import load_project as lp\nx = lp(p)\nx.project.unchanged()\n')
        self.assertIn({'line': 2, 'kind': 'call', 'expression': 'lp'}, rows)
        self.assertIn({'line': 3, 'kind': 'surface', 'expression': 'x.project.unchanged'}, rows)

    def test_existing_public_function_signatures_remain_unchanged(self):
        expected = {
            modules.load_project: '(entry, *, locked=False, source_overrides=None)',
            packages.load_package: '(root, _stack=None, _cache=None)',
            packages.package_snapshot: '(package)', packages.verify_lock: '(package)',
            packages.write_lock: '(root)',
            modules.LoadedProject.unchanged: '(self, *, except_paths=())',
            modules.LoadedProject.report: '(self)',
        }
        for function, signature in expected.items():
            actual = inspect.signature(function)
            # Parameter annotations are not part of this formatting assertion.
            actual = actual.replace(return_annotation=inspect.Signature.empty,
                                    parameters=[p.replace(annotation=inspect.Parameter.empty)
                                                for p in actual.parameters.values()])
            self.assertEqual(str(actual), signature)

    def test_legacy_dataclass_fields_constructor_and_match_args_are_eleven(self):
        names = ('program', 'entry', 'sources', 'source_bytes', 'identity', 'modules',
                 'package', 'package_state', 'locked', 'bindings', 'c_imports')
        self.assertEqual(tuple(f.name for f in fields(modules.LoadedProject)), names)
        self.assertEqual(tuple(inspect.signature(modules.LoadedProject).parameters), names)
        self.assertEqual(modules.LoadedProject.__match_args__, names)
        graph = modules.load_project(self.entry)
        self.assertEqual(set(vars(graph)), set(names))
        rebuilt = modules.LoadedProject(*(getattr(graph, name) for name in names))
        self.assertEqual(rebuilt, graph)

    def test_candidate_is_not_a_dataclass_or_object_identity_drop_in(self):
        old, new = self.pair()
        self.assertIsNot(type(old), type(new))
        self.assertFalse(isinstance(new, modules.LoadedProject))
        self.assertNotEqual(old, new)
        self.assertEqual(set(asdict(new)) - set(asdict(old)), {'_ops'})
        self.assertEqual(candidate.modules.LoadedProject.__match_args__[-1], '_ops')
        self.assertNotEqual(inspect.signature(modules.load_project), inspect.signature(candidate.modules.load_project))

    def test_pickle_deepcopy_replace_keep_the_legacy_class(self):
        old, new = self.pair()
        for value in (pickle.loads(pickle.dumps(old)), copy.deepcopy(old), replace(old)):
            self.assertIs(type(value), modules.LoadedProject)
            self.assertEqual(value, old)
            self.assertTrue(value.unchanged())
        restored = pickle.loads(pickle.dumps(new))
        self.assertIs(type(restored), candidate.modules.LoadedProject)
        self.assertIsNot(type(restored), modules.LoadedProject)
        # Candidate pickle needs its experiment namespace; no cross-version promise.
        self.assertIn(b'experiments.legacy_loader_ops.modules', pickle.dumps(new))

    def test_frontend_supplied_project_consumes_equivalent_reports_and_programs(self):
        self.package()
        for graph in self.pair():
            result = pipeline.analyze(self.entry.read_text(), str(self.entry),
                                      loaded_project=graph, native=False)
            self.assertTrue(result.report['ok'])
            self.assertIs(result.project, graph)
            if graph.__class__ is modules.LoadedProject:
                expected = (result.report, asdict(result.program), result.rust)
            else:
                self.assertEqual((result.report, asdict(result.program), result.rust), expected)

    def test_frontend_module_override_preserves_disk_revalidation_distinction(self):
        (self.root / 'dep.hepta').write_text('pub fn value() -> i32 effects {} { return 4; }')
        text = 'import dep; fn main() -> i32 effects {} { return dep::value(); }'
        result = pipeline.analyze(text, str(self.entry), native=False)
        self.assertTrue(result.report['ok'])
        self.assertFalse(result.project.unchanged())
        self.assertTrue(result.project.unchanged(except_paths=[self.entry]))
        explicit = pipeline.analyze_project(self.entry, source_overrides={str(self.entry): text}, native=False)
        self.assertTrue(explicit.report['ok'])
        self.assertEqual(result.report, explicit.report)

    def test_locked_overlay_reports_disk_lock_not_overlay_authentication(self):
        self.package(); packages.write_lock(self.root)
        override = 'fn main() -> i32 effects {} { return 9; }'
        result = pipeline.analyze_project(self.entry, locked=True,
                                         source_overrides={self.entry: override}, native=False)
        self.assertTrue(result.report['ok'])
        self.assertTrue(result.report['project']['locked'])
        self.assertFalse(result.project.unchanged())
        self.assertTrue(result.project.unchanged(except_paths=[self.entry]))
        self.assertEqual(result.project.package_state, packages.verify_lock(packages.load_package(self.root)))

    def test_loader_error_is_raised_before_analyze_report_boundary(self):
        self.entry.write_text('not syntax')
        with self.assertRaises(HeptaError) as caught:
            pipeline.analyze_project(self.entry, native=False)
        report = pipeline.analyze(self.entry.read_text(), str(self.entry), native=False).report
        self.assertFalse(report['ok'])
        self.assertEqual(report['diagnostics'], [caught.exception.diagnostic.to_dict()])

    def test_runtime_failure_is_not_silently_converted_to_stale(self):
        from unittest.mock import patch
        graph = modules.load_project(self.entry)
        with patch.object(Path, 'read_bytes', side_effect=RuntimeError('injected')):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                graph.unchanged()
        with patch.object(Path, 'read_bytes', side_effect=OSError('injected')):
            self.assertFalse(graph.unchanged())

    def test_production_sources_do_not_import_experimental_loader(self):
        import ast
        for path in (ROOT / 'hepta').rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith('experiments'), str(path))
                elif isinstance(node, ast.Import):
                    self.assertFalse(any(n.name.startswith('experiments') for n in node.names), str(path))


    def test_pipeline_loader_injection_preserves_success_and_loader_errors(self):
        from unittest.mock import patch
        for scenario in ('plain', 'invalid', 'overlay', 'locked', 'locked-overlay', 'bad-lock'):
            with self.subTest(scenario=scenario):
                self.entry.write_text('fn main() -> i32 effects {} { return 1; }')
                self.package(); packages.write_lock(self.root)
                kwargs = {'native': False}
                if scenario == 'invalid':
                    self.entry.write_text('not syntax')
                if scenario in ('overlay', 'locked-overlay'):
                    kwargs['source_overrides'] = {self.entry: 'fn main() -> i32 effects {} { return 9; }'}
                if scenario in ('locked', 'locked-overlay', 'bad-lock'):
                    kwargs['locked'] = True
                if scenario == 'bad-lock':
                    (self.root / 'Hepta.lock').write_text('{')
                outcomes = []
                for loader in (modules.load_project, candidate.modules.load_project):
                    with patch.object(modules, 'load_project', loader):
                        try:
                            result = pipeline.analyze_project(self.entry, **kwargs)
                            outcomes.append(('result', result.report, asdict(result.program), result.rust))
                        except HeptaError as error:
                            outcomes.append(('error', error.diagnostic.to_dict()))
                self.assertEqual(outcomes[0], outcomes[1])
                self.assertEqual(outcomes[0][0], 'error' if scenario in ('invalid', 'bad-lock') else 'result')
                if scenario not in ('invalid', 'bad-lock'):
                    self.assertTrue(outcomes[0][1]['ok'])

    def test_pipeline_final_revalidation_detects_same_mutation(self):
        from unittest.mock import patch
        original_analyze = pipeline.analyze
        outcomes = []
        for loader in (modules.load_project, candidate.modules.load_project):
            self.entry.write_text('fn main() -> i32 effects {} { return 1; }')
            def analyze_then_mutate(*args, **kwargs):
                result = original_analyze(*args, **kwargs)
                self.entry.write_text('fn main() -> i32 effects {} { return 2; }')
                return result
            with patch.object(modules, 'load_project', loader), patch.object(pipeline, 'analyze', analyze_then_mutate):
                result = pipeline.analyze_project(self.entry, native=False)
                outcomes.append(result.report)
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertFalse(outcomes[0]['ok'])
        self.assertEqual(outcomes[0]['diagnostics'][-1]['code'], 'E_MODULE_RACE')

    def test_package_identity_is_also_not_experiment_compatible(self):
        self.package()
        old, new = self.pair()
        self.assertIs(type(old.package), packages.Package)
        self.assertIsNot(type(new.package), packages.Package)
        self.assertFalse(isinstance(new.package, packages.Package))
        self.assertEqual(asdict(old.package), asdict(new.package))

    def test_report_retains_legacy_aliasing(self):
        for graph in self.pair():
            report = graph.report()
            self.assertIs(report['sources'], graph.sources)
            self.assertIs(report['modules'], graph.modules)
            self.assertIs(report['path_bindings'], graph.bindings)
            self.assertIs(report['c_imports'], graph.c_imports)

    def test_unchanged_does_not_reverify_lock_file_after_load(self):
        self.package(); packages.write_lock(self.root)
        graphs = self.pair(locked=True)
        (self.root / 'Hepta.lock').write_text('{')
        for graph in graphs:
            self.assertTrue(graph.unchanged())
        with self.assertRaises(HeptaError) as caught:
            packages.verify_lock(packages.load_package(self.root))
        self.assertEqual(caught.exception.diagnostic.code, 'E_LOCK_INVALID')
