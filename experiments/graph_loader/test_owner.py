from dataclasses import asdict, replace
from collections import Counter
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import modules, packages
from hepta.ast import HeptaError
from experiments.request_load.context import Limits, Rejected
from .owner import Owner


class GraphTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.entry = self.root/'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def package(self, root=None, name='app', deps=(), lib=False):
        root = root or self.root; root.mkdir(exist_ok=True)
        entry = 'lib.hepta' if lib else 'main.hepta'
        if not (root/entry).exists(): (root/entry).write_text('')
        manifest = f'[package]\nname="{name}"\nversion="1.0.0"\nkind="{"lib" if lib else "bin"}"\nsource_root="."\nentry="{entry}"\n'
        if deps:
            manifest += '[dependencies]\n' + ''.join(f'{alias}={{path="{path}"}}\n' for alias,path in deps)
        (root/'hepta.toml').write_text(manifest)
        return root

    def module_diamond(self):
        self.entry.write_text('import left; import right; fn main()->Unit effects {} {}')
        for name in ('left','right'): (self.root/(name+'.hepta')).write_text('import shared;')
        (self.root/'shared.hepta').write_text('')

    def package_diamond(self):
        self.package(self.root/'common', 'common', lib=True)
        for name in ('left','right'):
            self.package(self.root/name, name, [('common','../common')], lib=True)
        self.package(deps=[('left','left'),('right','right')])

    def test_module_cached_edge_is_charged(self):
        self.module_diamond(); owner=Owner(); handle=owner.load(self.entry)
        self.assertEqual(owner.context.counts['modules'],4)
        self.assertEqual(owner.context.counts['module_edges'],5)
        self.assertEqual(handle.project.report(), modules.load_project(self.entry).report())

    def test_module_edge_exact_limit_and_cached_overrun(self):
        self.module_diamond(); Owner(Limits(module_edges=5)).load(self.entry)
        owner=Owner(Limits(module_edges=4))
        with self.assertRaisesRegex(Rejected,'module_edges'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['module_edges'],4)
        self.assertEqual(owner.context.counts['modules'],4)
        self.assertTrue(owner.context.closed)

    def test_module_node_exact_limit_and_overrun_before_read(self):
        self.module_diamond(); Owner(Limits(modules=4)).load(self.entry)
        owner=Owner(Limits(modules=3))
        with self.assertRaisesRegex(Rejected,'modules'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['modules'],3)
        self.assertEqual(owner.context.reader.reads,3)

    def test_module_depth_root_one_and_boundary(self):
        self.module_diamond(); Owner(Limits(module_depth=3)).load(self.entry)
        owner=Owner(Limits(module_depth=2))
        with self.assertRaisesRegex(Rejected,'depth'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['modules'],2)
        self.assertEqual(owner.context.counts['module_edges'],2)

    def test_cache_hit_depth_is_not_bypassed(self):
        self.entry.write_text('import shared; import left; fn main()->Unit effects {} {}')
        (self.root/'shared.hepta').write_text(''); (self.root/'left.hepta').write_text('import shared;')
        owner=Owner(Limits(module_depth=2))
        with self.assertRaisesRegex(Rejected,'depth'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['modules'],3)

    def test_module_reload_accumulates_nodes_and_edges(self):
        owner=Owner(Limits(modules=1)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'modules'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['module_edges'],2)
        self.assertEqual(owner.context.counts['modules'],1)

    def test_package_construction_and_snapshot_counts(self):
        self.package(); owner=Owner(); handle=owner.load(self.entry)
        self.assertEqual(owner.context.counts['packages'],4)
        self.assertEqual(owner.context.counts['package_edges'],4)
        self.assertTrue(handle.unchanged())
        self.assertEqual(owner.context.counts['packages'],6)
        self.assertEqual(owner.context.counts['package_edges'],6)

    def test_package_cached_and_seen_edges_count(self):
        self.package_diamond(); owner=Owner(); owner.load(self.entry)
        self.assertEqual(owner.context.counts['packages'],16)
        self.assertEqual(owner.context.counts['package_edges'],20)

    def test_package_exact_node_and_edge_limits(self):
        self.package_diamond(); Owner(Limits(packages=16,package_edges=20)).load(self.entry)
        for values, message in (({'packages':15},'packages'),({'package_edges':19},'package_edges')):
            owner=Owner(replace(Limits(),**values))
            with self.assertRaisesRegex(Rejected,message):owner.load(self.entry)
            self.assertTrue(owner.context.closed)

    def test_package_depth_boundary(self):
        self.package_diamond(); Owner(Limits(package_depth=3)).load(self.entry)
        owner=Owner(Limits(package_depth=2))
        with self.assertRaisesRegex(Rejected,'depth'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['packages'],2)

    def test_snapshot_seen_edge_charged_and_depth_checked(self):
        self.package_diamond(); package=packages.load_package(self.root)
        owner=Owner(Limits(package_edges=5)); packages._package_snapshot(package,ops=owner._ops)
        self.assertEqual(owner.context.counts['packages'],4)
        self.assertEqual(owner.context.counts['package_edges'],5)
        with self.assertRaisesRegex(Rejected,'package_edges'):packages._package_snapshot(package,ops=owner._ops)
        owner=Owner(Limits(package_depth=2))
        with self.assertRaisesRegex(Rejected,'depth'):packages._package_snapshot(package,ops=owner._ops)

    def test_package_revalidation_budget_is_cumulative(self):
        self.package(); owner=Owner(Limits(packages=4)); handle=owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'packages'): handle.unchanged()
        self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected,'terminal'): owner.load(self.entry)

    def test_package_reload_has_no_reset(self):
        self.package(); owner=Owner(Limits(package_edges=4)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'package_edges'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['package_edges'],4)

    def test_cycle_diagnostics_retained_at_sufficient_budget(self):
        self.entry.write_text('import main as recur; fn main()->Unit effects {} {}')
        for load in (modules.load_project,Owner().load):
            with self.assertRaises(HeptaError) as e:load(self.entry)
            self.assertEqual(e.exception.diagnostic.code,'E_MODULE_CYCLE')
        with self.assertRaisesRegex(Rejected,'module_edges'):Owner(Limits(module_edges=1)).load(self.entry)

    def test_package_cycle_diagnostics_retained(self):
        self.package(deps=[('self','.')])
        for load in (modules.load_project,Owner().load):
            with self.assertRaises(HeptaError) as e:load(self.entry)
            self.assertEqual(e.exception.diagnostic.code,'E_PACKAGE_CYCLE')
        with self.assertRaisesRegex(Rejected,'package_edges'):Owner(Limits(package_edges=1)).load(self.entry)

    def test_path_limit_exact_and_overrun(self):
        first=Owner(); first.load(self.entry); n=first.context.counts['path_checks']
        self.assertGreater(n,5)
        Owner(Limits(path_checks=n)).load(self.entry)
        owner=Owner(Limits(path_checks=n-1))
        with self.assertRaisesRegex(Rejected,'path_checks'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['path_checks'],n-1)

    def test_path_revalidation_quota_not_swallowed_as_stale(self):
        first=Owner(); first.load(self.entry); n=first.context.counts['path_checks']
        owner=Owner(Limits(path_checks=n)); handle=owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'path_checks'):handle.unchanged()
        self.assertTrue(owner.context.closed)

    def test_path_charge_precedes_underlying_operation(self):
        owner=Owner(Limits(path_checks=1)); owner._ops.path(self.entry,'absolute')
        with patch.object(Path,'resolve',side_effect=AssertionError('unadmitted resolve')) as resolve:
            with self.assertRaisesRegex(Rejected,'path_checks'):owner._ops.path(self.entry,'resolve')
            resolve.assert_not_called()

    def test_manifest_search_path_checks_are_admitted(self):
        owner=Owner(Limits(path_checks=1))
        with patch.object(Path,'is_file',side_effect=AssertionError('unadmitted stat')) as stat:
            with self.assertRaisesRegex(Rejected,'path_checks'):packages._find_manifest(self.entry,ops=owner._ops)
            stat.assert_not_called()

    def test_manifest_hook_forwarding_is_refused(self):
        original=modules.find_manifest
        with patch.object(modules,'find_manifest',Mock(wraps=original)) as replacement:
            owner=Owner()
            with self.assertRaisesRegex(Rejected,'hook'):owner.load(self.entry)
            replacement.assert_not_called(); self.assertEqual(owner.context.reader.reads,0)

    def test_checkpoint_swap_during_path_charge_is_refused(self):
        owner=Owner(); replacement=Mock(); original=modules.find_manifest
        def checkpoint():
            if owner.context.counts['path_checks']==1:modules.find_manifest=replacement
        owner.context.checkpoint=checkpoint
        try:
            with self.assertRaisesRegex(Rejected,'hook'):owner.load(self.entry)
        finally:modules.find_manifest=original
        replacement.assert_not_called(); self.assertTrue(owner.context.closed)

    def test_locked_parity_and_no_new_lock_authentication(self):
        self.package(); packages.write_lock(self.root); owner=Owner(); handle=owner.load(self.entry,locked=True)
        self.assertEqual(handle.project.report(),modules.load_project(self.entry,locked=True).report())
        (self.root/'Hepta.lock').write_text('bad')
        self.assertTrue(handle.unchanged())
        with self.assertRaises(HeptaError):packages.verify_lock(handle.project.package)

    def test_locked_stale_diagnostic_retained(self):
        self.package();packages.write_lock(self.root);self.entry.write_text(self.entry.read_text()+'\n')
        with self.assertRaises(HeptaError) as e:Owner().load(self.entry,locked=True)
        self.assertEqual(e.exception.diagnostic.code,'E_LOCK_STALE')

    def test_override_refused_before_graph_path_or_read_work(self):
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'overrides'):owner.load(self.entry,source_overrides={})
        self.assertEqual(owner.context.reader.reads,0)
        self.assertEqual(sum(owner.context.counts.values()),0)

    def test_all_example_graph_and_diagnostic_outcomes(self):
        paths=sorted((Path(__file__).resolve().parents[2]/'examples').rglob('*.hepta')); counts=Counter()
        self.assertEqual(len(paths),80)
        def outcome(load,path):
            try:
                g=load(path);return ('graph',g.report(),g.source_bytes,asdict(g.program))
            except HeptaError as e:return ('diagnostic',e.diagnostic.to_dict())
        for path in paths:
            with self.subTest(path=path):
                actual=outcome(lambda p:Owner().load(p).project,path)
                self.assertEqual(actual,outcome(modules.load_project,path));counts[actual[0]]+=1
        self.assertEqual(counts,{'graph':68,'diagnostic':12})

    def test_cached_package_edge_refusal_precedes_path_work(self):
        self.package(); package=packages.load_package(self.root)
        owner=Owner(Limits(package_edges=1));owner._ops.edge('package',1)
        with patch.object(owner._ops,'path',side_effect=AssertionError('unadmitted path')) as path:
            with self.assertRaisesRegex(Rejected,'package_edges'):
                packages._load_package(self.root,_cache={self.root:package},ops=owner._ops)
            path.assert_not_called()
        self.assertEqual(owner.context.counts['packages'],0)

    def test_all_path_operations_charge_before_call(self):
        for operation in ('absolute','resolve','is_file','is_dir','is_symlink'):
            with self.subTest(operation=operation):
                owner=Owner(Limits(path_checks=1));owner._ops.path(self.entry,'absolute')
                with patch.object(Path,operation,side_effect=AssertionError('unadmitted path')) as call:
                    with self.assertRaisesRegex(Rejected,'path_checks'):owner._ops.path(self.entry,operation)
                    call.assert_not_called()

    def test_cancellation_at_graph_admission_is_terminal(self):
        owner=Owner()
        def stop():
            if owner.context.counts['module_edges']:raise TimeoutError('cancelled')
        owner.context.checkpoint=stop
        with self.assertRaisesRegex(TimeoutError,'cancelled'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['modules'],0)
        self.assertEqual(owner.context.reader.reads,0)
        with self.assertRaisesRegex(Rejected,'terminal'):owner.load(self.entry)

    def test_graph_revalidation_descriptor_refused_without_get(self):
        owner=Owner();handle=owner.load(self.entry);calls=[]
        class Descriptor:
            def __get__(self,*args):calls.append(True);return lambda **kwargs:True
        with patch.object(modules.LoadedProject,'unchanged',Descriptor()):
            with self.assertRaisesRegex(Rejected,'hook'):handle.unchanged()
        self.assertEqual(calls,[]);self.assertTrue(owner.context.closed)

    def test_locked_quota_refusal_never_changes_lock(self):
        self.package();packages.write_lock(self.root);lock=self.root/'Hepta.lock';before=lock.read_bytes()
        owner=Owner(Limits(packages=1))
        with self.assertRaisesRegex(Rejected,'packages'):owner.load(self.entry,locked=True)
        self.assertEqual(lock.read_bytes(),before)
        self.assertFalse(list(self.root.glob('.hepta-lock-*')))

    def test_cached_package_depth_refusal_precedes_resolution(self):
        self.package();package=packages.load_package(self.root)
        owner=Owner(Limits(package_depth=1))
        with patch.object(Path,'resolve',side_effect=AssertionError('unadmitted resolution')) as resolve:
            with self.assertRaisesRegex(Rejected,'depth'):
                packages._load_package(self.root,_stack=[self.root/'ancestor'],
                                       _cache={self.root:package},ops=owner._ops)
            resolve.assert_not_called()
        self.assertEqual(owner.context.counts['package_edges'],0)
        self.assertEqual(owner.context.counts['packages'],0)

    def test_normal_algorithms_have_no_direct_admitted_path_fallback(self):
        import ast
        import inspect
        operations={'absolute','resolve','is_file','is_dir','is_symlink'}
        for module in (modules,packages):
            tree=ast.parse(inspect.getsource(module))
            direct=[(n.lineno,n.func.attr) for n in ast.walk(tree)
                    if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                    and n.func.attr in operations]
            self.assertEqual(direct,[],module.__name__)
