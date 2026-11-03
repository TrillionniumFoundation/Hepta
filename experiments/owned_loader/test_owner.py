from dataclasses import fields, replace
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from hepta import modules, packages
from hepta.ast import HeptaError
from experiments.request_load.context import Limits, Rejected
from .owner import Owner, _OwnedGraph


class OwnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def package(self):
        (self.root/'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def test_real_production_algorithm_and_original_type(self):
        original = modules._load_project
        with patch.object(modules, '_load_project', wraps=original) as call:
            actual = Owner().load(self.entry)
        self.assertEqual(call.call_count, 1)
        expected = modules.load_project(self.entry)
        self.assertIs(type(actual.project), modules.LoadedProject)
        self.assertEqual(len(fields(actual.project)), 11)
        self.assertEqual(actual.project.report(), expected.report())
        self.assertEqual(actual.project.program, expected.program)
        self.assertTrue(actual.unchanged())

    def test_cumulative_read_budget_revalidation_and_terminal(self):
        n = len(self.entry.read_bytes()); owner = Owner(Limits(total_bytes=2*n))
        handle = owner.load(self.entry)
        self.assertEqual(owner.context.reader.bytes_read, 2*n)
        with self.assertRaisesRegex(Rejected, 'quota'): handle.unchanged()
        with self.assertRaisesRegex(Rejected, 'terminal'): owner.load(self.entry)

    def test_reload_cannot_reset_budget(self):
        owner = Owner(Limits(reads=2)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'quota'): owner.load(self.entry)

    def test_public_revalidation_is_explicitly_not_owner_authority(self):
        owner = Owner(Limits(reads=2)); handle = owner.load(self.entry)
        self.assertTrue(handle.project.unchanged())
        self.assertEqual(owner.context.reader.reads, 2)
        with self.assertRaises(Rejected): handle.unchanged()

    def test_override_even_empty_is_rejected_before_reads(self):
        for value in ({}, {str(self.entry): 'bad'}):
            owner = Owner()
            with self.assertRaisesRegex(Rejected, 'overrides'): owner.load(self.entry, source_overrides=value)
            self.assertEqual(owner.context.reader.reads, 0)

    def test_locked_parity_and_stale_diagnostic(self):
        self.package(); packages.write_lock(self.root)
        self.assertEqual(Owner().load(self.entry, locked=True).project.report(), modules.load_project(self.entry, locked=True).report())
        self.entry.write_text(self.entry.read_text()+'\n')
        with self.assertRaises(HeptaError) as error: Owner().load(self.entry, locked=True)
        self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_STALE')

    def test_no_new_lock_authority_is_claimed(self):
        self.package(); packages.write_lock(self.root)
        handle = Owner().load(self.entry, locked=True)
        (self.root/'Hepta.lock').write_text('broken')
        self.assertTrue(handle.unchanged())
        with self.assertRaises(HeptaError): packages.verify_lock(handle.project.package)

    def test_forged_and_cross_owner_handles_rejected(self):
        first = Owner(); handle = first.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'does not belong'): Owner().unchanged(handle)
        with self.assertRaisesRegex(Rejected, 'does not belong'): first.unchanged(_OwnedGraph(handle.project, first))

    def test_mutable_public_maps_cannot_erase_private_disk_authority(self):
        handle = Owner().load(self.entry)
        handle.project.source_bytes.clear(); handle.project.bindings.clear()
        self.entry.write_text('changed')
        self.assertFalse(handle.unchanged())

    def test_public_package_state_cannot_replace_private_authority(self):
        self.package(); handle = Owner().load(self.entry)
        handle.project.package_state = None; handle.project.package.root = self.root/'unrelated'
        (self.root/'unused.hepta').write_text('')
        self.assertFalse(handle.unchanged())

    def test_namespace_forwarding_hook_rejected_without_execution(self):
        self.package()
        for namespace in (modules, packages):
            original = namespace.load_package
            replacement = Mock(wraps=original)
            with patch.object(namespace, 'load_package', replacement):
                with self.assertRaisesRegex(Rejected, 'hook'): Owner().load(self.entry)
            replacement.assert_not_called()

    def test_find_manifest_hook_rejected_without_execution(self):
        replacement = Mock(wraps=modules.find_manifest)
        with patch.object(modules, 'find_manifest', replacement):
            with self.assertRaisesRegex(Rejected, 'hook'): Owner().load(self.entry)
        replacement.assert_not_called()

    def test_revalidation_descriptor_rejected_before_get(self):
        handle = Owner().load(self.entry)
        calls = []
        class Descriptor:
            def __get__(self, instance, owner):
                calls.append(1); raise AssertionError('descriptor executed')
        with patch.object(modules.LoadedProject, 'unchanged', Descriptor()):
            with self.assertRaisesRegex(Rejected, 'hook'): handle.unchanged()
        self.assertEqual(calls, [])

    def test_instance_revalidation_replacement_rejected(self):
        handle = Owner().load(self.entry); hook = Mock(return_value=True)
        handle.project.unchanged = hook
        with self.assertRaisesRegex(Rejected, 'hook'): handle.unchanged()
        hook.assert_not_called()

    def test_checkpoint_decoder_swap_rejected_before_invocation(self):
        owner = Owner(); hook = Mock(return_value={})
        original = json.loads
        owner.context.checkpoint = lambda: setattr(json, 'loads', hook)
        try:
            with self.assertRaisesRegex(Rejected, 'hook'): owner._ops.json(original, b'{}', self.entry)
        finally:
            json.loads = original
        hook.assert_not_called()

    def test_checkpoint_helper_swap_rejected_before_invocation(self):
        owner = Owner(); hook = Mock()
        original = packages.load_package
        owner.context.checkpoint = lambda: setattr(packages, 'load_package', hook)
        try:
            with self.assertRaisesRegex(Rejected, 'hook'): owner.load(self.entry)
        finally:
            packages.load_package = original
        hook.assert_not_called()

    def test_role_provenance_survives_misleading_extension(self):
        self.entry.write_bytes(b'1234')
        owner = Owner(Limits(source=100, header=4))
        self.assertEqual(owner._ops.read(self.entry, 'header'), b'1234')
        self.entry.write_bytes(b'12345')
        with self.assertRaisesRegex(Rejected, 'quota'): owner._ops.read(self.entry, 'revalidation')

    def test_alias_uses_strongest_previously_admitted_cap(self):
        self.entry.write_bytes(b'1234'); alias = self.root/'alias.h'; alias.symlink_to(self.entry)
        owner = Owner(Limits(source=100, header=4))
        owner._ops.read(alias, 'header'); owner._ops.read(self.entry, 'source')
        self.entry.write_bytes(b'12345')
        with self.assertRaisesRegex(Rejected, 'quota'): owner._ops.read(self.entry, 'revalidation')

    def test_missing_and_unknown_roles_fail_closed(self):
        for role in ('revalidation', 'invented'):
            owner = Owner()
            with self.assertRaises(Rejected): owner._ops.read(self.entry, role)
            self.assertEqual(owner.context.reader.reads, 0)

    def test_no_path_read_bytes_fallback(self):
        self.package(); packages.write_lock(self.root)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded fallback')):
            self.assertTrue(Owner().load(self.entry, locked=True).unchanged())

    def test_reentrant_checkpoint_rejected_before_reads(self):
        owner = Owner(); owner.context.checkpoint = lambda: owner.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'reentrant'): owner.load(self.entry)
        self.assertEqual(owner.context.reader.reads, 0)
        self.assertTrue(owner.context.closed)

    def test_cross_thread_owner_rejected(self):
        owner = Owner(); errors = []
        def run():
            try: owner.load(self.entry)
            except Rejected as e: errors.append(str(e))
        thread = threading.Thread(target=run); thread.start(); thread.join()
        self.assertEqual(len(errors), 1); self.assertIn('threads', errors[0])
        self.assertTrue(owner.context.closed)

    def test_legacy_double_lexing_is_charged_without_token_replay(self):
        owner = Owner(); handle = owner.load(self.entry)
        from hepta.lexer import tokenize
        self.assertEqual(owner.context.counts['total_tokens'], 2*len(tokenize(self.entry.read_text())))
        self.assertEqual(owner.context.counts['parses'], 1)
        self.assertTrue(handle.unchanged())

    def test_inventory_admission_before_retention(self):
        self.package()
        for i in range(5): (self.root/str(i)).touch()
        owner = Owner(Limits(inventory_entries=2))
        with self.assertRaisesRegex(Rejected, 'inventory_entries'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['inventory_entries'], 2)

    def test_independent_owners_do_not_share_terminal_state(self):
        with self.assertRaises(Rejected): Owner(Limits(reads=1)).load(self.entry)
        self.assertTrue(Owner().load(self.entry).unchanged())

    def test_retargeted_header_alias_cannot_inherit_weaker_source_role(self):
        self.entry.write_bytes(b'1234')
        other = self.root/'other.hepta'; other.write_bytes(b'12345')
        alias = self.root/'header.h'; alias.symlink_to(self.entry)
        owner = Owner(Limits(source=100, header=4))
        owner._ops.read(alias, 'header'); owner._ops.read(other, 'source')
        alias.unlink(); alias.symlink_to(other)
        with self.assertRaisesRegex(Rejected, 'binding changed'): owner._ops.read(alias, 'revalidation')

    def test_checkpoint_retarget_during_read_retains_lexical_header_cap(self):
        self.entry.write_bytes(b'1234')
        other = self.root/'other.hepta'; other.write_bytes(b'12345')
        alias = self.root/'header.h'; alias.symlink_to(self.entry)
        owner = Owner(Limits(source=100, header=4))
        owner._ops.read(alias, 'header'); owner._ops.read(other, 'source')
        count = [0]
        def retarget():
            count[0] += 1
            if count[0] == 2:
                alias.unlink(); alias.symlink_to(other)
        owner.context.checkpoint = retarget
        with self.assertRaises(Rejected): owner._ops.read(alias, 'revalidation')

    def test_repository_corpus_full_graph_and_diagnostic_parity(self):
        from dataclasses import asdict
        from collections import Counter
        paths = sorted((Path(__file__).resolve().parents[2]/'examples').rglob('*.hepta'))
        self.assertEqual(len(paths), 80)
        counts = Counter()
        def outcome(loader, path):
            try:
                graph = loader(path)
                return ('graph', graph.report(), graph.source_bytes, asdict(graph.program))
            except HeptaError as error:
                return ('diagnostic', error.diagnostic.to_dict())
        for path in paths:
            with self.subTest(path=path):
                expected = outcome(modules.load_project, path)
                actual = outcome(lambda p: Owner().load(p).project, path)
                self.assertEqual(actual, expected)
                counts[actual[0]] += 1
        self.assertEqual(counts, {'graph': 68, 'diagnostic': 12})

    def test_source_refusal_precedes_parser(self):
        with patch('experiments.request_load.context.BoundedParser.parse') as parser:
            with self.assertRaisesRegex(Rejected, 'quota'):
                Owner(Limits(source=4)).load(self.entry)
        parser.assert_not_called()

    def test_real_c_header_roles_survive_revalidation(self):
        from experiments.c_char_boundary.test_prototype import CharPrototypeTests
        fixture = CharPrototypeTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        entry, _ = fixture.fixture()
        owner = Owner(); handle = owner.load(entry)
        self.assertTrue(handle.unchanged())
        self.assertEqual(owner._ops.roles[str((fixture.root/'api.h').resolve())], 'header')
        self.assertEqual(owner._ops.roles[str(fixture.sidecar.resolve())], 'sidecar')
        self.assertEqual(handle.project.report(), modules.load_project(entry).report())

    def test_unenforced_graph_limit_overrides_are_rejected(self):
        for name in ('packages', 'package_depth', 'package_edges', 'module_edges',
                     'path_checks', 'modules', 'module_depth'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'unsupported normal-loader limit'):
                    Owner(replace(Limits(), **{name: 1}))

    def test_deleted_namespace_hook_rejects_and_closes_owner(self):
        for namespace, name in ((modules, 'parse'), (modules.LoadedProject, 'unchanged')):
            with self.subTest(name=name):
                owner = Owner(); original = getattr(namespace, name)
                try:
                    delattr(namespace, name)
                    with self.assertRaisesRegex(Rejected, 'hook'): owner.load(self.entry)
                finally:
                    setattr(namespace, name, original)
                self.assertTrue(owner.context.closed)
                with self.assertRaisesRegex(Rejected, 'terminal'): owner.load(self.entry)
