from dataclasses import asdict, replace
import ast as syntax
import inspect
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import ast, lexer, modules, packages, parser
from experiments.request_load.context import Rejected
from experiments.owned_tokens.owner import Owner as TokenOwner
from .owner import Owner, Limits, _Parser, _NAMES

TEXT = 'fn main()->Unit effects {} {}'


class StructureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.entry = self.root/'main.hepta'
        self.entry.write_text(TEXT)

    def package(self):
        (self.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def parse(self, owner, text=TEXT):
        batch = owner._ops.tokenize(lexer.tokenize, text, 'unit.hepta')
        return owner._ops.parse_admitted(parser.parse, text, 'unit.hepta', batch)

    def test_limit_validation(self):
        for value in (0, -1, True, 1.5, '10'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Limits(ast_nodes=value)
        self.assertEqual(Limits(ast_nodes=1).ast_nodes, 1)

    def test_exact_three_nodes_for_empty_function(self):
        owner = Owner(Limits(ast_nodes=3)); result = owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 3)
        self.assertEqual(result.project.report(), modules.load_project(self.entry).report())

    def test_quota_refuses_before_program_constructor(self):
        owner = Owner(Limits(ast_nodes=2))
        with patch.object(ast.Program, '__init__', side_effect=AssertionError('constructor ran')) as init:
            with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
            init.assert_not_called()
        self.assertEqual(owner.context.counts['ast_nodes'], 2)
        self.assertTrue(owner.context.closed)

    def test_refusal_precedes_argument_evaluation(self):
        owner = Owner(Limits(ast_nodes=1)); p = _Parser('', 'x', [], owner.context)
        p._admit_node(ast.Type)('i64')
        argument = Mock(side_effect=AssertionError('argument ran'))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'):
            p._admit_node(ast.Expr)(argument())
        argument.assert_not_called()

    def test_unknown_factory_never_uses_hash_or_equality(self):
        class Evil:
            def __eq__(self, other): raise AssertionError('equality')
            def __hash__(self): raise AssertionError('hash')
        owner = Owner(); p = _Parser('', 'x', [], owner.context)
        with self.assertRaisesRegex(Rejected, 'unknown AST'): p._admit_node(Evil())
        self.assertEqual(owner.context.counts['ast_nodes'], 0)

    def test_constructor_failure_consumes_attempt_and_closes_owner(self):
        owner = Owner()
        with patch.object(ast.Type, '__init__', side_effect=RuntimeError('constructor failure')):
            with self.assertRaisesRegex(RuntimeError, 'constructor failure'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 1)
        self.assertTrue(owner.context.closed)

    def test_malformed_parse_consumes_prior_attempt(self):
        owner = Owner(); self.entry.write_text('fn main()->Unit effects {} {let x:i64=;}')
        with self.assertRaises(ast.HeptaError): owner.load(self.entry)
        self.assertGreater(owner.context.counts['ast_nodes'], 0)
        self.assertTrue(owner.context.closed)

    def test_wide_function_declarations_are_refused(self):
        self.entry.write_text('\n'.join(f'fn f{i}()->Unit effects {{}} {{}}' for i in range(200)))
        owner = Owner(Limits(ast_nodes=20))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 20)

    def test_wide_struct_fields_are_refused(self):
        self.entry.write_text('struct S {' + ','.join(f'f{i}:i64' for i in range(200)) + '}')
        owner = Owner(Limits(ast_nodes=20))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 20)

    def test_wide_array_elements_are_refused(self):
        self.entry.write_text('fn main()->Unit effects {} {let x=[' + ','.join('1' for _ in range(200)) + '];}')
        owner = Owner(Limits(ast_nodes=20))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 20)

    def test_left_associated_chain_refused_before_posthoc_depth_check(self):
        self.entry.write_text('fn main()->Unit effects {} {let x:i64=' + '+'.join('1' for _ in range(150)) + ';}')
        with self.assertRaises(ast.HeptaError) as legacy: modules.load_project(self.entry)
        self.assertEqual(legacy.exception.diagnostic.code, 'E_PARSE_DEPTH')
        with self.assertRaises(ast.HeptaError) as ample: Owner().load(self.entry)
        self.assertEqual(ample.exception.diagnostic.to_dict(), legacy.exception.diagnostic.to_dict())
        owner = Owner(Limits(ast_nodes=20))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 20)

    def test_reload_budget_is_cumulative(self):
        owner = Owner(Limits(ast_nodes=5)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], 5)

    def test_revalidation_without_parse_does_not_charge_nodes(self):
        owner = Owner(Limits(ast_nodes=3)); handle = owner.load(self.entry)
        self.assertTrue(handle.unchanged()); self.assertTrue(handle.unchanged())
        self.assertEqual(owner.context.counts['ast_nodes'], 3)

    def test_multiple_modules_share_node_budget(self):
        self.entry.write_text('import lib; ' + TEXT); (self.root/'lib.hepta').write_text('')
        probe = Owner(); probe.load(self.entry); count = probe.context.counts['ast_nodes']
        self.assertEqual(count, 5)
        owner = Owner(Limits(ast_nodes=count-1))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['ast_nodes'], count-1)

    def test_locked_load_and_revalidation_preserve_semantics(self):
        self.package(); packages.write_lock(self.root)
        owner = Owner(); handle = owner.load(self.entry, locked=True)
        before = owner.context.counts['ast_nodes']; (self.root/'Hepta.lock').write_text('{}')
        self.assertTrue(handle.unchanged()); self.assertEqual(owner.context.counts['ast_nodes'], before)
        with self.assertRaises(ast.HeptaError): modules.load_project(self.entry, locked=True)

    def test_stale_lock_refused_before_ast_work(self):
        self.package(); packages.write_lock(self.root); self.entry.write_text(TEXT+' ')
        owner = Owner()
        with self.assertRaises(ast.HeptaError) as caught: owner.load(self.entry, locked=True)
        self.assertEqual(caught.exception.diagnostic.code, 'E_LOCK_STALE')
        self.assertEqual(owner.context.counts['ast_nodes'], 0)

    def test_overrides_refused_before_ast_work(self):
        owner = Owner()
        with self.assertRaisesRegex(Rejected, 'overrides'): owner.load(self.entry, source_overrides={})
        self.assertEqual(owner.context.counts['ast_nodes'], 0)
        self.assertEqual(owner.context.reader.reads, 0)

    def test_constructor_alias_hooks_rejected_without_invocation(self):
        for name in _NAMES:
            with self.subTest(name=name):
                owner = Owner()
                with patch.object(parser, name, side_effect=AssertionError('hook invoked')) as hook:
                    with self.assertRaisesRegex(Rejected, 'constructor'): owner.load(self.entry)
                    hook.assert_not_called()
                self.assertTrue(owner.context.closed)

    def test_ast_namespace_replacement_is_refused(self):
        owner = Owner()
        with patch.object(ast, 'Expr', side_effect=AssertionError('hook invoked')):
            with self.assertRaisesRegex(Rejected, 'constructor'): owner.load(self.entry)

    def test_checkpoint_constructor_swap_is_refused(self):
        owner = Owner(); replacement = Mock(side_effect=AssertionError('hook invoked'))
        def swap():
            if owner.context.counts['ast_nodes'] == 1: parser.Expr = replacement
        with patch.object(parser, 'Expr', parser.Expr):
            owner.context.checkpoint = swap
            with self.assertRaisesRegex(Rejected, 'constructor'): owner.load(self.entry)
        replacement.assert_not_called(); self.assertTrue(owner.context.closed)

    def test_cancellation_at_node_admission_is_terminal(self):
        owner = Owner(); p = _Parser('', 'x', [], owner.context)
        def cancel(): raise TimeoutError('cancelled')
        owner.context.checkpoint = cancel
        with self.assertRaises(TimeoutError): p._admit_node(ast.Type)
        self.assertTrue(owner.context.closed); self.assertEqual(owner.context.counts['ast_nodes'], 0)

    def test_swallowed_reentrant_final_checkpoint_cannot_return_success(self):
        probe = Owner(); calls = []; probe.context.checkpoint = lambda: calls.append(None)
        probe.load(self.entry); last = len(calls)
        owner = Owner(); calls = []
        def swallow():
            calls.append(None)
            if len(calls) == last:
                try: owner.load(self.entry)
                except Rejected: pass
        owner.context.checkpoint = swallow
        with self.assertRaisesRegex(Rejected, 'terminal'): owner.load(self.entry)
        self.assertTrue(owner.context.closed)

    def test_cross_owner_batch_remains_refused(self):
        first = Owner(); batch = first._ops.tokenize(lexer.tokenize, TEXT, 'x')
        second = Owner()
        with self.assertRaisesRegex(Rejected, 'belong'): second._ops.parse_admitted(parser.parse, TEXT, 'x', batch)
        self.assertEqual(second.context.counts['ast_nodes'], 0)

    def test_token_replay_remains_refused(self):
        owner = Owner(); batch = owner._ops.tokenize(lexer.tokenize, TEXT, 'x')
        owner._ops.parse_admitted(parser.parse, TEXT, 'x', batch)
        before = owner.context.counts['ast_nodes']
        with self.assertRaisesRegex(Rejected, 'consumed'): owner._ops.parse_admitted(parser.parse, TEXT, 'x', batch)
        self.assertEqual(owner.context.counts['ast_nodes'], before)

    def test_single_lex_profile_and_legacy_double_lex(self):
        owner = Owner(); owner.load(self.entry)
        self.assertEqual(owner.context.counts['total_tokens'], len(lexer.tokenize(TEXT)))
        scan = Mock(wraps=lexer.tokenize); second = Mock(wraps=lexer.tokenize)
        with patch.object(modules, 'tokenize', scan), patch.object(parser, 'tokenize', second):
            modules.load_project(self.entry)
        scan.assert_called_once(); second.assert_called_once()

    def test_legacy_constructor_alias_hook_receives_original_arguments(self):
        original = parser.Type; hook = Mock(wraps=original)
        with patch.object(parser, 'Type', hook): parser.parse(TEXT, 'x')
        hook.assert_called_once_with('Unit', (), lifetimes=())

    def test_legacy_curried_seam_returns_exact_callable(self):
        p = parser.Parser('', 'x')
        sentinel = object()
        self.assertIs(p._admit_node(sentinel), sentinel)

    def test_no_direct_semantic_ast_constructor_calls_remain(self):
        tree = syntax.parse(inspect.getsource(parser))
        direct = [n for n in syntax.walk(tree) if isinstance(n, syntax.Call)
                  and isinstance(n.func, syntax.Name) and n.func.id in _NAMES]
        self.assertEqual(direct, [])
        admitted = [n for n in syntax.walk(tree) if isinstance(n, syntax.Call)
                    and isinstance(n.func, syntax.Attribute) and n.func.attr == '_admit_node']
        self.assertEqual(len(admitted), 36)

    def test_no_copied_parser_algorithm(self):
        from .owner import _Parser, _Ops
        self.assertEqual(set(_Parser.__dict__) - {'__module__','__doc__'}, {'_admit_node'})
        self.assertNotIn('parse_admitted', _Ops.__dict__)
        self.assertIs(_Parser.parse, parser.Parser.parse)

    def test_all_examples_keep_full_graph_and_diagnostic_outcomes(self):
        root = Path(__file__).resolve().parents[2]; passed = failed = 0
        for entry in sorted((root/'examples').rglob('*.hepta')):
            with self.subTest(entry=str(entry.relative_to(root))):
                try: expected = modules.load_project(entry)
                except ast.HeptaError as old:
                    with self.assertRaises(ast.HeptaError) as new: Owner().load(entry)
                    self.assertEqual(new.exception.diagnostic.to_dict(), old.diagnostic.to_dict()); failed += 1
                else:
                    actual = Owner().load(entry).project
                    self.assertEqual(actual.report(), expected.report())
                    self.assertEqual(actual.source_bytes, expected.source_bytes)
                    self.assertEqual(asdict(actual.program), asdict(expected.program)); passed += 1
        self.assertEqual((passed, failed), (68, 12))

    def test_legacy_nested_constructor_capture_and_finalizer_order(self):
        original = parser.Type; events = []
        def replacement(*args, **kwargs):
            events.append('B:' + args[0]); return original(*args, **kwargs)
        class First:
            def __call__(self, *args, **kwargs):
                events.append('A:' + args[0])
                if args[0] == 'i64': parser.Type = replacement
                return original(*args, **kwargs)
            def __del__(self): events.append('del:A')
        with patch.object(parser, 'Type', parser.Type):
            parser.Type = First()
            parser.parse('fn f(x:raw const i64)->Unit effects {} {}', 'x')
        self.assertEqual(events, ['A:i64', 'A:raw_const', 'del:A', 'B:Unit'])

    def test_inline_nested_type_admits_parent_before_child_constructor(self):
        owner = Owner(Limits(ast_nodes=1))
        self.entry.write_text('fn f(x:raw const i64)->Unit effects {} {}')
        with patch.object(ast.Type, '__init__', side_effect=AssertionError('constructor ran')) as init:
            with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
            init.assert_not_called()
        self.assertEqual(owner.context.counts['ast_nodes'], 1)
        self.assertTrue(owner.context.closed)
