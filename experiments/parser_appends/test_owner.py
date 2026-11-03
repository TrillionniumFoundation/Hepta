import ast as syntax
import inspect
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import lexer, parser
from experiments.request_load.context import Rejected
from experiments.ast_structure.owner import Owner as AstOwner
from .owner import Owner, Limits, _Parser

TEXT = 'fn main()->Unit effects {} {}'


class AppendTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.entry = Path(tmp.name)/'main.hepta'; self.entry.write_text(TEXT)

    def parse(self, owner, text=TEXT):
        batch = owner._ops.tokenize(lexer.tokenize, text, 'unit.hepta')
        return owner._ops.parse_admitted(parser.parse, text, 'unit.hepta', batch)

    def test_positive_integer_limits(self):
        for value in (0, -1, True, 1.5, '10'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Limits(parser_appends=value)

    def test_exact_empty_function(self):
        owner = Owner(Limits(parser_appends=1)); owner.load(self.entry)
        self.assertEqual(owner.context.counts['parser_appends'], 1)
        self.assertEqual(owner.context.counts['ast_nodes'], 3)

    def test_next_function_refused_before_argument(self):
        owner = Owner(Limits(parser_appends=1))
        self.entry.write_text(TEXT + ' fn another()->Unit effects {} {}')
        with self.assertRaisesRegex(Rejected, 'parser_appends'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['parser_appends'], 1)
        self.assertEqual(owner.context.counts['ast_nodes'], 2)
        self.assertTrue(owner.context.closed)

    def test_refuses_before_argument_and_mutation(self):
        owner = Owner(Limits(parser_appends=1)); p = _Parser('', 'x', [], owner.context)
        items=[]; p._admit_append(items.append)(1)
        argument=Mock(side_effect=AssertionError('argument ran'))
        with self.assertRaisesRegex(Rejected, 'parser_appends'):
            p._admit_append(items.append)(argument())
        argument.assert_not_called(); self.assertEqual(items, [1])

    def test_failed_argument_keeps_attempt(self):
        owner = Owner(); p = _Parser('', 'x', [], owner.context); items=[]
        def fail(): raise ValueError('argument failed')
        with self.assertRaisesRegex(ValueError, 'argument failed'):
            p._admit_append(items.append)(fail())
        self.assertEqual(items, [])
        self.assertEqual(owner.context.counts['parser_appends'], 1)

    def test_returns_identical_bound_method(self):
        owner=Owner(); p=_Parser('', 'x', [], owner.context); operation=[].append
        self.assertIs(p._admit_append(operation), operation)
        self.assertIs(parser.Parser('')._admit_append(operation), operation)

    def test_unknown_operation_without_attribute_or_equality_hooks(self):
        class Evil:
            def __getattribute__(self, name): raise AssertionError('attribute')
            def __eq__(self, other): raise AssertionError('equality')
            def __hash__(self): raise AssertionError('hash')
        owner=Owner(); p=_Parser('', 'x', [], owner.context)
        with self.assertRaisesRegex(Rejected, 'unknown'): p._admit_append(Evil())
        self.assertEqual(owner.context.counts['parser_appends'], 0)

    def test_other_builtin_methods_and_list_subclasses_refused(self):
        class Sub(list): pass
        for operation in ([].extend, set().add, Sub().append):
            with self.subTest(operation=operation):
                owner=Owner(); p=_Parser('', 'x', [], owner.context)
                with self.assertRaisesRegex(Rejected, 'unknown'): p._admit_append(operation)

    def test_generic_names_refused_before_first_ast_node(self):
        text='fn f<'+','.join('T'+str(i) for i in range(1000))+'>()->Unit effects {} {}'
        owner=Owner(Limits(parser_appends=10))
        with self.assertRaisesRegex(Rejected, 'parser_appends'): self.parse(owner,text)
        self.assertEqual(owner.context.counts['parser_appends'],10)
        self.assertEqual(owner.context.counts['ast_nodes'],0)

    def test_generic_lifetimes_refused_before_first_ast_node(self):
        text='fn f<'+','.join("'a"+str(i) for i in range(100))+'>()->Unit effects {} {}'
        owner=Owner(Limits(parser_appends=10))
        with self.assertRaisesRegex(Rejected, 'parser_appends'): self.parse(owner,text)
        self.assertEqual(owner.context.counts['ast_nodes'],0)

    def test_long_qualified_path_refused(self):
        text='import '+ '::'.join('n'+str(i) for i in range(100))+';'
        owner=Owner(Limits(parser_appends=10))
        with self.assertRaisesRegex(Rejected, 'parser_appends'): self.parse(owner,text)
        self.assertEqual(owner.context.counts['ast_nodes'],0)

    def test_wide_match_binding_refused(self):
        text='fn main()->Unit effects {} {match x {E::V('+','.join('b'+str(i) for i in range(100))+')=>{}}}'
        owner=Owner(Limits(parser_appends=10))
        with self.assertRaisesRegex(Rejected, 'parser_appends'): self.parse(owner,text)
        self.assertEqual(owner.context.counts['parser_appends'],10)

    def test_reload_budget_cumulative(self):
        owner=Owner(Limits(parser_appends=1)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'parser_appends'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['parser_appends'],1)

    def test_revalidation_does_not_charge(self):
        owner=Owner(Limits(parser_appends=1)); handle=owner.load(self.entry)
        self.assertTrue(handle.unchanged()); self.assertTrue(handle.unchanged())
        self.assertEqual(owner.context.counts['parser_appends'],1)

    def test_ast_quota_remains_independent(self):
        owner=Owner(Limits(ast_nodes=1))
        with self.assertRaisesRegex(Rejected, 'ast_nodes'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['parser_appends'],1)

    def test_old_profile_does_not_charge_appends(self):
        owner=AstOwner(); self.parse(owner)
        self.assertNotIn('parser_appends',owner.context.counts)

    def test_replaced_seam_refused_without_invocation(self):
        owner=Owner()
        with patch.object(parser.Parser,'_admit_append',side_effect=AssertionError('called')) as hook:
            with self.assertRaisesRegex(Rejected,'append hook'): owner.load(self.entry)
            hook.assert_not_called()
        self.assertTrue(owner.context.closed)

    def test_static_25_grammar_sites_and_validator_exclusion(self):
        tree=syntax.parse(inspect.getsource(parser))
        validator=next(n for n in syntax.walk(tree) if isinstance(n,syntax.FunctionDef) and n.name=='_validate_tree_depth')
        admitted=[]; direct=[]
        for n in syntax.walk(tree):
            if not isinstance(n,syntax.Call): continue
            if isinstance(n.func,syntax.Attribute) and n.func.attr=='_admit_append':
                admitted.append(n)
                self.assertEqual(len(n.args),1)
                self.assertIsInstance(n.args[0],syntax.Attribute)
                self.assertEqual(n.args[0].attr,'append')
            if isinstance(n.func,syntax.Attribute) and n.func.attr=='append': direct.append(n)
        self.assertEqual(len(admitted),25)
        self.assertEqual(len(direct),1)
        self.assertTrue(validator.lineno<=direct[0].lineno<=validator.end_lineno)

    def test_malformed_parse_terminal(self):
        owner=Owner()
        from hepta.ast import HeptaError
        with self.assertRaises(HeptaError): self.parse(owner,'fn broken')
        self.assertTrue(owner.context.closed)
        with self.assertRaises(Rejected): self.parse(owner)

    def test_default_ast_parity(self):
        from dataclasses import asdict
        self.assertEqual(asdict(self.parse(Owner())),asdict(parser.parse(TEXT,'unit.hepta')))


    def test_legacy_bound_receiver_capture_and_finalizer_order(self):
        events = []
        p = parser.Parser('ns::member', 'unit.hepta')
        class Target:
            def append(self, value):
                events.append('append')
            def __del__(self):
                events.append('del')
        p.qualified_expressions = Target()
        original_cover = parser._cover
        def rebind(*args):
            events.append('cover')
            p.qualified_expressions = []
            return original_cover(*args)
        with patch.object(parser, '_cover', rebind):
            p._prefix(True)
        self.assertEqual(events, ['cover', 'append', 'del', 'cover'])

    def test_cancellation_at_append_admission_is_terminal(self):
        owner = Owner(); p = _Parser('', 'x', [], owner.context); items = []
        argument = Mock(side_effect=AssertionError('argument ran'))
        def cancel():
            raise TimeoutError('cancelled')
        owner.context.checkpoint = cancel
        with self.assertRaisesRegex(TimeoutError, 'cancelled'):
            p._admit_append(items.append)(argument())
        argument.assert_not_called()
        self.assertEqual(items, [])
        self.assertEqual(owner.context.counts['parser_appends'], 0)
        self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected, 'terminal'):
            p._admit_append(items.append)(2)

    def test_swallowed_reentrant_append_cannot_return_success(self):
        owner = Owner(); p = _Parser('', 'x', [], owner.context); items = []
        argument = Mock(side_effect=AssertionError('argument ran'))
        def swallow():
            try:
                p._admit_append(items.append)(99)
            except Rejected:
                pass
        owner.context.checkpoint = swallow
        with self.assertRaisesRegex(Rejected, 'terminal'):
            p._admit_append(items.append)(argument())
        argument.assert_not_called()
        self.assertEqual(items, [])
        self.assertEqual(owner.context.counts['parser_appends'], 0)
        self.assertTrue(owner.context.closed)

    def test_checkpoint_replaces_append_seam_before_operation(self):
        owner = Owner(); p = _Parser('', 'x', [], owner.context); items = []
        argument = Mock(side_effect=AssertionError('argument ran'))
        replacement = Mock(side_effect=AssertionError('replacement ran'))
        def swap():
            parser.Parser._admit_append = replacement
        owner.context.checkpoint = swap
        with patch.object(parser.Parser, '_admit_append', parser.Parser._admit_append):
            with self.assertRaisesRegex(Rejected, 'append hook'):
                p._admit_append(items.append)(argument())
        argument.assert_not_called(); replacement.assert_not_called()
        self.assertEqual(items, [])
        self.assertEqual(owner.context.counts['parser_appends'], 0)
        self.assertTrue(owner.context.closed)

    def test_all_examples_keep_full_graph_and_diagnostic_outcomes(self):
        from dataclasses import asdict
        from hepta import ast, modules
        root = Path(__file__).resolve().parents[2]
        passed = failed = 0
        for entry in sorted((root / 'examples').rglob('*.hepta')):
            with self.subTest(entry=str(entry.relative_to(root))):
                try:
                    expected = modules.load_project(entry)
                except ast.HeptaError as old:
                    with self.assertRaises(ast.HeptaError) as new:
                        Owner().load(entry)
                    self.assertEqual(new.exception.diagnostic.to_dict(),
                                     old.diagnostic.to_dict())
                    failed += 1
                else:
                    actual = Owner().load(entry).project
                    self.assertEqual(actual.report(), expected.report())
                    self.assertEqual(actual.source_bytes, expected.source_bytes)
                    self.assertEqual(asdict(actual.program), asdict(expected.program))
                    passed += 1
        self.assertEqual((passed, failed), (68, 12))


if __name__ == '__main__': unittest.main()
