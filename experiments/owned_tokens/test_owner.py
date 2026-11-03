from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import lexer, parser, modules, packages
from hepta.ast import HeptaError, Span
from experiments.graph_loader.owner import Owner as GraphOwner
from experiments.request_load.context import Limits, Rejected
from .owner import Owner, _Batch, _Parser

TEXT='fn main()->Unit effects {} {}'


class TokenTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.entry=self.root/'main.hepta';self.entry.write_text(TEXT)

    def batch(self,owner,text=TEXT,path='unit.hepta'):
        return owner._ops.tokenize(lexer.tokenize,text,path)

    def parse(self,owner,batch,text=TEXT,path='unit.hepta'):
        return owner._ops.parse_admitted(parser.parse,text,path,batch)

    def test_single_lex_and_original_graph_identity(self):
        owner=Owner();h=owner.load(self.entry)
        self.assertIs(type(h.project),modules.LoadedProject)
        self.assertEqual(h.project.report(),modules.load_project(self.entry).report())
        self.assertEqual(owner.context.counts['total_tokens'],len(lexer.tokenize(TEXT)))
        self.assertEqual(owner.context.counts['parses'],1)
        self.assertTrue(h.unchanged())

    def test_previous_graph_owner_retains_two_lexes(self):
        owner=GraphOwner();owner.load(self.entry)
        self.assertEqual(owner.context.counts['total_tokens'],2*len(lexer.tokenize(TEXT)))

    def test_legacy_namespace_hooks_still_lex_twice(self):
        scan=Mock(wraps=lexer.tokenize);second=Mock(wraps=lexer.tokenize)
        with patch.object(modules,'tokenize',scan),patch.object(parser,'tokenize',second):
            modules.load_project(self.entry)
        scan.assert_called_once();second.assert_called_once()

    def test_legacy_parse_override_receives_old_arguments(self):
        hook=Mock(wraps=parser.parse)
        with patch.object(modules,'parse',hook):modules.load_project(self.entry)
        hook.assert_called_once_with(TEXT,str(self.entry))

    def test_shared_lexer_tokens_match_all_primitive_shapes(self):
        text='// hi\r\n fn f(x: f64)->Unit effects {} {let a:i64=0xff; let b:f64=0.0; let c:f64=1.5e2;} '
        owner=Owner();batch=self.batch(owner,text)
        self.assertEqual(list(batch),lexer.tokenize(text,'unit.hepta'))

    def test_batch_replay_rejected_terminally(self):
        owner=Owner();batch=self.batch(owner);self.parse(owner,batch)
        with self.assertRaisesRegex(Rejected,'consumed'):self.parse(owner,batch)
        self.assertTrue(owner.context.closed)
        self.assertEqual(owner._ops._pending,{})

    def test_cross_owner_batch_rejected(self):
        first=Owner();batch=self.batch(first);second=Owner()
        with self.assertRaisesRegex(Rejected,'belong'):self.parse(second,batch)
        self.assertTrue(second.context.closed);self.assertFalse(first.context.closed)
        self.assertEqual(self.parse(first,batch).functions[0].name,'main')

    def test_forged_equal_batch_rejected(self):
        owner=Owner();batch=self.batch(owner)
        with self.assertRaisesRegex(Rejected,'belong'):self.parse(owner,_Batch(batch.tokens))

    def test_wrong_source_rejected(self):
        owner=Owner();batch=self.batch(owner)
        with self.assertRaisesRegex(Rejected,'source'):self.parse(owner,batch,TEXT+' ')

    def test_wrong_path_rejected(self):
        owner=Owner();batch=self.batch(owner)
        with self.assertRaisesRegex(Rejected,'path'):self.parse(owner,batch,path='other.hepta')

    def test_str_subclass_is_refused_without_equality(self):
        class Evil(str):
            def __eq__(self,other):raise AssertionError('custom equality')
        owner=Owner();batch=self.batch(owner)
        with self.assertRaises(Rejected):self.parse(owner,batch,text=Evil(TEXT))

    def test_forged_batch_does_not_invoke_custom_iteration(self):
        class Evil:
            def __iter__(self):raise AssertionError('custom iteration')
        with self.assertRaises(Rejected):self.parse(Owner(),Evil())

    def test_replaced_token_collection_refused(self):
        owner=Owner();batch=self.batch(owner);object.__setattr__(batch,'tokens',tuple(list(batch.tokens)))
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch)

    def test_mutated_token_value_refused(self):
        owner=Owner();batch=self.batch(owner);token=next(t for t in batch if t.kind=='IDENT')
        object.__setattr__(token,'value','evil')
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch)

    def test_mutated_span_refused(self):
        owner=Owner();batch=self.batch(owner);object.__setattr__(batch.tokens[0].span,'path','other')
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch)

    def test_bool_does_not_equal_admitted_integer(self):
        text='fn main()->Unit effects {} {let x:i64=1;}'
        owner=Owner();batch=self.batch(owner,text);object.__setattr__(next(t for t in batch if t.kind=='INT'),'value',True)
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch,text)

    def test_signed_zero_change_refused(self):
        text='fn main()->Unit effects {} {let x:f64=0.0;}'
        owner=Owner();batch=self.batch(owner,text);object.__setattr__(next(t for t in batch if t.kind=='FLOAT'),'value',-0.0)
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch,text)

    def test_malicious_token_value_equality_is_not_called(self):
        class Evil:
            def __eq__(self,other):raise AssertionError('custom equality')
        owner=Owner();batch=self.batch(owner);object.__setattr__(batch.tokens[0],'value',Evil())
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch)

    def test_checkpoint_mutation_before_consumption_refused(self):
        owner=Owner();batch=self.batch(owner)
        def mutate():object.__setattr__(batch.tokens[0],'kind','evil')
        owner.context.checkpoint=mutate
        with self.assertRaisesRegex(Rejected,'modified'):self.parse(owner,batch)

    def test_private_parser_snapshot_ignores_later_exposed_mutation(self):
        owner=Owner();batch=self.batch(owner);name=next(t for t in batch if t.kind=='IDENT')
        def mutate():
            if id(batch) not in owner._ops._pending:object.__setattr__(name,'value','evil')
        owner.context.checkpoint=mutate
        self.assertEqual(self.parse(owner,batch).functions[0].name,'main')
        self.assertEqual(name.value,'evil')

    def test_reentrant_replay_from_parser_checkpoint_terminal(self):
        owner=Owner();batch=self.batch(owner)
        def replay():
            if id(batch) not in owner._ops._pending:self.parse(owner,batch)
        owner.context.checkpoint=replay
        with self.assertRaises(Rejected):self.parse(owner,batch)
        self.assertTrue(owner.context.closed);self.assertEqual(owner._ops._pending,{})

    def test_cancellation_after_consumption_terminal(self):
        owner=Owner();batch=self.batch(owner)
        def cancel():
            if id(batch) not in owner._ops._pending:raise TimeoutError('stop')
        owner.context.checkpoint=cancel
        with self.assertRaises(TimeoutError):self.parse(owner,batch)
        self.assertTrue(owner.context.closed);self.assertEqual(owner._ops._pending,{})

    def test_parse_without_batch_refused(self):
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'batch'):owner._ops.parse(parser.parse,TEXT,'unit.hepta')

    def test_token_quota_precedes_parser(self):
        owner=Owner(Limits(tokens_per_parse=3))
        with patch.object(_Parser,'parse',side_effect=AssertionError('parser ran')):
            with self.assertRaisesRegex(Rejected,'tokens per parse'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['total_tokens'],3)
        self.assertEqual(owner.context.counts['parses'],0)

    def test_single_pass_exact_total_budget_and_reload_overrun(self):
        count=len(lexer.tokenize(TEXT));owner=Owner(Limits(total_tokens=count));owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'total_tokens'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['total_tokens'],count)

    def test_parse_budget_is_cumulative(self):
        owner=Owner(Limits(parses=1));owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'parses'):owner.load(self.entry)
        self.assertTrue(owner.context.closed)

    def test_parser_tokenize_hook_refused(self):
        owner=Owner()
        with patch.object(parser,'tokenize',side_effect=AssertionError('hook ran')):
            with self.assertRaisesRegex(Rejected,'token hook'):owner.load(self.entry)

    def test_checkpoint_replaces_shared_lexer_hook(self):
        owner=Owner();original=lexer.Lexer._tokenize
        owner.context.checkpoint=lambda:setattr(lexer.Lexer,'_tokenize',lambda *a: (_ for _ in ()).throw(AssertionError('hook ran')))
        try:
            with self.assertRaisesRegex(Rejected,'hook'):owner.load(self.entry)
        finally:lexer.Lexer._tokenize=original

    def test_checkpoint_replaces_parser_initializer(self):
        owner=Owner();batch=self.batch(owner);original=parser.Parser._initialize_tokens
        owner.context.checkpoint=lambda:setattr(parser.Parser,'_initialize_tokens',lambda *a: (_ for _ in ()).throw(AssertionError('hook ran')))
        try:
            with self.assertRaisesRegex(Rejected,'hook'):self.parse(owner,batch)
        finally:parser.Parser._initialize_tokens=original

    def test_lexer_diagnostics_match_legacy(self):
        for text in ('@', 'fn x(){/*', 'fn x(){let a:i64=0x_;}', 'fn x(){"bad\\escape"}'):
            def outcome(call):
                try:call()
                except HeptaError as e:return e.diagnostic.to_dict()
            self.assertEqual(outcome(lambda:lexer.tokenize(text,'unit.hepta')),
                             outcome(lambda:self.batch(Owner(),text)))

    def test_parser_diagnostics_match_legacy(self):
        for text in ('fn main(', 'fn main()->Unit effects {} {let x=;}', 'import foo'):
            def outcome(call):
                try:call()
                except HeptaError as e:return e.diagnostic.to_dict()
            owner=Owner();batch=self.batch(owner,text)
            self.assertEqual(outcome(lambda:parser.parse(text,'unit.hepta')),
                             outcome(lambda:self.parse(owner,batch,text)))

    def test_locked_profile_preserves_lock_and_revalidation(self):
        (self.root/'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(self.root);owner=Owner();h=owner.load(self.entry,locked=True)
        (self.root/'Hepta.lock').write_text('corrupt')
        self.assertTrue(h.unchanged())
        with self.assertRaises(HeptaError):packages.verify_lock(h.project.package)

    def test_override_rejected_before_token_or_path_work(self):
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'override'):owner.load(self.entry,source_overrides={})
        self.assertEqual(sum(owner.context.counts.values()),0)

    def test_all_example_graph_and_diagnostic_outcomes(self):
        paths=sorted((Path(__file__).resolve().parents[2]/'examples').rglob('*.hepta'));counts=Counter()
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

    def test_swallowed_reentrant_rejection_cannot_return_program(self):
        baseline=Owner();batch=self.batch(baseline);calls=[]
        baseline.context.checkpoint=lambda:calls.append(None)
        self.parse(baseline,batch);last=len(calls)
        owner=Owner();batch=self.batch(owner);calls=[]
        def swallow():
            calls.append(None)
            if len(calls)==last:
                try:self.parse(owner,batch)
                except Rejected:pass
        owner.context.checkpoint=swallow
        with self.assertRaisesRegex(Rejected,'terminal'):self.parse(owner,batch)
        self.assertTrue(owner.context.closed);self.assertEqual(owner._ops._pending,{})

    def test_generic_close_splits_private_tokens_not_batch(self):
        text='fn f(x: Box<Box<i64>>)->Unit effects {} {}'
        owner=Owner();batch=self.batch(owner,text);original=batch.tokens
        expected=parser.parse(text,'unit.hepta')
        self.assertEqual(asdict(self.parse(owner,batch,text)),asdict(expected))
        self.assertIs(batch.tokens,original)
        self.assertTrue(any(t.kind=='>>' for t in batch))

    def test_all_owner_profiles_reject_swallowed_final_callback_failure(self):
        from experiments.owned_loader.owner import Owner as ReadOwner
        for cls in (ReadOwner,GraphOwner,Owner):
            with self.subTest(profile=cls.__module__):
                probe=cls();calls=[];probe.context.checkpoint=lambda:calls.append(None)
                probe.load(self.entry);last=len(calls)
                owner=cls();calls=[]
                def swallow():
                    calls.append(None)
                    if len(calls)==last:
                        try:owner.load(self.entry)
                        except Rejected:pass
                owner.context.checkpoint=swallow
                with self.assertRaisesRegex(Rejected,'terminal'):owner.load(self.entry)
                self.assertTrue(owner.context.closed)

    def test_reserved_scan_failure_clears_pending_batch(self):
        self.entry.write_text('fn M0123456789abcdef_bad()->Unit effects {} {}')
        owner=Owner()
        with self.assertRaises(HeptaError) as error:owner.load(self.entry)
        self.assertEqual(error.exception.diagnostic.code,'E_MODULE_RESERVED')
        self.assertTrue(owner.context.closed);self.assertEqual(owner._ops._pending,{})

    def test_split_token_constructor_aliases_are_guarded(self):
        for name in ('Token','Span'):
            with self.subTest(alias=name):
                owner=Owner();batch=self.batch(owner)
                with patch.object(parser,name,side_effect=AssertionError('constructor hook ran')):
                    with self.assertRaisesRegex(Rejected,'hook'):self.parse(owner,batch)

    def test_shared_entry_seams_have_no_copied_algorithm(self):
        import ast,inspect,textwrap
        from .owner import _Lexer, _Parser
        for function in (_Lexer.tokenize,_Parser.__init__):
            tree=ast.parse(textwrap.dedent(inspect.getsource(function)))
            self.assertFalse(any(isinstance(n,(ast.For,ast.While)) for n in ast.walk(tree)))
        self.assertIn('_LEX_LOOP',inspect.getsource(_Lexer.tokenize))
        self.assertIn('_PARSE_INIT',inspect.getsource(_Parser.__init__))

    def test_legacy_iterable_finalizer_hook_runs_at_original_boundary(self):
        original=modules.tokenize
        def poison(*args,**kwargs):raise RuntimeError('iterable finalized before parse')
        class Tokens:
            def __init__(self,values):self.values=values
            def __iter__(self):return iter(self.values)
            def __del__(self):modules.parse=poison
        with patch.object(modules,'parse',modules.parse),patch.object(modules,'tokenize',lambda text,path:Tokens(original(text,path))):
            with self.assertRaisesRegex(RuntimeError,'iterable finalized'):modules.load_project(self.entry)

    def test_legacy_iterator_finalizer_hook_runs_before_parse(self):
        original=modules.tokenize
        def poison(*args,**kwargs):raise RuntimeError('iterator finalized before parse')
        class Tokens:
            def __init__(self,values):self.values=iter(values)
            def __iter__(self):return self
            def __next__(self):return next(self.values)
            def __del__(self):modules.parse=poison
        with patch.object(modules,'parse',modules.parse),patch.object(modules,'tokenize',lambda text,path:Tokens(original(text,path))):
            with self.assertRaisesRegex(RuntimeError,'iterator finalized'):modules.load_project(self.entry)

    def test_scan_receipt_is_owner_local_and_cleared_on_consumption(self):
        first=Owner();second=Owner();batch=self.batch(first)
        receipt=first._ops.scan_receipt();self.assertIs(receipt,batch)
        self.assertIsNone(first._ops.scan_receipt())
        self.assertIsNone(second._ops.scan_receipt())
        self.parse(first,receipt)
        self.assertIsNone(first._ops.scan_receipt())
        with self.assertRaises(Rejected):self.parse(first,first._ops.scan_receipt())

    def test_scan_receipt_cannot_substitute_another_source(self):
        owner=Owner();self.batch(owner);self.batch(owner,TEXT+' ')
        with self.assertRaisesRegex(Rejected,'source'):self.parse(owner,owner._ops.scan_receipt())
