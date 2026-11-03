from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.modules import load_project
from hepta.packages import write_lock
from hepta.lexer import tokenize
from experiments.c_char_boundary import test_prototype as fixtures
from experiments.c_char_boundary.prototype import Prepared, Rejected as NativeRejected
from experiments.c_char_boundary.build_plan import Request
from .context import Context, Limits, Rejected
from .build_plan import execute


class ContextTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entry = self.root/'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def package(self):
        (self.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def test_standalone_identity_and_report_parity(self):
        expected = load_project(self.entry)
        actual = Context().load(self.entry)
        self.assertEqual(actual.report(), expected.report())
        self.assertEqual(actual.source_bytes, expected.source_bytes)

    def test_valid_locked_package_identity_and_report_parity(self):
        self.package(); write_lock(self.root)
        expected = load_project(self.entry, locked=True)
        actual = Context().load(self.entry, locked=True)
        self.assertEqual(actual.report(), expected.report())
        self.assertTrue(actual.unchanged())

    def test_stale_lock_preserves_original_diagnostic(self):
        self.package(); write_lock(self.root)
        self.entry.write_text(self.entry.read_text()+'\n')
        for loader in (load_project, Context().load):
            with self.assertRaises(HeptaError) as error:
                loader(self.entry, locked=True)
            self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_STALE')

    def test_source_refused_before_parser(self):
        with patch('experiments.request_load.context.BoundedParser.parse') as parser:
            with self.assertRaisesRegex(Rejected, 'quota'):
                Context(Limits(source=10)).load(self.entry)
            parser.assert_not_called()

    def test_unused_inventory_source_is_bounded(self):
        self.package(); (self.root/'unused.hepta').write_bytes(b'x'*101)
        with self.assertRaisesRegex(Rejected, 'quota'):
            Context(Limits(source=100)).load(self.entry)

    def test_padded_manifest_is_bounded_before_toml(self):
        self.package()
        with patch('tomllib.loads') as parse:
            with self.assertRaisesRegex(Rejected, 'quota'):
                Context(Limits(manifest=10)).load(self.entry)
            parse.assert_not_called()

    def test_valid_padded_lock_is_bounded_before_json(self):
        self.package();write_lock(self.root)
        lock=self.root/'Hepta.lock';lock.write_bytes(b' '*1000+lock.read_bytes())
        with patch('json.loads') as parse:
            with self.assertRaisesRegex(Rejected, 'quota'):
                Context(Limits(lock=1000)).load(self.entry, locked=True)
            parse.assert_not_called()

    def test_read_budget_spans_initial_unchanged_and_later_reloads(self):
        data=self.entry.read_bytes()
        context=Context(Limits(total_bytes=len(data)*2))
        project=context.load(self.entry)
        self.assertEqual(context.reader.bytes_read, len(data)*2)
        with self.assertRaisesRegex(Rejected, 'quota'):
            project.unchanged()
        self.assertTrue(context.closed)
        with self.assertRaisesRegex(Rejected, 'terminal'):
            context.load(self.entry)

    def test_changed_source_recheck_does_not_materialize_overrun(self):
        context=Context(Limits(source=100))
        project=context.load(self.entry)
        self.entry.write_bytes(b'x'*101)
        before=context.reader.bytes_read
        with self.assertRaisesRegex(Rejected, 'quota'):
            project.unchanged()
        self.assertEqual(context.reader.bytes_read, before)

    def test_inventory_counts_irrelevant_entries_before_sort(self):
        self.package()
        for i in range(20): (self.root/f'irrelevant-{i}').touch()
        context=Context(Limits(inventory_entries=5))
        with self.assertRaisesRegex(Rejected, 'inventory_entries'):
            context.load(self.entry)
        self.assertEqual(context.counts['inventory_entries'], 5)

    def test_directory_depth_before_descending(self):
        self.package();(self.root/'a'/'b').mkdir(parents=True)
        with self.assertRaisesRegex(Rejected, 'depth'):
            Context(Limits(directory_depth=2)).load(self.entry)

    def test_module_depth_and_edge_work(self):
        self.entry.write_text('import first; fn main()->Unit effects {} {}')
        (self.root/'first.hepta').write_text('import second;')
        (self.root/'second.hepta').write_text('')
        with self.assertRaisesRegex(Rejected, 'depth'):
            Context(Limits(module_depth=2)).load(self.entry)
        with self.assertRaisesRegex(Rejected, 'module_edges'):
            Context(Limits(module_edges=2)).load(self.entry)

    def test_package_depth_and_cumulative_rechecks(self):
        self.package()
        dep=self.root/'dep';dep.mkdir()
        (dep/'lib.hepta').write_text('')
        (dep/'hepta.toml').write_text('[package]\nname="dep"\nversion="1.0.0"\nkind="lib"\nsource_root="."\nentry="lib.hepta"\n')
        with (self.root/'hepta.toml').open('a') as f:f.write('[dependencies]\ndep={path="dep"}\n')
        with self.assertRaisesRegex(Rejected, 'depth'):
            Context(Limits(package_depth=1)).load(self.entry)
        with self.assertRaisesRegex(Rejected, 'packages'):
            Context(Limits(packages=2)).load(self.entry)

    def test_tokens_admitted_during_lexing_not_after_full_list(self):
        context=Context(Limits(tokens_per_parse=5))
        with self.assertRaisesRegex(Rejected, 'tokens per parse'):
            context.load(self.entry)
        self.assertEqual(context.counts['total_tokens'], 5)
        self.assertEqual(context.counts['parses'], 0)

    def test_lexer_parity_without_duplicate_tokenization(self):
        text='// comment\nfn main()->Unit effects {} {let n:i64=12+3;} '
        context=Context()
        self.assertEqual(context.tokenize(text), tokenize(text))
        with patch('hepta.parser.tokenize', side_effect=AssertionError('duplicate tokenization')):
            self.assertEqual(context.parse(text).functions[0].name, 'main')

    def test_parse_and_token_counts_span_reload(self):
        context=Context(Limits(parses=1))
        context.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'parses'):
            context.load(self.entry)
        context=Context(Limits(total_tokens=12))
        context.load(self.entry)
        with self.assertRaisesRegex(Rejected, 'total_tokens'):
            context.load(self.entry)

    def test_existing_deep_expression_diagnostic_is_retained(self):
        self.entry.write_text('fn main()->Unit effects {} {let n:i64='+'+'.join(['1']*150)+';}')
        for loader in (load_project, Context().load):
            with self.assertRaises(HeptaError) as error:loader(self.entry)
            self.assertEqual(error.exception.diagnostic.code, 'E_PARSE_DEPTH')

    def test_stricter_parser_nesting_is_opt_in(self):
        self.entry.write_text('fn main()->Unit effects {} {let n:i64=((((1))));}')
        load_project(self.entry)
        with self.assertRaisesRegex(Rejected, 'depth'):
            Context(Limits(parser_depth=2)).load(self.entry)

    def test_json_nesting_and_quoted_brackets(self):
        context=Context(Limits(json_depth=2))
        self.assertEqual(context.json(b'{"brackets":"[[[[["}', self.entry), {'brackets':'[[[[['})
        with self.assertRaisesRegex(Rejected, 'depth'):
            context.json(b'[[[]]]', self.entry)

    def test_overrides_rejected_before_any_read(self):
        context=Context()
        with self.assertRaisesRegex(Rejected, 'overrides'):
            context.load(self.entry, source_overrides={})
        self.assertEqual(context.reader.reads, 0)

    def test_contexts_are_independent(self):
        first=Context(Limits(reads=1));second=Context()
        with self.assertRaises(Rejected):first.load(self.entry)
        self.assertTrue(second.load(self.entry).unchanged())
        self.assertFalse(second.closed)

    def test_no_path_read_bytes_fallback(self):
        self.package();write_lock(self.root)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded read')):
            self.assertTrue(Context().load(self.entry, locked=True).unchanged())

    def test_directory_symlink_original_rejection(self):
        self.package();(self.root/'real').mkdir();(self.root/'alias').symlink_to(self.root/'real',target_is_directory=True)
        with self.assertRaises(HeptaError) as error:Context().load(self.entry)
        self.assertEqual(error.exception.diagnostic.code, 'E_PACKAGE_SOURCE_LINK')

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO required')
    def test_fifo_entry_rejected_without_waiting(self):
        self.entry.unlink();os.mkfifo(self.entry)
        with self.assertRaisesRegex(Rejected,'regular'):Context().load(self.entry)

    def test_expired_checkpoint_before_any_file_read(self):
        def expired():raise TimeoutError('deadline')
        context=Context(checkpoint=expired)
        with self.assertRaises(TimeoutError):context.load(self.entry)
        self.assertEqual(context.reader.reads,0)
        self.assertTrue(context.closed)


    def test_all_role_exact_limits_and_one_over(self):
        for role in ('source','manifest','lock','sidecar','header'):
            with self.subTest(role=role):
                self.entry.write_bytes(b'12345678')
                context=Context(replace(Limits(), **{role:8}))
                self.assertEqual(context.read(self.entry,role),b'12345678')
                self.entry.write_bytes(b'123456789')
                with self.assertRaisesRegex(Rejected,'quota'):
                    context.read(self.entry,role)
                self.assertEqual(context.reader.bytes_read,8)

    def test_header_role_survives_misleading_source_extension(self):
        self.entry.write_bytes(b'12345678')
        context=Context(Limits(source=100,header=8))
        context.read(self.entry,'header')
        self.entry.write_bytes(b'x'*9)
        with self.assertRaisesRegex(Rejected,'quota'):
            context.read(self.entry)
        self.assertEqual(context.reader.bytes_read,8)

    def test_role_cap_controls_post_stat_growth(self):
        self.entry.write_bytes(b'1234')
        context=Context(Limits(source=100,header=4))
        original=os.fstat
        def grow(fd):
            result=original(fd)
            with self.entry.open('ab') as f:f.write(b'x'*1000)
            return result
        with patch('os.fstat',grow):
            with self.assertRaisesRegex(Rejected,'grew'):
                context.read(self.entry,'header')
        self.assertEqual(context.reader.bytes_read,5)

    def test_reentrant_checkpoint_cannot_load_or_reset_budget(self):
        context=Context()
        context.checkpoint=lambda:context.load(self.entry)
        with self.assertRaisesRegex(Rejected,'reentrant'):
            context.load(self.entry)
        self.assertTrue(context.closed)
        self.assertEqual(context.reader.reads,0)

    def test_diamond_module_identity_and_cached_edge_count(self):
        self.entry.write_text('import left; import right; fn main()->Unit effects {} {}')
        for name in ('left','right'):(self.root/(name+'.hepta')).write_text('import shared;')
        (self.root/'shared.hepta').write_text('')
        context=Context()
        actual=context.load(self.entry)
        self.assertEqual(actual.report(),load_project(self.entry).report())
        self.assertEqual(context.counts['modules'],4)
        self.assertEqual(context.counts['module_edges'],5)

    def test_source_file_symlink_identity_parity(self):
        original=self.root/'actual.hepta'
        self.entry.rename(original);self.entry.symlink_to(original)
        self.assertEqual(Context().load(self.entry).report(),load_project(self.entry).report())

    def test_metadata_parse_invocations_are_cumulative(self):
        context=Context(Limits(metadata_parses=1))
        context.json(b'{}',self.entry)
        with self.assertRaisesRegex(Rejected,'metadata_parses'):
            context.toml(b'',self.entry)


    def test_upstream_fork_inputs_are_pinned(self):
        import hashlib
        # Private owner admission seams reviewed against normal-source #623;
        # raw #622 legacy differential behavior remains independently covered.
        expected={
            '_loader_ops':'f9a4e12a33f64352c007dd82625d07c55160bc3c77e39eed65bbd53295dd5cad',
            'modules':'9436ee8b62127adfff70add4c81426efbbdb502cf234ca790337e1046d3fbd76',
            'packages':'a3c588c7d1b77ff8a8c6c98c057ada28437a802d646299a8903e54fa033afa2b',
            'lexer':'e8614da15be2ab89f5e9e70f206476db9884b3ddb6e0c4e0839f66940eda7d87',
            'parser':'6dfb89824e8cdc6992af22a9f3a422205ec4387def1c3cb6739937364253d4e0'}
        root=Path(__file__).resolve().parents[2]
        for name,digest in expected.items():
            self.assertEqual(hashlib.sha256((root/'hepta'/(name+'.py')).read_bytes()).hexdigest(),digest,
                             'upstream changed: review isolated fork before refreshing pin')


    def test_encoded_json_escaped_quote_cannot_hide_depth(self):
        data=json.dumps(['"', [[[[[]]]]]])
        for encoding in ('utf-8','utf-8-sig','utf-16','utf-16-le','utf-16-be','utf-32','utf-32-le','utf-32-be'):
            with self.subTest(encoding=encoding):
                context=Context(Limits(json_depth=2))
                with self.assertRaisesRegex(Rejected,'depth'):
                    context.json(data.encode(encoding), self.entry)
                self.assertTrue(context.closed)
                self.assertEqual(Context().json(data.encode(encoding),self.entry),json.loads(data))


@unittest.skipUnless(fixtures.CC, 'GCC required')
class PreparedContextTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CharPrototypeTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.entry,_=self.fixture.fixture()

    def test_native_plan_uses_context_through_revalidation(self):
        result=execute(Request(str(self.entry),'run',cc=fixtures.CC))
        self.assertTrue(result['ok'])
        self.assertTrue(result['user_program_executed'])

    def test_prepared_reloads_share_parse_budget(self):
        context=Context(Limits(parses=3))
        loaded=context.load(self.entry)
        self.assertEqual(context.counts['parses'],2)
        with self.assertRaisesRegex(Rejected,'parses'):
            Prepared(self.entry,cc=fixtures.CC,_context=context,_project=loaded)
        self.assertTrue(context.closed)

    def test_unrelated_supplied_project_cannot_bypass_context(self):
        with self.assertRaisesRegex(NativeRejected,'does not belong'):
            Prepared(self.entry,cc=fixtures.CC,_context=Context(),_project=load_project(self.entry))

    def test_sidecar_and_original_header_roles(self):
        for limits in (Limits(sidecar=10),Limits(header=10)):
            with self.subTest(limits=limits):
                with self.assertRaisesRegex(Rejected,'quota'):
                    Context(limits).load(self.entry)

    def test_prepared_source_sidecar_header_reads_never_fallback(self):
        context=Context()
        loaded=context.load(self.entry)
        forbidden={self.entry,self.fixture.sidecar,self.fixture.root/'native.hepta',self.fixture.root/'api.h'}
        original=Path.read_bytes
        def checked(path):
            if path in forbidden:raise AssertionError('unbounded qualification input read: '+str(path))
            return original(path)
        with patch.object(Path,'read_bytes',checked),Prepared(self.entry,cc=fixtures.CC,_context=context,_project=loaded):
            pass
        self.assertGreater(context.counts['parses'],2)
        self.assertGreater(context.reader.reads,10)

    def test_locked_native_build_and_late_source_mutation(self):
        root=self.fixture.root
        (root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        write_lock(root)
        output=root/'out'
        request=Request(str(self.entry),'build',output=str(output),cc=fixtures.CC,locked=True)
        self.assertTrue(execute(request)['ok'])
        original_output=output.read_bytes()
        original_compile=Prepared.compile
        def mutate(prepared,**options):
            artifact,receipt=original_compile(prepared,**options)
            self.entry.write_text(self.entry.read_text()+'\n')
            return artifact,receipt
        with patch.object(Prepared,'compile',mutate):
            with self.assertRaises(NativeRejected):execute(request)
        self.assertEqual(output.read_bytes(),original_output)

    def test_crlf_binding_default_and_context_compatibility(self):
        bindings=self.fixture.root/'native.hepta'
        source=bindings.read_text()
        first,rest=source.split('\n',1)
        bindings.write_bytes((first+'\n'+rest.replace('\n','\r\n')).encode())
        metadata=json.loads(self.fixture.sidecar.read_text())
        from hepta.packages import digest
        metadata['source_sha256']=digest(bindings.read_bytes())
        self.fixture.sidecar.write_text(json.dumps(metadata))
        with Prepared(self.entry,cc=fixtures.CC):pass
        with Prepared(self.entry,cc=fixtures.CC,_context=Context()):pass
