import tempfile
from pathlib import Path
import unittest
from .context import Context, Limits
from .observer import Observer
from experiments.request_load.context import Rejected


class ObserverTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.source=self.root/'source.h';self.source.write_bytes(b'abc')
        self.dep=self.root/'unit.d';self.dep.write_text('obj.o: '+str(self.source)+'\n')

    def observe(self, **limits):
        context=Context(Limits(**limits));observer=Observer(context)
        observer.collect(self.dep)
        return context,observer

    def rejected(self, **limits):
        context=Context(Limits(**limits));observer=Observer(context)
        with self.assertRaises(Exception):observer.collect(self.dep)
        self.assertTrue(context.closed)
        with self.assertRaises(Rejected):context.read(self.source)
        return context

    def test_exact_dependency_bytes(self):
        context,obs=self.observe(native_dependency=3)
        self.assertEqual(context.reader.bytes_read,self.dep.stat().st_size+3)
        obs.revalidate();self.assertEqual(context.counts['native_entries'],2)

    def test_dependency_one_short(self):self.rejected(native_dependency=2)
    def test_exact_depfile_bytes(self):self.observe(depfile=self.dep.stat().st_size)
    def test_depfile_one_short(self):self.rejected(depfile=self.dep.stat().st_size-1)
    def test_exact_aggregate_bytes(self):self.observe(total_bytes=self.dep.stat().st_size+3)
    def test_aggregate_one_short(self):self.rejected(total_bytes=self.dep.stat().st_size+2)
    def test_exact_read_count(self):self.observe(reads=2)
    def test_read_count_one_short(self):self.rejected(reads=1)
    def test_exact_entry_count(self):self.observe(native_entries=1)
    def test_duplicate_entry_charges_before_deduplication(self):
        self.dep.write_text('o: '+str(self.source)+' '+str(self.source)+'\n')
        context=self.rejected(native_entries=1)
        self.assertEqual(context.reader.reads,2)
    def test_exact_path_length(self):self.observe(native_path_chars=len(str(self.source)))
    def test_path_length_one_short(self):self.rejected(native_path_chars=len(str(self.source))-1)

    def test_revalidation_cannot_reset_bytes(self):
        context,obs=self.observe(total_bytes=self.dep.stat().st_size+5)
        with self.assertRaises(Rejected):obs.revalidate()
        self.assertTrue(context.closed)

    def test_revalidation_cannot_reset_reads(self):
        context,obs=self.observe(reads=2)
        with self.assertRaises(Rejected):obs.revalidate()
        self.assertTrue(context.closed)

    def test_revalidation_cannot_reset_entries(self):
        context,obs=self.observe(native_entries=1)
        with self.assertRaises(Rejected):obs.revalidate()
        self.assertTrue(context.closed)

    def test_loader_reads_reduce_native_allowance(self):
        context=Context(Limits(total_bytes=self.dep.stat().st_size+5));context.read(self.source,'source')
        with self.assertRaises(Rejected):Observer(context).collect(self.dep)
        self.assertTrue(context.closed)

    def test_duplicate_changed_content_does_not_overwrite_prior_digest(self):
        context,obs=self.observe();self.source.write_bytes(b'xyz')
        with self.assertRaisesRegex(Rejected,'between observations'):obs.collect(self.dep)
        self.assertTrue(context.closed)

    def test_equal_content_symlink_retarget_refused(self):
        other=self.root/'other.h';other.write_bytes(b'abc')
        alias=self.root/'alias.h';alias.symlink_to(self.source)
        self.dep.write_text('o: '+str(alias)+'\n');context,obs=self.observe()
        alias.unlink();alias.symlink_to(other)
        with self.assertRaisesRegex(Rejected,'changed'):obs.revalidate()
        self.assertTrue(context.closed)

    def test_changed_deleted_and_nonregular_dependency_terminal(self):
        for change in ('changed','deleted','directory'):
            with self.subTest(change=change):
                self.source.write_bytes(b'abc');context,obs=self.observe()
                if change=='changed':self.source.write_bytes(b'xyz')
                else:self.source.unlink()
                if change=='directory':self.source.mkdir()
                with self.assertRaises(Exception):obs.revalidate()
                self.assertTrue(context.closed)
                if self.source.is_dir():self.source.rmdir()

    def test_output_alias_retarget_refused(self):
        output=self.root/'result';original=self.root/'old';original.write_text('old')
        output.symlink_to(original);context,obs=self.observe()
        destination=output.resolve();output.unlink();output.symlink_to(self.source)
        with self.assertRaisesRegex(Rejected,'output binding'):obs.revalidate(output=str(output),destination=destination)
        self.assertEqual(self.source.read_bytes(),b'abc');self.assertTrue(context.closed)

    def test_near_publication_dependency_alias_collision_refused(self):
        alias=self.root/'alias.h';alias.symlink_to(self.source)
        self.dep.write_text('o: '+str(alias)+'\n');context,obs=self.observe()
        output=self.root/'result';output.write_bytes(b'abc')
        alias.unlink();alias.symlink_to(output)
        with self.assertRaisesRegex(Rejected,'binding changed'):
            obs.check_destination(str(output),output.resolve(),())
        self.assertTrue(context.closed)

    def test_direct_output_collision_refused(self):
        context,obs=self.observe()
        with self.assertRaisesRegex(Rejected,'aliases'):
            obs.revalidate(output=str(self.source),destination=self.source.resolve())
        self.assertTrue(context.closed)

    def test_parser_failures_are_terminal(self):
        bad=['o: $bad\n','o: x\\q\n','o: a\nx: b\n','o: a #comment\n','o: a:b\n','o:\n','o a\n','o: a\\','o: \0\n']
        for text in bad:
            with self.subTest(text=text):
                self.dep.write_text(text);self.rejected()

    def test_invalid_utf8_terminal(self):
        self.dep.write_bytes(b'o: \xff\n');self.rejected()

    def test_escaped_paths_and_continuation(self):
        paths=[]
        for name in ['a$b.h', "a'b.h"]:
            path=self.root/name;path.write_bytes(b'ok');paths.append(path)
        self.dep.write_text('o: '+ ' \\\n '.join(str(p).replace('$','$$') for p in paths)+'\n')
        context,obs=self.observe();self.assertEqual(set(obs.receipt()),set(map(str,paths)))
        obs.revalidate()
        for token in ('a\\ b.h', 'a\\#b.h', 'a\\\\b.h', 'a\\\n'):
            with self.subTest(token=token):
                self.dep.write_text('o: '+str(self.root)+'/'+token+'\n');self.rejected()

    def test_growth_sentinel_is_cumulative_and_terminal(self):
        changed=[]
        context=None
        def checkpoint():
            if context and context.reader.reads==2 and not changed:
                with self.source.open('ab') as stream:stream.write(b'x')
                changed.append(True)
        context=Context(Limits(native_dependency=3),checkpoint)
        with self.assertRaisesRegex(Rejected,'grew'):Observer(context).collect(self.dep)
        self.assertEqual(context.reader.bytes_read,self.dep.stat().st_size+4)
        self.assertTrue(context.closed)

    def test_callback_exception_identity_and_terminal_state(self):
        error=RuntimeError('stop')
        def checkpoint():raise error
        context=Context(checkpoint=checkpoint)
        with self.assertRaises(RuntimeError) as caught:Observer(context).collect(self.dep)
        self.assertIs(caught.exception,error);self.assertTrue(context.closed)

    def test_native_roles_configured_before_reads(self):
        context=Context(Limits(native_dependency=2_000_000,depfile=3_000_000))
        self.assertEqual(context.reader.limits.per_file,3_000_000)
        self.assertEqual(context.reader.reads,0)
