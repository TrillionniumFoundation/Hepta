"""Real graph/pipeline late-lock regression controls, with test-only mutation probes."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import modules, packages, pipeline
from hepta.ast import HeptaError
from experiments.policy_failures.owner import Cancelled, Policy, Rejected
from .adapter import FrontendRequest
from .owner import Owner
from . import cli

TEXT = 'fn main()->Unit effects {} {}'
PREFIX = ['check', '--frontend-only', '--policy', 'loader-experimental-v1']


class LockRevalidationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)
        self.manifest = self.root / 'hepta.toml'
        self.manifest.write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(self.root)
        self.lock = self.root / 'Hepta.lock'
        self.argv = PREFIX + [str(self.entry), '--locked']

    def mutate(self, mode):
        if mode == 'missing': self.lock.unlink()
        elif mode == 'directory':
            self.lock.unlink(); self.lock.mkdir()
        elif mode == 'malformed': self.lock.write_text('broken')
        elif mode == 'utf8': self.lock.write_bytes(b'\xff')
        elif mode == 'stale': self.lock.write_text('{}')
        elif mode == 'schema': self.lock.write_text('[]')
        elif mode == 'pretty': self.lock.write_text(json.dumps(json.loads(self.lock.read_text()), indent=4))

    def evaluate_after(self, action, request=None):
        real = pipeline.analyze
        def analyze(*args, **kwargs):
            result = real(*args, **kwargs)
            action()
            return result
        with ExitStack() as stack:
            stack.enter_context(patch.object(pipeline, 'analyze', analyze))
            if request is not None:
                stack.enter_context(patch.object(cli, 'FrontendRequest', return_value=request))
            return cli.evaluate(self.argv)

    def assert_late(self, mode, diagnostic):
        response, code = self.evaluate_after(lambda: self.mutate(mode))
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], diagnostic)
        self.assertEqual(response['first_failure']['category'], 'diagnostic')
        self.assertEqual(response['first_failure']['phase'], 'lock_revalidation')
        self.assertEqual(response['lock_revalidation'], 'not_completed')
        self.assertFalse(response['ok'])
        self.assertFalse(response['atomic_snapshot'])

    def test_late_malformed(self): self.assert_late('malformed', 'E_LOCK_INVALID')
    def test_late_deleted(self): self.assert_late('missing', 'E_LOCK_MISSING')
    def test_late_stale(self): self.assert_late('stale', 'E_LOCK_STALE')
    def test_late_directory(self): self.assert_late('directory', 'E_LOCK_MISSING')
    def test_late_wrong_schema(self): self.assert_late('schema', 'E_LOCK_STALE')
    def test_late_invalid_utf8(self): self.assert_late('utf8', 'E_LOCK_INVALID')

    def test_initial_lock_diagnostics_unchanged(self):
        original = self.lock.read_bytes()
        for mode in ('malformed', 'missing', 'stale', 'utf8', 'schema'):
            with self.subTest(mode=mode):
                self.lock.write_bytes(original); self.mutate(mode)
                with self.assertRaises(HeptaError) as old:
                    pipeline.analyze_project(self.entry, native=False, locked=True)
                response, code = cli.evaluate(self.argv)
                self.assertEqual(code, 1)
                self.assertEqual(response['diagnostics'], [old.exception.diagnostic.to_dict()])
                self.assertEqual(response['lock_revalidation'], 'not_completed')

    def test_unchanged_lock_report_parity(self):
        expected = pipeline.analyze_project(self.entry, native=False, locked=True).report
        response, code = cli.evaluate(self.argv)
        self.assertEqual(code, 0)
        self.assertEqual(response['report'], expected)
        self.assertEqual(response['lock_revalidation'], 'post_analysis_observed')

    def test_semantic_reserialization(self):
        response, code = self.evaluate_after(lambda: self.mutate('pretty'))
        self.assertEqual(code, 0)
        self.assertEqual(response['lock_revalidation'], 'post_analysis_observed')

    def test_unlocked_locks_ignored(self):
        self.argv.remove('--locked')
        for mode in ('missing', 'malformed', 'schema', 'pretty'):
            with self.subTest(mode=mode):
                packages.write_lock(self.root)
                response, code = self.evaluate_after(lambda: self.mutate(mode))
                self.assertEqual(code, 0)
                self.assertEqual(response['lock_revalidation'], 'not_requested')

    def test_unlocked_creating_lock_ignored(self):
        self.lock.unlink(); self.argv.remove('--locked')
        response, code = self.evaluate_after(lambda: self.lock.write_text('broken'))
        self.assertEqual(code, 0)
        self.assertEqual(response['lock_revalidation'], 'not_requested')

    def test_locked_standalone_context(self):
        self.manifest.unlink()
        response, code = cli.evaluate(self.argv)
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], 'E_LOCK_CONTEXT')

    def test_source_change_old_lock_graph_race(self):
        response, code = self.evaluate_after(lambda: self.entry.write_text(TEXT+'\n'))
        self.assertEqual(code, 1)
        self.assertEqual(response['report']['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertEqual(response['lock_revalidation'], 'not_completed')

    def test_source_change_regenerated_lock_stale(self):
        def action():
            self.entry.write_text(TEXT+'\n'); packages.write_lock(self.root)
        response, code = self.evaluate_after(action)
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], 'E_LOCK_STALE')

    def test_lock_error_precedes_graph_drift(self):
        def action():
            self.entry.write_text('broken'); self.mutate('malformed')
        response, code = self.evaluate_after(action)
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], 'E_LOCK_INVALID')

    def test_manifest_mutation_matrix(self):
        original = self.manifest.read_text()
        for text in (original.replace('1.0.0','2.0.0'), original.replace('main.hepta','other.hepta'),
                     original.replace('source_root="."','source_root="src"'), '[broken'):
            with self.subTest(text=text):
                self.manifest.write_text(original)
                response, code = self.evaluate_after(lambda: self.manifest.write_text(text))
                self.assertEqual(code, 1)
                self.assertEqual(response['report']['diagnostics'][-1]['code'], 'E_MODULE_RACE')
                self.assertEqual(response['lock_revalidation'], 'not_completed')

    def test_inventory_change(self):
        response, code = self.evaluate_after(lambda: (self.root/'new.hepta').write_text(TEXT))
        self.assertEqual(code, 1)
        self.assertEqual(response['report']['diagnostics'][-1]['code'], 'E_MODULE_RACE')

    def test_public_graph_mutation_cannot_replace_authority(self):
        request = FrontendRequest(config={'locked': True})
        def action():
            public = request.handle.project
            public.locked = False; public.package = None; public.package_state = {}
            public.source_bytes.clear(); public.bindings.clear()
            self.mutate('stale')
        response, code = self.evaluate_after(action, request)
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], 'E_LOCK_STALE')

    def test_foreign_handle_no_additional_reads(self):
        owner = Owner(); handle = Owner().load(self.entry, locked=True)
        with self.assertRaises(Rejected): owner.revalidate(handle)
        self.assertEqual(owner.context.reader.reads, 0)
        self.assertEqual(owner.context.failure.category, 'schema')
        self.assertFalse(owner._busy)

    def test_reused_request_no_more_reads(self):
        request = FrontendRequest(config={'locked':True}); request.check(self.entry)
        reads = request.owner.context.reader.reads
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, reads)

    def test_wrong_thread_no_reads(self):
        request = FrontendRequest(config={'locked':True}); caught=[]
        def run():
            try: request.check(self.entry)
            except BaseException as error: caught.append(error)
        worker = threading.Thread(target=run); worker.start(); worker.join()
        self.assertIsInstance(caught[0], Rejected)
        self.assertEqual(request.owner.context.failure.category, 'thread')
        self.assertEqual(request.owner.context.reader.reads, 0)

    def test_overlay_refused_before_reads(self):
        request = FrontendRequest(config={'locked':True})
        with self.assertRaises(Rejected): request.check(self.entry, source_overrides={})
        self.assertEqual(request.owner.context.reader.reads, 0)

    def test_reentrant_owner_sticky_no_more_reads(self):
        owner = None; active = False; caught=[]
        def checkpoint():
            nonlocal active
            if active:
                active = False
                try: owner.revalidate(handle)
                except Rejected as error: caught.append(error)
        owner = Owner(checkpoint=checkpoint); handle = owner.load(self.entry, locked=True)
        active=True; reads=owner.context.reader.reads
        with self.assertRaises(Rejected): owner.revalidate(handle)
        self.assertEqual(owner.context.failure.category, 'reentrancy')
        self.assertEqual(owner.context.reader.reads, reads)
        self.assertFalse(owner._busy)

    def test_one_owner_ledger_and_extra_read_charged(self):
        request = FrontendRequest(config={'locked':True})
        owner=request.owner; context=owner.context; ops=owner._ops; reader=context.reader; before=[]
        response, code=self.evaluate_after(lambda:before.append((reader.reads,reader.bytes_read)),request)
        self.assertEqual(code,0)
        self.assertIs(request.owner,owner); self.assertIs(owner.context,context)
        self.assertIs(owner._ops,ops); self.assertIs(context.reader,reader)
        self.assertGreater(reader.reads,before[0][0])
        self.assertGreaterEqual(reader.bytes_read,before[0][1]+self.lock.stat().st_size)

    def initial_usage(self):
        owner=Owner(); owner.load(self.entry,locked=True)
        return owner.context.reader.reads, owner.context.reader.bytes_read

    def test_cumulative_read_exhaustion(self):
        reads,_=self.initial_usage()
        request=FrontendRequest(config={'locked':True},policy=Policy(limits={'reads':reads}))
        response,code=self.evaluate_after(lambda:None,request)
        self.assertEqual(code,3); self.assertEqual(response['first_failure']['dimension'],'reads')
        self.assertEqual(response['first_failure']['observed_reads'],reads)
        self.assertEqual(response['lock_revalidation'],'not_completed')

    def test_cumulative_total_byte_exhaustion(self):
        _,used=self.initial_usage()
        request=FrontendRequest(config={'locked':True},policy=Policy(limits={'total_bytes':used+1}))
        response,code=self.evaluate_after(lambda:None,request)
        self.assertEqual(code,3); self.assertEqual(response['first_failure']['dimension'],'total_bytes')
        self.assertEqual(response['first_failure']['observed_bytes'],used) # fstat rejects before bytes

    def test_lock_file_cap_overflow_sentinel(self):
        cap=self.lock.stat().st_size
        request=FrontendRequest(config={'locked':True},policy=Policy(limits={'lock':cap}))
        real_stat=os.fstat
        def stat(fd):
            info=real_stat(fd)
            if request.phase=='revalidation': self.lock.write_bytes(b' '*(cap+5))
            return info
        with patch.object(os,'fstat',stat):
            response,code=self.evaluate_after(lambda:None,request)
        self.assertEqual(code,3); self.assertEqual(response['first_failure']['dimension'],'lock')
        self.assertEqual(response['first_failure']['attempted'],cap+1)

    def test_json_depth_budget(self):
        request=FrontendRequest(config={'locked':True})
        response,code=self.evaluate_after(lambda:self.lock.write_text('['*500+'0'+']'*500),request)
        self.assertEqual(code,3); self.assertEqual(response['first_failure']['dimension'],'json_depth')

    def test_cancel_stage_matrix(self):
        for phase in ('before_load','before_analysis','after_analysis','revalidation'):
            with self.subTest(phase=phase):
                request=None
                def checkpoint():
                    if request.phase==phase: request.cancel()
                request=FrontendRequest(config={'locked':True},checkpoint=checkpoint)
                with patch.object(cli,'FrontendRequest',return_value=request): response,code=cli.evaluate(self.argv)
                self.assertEqual(code,130)
                self.assertEqual(response['first_failure']['category'],'cancelled')
                self.assertEqual(response['lock_revalidation'],'not_completed')

    def test_late_checkpoint_oserror_unexpected(self):
        request=None; original=OSError('private')
        def checkpoint():
            if request.phase=='revalidation': raise original
        request=FrontendRequest(config={'locked':True},checkpoint=checkpoint)
        with self.assertRaises(OSError) as raised: request.check(self.entry)
        self.assertIs(raised.exception,original)
        self.assertEqual(request.owner.context.failure.category,'unexpected')

    def test_late_unreadable_io_identity(self):
        request=FrontendRequest(config={'locked':True}); original=OSError('private')
        real=os.open
        def opened(path,*args,**kwargs):
            if Path(path)==self.lock and request.phase=='revalidation': raise original
            return real(path,*args,**kwargs)
        with patch.object(os,'open',opened):
            with self.assertRaises(OSError) as raised: request.check(self.entry)
        self.assertIs(raised.exception,original)
        self.assertEqual(request.owner.context.failure.category,'io')

    def test_source_mutation_during_lock_read_rechecked(self):
        request=FrontendRequest(config={'locked':True}); real=os.open
        def opened(path,*args,**kwargs):
            if Path(path)==self.lock and request.phase=='revalidation': self.entry.write_text(TEXT+'\n')
            return real(path,*args,**kwargs)
        with patch.object(os,'open',opened): result=request.check(self.entry)
        self.assertFalse(result.report['ok'])
        self.assertEqual(result.report['diagnostics'][-1]['code'],'E_MODULE_RACE')
        self.assertEqual(request.lock_revalidation,'not_completed')
        # Real generated C import metadata proves header and sidecar maps are
        # also rechecked after the additional lock read, with no loader mocks.
        from experiments.c_char_boundary.test_prototype import CharPrototypeTests
        for role in ('header','sidecar'):
            with self.subTest(role=role):
                fixture=CharPrototypeTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
                entry,_=fixture.fixture()
                (fixture.root/'hepta.toml').write_text(self.manifest.read_text())
                packages.write_lock(fixture.root)
                lock=fixture.root/'Hepta.lock'
                target=fixture.root/'api.h' if role=='header' else fixture.sidecar
                request=FrontendRequest(config={'locked':True})
                real_open=os.open
                def opened(path,*args,**kwargs):
                    if Path(path)==lock and request.phase=='revalidation':
                        target.write_bytes(target.read_bytes()+b'\n')
                    return real_open(path,*args,**kwargs)
                with patch.object(os,'open',opened): result=request.check(entry)
                self.assertFalse(result.report['ok'])
                self.assertEqual(result.report['diagnostics'][-1]['code'],'E_MODULE_RACE')
                self.assertEqual(request.lock_revalidation,'not_completed')

    def test_checker_diagnostic_stable_observation(self):
        self.entry.write_text('fn main()->bool effects {} { return 1; }'); packages.write_lock(self.root)
        response,code=cli.evaluate(self.argv)
        self.assertEqual(code,1); self.assertFalse(response['ok'])
        self.assertEqual(response['lock_revalidation'],'post_analysis_observed')
        self.assertIsNone(response['first_failure'])

    def test_checker_diagnostic_does_not_hide_late_lock(self):
        self.entry.write_text('fn main()->bool effects {} { return 1; }'); packages.write_lock(self.root)
        self.assert_late('malformed','E_LOCK_INVALID')

    def test_no_public_loader_or_native_fallback(self):
        with ExitStack() as stack:
            for obj,name in ((modules,'load_project'),(pipeline,'analyze_project'),(pipeline,'compile_rust')):
                stack.enter_context(patch.object(obj,name,side_effect=AssertionError(name)))
            stack.enter_context(patch('subprocess.Popen',side_effect=AssertionError('native')))
            response,code=cli.evaluate(self.argv)
        self.assertEqual(code,0)
        self.assertFalse(response['native_qualified'])

    def test_module_cli(self):
        result=subprocess.run([sys.executable,'-B','-m','experiments.frontend_lock_revalidation',*self.argv],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        response=json.loads(result.stdout)
        self.assertEqual(response['schema'],'hepta.experimental.frontend-lock-cli.v1')
        self.assertEqual(response['lock_revalidation'],'post_analysis_observed')
        self.assertFalse(response['atomic_snapshot'])

    def test_usage_and_constructor_conservative(self):
        for argv in ([],['--help']):
            response,_=cli.evaluate(argv)
            self.assertEqual(response['lock_revalidation'],'not_completed')
        with patch.object(cli,'FrontendRequest',side_effect=ValueError('private')):
            response,code=cli.evaluate(self.argv)
        self.assertEqual(code,70); self.assertEqual(response['lock_revalidation'],'not_completed')
        self.assertNotIn('private',json.dumps(response))

    def test_output_failure_exit(self):
        class Broken(io.StringIO):
            def write(self,value): raise OSError()
        self.assertEqual(cli.main(self.argv,stdout=Broken(),stderr=io.StringIO()),74)
        read_fd,write_fd=os.pipe(); os.close(read_fd)
        try:
            result=subprocess.run([sys.executable,'-B','-m',
                'experiments.frontend_lock_revalidation',*self.argv],
                stdout=write_fd,stderr=subprocess.PIPE,text=True)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode,74,result.stderr)
        self.assertEqual(result.stderr,'frontend CLI output delivery failed\n')

    def test_exact_locked_config(self):
        for value in (0,1,'true',None):
            with self.subTest(value=value),self.assertRaises(TypeError): FrontendRequest(config={'locked':value})

    def test_dependency_topology_drift(self):
        dep=self.root/'dep'; dep.mkdir(); (dep/'lib.hepta').write_text(TEXT)
        (dep/'hepta.toml').write_text('[package]\nname="dep"\nversion="1.0.0"\nkind="lib"\nsource_root="."\nentry="lib.hepta"\n')
        self.manifest.write_text(self.manifest.read_text()+'\n[dependencies]\ndep={path="dep"}\n')
        packages.write_lock(self.root)
        response,code=self.evaluate_after(lambda:(dep/'hepta.toml').write_text('[broken'))
        self.assertEqual(code,1)
        self.assertEqual(response['report']['diagnostics'][-1]['code'],'E_MODULE_RACE')

    def test_fresh_graph_budget_dimensions(self):
        initial=Owner(); initial.load(self.entry,locked=True)
        for dimension in ('metadata_parses','packages','package_edges','path_checks','inventory_entries'):
            with self.subTest(dimension=dimension):
                cap=initial.context.counts[dimension]
                request=FrontendRequest(config={'locked':True},policy=Policy(limits={dimension:cap}))
                response,code=self.evaluate_after(lambda:None,request)
                self.assertEqual(code,3)
                self.assertEqual(response['first_failure']['dimension'],dimension)
                self.assertEqual(response['lock_revalidation'],'not_completed')

    def test_final_graph_cancel_and_before_return_cancel(self):
        real=modules._revalidate
        for before in (True,False):
            with self.subTest(before=before):
                request=FrontendRequest(config={'locked':True})
                def revalidate(*args,**kwargs):
                    if before: request.cancel()
                    result=real(*args,**kwargs)
                    if not before: request.cancel()
                    return result
                with patch.object(modules,'_revalidate',revalidate):
                    with self.assertRaises(Cancelled): request.check(self.entry)
                self.assertEqual(request.lock_revalidation,'not_completed')
                self.assertEqual(request.owner.context.failure.category,'cancelled')

    def test_substituted_configuration_matrix(self):
        for name in ('owner','policy','config','reader','ops','context'):
            with self.subTest(name=name):
                request=FrontendRequest(config={'locked':True}); original=request.owner.context
                reads=[]
                def action():
                    reads.append(original.reader.reads)
                    if name=='reader': original.reader=object()
                    elif name=='ops': request.owner._ops=object()
                    elif name=='context': request.owner.context=object()
                    else: setattr(request,name,object())
                response,code=self.evaluate_after(action,request)
                self.assertEqual(code,3)
                self.assertEqual(response['first_failure']['category'],'policy_drift')
                self.assertEqual(response['first_failure']['observed_reads'],reads[0])

    def test_standalone_new_manifest_remains_unobserved(self):
        self.manifest.unlink(); self.lock.unlink(); self.argv.remove('--locked')
        response,code=self.evaluate_after(lambda:self.manifest.write_text('[broken'))
        self.assertEqual(code,0)
        self.assertEqual(response['lock_revalidation'],'not_requested')

    def test_manifest_transient_restoration_is_observation_only(self):
        original=self.manifest.read_text()
        def action():
            self.manifest.write_text('[broken'); self.manifest.write_text(original)
        response,code=self.evaluate_after(action)
        self.assertEqual(code,0)
        self.assertFalse(response['atomic_snapshot'])

    def test_source_symlink_retarget_during_final_graph(self):
        original=self.entry.read_text(); other=self.root/'other.hepta'; other.write_text(original)
        alias=self.root/'alias.hepta'; alias.symlink_to(self.entry)
        self.argv=PREFIX+[str(alias),'--locked']; packages.write_lock(self.root)
        def action():
            alias.unlink(); alias.symlink_to(other)
        response,code=self.evaluate_after(action)
        self.assertEqual(code,1)
        self.assertEqual(response['report']['diagnostics'][-1]['code'],'E_MODULE_RACE')


if __name__=='__main__': unittest.main()
