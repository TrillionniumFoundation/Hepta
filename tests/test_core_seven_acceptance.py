"""Adversarial v3 tests. Only Python fake children; never the Lean executable.

Run individual classes/method groups under timeout 180s. Fake installations copy
all 230 source files and create all 780 actual support files. Only the copied
lock names the fake binary; production has no test switch or verifier callback.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from functools import lru_cache
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import core_seven_acceptance_plan as p
from tools import core_seven_acceptance_replay as replay
from tools import check_core_seven_certificate as runner
from tools import core_seven_acceptance_capture as c


@lru_cache(maxsize=1)
def fixture():
    return p.prepare()


@contextmanager
def installation(behavior=None):
    prepared, proposal = fixture()
    behavior = behavior or {}
    with tempfile.TemporaryDirectory(prefix='seven-') as directory, ExitStack() as stack:
        home = Path(directory)
        repo = home / 'repo'
        for name in p.source_paths():
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p.ROOT / name, target)
        exe = home / 'pinned/bin/lean'
        exe.parent.mkdir(parents=True)
        inventories = {s.name: ''.join("'" + n + "' does not depend on any axioms\n" for n in p.seven._qualified_prints(s.source)) for s in proposal.stages}
        script = ('#!' + sys.executable + '\nimport os,sys,pathlib,time\n' +
            'logs=' + repr(inventories) + '\nbehavior=' + repr(behavior) + '\n' +
            "source=pathlib.Path(sys.argv[-1]); name=source.stem; out=logs[name]; mode=behavior.get(name)\n" +
            "if mode=='exit': raise SystemExit(7)\n" +
            "if mode=='missing': out=out.split('\\n',1)[1]\n" +
            "if mode=='sorry': out=out.replace('does not depend on any axioms','depends on axioms: [sorryAx]',1)\n" +
            "if mode=='extra': out+=\"'extra' does not depend on any axioms\\n\"\n" +
            "if mode=='invalid_utf8': os.write(1,b'\\xff'); raise SystemExit(1)\n" +
            "if mode=='source': source.write_bytes(source.read_bytes()+b'\\n')\n" +
            "if mode!='no_module': pathlib.Path(sys.argv[sys.argv.index('-o')+1]).write_bytes(('fake '+name).encode())\n" +
            "if mode=='overflow': out='x'*507393\n" +
            "os.write(1,out.encode()); time.sleep(.005)\n")
        exe.write_text(script); exe.chmod(0o700)
        lock = repo / 'formal/toolchain-lock.json'
        data = json.loads(lock.read_text()); data['lean_binary_sha256'] = p.digest(exe.read_bytes())
        lock.write_text(json.dumps(data))
        for name in p.support_paths():
            target = exe.parent.parent / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(('support:' + name).encode())
        stack.enter_context(patch.object(p, 'ROOT', repo))
        yield home, exe, prepared, proposal


class SchemaTests(unittest.TestCase):
    def test_json_exact_types_and_canonical_form(self):
        for raw in (b'{"a":1,"a":1}\n', b'{"a":NaN}\n', b'{ "a":1}\n', b'[]\n', b'{"a":1}', b'{"a":1}\n\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): p.parse(raw)
        for value in (True, False, None, '1', 1.0, -1, 12):
            with self.subTest(value=value), self.assertRaises(ValueError): p.integer(value, 0, 11)
        self.assertEqual(p.parse(p.encode({'a': 1})), {'a': 1})
        for value in ('f'*63, 'F'*64, None, 1):
            with self.assertRaises(ValueError): p.hash_value(value)

    def test_path_alphabet_boundaries(self):
        self.assertEqual(p.absolute('/'+'x'*127), '/'+'x'*127)
        for path in ('/'+'x'*128, '/a b', '/a"b', '/a\\b', '/a\nb', '/a/../b', '/a//b', '/a/', 'relative', '/', '/a/./b'):
            with self.subTest(path=path), self.assertRaises(ValueError): p.absolute(path)

    def failure(self, phase='preparation', index=None, code='preparation_invalid'):
        return dict(**p.common('a'*64), status='failed', run_sha256=None if phase=='preparation' else '1'*64,
            plan_sha256=None if phase=='preparation' else '2'*64, identity_sha256=None if phase=='preparation' else '3'*64,
            failed_stage=index, phase=phase, error_code=code, invocations=0 if index is None else index+(phase!='prelaunch'),
            wall_ns=0, committed_receipt_sha256=[format(i+16,'064x') for i in range(index or 0)], **p.flags())

    def test_all_failure_cross_products(self):
        admitted = rejected = 0
        phases = ('preparation','prelaunch','capturing','verifying','receipt_commit','finalization')
        for code in p.PHASE_CODES:
            for phase in phases:
                for index in (None,*range(11)):
                    value = self.failure(phase,index,code)
                    valid = phase in p.PHASE_CODES[code] and ((index is None)==(phase in ('preparation','finalization')))
                    if valid:
                        p.validate_failure(value); admitted += 1
                    else:
                        with self.assertRaises(ValueError): p.validate_failure(value)
                        rejected += 1
        self.assertEqual(admitted+rejected,1008)
        self.assertGreater(admitted,0); self.assertGreater(rejected,0)

    def test_failure_every_field(self):
        good = self.failure()
        for key in good:
            with self.subTest(key=key):
                value=copy.deepcopy(good);del value[key]
                with self.assertRaises((ValueError,KeyError,TypeError)):p.validate_failure(value)
                value=copy.deepcopy(good);value[key]=None
                if good[key] is not None:
                    with self.assertRaises((ValueError,KeyError,TypeError)):p.validate_failure(value)
        with self.assertRaises(ValueError):p.validate_failure(dict(good,unknown=0))
        for key,value in [('invocations',True),('wall_ns',-1),('wall_ns',600000000001),('committed_receipt_sha256',['a'*64]),('kernel_core_syntax_connection_checked',True)]:
            with self.assertRaises(ValueError):p.validate_failure(dict(good,**{key:value}))

    def test_unspawned_process_every_field(self):
        good=c.unspawned_process();p.validate_process(good)
        for key in good:
            bad=dict(good);del bad[key]
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate_process(bad)
        for key,value in [('leader_pid',1),('original_group_empty',True),('returncode',0),('elapsed_ns',1),('stdout_eof',True),('spawned',0),('cleanup_ns',2000000001)]:
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate_process(dict(good,**{key:value}))
        with self.assertRaises(ValueError):p.validate_process(good,True)
        for key in ('timed_out','incomplete','output_truncated'):
            with self.assertRaises(ValueError):p.validate_process(dict(good,**{key:True}))
        with self.assertRaises(ValueError):p.validate_process(dict(good,cleanup_ns=1))
        with self.assertRaises(ValueError):p.validate_process(dict(good,leader_reaped=True,leader_reap_observed=True))
        with self.assertRaises(ValueError):p.validate_process(dict(good,post_reap_group_probe='group_exists'))

    def test_budget_edges(self):
        p.budgets({'Baseline.stdout':b'x'*507392})
        with self.assertRaises(ValueError):p.budgets({'Baseline.stdout':b'x'*507393})
        p.budgets({'Baseline.stdout':b'x'*507392,'SyntaxData.stdout':b'x'*(p.RAW_GLOBAL-507392)})
        with self.assertRaises(ValueError):p.budgets({'Baseline.stdout':b'x'*507392,'SyntaxData.stdout':b'x'*(p.RAW_GLOBAL-507392+1)})
        for name in ('PLAN.json','RUN.json','Baseline.finished.json','RESULT.json'):
            p.budgets({name:b'x'*p.cap(name)})
            with self.assertRaises(ValueError):p.budgets({name:b'x'*(p.cap(name)+1)})
        p.budgets({},b'x'*4096)
        with self.assertRaises(ValueError):p.budgets({},b'x'*4097)
        source=b'x'*p.BUDGETS['source'];module=b'x'*p.BUDGETS['module']
        p.budgets({n:source for n in p.SOURCE_FILES[:4]})
        with self.assertRaises(ValueError):p.budgets({n:source for n in p.SOURCE_FILES[:5]})
        p.budgets({n:module for n in p.MODULE_FILES[:4]})
        with self.assertRaises(ValueError):p.budgets({n:module for n in p.MODULE_FILES[:5]})
        with self.assertRaises(ValueError):p.budgets({p.SOURCE_FILES[0]:source+b'x'})
        with self.assertRaises(ValueError):p.budgets({p.MODULE_FILES[0]:module+b'x'})
        with self.assertRaises(ValueError):p.budgets({'foreign':b''})
        with self.assertRaises(ValueError):p.budgets({n:b'x'*p.cap(n) for n in p.GLOBALS+p.RECEIPT_FILES+p.TERMINALS})


class FullRunTests(unittest.TestCase):
    def test_full_eleven_unpatched_source_inverse_and_replay(self):
        with installation() as (home,exe,prepared,proposal):
            result=runner.qualify(exe,home/'out')
            self.assertEqual(result['exit_code'],0,result['result'])
            self.assertEqual(result['result']['invocations'],11)
            self.assertTrue(result['result']['kernel_core_syntax_connection_checked'])
            self.assertEqual(len(list((home/'out').rglob('*.olean'))),11)
            self.assertEqual(sum((home/'out'/n).stat().st_size for n in p.SOURCE_FILES),5593354)
            self.assertEqual(result['result']['authority']['authority'],'DENY_ALL')
            self.assertEqual(len(result['result']['obligations']),12)
            # Full replay already ran inside qualify, with no source/inverse patch.
            self.assertEqual(p.parse(result['display'])['status'],'full_replay_verified')


class RunnerAdversaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.prepared,cls.proposal=fixture()

    @contextmanager
    def fast_fixture(self, behavior=None):
        # Orchestration adversaries use one fully validated immutable source
        # fixture. Independent inverse tests and FullRunTests remain unpatched.
        with installation(behavior) as values, patch.object(p,'prepare',return_value=(self.prepared,self.proposal)):
            yield values

    def test_failure_at_each_of_eleven_stages(self):
        for i,name in enumerate(p.seven.NAMES):
            with self.subTest(stage=name),self.fast_fixture({name:'exit'}) as (home,exe,_,__):
                result=runner.qualify(exe,home/'out')['result']
                self.assertEqual(result['status'],'failed',result)
                self.assertEqual(result['failed_stage'],i,result)
                self.assertEqual(result['invocations'],i+1,result)
                self.assertEqual(len(result['committed_receipt_sha256']),i,result)
                self.assertFalse(result['kernel_core_syntax_connection_checked'])
                self.assertFalse(any((home/'out'/(n+'.started.json')).exists() for n in p.seven.NAMES[i+1:]))
                with self.assertRaises(ValueError):replay.verify_evidence(home/'out')

    def test_bad_capture_inventory_source_module(self):
        for mode in ('missing','extra','sorry','invalid_utf8','no_module','source','overflow'):
            with self.subTest(mode=mode),self.fast_fixture({'Baseline':mode}) as (home,exe,_,__):
                result=runner.qualify(exe,home/'out')['result']
                self.assertEqual(result['status'],'failed',result)
                self.assertEqual(result['invocations'],1)
                self.assertEqual(result['failed_stage'],0)
                self.assertFalse((home/'out/SyntaxData.started.json').exists())

    def test_deadline_after_expensive_prelaunch_checks(self):
        with self.fast_fixture() as (home,exe,_,__):
            real=c.capture
            def expired(*a,**kw):
                kw['launch_deadline_ns']=0
                return real(*a,**kw)
            with patch.object(c,'capture',side_effect=expired):result=runner.qualify(exe,home/'out')['result']
            self.assertEqual(result['invocations'],0)
            self.assertEqual(result['error_code'],'launch_deadline')
            self.assertEqual(result['phase'],'prelaunch')

    def test_stale_root_and_symlink(self):
        with self.fast_fixture() as (home,exe,_,__):
            target=home/'out';target.mkdir();(target/'keep').write_text('keep')
            result=runner.qualify(exe,target)['result']
            self.assertEqual(result['phase'],'preparation');self.assertEqual(result['invocations'],0)
            self.assertEqual((target/'keep').read_text(),'keep')
            (home/'alias').symlink_to(target,target_is_directory=True)
            self.assertEqual(runner.qualify(exe,home/'alias')['result']['invocations'],0)


class CaptureTests(unittest.TestCase):
 def run_child(self,code,remaining=c.RAW_GLOBAL,deadline=None):
  with tempfile.TemporaryDirectory() as d:
   r=c.capture([sys.executable,'-c',code],cwd=d,env={},stdout_path=d+'/out',stderr_path=d+'/err',raw_remaining=remaining,launch_deadline_ns=deadline if deadline is not None else time.monotonic_ns()+10**10)
   for name,path in [('stdout','out'),('stderr','err')]:
    if r['logs']:
     data=Path(d+'/'+path).read_bytes(); self.assertEqual(r['logs'][name],dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
   p.validate_process(r['process'])
   return r
 def test_success_order(self):
  events=[]; kill=c.os.killpg; wait=c.os.waitpid
  def k(pid,sig): events.append(('kill',sig)); return kill(pid,sig)
  def w(pid,flags):
   v=wait(pid,flags)
   if v[0]: events.append(('reap',v[0]))
   return v
  with patch.object(c.os,'killpg',k),patch.object(c.os,'waitpid',w):
   r=self.run_child("import os; os.write(1,b'hello'); os.write(2,b'world')")
  self.assertIsNone(r['error_code'],r); p=r['process']; self.assertTrue(p['original_group_empty']); self.assertEqual(p['terminal_observation'],'waitid_wnowait'); self.assertIsInstance(p['leader_start_ticks'],int)
  self.assertEqual([x for x in events if x==('kill',9)],[('kill',9)])
  self.assertLess(events.index(('kill',9)),next(i for i,x in enumerate(events) if x[0]=='reap'))
  self.assertEqual(events[-1],('kill',0))
 def test_nonzero(self): self.assertEqual(self.run_child('raise SystemExit(7)')['error_code'],'process_failed')
 def test_invalid_utf8(self): self.assertEqual(self.run_child("import os; os.write(1,b'\\xff')")['error_code'],'capture_incomplete')
 def test_incomplete_utf8(self): self.assertEqual(self.run_child("import os; os.write(1,b'\\xe2\\x82')")['error_code'],'capture_incomplete')
 def test_split_utf8(self): self.assertIsNone(self.run_child("import os,time; os.write(1,b'\\xe2'); time.sleep(.03); os.write(1,b'\\x82\\xac')")['error_code'])
 def test_stage_exact(self): self.assertIsNone(self.run_child("import os; os.write(1,b'x'*507392)")['error_code'])
 def test_stage_over(self):
  r=self.run_child("import os; os.write(1,b'x'*507393)"); self.assertEqual(r['error_code'],'output_limit'); self.assertTrue(r['process']['output_truncated']); self.assertLessEqual(sum(x['bytes'] for x in r['logs'].values()),c.RAW_STAGE)
 def test_global_exact(self): self.assertIsNone(self.run_child("import os; os.write(1,b'x'*100)",100)['error_code'])
 def test_global_over(self): self.assertEqual(self.run_child("import os; os.write(1,b'x'*101)",100)['error_code'],'output_limit')
 def test_zero_empty(self): self.assertIsNone(self.run_child('pass',0)['error_code'])
 def test_zero_nonempty(self): self.assertEqual(self.run_child("print('x')",0)['error_code'],'output_limit')
 def test_deadline(self):
  r=self.run_child("raise Exception('MUST NOT LAUNCH')",deadline=0); self.assertEqual(r['error_code'],'launch_deadline'); self.assertFalse(r['process']['spawned'])
 def test_spawn_fail(self):
  with tempfile.TemporaryDirectory() as d:
   r=c.capture(['/does/not/exist'],cwd=d,env={},stdout_path=d+'/o',stderr_path=d+'/e',raw_remaining=100,launch_deadline_ns=time.monotonic_ns()+10**10)
  p.validate_process(r['process']); self.assertEqual(r['error_code'],'process_failed'); self.assertFalse(r['process']['spawned'])
 def test_exclusive(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d+'/o').write_bytes(b'keep')
   r=c.capture([sys.executable],cwd=d,env={},stdout_path=d+'/o',stderr_path=d+'/e',raw_remaining=100,launch_deadline_ns=time.monotonic_ns()+10**10)
   p.validate_process(r['process']); self.assertEqual(Path(d+'/o').read_bytes(),b'keep'); self.assertEqual(r['error_code'],'filesystem_invalid')
 def test_fsync_failure(self):
  with patch.object(c.os,'fsync',side_effect=OSError(5,'injected')): self.assertEqual(self.run_child('pass')['error_code'],'filesystem_invalid')
 def test_identity_failure(self):
  with patch.object(c,'_leader_identity',side_effect=OSError(5,'injected')):
   r=self.run_child('import time; time.sleep(10)')
  self.assertEqual(r['error_code'],'capture_incomplete'); self.assertTrue(r['process']['leader_reaped']); self.assertTrue(r['process']['original_group_empty'])
 def test_signal_unknown(self):
  real=c.os.killpg
  def unknown(pid,sig):
   real(pid,sig)
   if sig: raise PermissionError(1,'injected after actual kill')
  with patch.object(c.os,'killpg',unknown): r=self.run_child('pass')
  self.assertEqual(r['error_code'],'cleanup_failed'); self.assertEqual(r['process']['pre_reap_group_signal'],'failed')
 def test_final_probe_unknown(self):
  real=c.os.killpg
  def unknown(pid,sig):
   if not sig: raise PermissionError(1,'injected')
   return real(pid,sig)
  with patch.object(c.os,'killpg',unknown): r=self.run_child('pass')
  self.assertEqual(r['error_code'],'cleanup_failed'); self.assertFalse(r['process']['original_group_empty'])
 def test_raw_both_pipes(self):
  r=self.run_child("import os; os.write(1,b'x'*60000); os.write(2,b'y'*60000)",100000)
  self.assertEqual(r['error_code'],'output_limit'); self.assertEqual(sum(x['bytes'] for x in r['logs'].values()),100000)
 def test_retained_child_group(self):
  import ctypes
  self.assertEqual(ctypes.CDLL(None).prctl(36,1,0,0,0),0)
  try:
   r=self.run_child("import os,time; pid=os.fork(); time.sleep(10) if pid==0 else None")
   self.assertEqual(r['error_code'],'cleanup_failed'); self.assertTrue(r['process']['leader_reaped']); self.assertFalse(r['process']['original_group_empty']); self.assertEqual(r['process']['post_reap_group_probe'],'group_exists')
  finally:
   while True:
    try:
     pid,status=os.waitpid(-1,os.WNOHANG)
     if not pid: break
    except ChildProcessError: break
   ctypes.CDLL(None).prctl(36,0,0,0,0)
 def test_write_eio(self):
  with patch.object(c.os,'write',side_effect=OSError(5,'injected')):
   r=self.run_child("print('write failure')")
  self.assertEqual(r['error_code'],'filesystem_invalid'); self.assertTrue(r['process']['leader_reaped']); self.assertTrue(r['process']['original_group_empty'])
 def test_selector_error(self):
  real=c.selectors.EpollSelector.select
  calls=0
  def once(self,timeout=None):
   nonlocal calls
   calls+=1
   if calls==1: raise OSError(5,'injected')
   return real(self,timeout)
  with patch.object(c.selectors.EpollSelector,'select',once):
   r=self.run_child('import time; time.sleep(10)')
  self.assertEqual(r['error_code'],'capture_incomplete'); self.assertTrue(r['process']['leader_reaped']); self.assertTrue(r['process']['original_group_empty'])


class OwnedProcessIdentityTests(unittest.TestCase):
    """Actual child identities, independent of whether procfs uses ancestor PIDs."""

    def capture_child(self, code):
        with tempfile.TemporaryDirectory() as directory:
            result = c.capture([sys.executable, '-c', code], cwd=directory, env={},
                stdout_path=directory+'/stdout', stderr_path=directory+'/stderr',
                raw_remaining=c.RAW_GLOBAL, launch_deadline_ns=time.monotonic_ns()+10**10)
            stdout = Path(directory+'/stdout').read_text()
            stderr = Path(directory+'/stderr').read_text()
        p.validate_process(result['process'])
        self.assertEqual(set(result['process']), set(c.unspawned_process()))
        return result, stdout, stderr

    def assert_identity_rejection(self, result):
        self.assertEqual(result['error_code'], 'capture_incomplete', result)
        observed = result['process']
        self.assertTrue(observed['spawned'])
        self.assertTrue(observed['incomplete'])
        self.assertIsNone(observed['leader_start_ticks'])
        self.assertTrue(observed['leader_reaped'])
        self.assertTrue(observed['original_group_empty'])
        self.assertEqual(observed['post_reap_group_probe'], 'esrch')
        self.assertIn(observed['pre_reap_group_signal'],
                      ('sigkill_sent', 'sigkill_no_signalable_group'))

    def test_actual_child_self_identity_matches_the_shared_authentication(self):
        code = ('import json,os,sys\nfrom pathlib import Path\n'
                'raw=Path("/proc/self/stat").read_text()\n'
                'fields=raw.rsplit(")",1)[1].split()\n'
                'print(json.dumps({"pid":os.getpid(),"pgid":os.getpgrp(),"sid":os.getsid(0),'
                '"proc_pid":int(raw.split("(",1)[0]),"ticks":int(fields[19])}))\n'
                'print("identity-stderr",file=sys.stderr)\n')
        authenticate = c.owned_leader_identity
        identities = []
        def observe(pid):
            identity = authenticate(pid)
            identities.append(identity)
            return identity
        with patch.object(c, 'owned_leader_identity', side_effect=observe):
            result, stdout, stderr = self.capture_child(code)
        self.assertIsNone(result['error_code'], result)
        expected = json.loads(stdout)
        self.assertEqual(identities, [(expected['proc_pid'], expected['ticks'])])
        self.assertEqual(result['process']['leader_start_ticks'], expected['ticks'])
        self.assertEqual(result['process']['leader_pid'], expected['pid'])
        self.assertEqual(expected['pid'], expected['pgid'])
        self.assertEqual(expected['pid'], expected['sid'])
        self.assertEqual(stderr, 'identity-stderr\n')

    def test_mismatched_pidfd_namespace_cannot_use_a_guessed_proc_pid(self):
        original = c._proc_nspid
        injected = []
        def mismatch(path):
            identity = original(path)
            if Path(path).parent == Path('/proc/self/fdinfo'):
                injected.append(identity)
                return (*identity[:-1], identity[-1]+1)
            return identity
        with patch.object(c, '_proc_nspid', side_effect=mismatch):
            result, _, _ = self.capture_child('pass')
        self.assertEqual(len(injected), 1)
        self.assert_identity_rejection(result)

    def test_inconsistent_procfs_session_cannot_attest_child_identity(self):
        original = c._proc_stat
        injected = []
        def mismatch(path):
            pid, fields = original(path)
            if Path(path).parent.name.isdigit():
                injected.append(pid)
                fields = list(fields)
                fields[3] = str(pid+1)
            return pid, fields
        with patch.object(c, '_proc_stat', side_effect=mismatch):
            result, _, _ = self.capture_child('pass')
        self.assertEqual(len(injected), 1)
        self.assert_identity_rejection(result)

    def test_unavailable_pidfd_never_falls_back_to_numeric_proc_path(self):
        with patch.object(c.os, 'pidfd_open', side_effect=OSError(38, 'unavailable pidfd')):
            result, _, _ = self.capture_child('pass')
        self.assert_identity_rejection(result)


class RecordAndSizingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.proposal=fixture()

    def records(self):
        h='f'*64
        identity=dict(**p.common(h),commit_sha='f'*40,tree_sha='f'*40,lean_binary_sha256=h,
            sources={n:dict(sha256=h,bytes=2097152) for n in p.source_paths()},
            support={n:dict(sha256=h,bytes=9223372036854775807) for n in p.support_paths()})
        plan=p.make_plan(h,identity,Path('/tmp/pinned/bin/lean'),Path('/tmp/output'),self.prepared,self.proposal)
        plan['process_spec'].update(executable='/'+'e'*127,root='/'+'r'*127,sysroot='/'+'s'*127)
        for v in plan['source_file_map'].values():v.update(sha256=h,bytes=2097152)
        return identity,plan

    def test_exact_approved_serialized_reserve(self):
        h='f'*64;identity,plan=self.records();run=p.make_run(plan)
        process=dict(c.unspawned_process(),returncode=-2147483648,elapsed_ns=600000000000,cleanup_ns=2000000000,
            leader_pid=2147483647,original_pgid=2147483647,leader_start_ticks=18446744073709551615,
            terminal_observation='waitid_wnowait',pre_reap_group_signal='sigkill_no_signalable_group',post_reap_group_probe='unknown_or_permission_error')
        metadata={'IDENTITY.json':identity,'PLAN.json':plan,'RUN.json':run,'seven-manifest.json':self.proposal.manifest}
        stage_fail=[]
        for st in plan['stages']:
            parents={par:dict(finished_receipt_sha256=h,olean_sha256=h,olean_bytes=33554432,source_sha256=h) for par in st['parents']}
            metadata[st['name']+'.started.json']=p.started(plan,run,st,parents,540000000000)
            finish=dict(**p.common(h),index=st['index'],name=st['name'],started_sha256=h,status='stage_passed',
                process=dict(process,returncode=0,spawned=True,leader_reaped=True,stdout_eof=True,stderr_eof=True,original_group_empty=True,leader_reap_observed=True,post_reap_group_probe='esrch'),
                logs={s:dict(sha256=h,bytes=507392) for s in ('stdout','stderr')},inventory=dict(subject_count=st['subject_count'],inventory_sha256=h),
                olean=dict(sha256=h,bytes=33554432,source_sha256=h))
            metadata[st['name']+'.finished.json']=finish
            for code in p.PHASE_CODES:
                stage_fail.append(dict(finish,status='stage_failed',error_code=code,process=process,inventory=None,olean=None))
        success=dict(**p.common(h),status='passed',run_sha256=h,plan_sha256=h,identity_sha256=h,frozen_files_count=81,frozen_files_sha256=h,
            stage_receipt_sha256=[h]*11,positive_inventory_count=66,positive_inventory_sha256=h,negative_certificate_count=10,negative_certificate_sha256=h,
            invocations=11,wall_ns=600000000000,**p.flags(True))
        failures=[]
        for code in p.PHASE_CODES:
            for phase in ('preparation','prelaunch','capturing','verifying','receipt_commit','finalization'):
                for index in (None,*range(11)):
                    failures.append(dict(**p.common(h),status='failed',run_sha256=None if phase=='preparation' else h,
                        plan_sha256=None if phase=='preparation' else h,identity_sha256=None if phase=='preparation' else h,
                        failed_stage=index,phase=phase,error_code=code,invocations=11,wall_ns=600000000000,committed_receipt_sha256=[h]*11,**p.flags()))
        reserve=sum(len(p.encode(v)) for v in metadata.values())+max(len(p.encode(v)) for v in stage_fail)+3*max(map(lambda v:len(p.encode(v)),[success,*failures]))
        self.assertEqual(len(failures)+len(stage_fail),1162)
        self.assertEqual(reserve,219144)
        self.assertEqual(1048576-reserve-4096,825336)
        self.assertEqual(len(p.encode(identity)),143429)
        self.assertEqual(len(p.encode(plan)),22733)
        self.assertEqual(len(p.encode(self.proposal.manifest)),20820)
        for name,value in metadata.items():self.assertLessEqual(len(p.encode(value)),p.cap(name))
        self.assertEqual(sum(len(("'"+n+"' depends on axioms: [propext, Classical.choice, Quot.sound]\n").encode())
            for s in self.proposal.stages for n in p.seven._qualified_prints(s.source)),744461)

    def test_every_nested_identity_plan_run_field(self):
        identity,_=self.records()
        exe,root=Path('/tmp/seven-fake/bin/lean'),Path('/tmp/seven-output')
        plan=p.make_plan(identity['run_id'],identity,exe,root,self.prepared,self.proposal);run=p.make_run(plan)
        records=[identity,plan,run]
        def check(values):p.validate_plan_records(*values,identity,exe,root,self.prepared,self.proposal)
        check(records)
        # Every field is traversed, including all230 source/all780 support rows,
        # ten exact negative descriptors, five complete input bindings and DAG.
        def paths(value,prefix=()):
            if isinstance(value,dict):
                for key,child in value.items():
                    yield prefix+(key,)
                    yield from paths(child,prefix+(key,))
            elif isinstance(value,list):
                for i,child in enumerate(value):yield from paths(child,prefix+(i,))
        for index,record in enumerate(records):
            for path in paths(record):
                # Serialization comparison is the same strict production gate.
                value=copy.deepcopy(record);parent=value
                for key in path[:-1]:parent=parent[key]
                del parent[path[-1]]
                values=list(records);values[index]=value
                with self.subTest(record=index,path=path),self.assertRaises(ValueError):check(values)
        for index,record in enumerate(records):
            for mutation in ({**record,'unknown':0},None,[],True):
                values=list(records);values[index]=mutation
                with self.assertRaises((ValueError,TypeError,KeyError)):check(values)
        for key,value in [('identity_sha256','0'*64),('positive_targets',[]),('budgets',{}),('negatives',{}),('input_bindings',{})]:
            with self.assertRaises(ValueError):check([identity,dict(plan,**{key:value}),run])

    def test_every_nested_wrong_type_unknown_and_numeric_bounds(self):
        identity,_=self.records()
        exe,root=Path('/tmp/seven-fake/bin/lean'),Path('/tmp/seven-output')
        plan=p.make_plan(identity['run_id'],identity,exe,root,self.prepared,self.proposal);run=p.make_run(plan)
        records=[identity,plan,run]
        def paths(value,prefix=()):
            yield prefix,value
            if isinstance(value,dict):
                for key,child in value.items():yield from paths(child,prefix+(key,))
            elif isinstance(value,list):
                for key,child in enumerate(value):yield from paths(child,prefix+(key,))
        for index,record in enumerate(records):
            for path,old in paths(record):
                replacements=[None]
                if isinstance(old,dict):replacements.append(dict(old,unknown=0))
                elif isinstance(old,list):replacements.append(old+[None])
                elif type(old) is int:replacements.extend((True,float(old),old-1,old+1))
                elif type(old) is str:replacements.append(False)
                for replacement in replacements:
                    if p.same(old,replacement):continue
                    value=copy.deepcopy(record)
                    if not path:value=replacement
                    else:
                        parent=value
                        for key in path[:-1]:parent=parent[key]
                        parent[path[-1]]=replacement
                    values=list(records);values[index]=value
                    with self.subTest(record=index,path=path),self.assertRaises((ValueError,TypeError,KeyError)):
                        p.validate_plan_records(*values,identity,exe,root,self.prepared,self.proposal)

    def test_all_failed_stage_codes_and_fields(self):
        for i,name in enumerate(p.seven.NAMES):
            for code in p.PHASE_CODES:
                value=dict(**p.common('a'*64),index=i,name=name,started_sha256='b'*64,status='stage_failed',error_code=code,
                    process=c.unspawned_process(),logs=None,inventory=None,olean=None)
                p.validate_failed_stage(value)
                for key in value:
                    bad=dict(value);del bad[key]
                    with self.assertRaises((ValueError,KeyError)):p.validate_failed_stage(bad)
                for key,val in [('inventory',{}),('olean',{}),('status','stage_passed'),('index',True),('name','SevenCertificatePart02'),('logs',{})]:
                    with self.assertRaises(ValueError):p.validate_failed_stage(dict(value,**{key:val}))


class ClockTests(CaptureTests):
 def test_cleanup_fsync_boundaries(self):
  for delta in (c.CLEANUP_NS-1,c.CLEANUP_NS,c.CLEANUP_NS+1):
   with self.subTest(delta=delta):
    now=[1_000_000_000]; real=c.os.fsync
    def fsync(fd):
     real(fd); now[0]=1_000_000_000+delta
    with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'fsync',fsync):
     r=self.run_child('pass',deadline=100_000_000_000)
    self.assertEqual(r['error_code'],None if delta<c.CLEANUP_NS else 'cleanup_failed',r)
    self.assertEqual(r['process']['cleanup_ns'],min(delta,c.CLEANUP_NS))
 def test_cleanup_final_probe_boundaries(self):
  for delta in (c.CLEANUP_NS-1,c.CLEANUP_NS,c.CLEANUP_NS+1):
   with self.subTest(delta=delta):
    now=[1_000_000_000]; real=c.os.killpg
    def probe(pid,sig):
     try: return real(pid,sig)
     finally:
      if sig==0: now[0]=1_000_000_000+delta
    with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'killpg',probe):
     r=self.run_child('pass',deadline=100_000_000_000)
    self.assertEqual(r['error_code'],None if delta<c.CLEANUP_NS else 'cleanup_failed',r)
 def test_cleanup_eof_boundaries(self):
  for delta in (c.CLEANUP_NS-1,c.CLEANUP_NS,c.CLEANUP_NS+1):
   with self.subTest(delta=delta):
    now=[1_000_000_000]; killed=[False]; real=c.os.read; kill=c.os.killpg
    def signal(pid,sig):
     if sig: killed[0]=True
     return kill(pid,sig)
    select=c.selectors.EpollSelector.select
    def after_kill(self,timeout=None):
     if not killed[0]:
      time.sleep(.001); return []
     return select(self,timeout)
    def read(fd,n):
     data=real(fd,n)
     if not data and killed[0]: now[0]=1_000_000_000+delta
     return data
    with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'read',read),patch.object(c.os,'killpg',signal),patch.object(c.selectors.EpollSelector,'select',after_kill):
     r=self.run_child('pass',deadline=100_000_000_000)
    self.assertEqual(r['error_code'],None if delta<c.CLEANUP_NS else 'cleanup_failed',r)
 def test_process_deadline_on_write(self):
  now=[1_000_000_000]; real=c.os.write; events=[]; kill=c.os.killpg
  def write(fd,data):
   n=real(fd,data); events.append('write'); now[0]=1_000_000_000+c.PROCESS_NS; return n
  def signal(pid,sig):
   if sig: events.append('kill')
   return kill(pid,sig)
  with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'write',write),patch.object(c.os,'killpg',signal):
   r=self.run_child("import os,time; os.write(1,b'crossing'); time.sleep(10)",deadline=100_000_000_000)
  self.assertEqual(r['error_code'],'process_timeout',r); self.assertEqual(events,['write','kill']); self.assertTrue(r['process']['leader_reaped'])
 def test_process_deadline_on_read(self):
  now=[1_000_000_000]; real=c.os.read; events=[]; kill=c.os.killpg
  def read(fd,n):
   data=real(fd,n)
   if data==b'crossing': events.append('read'); now[0]=1_000_000_000+c.PROCESS_NS
   return data
  def signal(pid,sig):
   if sig: events.append('kill')
   return kill(pid,sig)
  with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'read',read),patch.object(c.os,'killpg',signal):
   r=self.run_child("import os,time; os.write(1,b'crossing'); time.sleep(10)",deadline=100_000_000_000)
  self.assertEqual(r['error_code'],'process_timeout',r); self.assertEqual(events,['read','kill']); self.assertTrue(r['process']['leader_reaped'])


class FilesystemTests(unittest.TestCase):
    def test_output_symlink_hardlink_mutation_and_ancestor(self):
        for mode in ('symlink','hardlink','mutate','replace','ancestor'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
                root=p.base.SafeRoot(Path(temp)/'out');snapshot=p.Snapshot(root)
                try:
                    name='original/Baseline.lean';root.write(name,b'original');snapshot.read(name)
                    path=root.path/name
                    if mode=='symlink':path.unlink();path.symlink_to(Path(temp)/'outside')
                    if mode=='hardlink':os.link(path,Path(temp)/'other')
                    if mode=='mutate':path.write_bytes(b'changed!')
                    if mode=='replace':
                        other=Path(temp)/'other';other.write_bytes(b'original');os.replace(other,path)
                    if mode=='ancestor':
                        old=root.path/'original';old.rename(root.path/'moved');old.mkdir();(old/'Baseline.lean').write_bytes(b'original')
                    with self.assertRaises((ValueError,OSError)):snapshot.read(name)
                finally:root.close()

    def test_scan_foreign_and_special(self):
        for mode in ('foreign','fifo','directory'):
            with tempfile.TemporaryDirectory() as temp:
                root=p.base.SafeRoot(Path(temp)/'out')
                try:
                    if mode=='foreign':(root.path/'foreign').write_text('bad')
                    if mode=='fifo':os.mkfifo(root.path/'Baseline.stdout')
                    if mode=='directory':(root.path/'foreign').mkdir()
                    with self.assertRaises(ValueError):root.scan(p.FIXED_FILES)
                finally:root.close()

    def test_atomic_finalization_faults(self):
        result=SchemaTests().failure()
        for mode in ('write','file_fsync','reread','rename','directory_fsync','final_reread'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
                root=p.base.SafeRoot(Path(temp)/'out');snapshot=p.Snapshot(root)
                try:
                    if mode=='write':stack.enter_context(patch.object(root,'write',side_effect=OSError('write')))
                    if mode=='file_fsync':stack.enter_context(patch.object(runner,'sync_file',side_effect=OSError('sync')))
                    if mode in ('reread','final_reread'):
                        real=snapshot.read
                        def read(name,**kw):
                            if name==('RESULT.pending.json' if mode=='reread' else 'RESULT.json'):raise OSError('read')
                            return real(name,**kw)
                        stack.enter_context(patch.object(snapshot,'read',side_effect=read))
                    if mode=='rename':stack.enter_context(patch.object(runner.os,'replace',side_effect=OSError('rename')))
                    if mode=='directory_fsync':
                        real=runner.os.fsync
                        def sync(fd):
                            if fd==root.fd:raise OSError('directory sync')
                            return real(fd)
                        stack.enter_context(patch.object(runner.os,'fsync',side_effect=sync))
                    with self.assertRaises(OSError):runner.finalize(root,snapshot,result)
                finally:root.close()

    def test_finalization_happy_and_pending_exclusive(self):
        result=SchemaTests().failure()
        with tempfile.TemporaryDirectory() as temp:
            root=p.base.SafeRoot(Path(temp)/'out');snapshot=p.Snapshot(root)
            try:
                runner.finalize(root,snapshot,result)
                self.assertEqual(snapshot.read('RESULT.json',mutable=True),p.encode(result))
                self.assertFalse((root.path/'RESULT.pending.json').exists())
                root.write('RESULT.pending.json',b'uncertain')
                with self.assertRaises(FileExistsError):runner.finalize(root,snapshot,result)
                self.assertEqual((root.path/'RESULT.pending.json').read_bytes(),b'uncertain')
            finally:root.close()


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.proposal=fixture()

    def test_external_actual_binary_support_source_inodes(self):
        for mode in ('binary','support','source','replace','hardlink','symlink'):
            with self.subTest(mode=mode),installation() as (home,exe,_,__):
                external=p.External(exe)
                target=exe if mode=='binary' else exe.parent.parent/p.support_paths()[0] if mode=='support' else p.ROOT/p.source_paths()[0]
                if mode in ('binary','support','source'):target.write_bytes(target.read_bytes()+b'x')
                elif mode=='replace':
                    other=home/'replacement';other.write_bytes(target.read_bytes());os.replace(other,target)
                elif mode=='hardlink':os.link(target,home/'hardlink')
                else:
                    other=home/'original';target.rename(other);target.symlink_to(other)
                with self.assertRaises((ValueError,OSError)):external.check()

    def test_stage_log_receipt_olean_parent_splices(self):
        prepared,proposal=self.prepared,self.proposal
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'out');snapshot=p.Snapshot(root)
            try:
                h='a'*64;identity=dict(**p.common(h),commit_sha='b'*40,tree_sha='c'*40,lean_binary_sha256='d'*64,sources={},support={})
                plan=p.make_plan(h,identity,Path('/tmp/pinned/bin/lean'),root.path,prepared,proposal);run=p.make_run(plan)
                source=proposal.stages[0];stage=plan['stages'][0]
                started=p.started(plan,run,stage,{},p.BUDGETS['launch_ns'])
                out=''.join("'"+n+"' does not depend on any axioms\n" for n in p.seven._qualified_prints(source.source)).encode();err=b''
                process=dict(c.unspawned_process(),spawned=True,returncode=0,leader_reaped=True,leader_reap_observed=True,
                    stdout_eof=True,stderr_eof=True,original_group_empty=True,leader_pid=123,original_pgid=123,leader_start_ticks=1,
                    terminal_observation='waitid_wnowait',pre_reap_group_signal='sigkill_sent',post_reap_group_probe='esrch')
                iv=p.inventory(out,err,source);module=b'fake actual module'
                finished=dict(**p.common(h),index=0,name='Baseline',started_sha256=p.commitment(started),status='stage_passed',process=process,
                    logs=dict(stdout=p.file_record(out),stderr=p.file_record(err)),inventory=dict(subject_count=len(iv),inventory_sha256=p.commitment(iv)),
                    olean=dict(p.file_record(module),source_sha256=source.source_sha256))
                original={'Baseline.started.json':p.encode(started),'Baseline.finished.json':p.encode(finished),'Baseline.stdout':out,'Baseline.stderr':err,
                    'HiaSyntaxResearch/Baseline.olean':module}
                for n,raw in original.items():root.write(n,raw)
                replay.validate_stage(snapshot,plan,run,stage,source,{})
                mutations=[]
                for key in finished:
                    value=copy.deepcopy(finished);del value[key];mutations.append(('Baseline.finished.json',p.encode(value)))
                for key,value in [('run_id','f'*64),('started_sha256','f'*64),('olean',dict(finished['olean'],sha256='f'*64)),
                    ('inventory',dict(finished['inventory'],subject_count=55)),('process',dict(process,returncode=True)),('logs',dict(finished['logs'],stdout=dict(bytes=len(out),sha256='f'*64)))]:
                    mutations.append(('Baseline.finished.json',p.encode(dict(finished,**{key:value}))))
                for key,value in [('parents',{'HiaSyntaxResearch.WrongArm':{}}),('source_sha256','f'*64),('remaining_launch_ns',True),('run_sha256','f'*64)]:
                    mutations.append(('Baseline.started.json',p.encode(dict(started,**{key:value}))))
                mutations += [('Baseline.stdout',out+b"'foreign' does not depend on any axioms\n"),('Baseline.stderr',b'error: forged'),('HiaSyntaxResearch/Baseline.olean',b'other module')]
                for name,raw in mutations:
                    with self.subTest(name=name):
                        (root.path/name).write_bytes(raw)
                        with self.assertRaises((ValueError,KeyError,TypeError)):replay.validate_stage(p.Snapshot(root),plan,run,stage,source,{})
                        (root.path/name).write_bytes(original[name])
                (root.path/'HiaSyntaxResearch/Baseline.olean').unlink()
                with self.assertRaises(OSError):replay.validate_stage(p.Snapshot(root),plan,run,stage,source,{})
            finally:root.close()


class FinalReplayFailureTests(unittest.TestCase):
    def test_independent_replay_and_display_failure_cannot_return_success(self):
        prepared,proposal=fixture()
        for mode in ('replay','display'):
            with self.subTest(mode=mode),installation() as (home,exe,_,__),ExitStack() as stack:
                stack.enter_context(patch.object(p,'prepare',return_value=(prepared,proposal)))
                if mode=='replay':stack.enter_context(patch.object(replay,'verify_evidence',side_effect=ValueError('injected replay fault')))
                else:
                    real=replay.display
                    def display(result,*args):
                        if result['status']=='passed':raise ValueError('injected display fault')
                        return real(result,*args)
                    stack.enter_context(patch.object(replay,'display',side_effect=display))
                result=runner.qualify(exe,home/'out')
                self.assertEqual(result['exit_code'],1)
                self.assertEqual(result['result']['status'],'failed')
                self.assertEqual(result['result']['phase'],'finalization')
                self.assertEqual(result['result']['invocations'],11)
                self.assertFalse(result['result']['kernel_core_syntax_connection_checked'])
                self.assertEqual(p.parse((home/'out/RESULT.json').read_bytes())['status'],'failed')


class LaunchTests(CaptureTests):
 def test_delayed_popen_before_and_after_spawn(self):
  for before in (True,False):
   with self.subTest(before=before):
    original=c.subprocess.Popen
    def delayed(*args,**kwargs):
     if before: time.sleep(.04)
     child=original(*args,**kwargs)
     if not before: time.sleep(.04)
     return child
    with patch.object(c.subprocess,'Popen',delayed),patch.object(c,'_leader_identity') as identity:
     r=self.run_child('import time; time.sleep(10)',deadline=time.monotonic_ns()+10_000_000)
    self.assertEqual(r['error_code'],'capture_incomplete',r)
    self.assertTrue(r['process']['spawned']); self.assertTrue(r['process']['incomplete'])
    self.assertTrue(r['process']['leader_reaped']); self.assertTrue(r['process']['original_group_empty'])
    self.assertEqual(r['process']['pre_reap_group_signal'],'sigkill_sent')
    self.assertIsNone(r['process']['leader_start_ticks']); identity.assert_not_called()
 def test_exact_post_spawn_boundaries(self):
  for delta in (-1,0,1):
   with self.subTest(delta=delta):
    now=[1_000_000_000]; deadline=now[0]+10_000_000; original=c.subprocess.Popen
    def delayed(*args,**kwargs):
     child=original(*args,**kwargs); now[0]=deadline+delta; return child
    with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.subprocess,'Popen',delayed):
     r=self.run_child('pass',deadline=deadline)
    self.assertEqual(r['error_code'],None if delta<0 else 'capture_incomplete',r)
    self.assertTrue(r['process']['leader_reaped'])


class TransitionTests(CaptureTests):
 def test_esrch_then_exists_and_permission(self):
  for outcome in ('exists','permission'):
   with self.subTest(outcome=outcome):
    now=[1_000_000_000]; probes=[0]; kill=c.os.killpg; select=c.selectors.EpollSelector.select
    def signal(pid,sig):
     if sig: return kill(pid,sig)
     probes[0]+=1
     if probes[0]==1: raise ProcessLookupError(3,'first ESRCH')
     if outcome=='permission': raise PermissionError(1,'later EPERM')
     now[0]+=c.CLEANUP_NS
     return None
    def delay_eof(self,timeout=None):
     if probes[0]==0:
      time.sleep(.001); return []
     return select(self,timeout)
    with patch.object(c.time,'monotonic_ns',lambda:now[0]),patch.object(c.os,'killpg',signal),patch.object(c.selectors.EpollSelector,'select',delay_eof):
     r=self.run_child('pass',deadline=100_000_000_000)
    self.assertEqual(r['error_code'],'cleanup_failed',r)
    self.assertGreaterEqual(probes[0],2)
    self.assertFalse(r['process']['original_group_empty'])
    self.assertEqual(r['process']['post_reap_group_probe'],'group_exists' if outcome=='exists' else 'unknown_or_permission_error')


class NegativeMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.proposal=fixture()

    def check_group(self,keys):
        for key in keys:
            with self.subTest(negative=key):
                desc=self.prepared['negatives'][key]
                index=next(i for i,s in enumerate(self.proposal.stages) if key in s.rejection_names)
                old=self.proposal.stages[index]
                local=desc['certificate'].rsplit('.',1)[1]
                lines=old.source.splitlines(keepends=True)
                matches=[i for i,line in enumerate(lines) if line.startswith('theorem '+local+' :')]
                self.assertEqual(len(matches),1)
                lines[matches[0]]='theorem '+local+' : True := by trivial\n'
                stages=list(self.proposal.stages);stages[index]=replace(old,source=''.join(lines))
                manifest=p.seven._manifest(self.prepared,tuple(stages),self.proposal.manifest['previous_transform_manifest_sha256'])
                changed=replace(self.proposal,stages=tuple(stages),manifest_json=p.seven.encode(manifest))
                with self.assertRaises(ValueError):p.seven.validate_sources(self.prepared,changed)
                for kind in ('proposition','mapping'):
                    manifest=self.proposal.manifest
                    if kind=='proposition':manifest['historical_negatives'][key]['rejected_proposition']='True'
                    else:
                        mapping=manifest['historical_negatives'][key]['identifier_mapping']
                        mapping[next(iter(mapping))]='HiaCoreSyntaxSlice.forged'
                    changed=replace(self.proposal,manifest_json=p.seven.encode(manifest))
                    with self.assertRaises(ValueError):p.seven.validate_sources(self.prepared,changed)

    def test_exact_negation_byte_modulo_alias(self):
        self.check_group(['byte_modulo_alias'])

    def test_exact_negation_changed_exact_byte(self):
        self.check_group(['changed_exact_byte'])

    def test_exact_negation_duplicate_keys(self):
        self.check_group(['duplicate_keys'])

    def test_exact_negation_leading_zero(self):
        self.check_group(['leading_zero'])

    def test_exact_negation_literal_two(self):
        self.check_group(['literal_two'])

    def test_exact_negation_stale_descriptor(self):
        self.check_group(['stale_descriptor'])

    def test_exact_negation_unordered_keys(self):
        self.check_group(['unordered_keys'])

    def test_exact_negation_wrong_arm_implementation(self):
        self.check_group(['wrong_arm_implementation'])

    def test_exact_negation_wrong_condition(self):
        self.check_group(['wrong_condition'])

    def test_exact_negation_wrong_phi(self):
        self.check_group(['wrong_phi'])



class ReceiptTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.prepared,cls.proposal=fixture()

    def faults(self,kind):
        # All global/source/started/finished persistence sites. Failure at any
        # one is nonaccepting and cannot launch any subsequent compiler stage.
        targets=list(p.GLOBALS)+list(p.SOURCE_FILES)+list(p.RECEIPT_FILES)
        for target in targets:
            with self.subTest(kind=kind,target=target),installation() as (home,exe,_,__),ExitStack() as stack:
                stack.enter_context(patch.object(p,'prepare',return_value=(self.prepared,self.proposal)))
                hit=[]
                if kind=='write':
                    real=p.base.SafeRoot.write
                    def write(root,name,raw):
                        if name==target:hit.append(name);raise OSError('injected write')
                        return real(root,name,raw)
                    stack.enter_context(patch.object(p.base.SafeRoot,'write',write))
                elif kind=='fsync':
                    real=runner.sync_file
                    def sync(root,name):
                        if name==target:hit.append(name);raise OSError('injected sync')
                        return real(root,name)
                    stack.enter_context(patch.object(runner,'sync_file',sync))
                else:
                    real=p.Snapshot.read
                    def read(snapshot,name,**kwargs):
                        if name==target:hit.append(name);raise OSError('injected reread')
                        return real(snapshot,name,**kwargs)
                    stack.enter_context(patch.object(p.Snapshot,'read',read))
                output=runner.qualify(exe,home/'out')
                self.assertTrue(hit)
                self.assertEqual(output['exit_code'],1)
                result=output['result'];self.assertFalse(result['kernel_core_syntax_connection_checked'])
                if target in p.RECEIPT_FILES:
                    index=p.seven.NAMES.index(target.split('.')[0])
                    self.assertLessEqual(result['invocations'],index+int('.finished.' in target))
                    self.assertFalse(any((home/'out'/(n+'.started.json')).exists() for n in p.seven.NAMES[index+1:]))
                else:self.assertEqual(result['invocations'],0)

    def test_all_writes_fail_closed(self):self.faults('write')
    def test_all_fsyncs_fail_closed(self):self.faults('fsync')
    def test_all_rereads_fail_closed(self):self.faults('reread')


class VerifiedDisplayTests(unittest.TestCase):
    def test_replay_cli_never_rereads_after_verifier_snapshot(self):
        import io
        from types import SimpleNamespace
        result=SchemaTests().failure()
        # The caller consumes frozen bytes, never fresh mutable pathname data.
        trusted_display=b'{"trusted_snapshot":true}\n'
        verified=replay.VerifiedEvidence(p.encode(result),trusted_display)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('PLAN.json','IDENTITY.json'):(root/name).write_bytes(b'original')
            def verify(_):
                for name in ('PLAN.json','IDENTITY.json'):
                    (root/name).unlink();(root/name).write_bytes(b'forged-after-verification'*10000)
                return verified
            output=io.BytesIO()
            with (patch.object(replay,'verify_evidence',side_effect=verify),patch.object(Path,'read_bytes',side_effect=AssertionError('unbounded post-verification reread')),
                  patch.object(runner.sys,'stdout',SimpleNamespace(buffer=output))):
                status=runner.main(['--replay','--output-directory',str(root)])
            self.assertEqual(status,0)
            self.assertEqual(output.getvalue(),trusted_display)
            copy_result=verified.result;copy_result['status']='forged'
            self.assertEqual(verified.result['status'],'failed')
            with self.assertRaises(Exception):verified.display=b'forged'


class ReceiptBoundaryTests(unittest.TestCase):
    def test_strict_success_clock_boundaries(self):
        process=dict(c.unspawned_process(),spawned=True,returncode=0,leader_reaped=True,leader_reap_observed=True,
            stdout_eof=True,stderr_eof=True,original_group_empty=True,leader_pid=123,original_pgid=123,leader_start_ticks=1,
            terminal_observation='waitid_wnowait',pre_reap_group_signal='sigkill_sent',post_reap_group_probe='esrch')
        for key,bound in [('elapsed_ns',60000000000),('cleanup_ns',2000000000)]:
            p.validate_process(dict(process,**{key:bound-1}),True)
            for value in (bound,bound+1):
                with self.assertRaises(ValueError):p.validate_process(dict(process,**{key:value}),True)
            # Exact failure boundary is still representable, never admitted.
            p.validate_process(dict(process,incomplete=True,timed_out=(key=='elapsed_ns'),**{key:bound}))


class BoundaryReplayTests(unittest.TestCase):
    def test_rehashed_last_receipt_exact_boundaries_rejected(self):
        prepared,proposal=fixture()
        with installation() as (home,exe,_,__),patch.object(p,'prepare',return_value=(prepared,proposal)):
            output=runner.qualify(exe,home/'out');self.assertEqual(output['exit_code'],0,output['result'])
            root=home/'out';original=p.parse((root/'WrongArm.finished.json').read_bytes())
            original_result=p.parse((root/'RESULT.json').read_bytes())
            for key,bound in [('elapsed_ns',60000000000),('cleanup_ns',2000000000)]:
                finished=copy.deepcopy(original);finished['process'][key]=bound
                (root/'WrongArm.finished.json').write_bytes(p.encode(finished))
                result=copy.deepcopy(original_result)
                result['stage_receipt_sha256'][-1]=p.commitment(finished)
                result['frozen_files_sha256']=p.commitment({n:p.file_record((root/n).read_bytes()) for n in sorted(p.FROZEN_FILES)})
                result['wall_ns']=600000000000
                (root/'RESULT.json').write_bytes(p.encode(result))
                with self.subTest(key=key),self.assertRaisesRegex(ValueError,'unsafe successful process|spawned cleanup/timeout observations|expired cleanup cannot be complete'):
                    replay.verify_evidence(root)
                (root/'WrongArm.finished.json').write_bytes(p.encode(original))
                (root/'RESULT.json').write_bytes(p.encode(original_result))
            # Reseal the last start/finish and full frozen map consistently. A
            # late STARTED plus the final process must fit inside claimed wall.
            start=p.parse((root/'WrongArm.started.json').read_bytes())
            start['remaining_launch_ns']=1000000000
            (root/'WrongArm.started.json').write_bytes(p.encode(start))
            finished=copy.deepcopy(original);finished['started_sha256']=p.commitment(start)
            finished['process'].update(elapsed_ns=59900000000,cleanup_ns=1900000000)
            (root/'WrongArm.finished.json').write_bytes(p.encode(finished))
            result=copy.deepcopy(original_result);result['wall_ns']=539000000000
            result['stage_receipt_sha256'][-1]=p.commitment(finished)
            result['frozen_files_sha256']=p.commitment({n:p.file_record((root/n).read_bytes()) for n in sorted(p.FROZEN_FILES)})
            (root/'RESULT.json').write_bytes(p.encode(result))
            with self.assertRaisesRegex(ValueError,'impossible total wall clock'):replay.verify_evidence(root)


class SupportShadowTests(unittest.TestCase):
    def create_shadow(self,exe,mode):
        prefix=exe.parent.parent/'lib/lean/HiaSyntaxResearch'
        if mode=='directory':prefix.mkdir();(prefix/'foreign.olean').write_bytes(b'foreign')
        elif mode=='file':prefix.with_suffix('.olean').write_bytes(b'foreign')
        elif mode=='directory_symlink':prefix.symlink_to('/nonexistent-shadow',target_is_directory=True)
        else:prefix.with_suffix('.olean').symlink_to('/nonexistent-shadow')

    def test_initial_and_midcheck_directory_file_symlink_shadows(self):
        for mode in ('directory','file','directory_symlink','file_symlink'):
            for initial in (True,False):
                with self.subTest(mode=mode,initial=initial),installation() as (home,exe,_,__):
                    external=None if initial else p.External(exe)
                    self.create_shadow(exe,mode)
                    with self.assertRaisesRegex(ValueError,'support module-prefix shadow'):
                        p.External(exe) if initial else external.check()

    def test_shadow_created_by_first_child_stops_later_launch(self):
        prepared,proposal=fixture()
        for mode in ('directory','file','directory_symlink','file_symlink'):
            with self.subTest(mode=mode),installation() as (home,exe,_,__),patch.object(p,'prepare',return_value=(prepared,proposal)):
                actual=c.capture;calls=[]
                def capture(*args,**kwargs):
                    result=actual(*args,**kwargs);calls.append(result)
                    self.create_shadow(exe,mode)
                    return result
                with patch.object(c,'capture',side_effect=capture):output=runner.qualify(exe,home/'out')
                self.assertEqual(len(calls),1)
                self.assertEqual(output['exit_code'],1)
                self.assertEqual(output['result']['error_code'],'identity_changed')
                self.assertEqual(output['result']['phase'],'verifying')
                self.assertFalse((home/'out/SyntaxData.started.json').exists())
