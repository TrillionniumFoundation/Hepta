"""Do not accept historical raw binaries or changed build streams as a fresh composition."""
import copy
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import qualify_hia_composition as subject
from experiments.hia_round4_20261105 import run_frozen_candidate as frozen


def fixture_identity_code(ready):
    """Record syscall and procfs coordinates independently inside the child."""
    return ('raw=Path("/proc/self/stat").read_text()\n'
            'fields=raw.rsplit(")",1)[1].split()\n'
            'temporary=Path('+repr(str(ready))+').with_suffix(".pending")\n'
            'temporary.write_text(json.dumps({"pid":os.getpid(),"pgid":os.getpgrp(),'
            '"proc_pid":int(raw.split("(",1)[0]),"proc_pgid":int(fields[2]),'
            '"proc_sid":int(fields[3]),"starttime":fields[19]}))\n'
            'os.replace(temporary,Path('+repr(str(ready))+'))\n')


class RawCompositionIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-raw-build-identity-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = {'rust/hia-ndu-raw-model/Cargo.toml':'locked adapter\n',
                 'rust/hia-ndu-raw-model/src/main.rs':'selected source\n',
                 'tools/build_hia_ndu_bridge.py':'selected builder\n',
                 'build/command-evidence/cargo.stdout':'actual stdout\n',
                 'build/command-evidence/cargo.stderr':'actual stderr\n',
                 'target/release/hia-ndu-bridge':'actual image\n'}
        for name, text in files.items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.tools = {'cargo':{'path':'/fixed/cargo','version':'cargo 1.95.0 (fixed)'},
                      'rustc':{'version':'rustc 1.95.0 (fixed)'}}
        command = {'schema':'hepta.hia.ndu.build-command.v1',
                   'argv':['/fixed/cargo','build','--manifest-path',str(self.root/'build/Cargo.toml'),
                           '-p','hia-ndu-bridge','--locked','--release'],
                   'cwd':str(self.root),'wall_ns':12000,
                   'returncode':0,'launch_error':None,'original_streams_retained':True}
        for stream in ('stdout','stderr'):
            name = 'command-evidence/cargo.'+stream
            path = self.root/'build'/name
            command[stream] = {'path':name,'bytes':path.stat().st_size,'sha256':subject.digest(path)}
        adapter = self.root/'rust/hia-ndu-raw-model'
        self.manifest = {'schema':'hepta.hia.ndu-build.v1',
            'upstream':{'commit':subject.NDU_SOURCE_PIN},
            'original_rust_sources_unchanged':True,'all_original_non_manifest_inputs_unchanged':True,
            'build_inputs_unchanged':True,'locked_dependencies':True,'isolated_production_manifests':True,
            'adapter_files':{str(p.relative_to(adapter)):subject.digest(p) for p in adapter.rglob('*') if p.is_file()},
            'builder_sha256':subject.digest(self.root/'tools/build_hia_ndu_bridge.py'),
            'rustc_version':self.tools['rustc']['version']+'\nfull version receipt',
            'cargo_version':self.tools['cargo']['version'],
            'binary':str(self.root/'target/release/hia-ndu-bridge'),
            'binary_sha256':subject.digest(self.root/'target/release/hia-ndu-bridge'),
            'production_activation':False,
            'build_cost':{'schema':'hepta.hia.ndu.build-cost.v1','completed':True,'wall_ns':12345,
                          'cargo_wall_ns':12000,'parent_cpu_ns':123,'child_cpu_ns':456,
                          'scope':'observed bounded fixture','fully_cold_machine_claim':False,
                          'target_cache_at_start':'absent'},
            'build_command':command['argv'],'build_command_evidence':command}
        self.receipt = self.root/'build/build-receipt.json'

    def validate(self, manifest):
        self.receipt.write_text(json.dumps(manifest))
        with patch.object(subject, 'ROOT', self.root):
            return subject.validate_raw_build(self.receipt,self.tools)

    def test_tool_identity_keeps_symlink_driver_invocation_name(self):
        implementation = self.root/'real-driver'
        implementation.write_text('#!/usr/bin/env python3\nimport sys\nprint(sys.argv[0])\n')
        implementation.chmod(0o755)
        invocation = self.root/'clang++'
        invocation.symlink_to(implementation)
        observed = subject.executable(invocation)
        self.assertEqual(observed['path'],str(invocation))
        self.assertEqual(observed['resolved_path'],str(implementation))
        self.assertEqual(observed['version'],str(invocation))
        self.assertEqual(observed['sha256'],subject.digest(implementation))

    def test_current_bound_manifest_is_accepted(self):
        self.assertEqual(self.validate(self.manifest),self.manifest)

    def test_failed_process_launch_retains_attempt_cost_and_original_streams(self):
        row = subject.run_command(self.root,'missing-compiler',[self.root/'absent-compiler'])
        self.assertIsNone(row['returncode'])
        self.assertEqual(row['launch_error']['type'],'FileNotFoundError')
        self.assertGreater(row['wall_ns'],0)
        saved = json.loads((self.root/'missing-compiler.command.json').read_text())
        self.assertEqual(saved,row)
        self.assertEqual(set(row['logs']),{'missing-compiler.stdout','missing-compiler.stderr'})

    def test_frozen_deadline_kills_a_term_resistant_owned_child(self):
        ready = self.root/'term-resistant.ready'
        # The self-alarm also bounds a regression to the old unbounded TERM
        # behavior; it is not a successful observer cleanup.
        code = ('import json,os,signal,time\n'
                'from pathlib import Path\n'
                'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                'signal.alarm(8)\n'
                + fixture_identity_code(ready) +
                'print("retained-before-deadline",flush=True)\n'
                'while True: signal.pause()\n')
        started = time.monotonic()
        result = frozen.run_with_deadline([sys.executable,'-u','-c',code],1,
                                         capture_output=True,text=True)
        elapsed = time.monotonic()-started
        self.assertTrue(ready.is_file(), 'child must actually install its TERM handler')
        self.assertEqual(result.returncode,124)
        self.assertIn('retained-before-deadline', result.stdout)
        self.assertLess(elapsed,6, 'cleanup must precede the fixture self-alarm')
        identity = json.loads(ready.read_text())
        self.assertIsNone(self._fixture_state(identity), 'owned direct child must be reaped')
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID,identity['pid'],os.WEXITED|os.WNOWAIT|os.WNOHANG)

    def test_frozen_capture_refuses_live_descendant_after_leader_exit(self):
        ready = self.root/'descendant.ready'
        self.addCleanup(self._stop_owned_fixture_descendant, ready)
        code = ('import json,os,signal,time\n'
                'from pathlib import Path\n'
                'child=os.fork()\n'
                'if child:\n'
                '    time.sleep(0.1)\n'
                '    os._exit(0)\n'
                'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                'signal.alarm(8)\n'
                + fixture_identity_code(ready) +
                'print("descendant-keeps-capture",flush=True)\n'
                'while True: signal.pause()\n')
        started = time.monotonic()
        result = frozen.run_with_deadline([sys.executable,'-u','-c',code],1,
                                         capture_output=True,text=True)
        self.assertTrue(ready.is_file(), 'same-group descendant must actually start')
        # File-backed capture observes the exited leader directly; a live
        # descendant is terminal failure 125, not a new success deadline.
        self.assertEqual(result.returncode,125)
        self.assertIn('descendant-keeps-capture',result.stdout)
        self.assertLess(time.monotonic()-started,6)
        identity = json.loads(ready.read_text())
        # An adopted descendant may close its descriptors before the kernel
        # publishes Z/absence. Observe settlement within the same cleanup
        # allowance; do not mislabel this observation as descendant reaping.
        settle_until = min(started+3,time.monotonic()+0.5)
        while True:
            state = self._fixture_state(identity)
            if state in (None,'Z','X') or time.monotonic() >= settle_until:
                break
            time.sleep(0.005)
        self.assertIn(state,(None,'Z','X'), 'same-group capture writer must no longer execute')

    def test_frozen_deadline_preserves_normal_status_and_both_streams(self):
        for status in (0,7):
            with self.subTest(status=status):
                code = ('import sys\nprint("stdout-prefix")\n'
                        'print("stderr-prefix",file=sys.stderr)\nsys.exit('+str(status)+')\n')
                result = frozen.run_with_deadline([sys.executable,'-c',code],10,
                                                 capture_output=True,text=True)
                self.assertEqual(result.returncode,status)
                self.assertEqual(result.stdout,'stdout-prefix\n')
                self.assertEqual(result.stderr,'stderr-prefix\n')

    def _fixture_state(self, identity):
        # The fixture itself records this procfs coordinate and start time.
        # A reused PID is not the instance whose completion we are observing.
        try:
            raw = (Path('/proc')/str(identity['proc_pid'])/'stat').read_text()
        except (FileNotFoundError, ProcessLookupError):
            return None
        fields = raw.rsplit(')',1)[1].split()
        if fields[19] != identity['starttime']:
            return None
        self.assertEqual(int(raw.split('(',1)[0]), identity['proc_pid'])
        self.assertEqual(int(fields[2]), identity['proc_pgid'])
        self.assertEqual(int(fields[3]), identity['proc_sid'])
        return fields[0]

    def _stop_owned_fixture_descendant(self, ready):
        """Failing regressions clean only the recorded instance, using a pidfd."""
        if not ready.exists():
            return
        identity = json.loads(ready.read_text())
        if self._fixture_state(identity) in (None,'Z','X'):
            return
        try:
            fd = os.pidfd_open(identity['pid'])
        except ProcessLookupError:
            return
        try:
            if self._fixture_state(identity) in (None,'Z','X'):
                return
            info = (Path('/proc/self/fdinfo')/str(fd)).read_text().splitlines()
            nspid = [int(value) for line in info if line.startswith('NSpid:')
                     for value in line.partition(':')[2].split()]
            self.assertEqual((nspid[0],nspid[-1]), (identity['proc_pid'],identity['pid']))
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
        end = time.monotonic()+1
        while True:
            state = self._fixture_state(identity)
            if state in (None,'Z','X') or time.monotonic() >= end:
                break
            time.sleep(0.005)
        self.assertIn(state,(None,'Z','X'), 'owned regression descendant must stop')

    def test_frozen_regular_files_refuse_success_with_a_live_descendant(self):
        ready = self.root/'regular-descendant.ready'
        code = ('import json,os,signal,time\n'
                'from pathlib import Path\n'
                'ready=Path('+repr(str(ready))+')\n'
                'child=os.fork()\n'
                'if child:\n'
                '    signal.alarm(5)\n'
                '    while not ready.exists(): time.sleep(0.001)\n'
                '    os._exit(0)\n'
                'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                'signal.alarm(8)\n'
                'print("regular-file-descendant",flush=True)\n'
                'print("regular-file-stderr",file=__import__("sys").stderr,flush=True)\n'
                + fixture_identity_code(ready) +
                'while True: signal.pause()\n')
        started = time.monotonic()
        try:
            with (self.root/'regular.stdout').open('wb') as out, (self.root/'regular.stderr').open('wb') as err:
                result = frozen.run_with_deadline([sys.executable,'-u','-c',code],3,
                                                 stdout=out,stderr=err)
            self.assertTrue(ready.is_file(), 'live same-group descendant must really start')
            self.assertEqual(result.returncode,125, 'leader exit 0 cannot attest group completion')
            self.assertLess(time.monotonic()-started,5, 'terminal cleanup must precede the self-alarm')
            self.assertEqual((self.root/'regular.stdout').read_text(),'regular-file-descendant\n')
            self.assertEqual((self.root/'regular.stderr').read_text(),'regular-file-stderr\n')
            self.assertIsNone(result.stdout)
            self.assertIsNone(result.stderr)
        finally:
            self._stop_owned_fixture_descendant(ready)

    def test_frozen_group_signal_precedes_leader_reaping(self):
        observed = []
        signal_group = os.killpg

        def observe(leader, sig):
            terminal = os.waitid(os.P_PID,leader,os.WEXITED|os.WNOWAIT|os.WNOHANG)
            observed.append((leader,terminal.si_pid if terminal is not None else None,
                             os.getpgid(leader),os.getsid(leader),sig))
            return signal_group(leader,sig)

        with patch.object(frozen.os,'killpg',side_effect=observe):
            result = frozen.run_with_deadline([sys.executable,'-c','pass'],3,capture_output=True,text=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(len(observed),1)
        leader,terminal,group,session,sig = observed[0]
        self.assertEqual((terminal,group,session,sig),(leader,leader,leader,signal.SIGKILL))
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID,leader,os.WEXITED|os.WNOWAIT|os.WNOHANG)


    def test_frozen_unavailable_namespace_identity_cannot_attest_success(self):
        with patch.object(frozen,'_proc_nspid',side_effect=ValueError('unavailable namespace identity')):
            with self.assertRaisesRegex(ValueError,'unavailable namespace identity'):
                frozen.run_with_deadline([sys.executable,'-c','pass'],3,
                                         capture_output=True,text=True)

    def test_frozen_group_scan_requires_an_owned_unreaped_child(self):
        with self.assertRaises(ChildProcessError):
            frozen._owned_group_live(os.getpid(),time.monotonic()+1)

    def test_dynamic_adapter_requires_its_own_current_sources_and_original_streams(self):
        def validate_dynamic(manifest):
            self.receipt.write_text(json.dumps(manifest))
            with patch.object(subject,'ROOT',self.root):
                return subject.validate_dynamic_build(self.receipt,self.tools)

        # Same build schema and binary protocol do not authenticate a second
        # adapter. Its actual source inventory is an independent identity.
        with self.assertRaises((ValueError,FileNotFoundError)):
            validate_dynamic(self.manifest)
        adapter = self.root/'rust/hia-ndu-dynamic-model'
        (adapter/'src').mkdir(parents=True)
        (adapter/'Cargo.toml').write_text('locked dynamic adapter\n')
        (adapter/'src/main.rs').write_text('distinct supplied-candidate implementation\n')
        with self.assertRaises(ValueError):
            validate_dynamic(self.manifest)
        dynamic = copy.deepcopy(self.manifest)
        dynamic['adapter_files'] = {
            str(p.relative_to(adapter)):subject.digest(p) for p in adapter.rglob('*') if p.is_file()}
        self.assertEqual(validate_dynamic(dynamic),dynamic)
        with self.assertRaises(ValueError):
            self.validate(dynamic)
        for name in ('rust/hia-ndu-dynamic-model/src/main.rs',
                     'build/command-evidence/cargo.stdout','build/command-evidence/cargo.stderr'):
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name),self.assertRaises(ValueError):
                    validate_dynamic(dynamic)
            finally:
                path.write_bytes(original)

    def test_boolean_returncode_and_changed_fixed_argv_are_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['build_command_evidence']['returncode'] = False
        with self.assertRaises(ValueError):
            self.validate(changed)
        changed = copy.deepcopy(self.manifest)
        changed['build_command'].append('--offline')
        changed['build_command_evidence']['argv'] = list(changed['build_command'])
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_historical_or_incomplete_build_cannot_join_composition(self):
        cases = [('rustc_version','rustc 1.96.0 (historical)'),('adapter_files',{}),
                 ('original_rust_sources_unchanged',False),('production_activation',True),
                 ('build_cost',{'completed':True,'wall_ns':0,'target_cache_at_start':'absent'}),
                 ('build_cost',{'completed':True,'wall_ns':True,'target_cache_at_start':'absent'}),
                 ('build_cost',{'completed':True,'wall_ns':12345,'target_cache_at_start':'warm'})]
        for key, value in cases:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                self.validate({**self.manifest,key:value})

    def test_actual_image_and_command_streams_are_rechecked(self):
        for name in ('target/release/hia-ndu-bridge','build/command-evidence/cargo.stdout',
                     'build/command-evidence/cargo.stderr'):
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.validate(self.manifest)
            path.write_bytes(original)

    def test_retained_stream_cannot_escape_build_directory(self):
        changed = copy.deepcopy(self.manifest)
        changed['build_command_evidence']['stdout']['path'] = '../target/release/hia-ndu-bridge'
        with self.assertRaises(ValueError):
            self.validate(changed)


if __name__ == '__main__':
    unittest.main()
