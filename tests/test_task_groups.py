"""Compiler and real-thread regression tests for the bounded group profile."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.pipeline import analyze
from tools.validate_groups import run_scenario


EFFECTS = "alloc,block,panic,spawn,write"
WORKER = """fn producer(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64
effects {alloc,block,panic,write} {let n=len(data);let sent=group_send(read out,1);release(move data);return n as u64;}"""


def native_compiler():
    try:
        return find_rustc(os.environ.get("RUSTC"))
    except HeptaError:
        return None


RUSTC = native_compiler()


class GroupCheckTests(unittest.TestCase):
    def rejected(self, source, code):
        report = analyze(source, native=False).report
        self.assertFalse(report["ok"], report)
        self.assertIn(code, {d["code"] for d in report["diagnostics"]}, report)
        return report

    def parent(self, body, effects=EFFECTS):
        return WORKER + f"fn main()->Unit effects {{{effects}}} {{{body}}}"

    def test_resource_contract_reports_exact_scope(self):
        report = analyze(self.parent('let g=task_group(4,1024,8);group_cancel_and_join(move g);'), native=False).report
        self.assertTrue(report['ok'], report)
        contract = report['resource_contracts'][0]
        self.assertEqual(contract['scope'], 'one_runtime_instance')
        self.assertEqual(contract['limits'], {'admitted_tasks': 4, 'admitted_input_bytes': 1024, 'queued_u64_values': 8})
        self.assertIn('worker_internal_allocations', contract['excludes'])
        self.assertIn('process_RSS', contract['excludes'])

    def test_dynamic_budget_values_are_not_claimed_statically_proven(self):
        source = 'fn f(n:usize)->Unit effects {alloc,block,panic,write} {let g=task_group(n,n,n);group_cancel_and_join(move g);}'
        report = analyze(source, native=False).report
        self.assertTrue(report['ok'], report)
        self.assertEqual(set(report['resource_contracts'][0]['limits'].values()), {'dynamic_runtime_value'})

    def test_literal_zero_queue_is_rejected(self):
        self.rejected(self.parent('let g=task_group(1,8,0);group_cancel_and_join(move g);'), 'E_GROUP_CAPACITY')

    def test_global_numeric_bounds_still_fail_closed(self):
        self.rejected('fn f()->Unit effects {} resources {max_tasks=8;} {}', 'E_RESOURCE_UNSUPPORTED')

    def test_group_requires_consumption(self):
        self.rejected(self.parent('let g=task_group(1,8,1);'), 'E_LINEAR_UNCONSUMED')

    def test_fresh_group_cannot_be_discarded(self):
        self.rejected(self.parent('task_group(1,8,1);'), 'E_LINEAR_DISCARD')

    def test_group_cannot_escape_return(self):
        self.rejected('fn f()->TaskGroup effects {alloc,block,panic} {return move task_group(1,8,1);}', 'E_TASK_SCOPE')

    def test_group_cannot_escape_parameter(self):
        for mode in ['read', 'mut', 'take']:
            with self.subTest(mode=mode):
                self.rejected(f'fn f(g:{mode} TaskGroup)->Unit effects {{}} {{}}', 'E_TASK_SCOPE')

    def test_group_cannot_be_hidden_in_array(self):
        self.rejected(self.parent('let g=task_group(1,8,1);let a=[move g];'), 'E_NESTED_LINEAR')

    def test_group_cannot_be_hidden_in_pointer(self):
        self.rejected('fn f(p:raw mut TaskGroup)->Unit effects {} {}', 'E_NESTED_LINEAR')

    def test_join_requires_move(self):
        self.rejected(self.parent('let g=task_group(1,8,1);group_cancel_and_join(g);'), 'E_MOVE_REQUIRED')

    def test_double_join_rejected(self):
        self.rejected(self.parent('let g=task_group(1,8,1);group_cancel_and_join(move g);group_join(move g);'), 'E_USE_AFTER_MOVE')

    def test_conditional_join_rejected(self):
        self.rejected(self.parent('let g=task_group(1,8,1);if true {group_cancel_and_join(move g);}'), 'E_LINEAR_BRANCH')

    def test_sender_cannot_be_constructed_owned_or_retained(self):
        for source in ['struct Sender{x:u64}', 'fn f(s:Sender<u64>)->Unit effects {} {}',
                       'fn f(s:read Sender<u64>)->Unit effects {} {let retained=s;}',
                       'fn f(s:read Sender<u64>)->Sender<u64> effects {} {return s;}',
                       'fn f(s:read Sender<u64>)->Unit effects {} {let a=[s];}']:
            with self.subTest(source=source):
                report = analyze(source, native=False).report
                self.assertFalse(report['ok'], report)

    def test_sender_supports_only_u64_messages(self):
        self.rejected('fn f(s:read Sender<u8>)->Unit effects {} {}', 'E_SENDER_TYPE')

    def test_spawn_requires_mutable_local_group(self):
        self.rejected(self.parent('let g=task_group(1,8,1);group_spawn(mut g,producer,move buffer(4));group_drain_and_join(move g);'), 'E_IMMUTABLE')

    def test_group_worker_signature_checked(self):
        source = 'fn bad(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block} {release(move data);return 0;}'
        source += f'fn f()->Unit effects {{{EFFECTS}}} {{let mut g=task_group(1,8,1);group_spawn(mut g,bad,move buffer(4));group_drain_and_join(move g);}}'
        self.rejected(source, 'E_TASK_WORKER')

    def test_spawn_consumes_input_even_when_admission_might_fail(self):
        self.rejected(self.parent('let mut g=task_group(0,0,1);let b=buffer(4);group_spawn(mut g,producer,move b);release(move b);group_drain_and_join(move g);'), 'E_USE_AFTER_MOVE')

    def test_receive_requires_mutable_u64_output(self):
        self.rejected(self.parent('let mut g=task_group(0,0,1);group_seal(mut g);let x:u64=0;group_receive(read g,mut x);group_join(move g);'), 'E_IMMUTABLE')

    def test_zero_failure_code_rejected_when_literal(self):
        self.rejected('fn f(s:read Sender<u64>)->Unit effects {alloc,block,panic,write} {group_fail(read s,0);}', 'E_GROUP_FAILURE_CODE')

    def test_report_cannot_be_constructed_from_user_fields(self):
        self.rejected('fn f()->Unit effects {} {let r=GroupReport{};}', 'E_REPORT_CONSTRUCTION')

    def test_transitive_worker_effects_do_not_disappear(self):
        source = WORKER.replace('let n=len(data);', 'print_i64(1);let n=len(data);').replace('effects {alloc,block,panic,write}', 'effects {alloc,block,panic,write,io}')
        source += f'fn f()->Unit effects {{{EFFECTS}}} {{let mut g=task_group(1,8,1);group_spawn(mut g,producer,move buffer(4));group_drain_and_join(move g);}}'
        report = self.rejected(source, 'E_EFFECT')
        self.assertIn('io', report['effects']['f'])

    def test_worker_cannot_launch_nested_group_tasks(self):
        source = WORKER + f'''fn nested(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64
        effects {{{EFFECTS}}} {{let mut g=task_group(1,8,1);group_spawn(mut g,producer,move data);let r=group_drain_and_join(move g);return r.sum;}}
        fn main()->Unit effects {{{EFFECTS}}} {{let mut g=task_group(1,8,1);group_spawn(mut g,nested,move buffer(4));group_drain_and_join(move g);}}'''
        self.rejected(source, 'E_TASK_WORKER_EFFECT')


@unittest.skipUnless(RUSTC, 'requires a real Rust compiler')
class NativeGroupTests(unittest.TestCase):
    def execute(self, source):
        analysis = analyze(source, rustc=RUSTC, native=True, crate_type='bin')
        self.assertTrue(analysis.report['ok'], analysis.report)
        with tempfile.TemporaryDirectory(prefix='hepta-group-native-test-') as temporary:
            output = Path(temporary) / 'program'
            build = compile_rust(analysis.rust, rustc=RUSTC, crate_type='bin', output=output)
            self.assertTrue(build['ok'], build)
            def no_core():
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            return subprocess.run([str(output)], text=True, capture_output=True, timeout=15,
                                  preexec_fn=no_core if os.name == 'posix' else None)

    def test_real_bounded_pipeline_load(self):
        evidence = run_scenario('bounded_pipeline', rustc=RUSTC)
        metrics = evidence['runs'][0]['metrics']
        self.assertEqual(metrics['received_sum'], 32768)
        self.assertEqual(metrics['peak_queued'], 4)
        self.assertGreater(metrics['send_waits'], 0)
        self.assertEqual(metrics['active_tasks'], 0)

    def test_task_and_payload_admission_limits(self):
        evidence = run_scenario('admission_budgets', rustc=RUSTC)
        self.assertEqual(evidence['runs'][0]['metrics'], {
            'admitted_tasks': 2, 'task_budget_rejections': 1,
            'admitted_input_bytes': 8, 'input_budget_rejections': 1,
            'zero_budget_completed': 0})

    def test_multi_producer_messages_preserve_each_producers_order(self):
        source = '''fn producer(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64
        effects {alloc,block,panic,write} {
            let identity=len(data) as u64;
            for i in 0..256 {assert(group_send(read out,wrapping_add(wrapping_mul(identity,1000),i as u64)));}
            release(move data);return 256;
        }
        fn main()->Unit effects {alloc,block,panic,spawn,write} {
            let mut group=task_group(4,10,3);
            assert(group_spawn(mut group,producer,move buffer(1)));
            assert(group_spawn(mut group,producer,move buffer(2)));
            assert(group_spawn(mut group,producer,move buffer(3)));
            assert(group_spawn(mut group,producer,move buffer(4)));
            group_seal(mut group);
            let mut counts:[u64;4]=[0,0,0,0];let mut value:u64=0;
            while group_receive(read group,mut value) {
                let identity=((value/1000)-1) as usize;
                assert(value%1000==counts[identity]);
                counts[identity]=wrapping_add(counts[identity],1);
            }
            for i in 0..len(counts) {assert(counts[i]==256);}
            let report=group_join(move group);
            assert(report.received==1024);assert(report.peak_queued<=3);
        }'''
        proc = self.execute(source)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_closed_empty_receive_preserves_output(self):
        source = '''fn main()->Unit effects {alloc,block,panic,write} {
            let mut group=task_group(0,0,1);group_seal(mut group);let mut value:u64=99;
            assert(!group_receive(read group,mut value));assert(value==99);
            let report=group_join(move group);assert(report.joined);
        }'''
        proc = self.execute(source)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_sealing_rejects_later_admission(self):
        source = WORKER + f'''fn main()->Unit effects {{{EFFECTS}}} {{
            let mut group=task_group(1,8,1);group_seal(mut group);
            assert(!group_spawn(mut group,producer,move buffer(4)));
            let report=group_join(move group);
            assert(report.accepted_tasks==0);assert(report.rejected_tasks==1);
        }}'''
        proc = self.execute(source)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_cancel_wakes_blocked_senders_and_joins(self):
        evidence = run_scenario('cancellation', rustc=RUSTC)
        metrics = evidence['runs'][0]['metrics']
        self.assertEqual(metrics['completed_tasks'], 4)
        self.assertEqual(metrics['active_tasks'], 0)
        self.assertEqual(metrics['waiting_senders'], 0)

    def test_cooperative_worker_failure_joins_siblings(self):
        evidence = run_scenario('worker_failure', rustc=RUSTC)
        metrics = evidence['runs'][0]['metrics']
        self.assertEqual(metrics['failure_code'], 17)
        self.assertEqual(metrics['completed_tasks'], 4)
        self.assertEqual(metrics['active_tasks'], 0)

    def test_dynamic_zero_queue_fails_at_runtime(self):
        proc = self.execute('fn main()->Unit effects {alloc,block,panic,write} {let z:usize=0;let g=task_group(1,1,z);group_cancel_and_join(move g);}')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('queue capacity must be positive', proc.stderr)

    def test_receive_without_seal_is_guarded(self):
        proc = self.execute('fn main()->Unit effects {alloc,block,panic,write} {let g=task_group(0,0,1);let mut x:u64=0;group_receive(read g,mut x);group_cancel_and_join(move g);}')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('requires group_seal', proc.stderr)

    def test_undrained_join_is_guarded_instead_of_channel_deadlock(self):
        source = WORKER + f'''fn main()->Unit effects {{{EFFECTS}}} {{let mut g=task_group(1,1,1);
        assert(group_spawn(mut g,producer,move buffer(1)));while group_snapshot(read g).queued==0 {{}}
        group_join(move g);}}'''
        proc = self.execute(source)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('requires a drained channel', proc.stderr)

    def test_worker_panic_remains_process_fatal(self):
        source = WORKER.replace('let n=len(data);', 'assert(false);let n=len(data);')
        source += f'fn main()->Unit effects {{{EFFECTS}}} {{let mut g=task_group(1,1,1);group_spawn(mut g,producer,move buffer(1));group_drain_and_join(move g);}}'
        proc = self.execute(source)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('assertion failed', proc.stderr)

    def test_group_runtime_rejected_in_no_std_profile(self):
        report = analyze('fn f()->Unit effects {alloc,block,panic,write} {let g=task_group(0,0,1);group_drain_and_join(move g);}',
                         rustc=RUSTC, native=True, no_std=True).report
        self.assertFalse(report['ok'], report)
        self.assertIn('E_NO_STD', {d['code'] for d in report['diagnostics']})


if __name__ == '__main__':
    unittest.main()
