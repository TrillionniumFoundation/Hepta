"""Native deadline, channel-state and cancellation ownership regressions."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.backend import GROUP_RUNTIME, TASK_RUNTIME, compile_rust
from hepta.pipeline import analyze
from tests import test_task_groups as group_tests
from tools.validate_groups import run_scenario

RUSTC = group_tests.RUSTC


class TimeoutChecks(unittest.TestCase):
    def reject(self, source, code):
        result = analyze(source, native=False).report
        self.assertFalse(result['ok'], result)
        self.assertIn(code, {d['code'] for d in result['diagnostics']}, result)

    def test_timeout_preserves_typed_result_and_declared_effects(self):
        source = '''fn send(s:read Sender<u64>)->Result<bool,u8> effects {} {
            return group_send_timeout(read s,1,1);
        }'''
        self.reject(source, 'E_EFFECT')
        source = source.replace('effects {}', 'effects {alloc,block,panic,write}')
        result = analyze(source, native=False).report
        self.assertTrue(result['ok'], result)

    def test_timeout_arity_and_duration_type(self):
        self.reject('fn f(s:read Sender<u64>)->Unit effects {alloc,block,panic,write} {group_send_timeout(read s,1);}', 'E_ARITY')
        self.reject('fn f(s:read Sender<u64>)->Unit effects {alloc,block,panic,write} {group_send_timeout(read s,1,true);}', 'E_TYPE')

    def test_cancel_does_not_discharge_join_obligation(self):
        self.reject('fn f()->Unit effects {alloc,block,panic,write} {let mut g=task_group(0,0,1);group_cancel(mut g);}', 'E_LINEAR_UNCONSUMED')

    def test_timeout_cannot_overwrite_immutable_output(self):
        self.reject('fn f()->Unit effects {alloc,block,panic,write} {let mut g=task_group(0,0,1);group_seal(mut g);let x:u64=0;group_receive_timeout(read g,mut x,0);group_join(move g);}', 'E_IMMUTABLE')

    def test_cancel_requires_mutable_group(self):
        self.reject('fn f()->Unit effects {alloc,block,panic,write} {let g=task_group(0,0,1);group_cancel(mut g);group_join(move g);}', 'E_IMMUTABLE')


@unittest.skipUnless(RUSTC, 'requires the native Rust reference compiler')
class TimeoutNativeTests(unittest.TestCase):
    def execute(self, source):
        return group_tests.NativeGroupTests.execute(self, source)

    def runtime(self, source):
        with tempfile.TemporaryDirectory(prefix='hepta-timeout-runtime-') as directory:
            output = Path(directory) / 'run'
            built = compile_rust('#![allow(dead_code)]\n' + TASK_RUNTIME + GROUP_RUNTIME + source,
                                 rustc=RUSTC, crate_type='bin', output=output)
            self.assertTrue(built['ok'], built)
            executed = subprocess.run([output], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_language_timeouts_zero_poll_and_owned_cancel_cleanup(self):
        evidence = run_scenario('timeouts', rustc=RUSTC)
        self.assertEqual(evidence['runs'][0]['metrics'], {
            'send_timeouts': 1, 'receive_timeouts': 1, 'received': 1,
            'completed_tasks': 1, 'active_tasks': 0, 'worker_result_sum': 2})

    def test_timeout_still_requires_sealed_group(self):
        executed = self.execute('fn main()->Unit effects {alloc,block,panic,write} {let g=task_group(0,0,1);let mut x:u64=0;group_receive_timeout(read g,mut x,0);group_cancel_and_join(move g);}')
        self.assertNotEqual(executed.returncode, 0)
        self.assertIn('requires group_seal', executed.stderr)

    def test_nonzero_send_timeout_releases_waiter_and_does_not_publish_value(self):
        self.runtime(r'''
fn main() {
    let mut group=__hepta_group_new(0,0,1);
    let sender=HeptaSender{shared:std::sync::Arc::clone(&group.shared)};
    assert_eq!(__hepta_group_send_timeout(&sender,41,0),Ok(true));
    assert_eq!(__hepta_group_send_timeout(&sender,99,5),Err(1));
    let report=__hepta_group_snapshot(&group);
    assert_eq!(report.h_send_timeouts,1);
    assert_eq!(report.h_waiting_senders,0);
    assert_eq!(report.h_queued,1);
    __hepta_group_seal(&mut group);
    let mut value=17;
    assert_eq!(__hepta_group_receive_timeout(&group,&mut value,0),Ok(true));
    assert_eq!(value,41);
    assert_eq!(__hepta_group_receive_timeout(&group,&mut value,0),Ok(false));
    assert_eq!(__hepta_group_send_timeout(&sender,99,0),Ok(false));
    let report=__hepta_group_join(group,0);
    assert_eq!(report.h_received,1);
    assert_eq!(report.h_queued,0);
}
''')

    def test_cancellation_wakes_timed_sender_without_waiting_for_deadline(self):
        self.runtime(r'''
fn worker(data:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    assert!(__hepta_group_send(sender,41));
    assert_eq!(__hepta_group_send_timeout(sender,99,60000),Ok(false));
    drop(data); 7
}
fn main() {
    let mut group=__hepta_group_new(1,8,1);
    assert!(__hepta_group_spawn(&mut group,worker,vec![0;8]));
    while __hepta_group_snapshot(&group).h_waiting_senders!=1 {std::thread::yield_now();}
    __hepta_group_cancel(&mut group);
    __hepta_group_cancel(&mut group);
    let report=__hepta_group_join(group,0);
    assert!(report.h_cancelled && report.h_joined);
    assert_eq!(report.h_discarded,1);
    assert_eq!(report.h_send_timeouts,0);
    assert_eq!(report.h_waiting_senders,0);
    assert_eq!(report.h_active_tasks,0);
    assert_eq!(report.h_sum,7);
}
''')

    def test_spurious_wakes_do_not_restart_receive_deadline(self):
        self.runtime(r'''
fn worker(data:Vec<u8>,cancel:&HeptaCancellation,_:&HeptaSender)->u64 {
    while !cancel.flag.load(std::sync::atomic::Ordering::Acquire) {std::thread::yield_now();}
    drop(data); 0
}
fn main() {
    let mut group=__hepta_group_new(1,1,1);
    assert!(__hepta_group_spawn(&mut group,worker,vec![0]));
    __hepta_group_seal(&mut group);
    let shared=std::sync::Arc::clone(&group.shared);
    let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_waker=std::sync::Arc::clone(&stop);
    let waker=std::thread::spawn(move || {
        let until=std::time::Instant::now()+std::time::Duration::from_secs(3);
        while std::time::Instant::now()<until && !stop_waker.load(std::sync::atomic::Ordering::Acquire) {
            shared.readable.notify_all();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let start=std::time::Instant::now(); let mut value=47;
    assert_eq!(__hepta_group_receive_timeout(&group,&mut value,20),Err(1));
    let elapsed=start.elapsed();
    stop.store(true,std::sync::atomic::Ordering::Release); waker.join().unwrap();
    // A generous watchdog detects restarted deadlines; this is not a language
    // promise of a one-second real-time deadline on arbitrary hosts.
    assert!(elapsed<std::time::Duration::from_secs(2),"deadline restarted: {:?}",elapsed);
    assert_eq!(value,47);
    __hepta_group_cancel(&mut group);
    let report=__hepta_group_join(group,0);
    assert_eq!(report.h_receive_timeouts,1);
    assert_eq!(report.h_received,0);
    assert_eq!(report.h_active_tasks,0);
}
''')


if __name__ == '__main__':
    unittest.main()
