// Appended to the exact production TASK_RUNTIME and GROUP_RUNTIME. These tests
// can inspect private state; source-language behavior is qualified separately.
use std::sync::{Arc, Barrier};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

struct FaultAllocator;
static REFUSE_NEXT_ALLOC: AtomicBool = AtomicBool::new(false);
static TRACKED_POINTER: AtomicUsize = AtomicUsize::new(0);
static TRACKED_FREES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE_NEXT_ALLOC.swap(false, Ordering::SeqCst) { core::ptr::null_mut() }
        else { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer as usize == TRACKED_POINTER.load(Ordering::SeqCst) {
            TRACKED_FREES.fetch_add(1, Ordering::SeqCst);
        }
        System.dealloc(pointer, layout)
    }
}
#[global_allocator] static ALLOCATOR: FaultAllocator = FaultAllocator;
extern "C" { fn hepta_refuse_next_pthread_create(); }
static GO: AtomicBool = AtomicBool::new(false);
static FAIL_WORKER: AtomicBool = AtomicBool::new(false);

fn complete(data: Vec<u8>, _: &HeptaCancellation, _: &HeptaSender) -> u64 {
    let size = data.len() as u64; drop(data); size
}
fn gated(data: Vec<u8>, cancel: &HeptaCancellation, sender: &HeptaSender) -> u64 {
    while !GO.load(Ordering::Acquire) && !cancel.flag.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    if GO.load(Ordering::Acquire) {
        if FAIL_WORKER.load(Ordering::Acquire) { __hepta_group_fail(sender, 17); }
        else { assert!(__hepta_group_send(sender, 73)); }
    }
    drop(data); 1
}
fn await_registration(shared: &Arc<HeptaGroupShared>) -> Arc<HeptaSelectSignal> {
    loop {
        if let Some(signal) = shared.state.lock().unwrap().selectors.first().and_then(|w| w.upgrade()) {
            return signal;
        }
        std::thread::yield_now();
    }
}
fn registrations(group: &HeptaTaskGroup) -> usize {
    group.shared.state.lock().unwrap().selectors.len()
}
fn ready_and_invalid() {
    let mut left = __hepta_group_new(0, 0, 2);
    let mut right = __hepta_group_new(0, 0, 2);
    let l = HeptaSender {shared: Arc::clone(&left.shared)};
    let r = HeptaSender {shared: Arc::clone(&right.shared)};
    assert!(__hepta_group_send(&l, 11)); assert!(__hepta_group_send(&l, 12));
    assert!(__hepta_group_send(&r, 21)); assert!(__hepta_group_send(&r, 22));
    __hepta_group_seal(&mut left); __hepta_group_seal(&mut right);
    let mut output = 99;
    assert_eq!(__hepta_group_select_receive(&left, &left, &mut output, false, 0), Err(3));
    assert_eq!(output, 99);
    for (prefer, expected_side, expected_value) in [(true,2,21),(false,1,11),(false,1,12),(false,2,22)] {
        assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,prefer,0),Ok(expected_side));
        assert_eq!(output, expected_value);
    }
    assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,true,0),Ok(0));
    assert_eq!(output,22);
    assert_eq!(registrations(&left)+registrations(&right),0);
    assert_eq!(__hepta_group_join(left,0).h_received,2);
    assert_eq!(__hepta_group_join(right,0).h_received,2);
}
fn registration_refusals() {
    let mut left = __hepta_group_new(0,0,1);
    let mut right = __hepta_group_new(0,0,1);
    __hepta_group_seal(&mut left); __hepta_group_seal(&mut right);
    let signals: Vec<_> = (0..64).map(|_| Arc::new(HeptaSelectSignal {
        pending: std::sync::Mutex::new(false),changed: std::sync::Condvar::new(),
    })).collect();
    for signal in &signals { assert_eq!(__hepta_select_register(&right.shared,signal),Ok(())); }
    let mut output=91;
    assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,false,1000),Err(4));
    assert_eq!(output,91); assert_eq!(registrations(&left),0); assert_eq!(registrations(&right),64);
    drop(signals);
    __hepta_group_join(left,0); __hepta_group_join(right,0);
}
fn registration_allocator_refusal() {
    let mut group=__hepta_group_new(0,0,1); __hepta_group_seal(&mut group);
    let signal=Arc::new(HeptaSelectSignal{pending:std::sync::Mutex::new(false),changed:std::sync::Condvar::new()});
    REFUSE_NEXT_ALLOC.store(true,Ordering::SeqCst);
    assert_eq!(__hepta_select_register(&group.shared,&signal),Err(4));
    assert!(!REFUSE_NEXT_ALLOC.load(Ordering::SeqCst));
    assert_eq!(registrations(&group),0);
    assert_eq!(__hepta_select_register(&group.shared,&signal),Ok(()));
    group.shared.state.lock().unwrap().selectors.clear();
    __hepta_group_join(group,0);
}
fn select_races() -> usize {
    let mut cases=0;
    for side in 0..2 {
        for _ in 0..64 {
            GO.store(false,Ordering::Release); FAIL_WORKER.store(false,Ordering::Release);
            let mut left=__hepta_group_new(1,1,1); let mut right=__hepta_group_new(1,1,1);
            let selected=if side==0 {&mut left} else {&mut right};
            assert!(__hepta_group_spawn(selected,gated,vec![0]));
            let shared=Arc::clone(&selected.shared);
            __hepta_group_seal(&mut left); __hepta_group_seal(&mut right);
            let opener=std::thread::spawn(move||{await_registration(&shared);GO.store(true,Ordering::Release);});
            let mut output=0;
            assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,side==0,60000),Ok(side+1));
            assert_eq!(output,73); opener.join().unwrap();
            assert_eq!(registrations(&left)+registrations(&right),0);
            __hepta_group_join(left,1);__hepta_group_join(right,1);
            cases+=1;
        }
    }
    cases
}
fn spurious_deadlines() {
    for set_pending in [false,true] {
        GO.store(false,Ordering::Release);
        let mut left=__hepta_group_new(1,1,1);let mut right=__hepta_group_new(0,0,1);
        assert!(__hepta_group_spawn(&mut left,gated,vec![0]));
        __hepta_group_seal(&mut left);__hepta_group_seal(&mut right);
        let shared=Arc::clone(&left.shared);
        let stop=Arc::new(AtomicBool::new(false));let stopped=Arc::clone(&stop);
        let waker=std::thread::spawn(move||{
            let signal=await_registration(&shared);
            while !stopped.load(Ordering::Acquire) {
                if set_pending {*signal.pending.lock().unwrap()=true;}
                signal.changed.notify_all();
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        let start=std::time::Instant::now();let mut output=91;
        assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,false,20),Err(1));
        assert_eq!(output,91);
        assert!(start.elapsed()<std::time::Duration::from_secs(2));
        stop.store(true,Ordering::Release);waker.join().unwrap();
        assert_eq!(registrations(&left)+registrations(&right),0);
        __hepta_group_join(left,2);__hepta_group_join(right,0);
    }
}
fn failure_wakes() {
    GO.store(false,Ordering::Release);FAIL_WORKER.store(true,Ordering::Release);
    let mut left=__hepta_group_new(1,1,1);let mut right=__hepta_group_new(0,0,1);
    assert!(__hepta_group_spawn(&mut left,gated,vec![0]));
    __hepta_group_seal(&mut left);__hepta_group_seal(&mut right);
    let shared=Arc::clone(&left.shared);
    let opener=std::thread::spawn(move||{await_registration(&shared);GO.store(true,Ordering::Release);});
    let mut output=91;
    assert_eq!(__hepta_group_select_receive(&left,&right,&mut output,false,60000),Ok(0));
    assert_eq!(output,91);opener.join().unwrap();
    let failed=__hepta_group_join(left,0);assert!(failed.h_failed&&failed.h_cancelled&&failed.h_joined);
    assert_eq!(failed.h_failure_code,17);assert_eq!(failed.h_active_tasks,0);
    __hepta_group_join(right,0);FAIL_WORKER.store(false,Ordering::Release);
}
fn configured(threads:usize,bytes:usize,stack:usize)->HeptaTaskGroup {
    let mut group=__hepta_group_new(4,4096,1);
    assert!(__hepta_group_budget_configure(&mut group,threads,bytes,1,stack,65536));group
}
fn assert_empty(pool:&HeptaGroupBudget) {
    let s=pool.state.lock().unwrap();
    assert_eq!((s.h_reserved_threads,s.h_reserved_input_bytes,s.h_reserved_queue_slots,
                s.h_reserved_requested_stack_bytes,s.h_attached_groups),(0,0,0,0,0));
}
fn independent_budget_bounds() {
    for (threads,bytes,stack) in [(1,514,131072),(2,257,131072),(2,514,65536)] {
        let mut group=configured(threads,bytes,stack);let pool=Arc::clone(group.budget.as_ref().unwrap());
        assert!(__hepta_group_spawn(&mut group,complete,vec![0;257]));
        assert!(!__hepta_group_spawn(&mut group,complete,vec![0;257]));
        let usage=__hepta_group_budget_snapshot(&group);
        assert_eq!(usage.h_rejected_admissions,1);assert_eq!(usage.h_reserved_threads,1);
        assert_eq!(usage.h_reserved_input_bytes,257);assert_eq!(usage.h_reserved_requested_stack_bytes,65536);
        let report=__hepta_group_join(group,1);assert_eq!(report.h_sum,257);assert_empty(&pool);
    }
}
fn concurrent_budget_admission() -> usize {
    let mut cases=0;
    for _ in 0..64 {
        let mut root=__hepta_group_new(0,0,1);
        assert!(__hepta_group_budget_configure(&mut root,1,257,3,65536,65536));
        let mut left=__hepta_group_new(1,257,1);let mut right=__hepta_group_new(1,257,1);
        assert!(__hepta_group_budget_share(&mut left,&root));assert!(__hepta_group_budget_share(&mut right,&root));
        let barrier=Arc::new(Barrier::new(2));
        let mut threads=Vec::new();
        for mut group in [left,right] {
            let gate=Arc::clone(&barrier);
            threads.push(std::thread::spawn(move||{
                gate.wait();let accepted=__hepta_group_spawn(&mut group,complete,vec![0;257]);
                gate.wait();__hepta_group_join(group,1);accepted as usize
            }));
        }
        let accepted:usize=threads.into_iter().map(|t|t.join().unwrap()).sum();assert_eq!(accepted,1);
        let usage=__hepta_group_budget_snapshot(&root);
        assert_eq!(usage.h_peak_threads,1);assert_eq!(usage.h_rejected_admissions,1);
        assert_eq!(usage.h_reserved_threads,0);assert_eq!(usage.h_reserved_queue_slots,1);
        let pool=Arc::clone(root.budget.as_ref().unwrap());__hepta_group_join(root,0);assert_empty(&pool);
        cases+=1;
    }
    cases
}
fn tracked_payload()->Vec<u8> {
    let data=vec![0;257];TRACKED_FREES.store(0,Ordering::SeqCst);
    TRACKED_POINTER.store(data.as_ptr() as usize,Ordering::SeqCst);data
}
fn actual_failure_rollback() {
    for fail_os in [false,true] {
        let mut group=configured(2,514,131072);let pool=Arc::clone(group.budget.as_ref().unwrap());
        let data=tracked_payload();
        if fail_os {unsafe{hepta_refuse_next_pthread_create();}}
        else {REFUSE_NEXT_ALLOC.store(true,Ordering::SeqCst);}
        assert!(!__hepta_group_spawn(&mut group,complete,data));
        assert!(!REFUSE_NEXT_ALLOC.load(Ordering::SeqCst));
        assert_eq!(TRACKED_FREES.load(Ordering::SeqCst),1);TRACKED_POINTER.store(0,Ordering::SeqCst);
        let usage=__hepta_group_budget_snapshot(&group);
        assert_eq!((usage.h_reserved_threads,usage.h_reserved_input_bytes,usage.h_reserved_requested_stack_bytes),(0,0,0));
        assert_eq!(usage.h_spawn_failures,1);assert_eq!(usage.h_rejected_admissions,1);
        let local=__hepta_group_snapshot(&group);
        assert_eq!((local.h_accepted_tasks,local.h_active_tasks,local.h_input_bytes),(0,0,0));
        assert_eq!(local.h_spawn_failures,1);
        assert!(__hepta_group_spawn(&mut group,complete,vec![0;11]));
        let done=__hepta_group_join(group,1);assert_eq!(done.h_sum,11);assert_eq!(done.h_completed_tasks,1);
        assert_empty(&pool);
    }
}
fn main() {
    ready_and_invalid();registration_refusals();registration_allocator_refusal();
    let races=select_races();spurious_deadlines();failure_wakes();
    independent_budget_bounds();let admissions=concurrent_budget_admission();actual_failure_rollback();
    println!("6\n2\n{}\n2\n1\n3\n{}\n2\n2\n0",races,admissions);
}
