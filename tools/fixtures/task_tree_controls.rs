// Appended to the exact production runtime. No fixture implementation replaces
// tree adoption, cancellation, queue draining, native spawn or join.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct FaultAllocator;
static REFUSE_ALLOC: AtomicBool = AtomicBool::new(false);
static TRACKED_POINTER: AtomicUsize = AtomicUsize::new(0);
static TRACKED_BYTES: AtomicUsize = AtomicUsize::new(0);
static TRACKED_FREES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE_ALLOC.swap(false, Ordering::SeqCst) { core::ptr::null_mut() }
        else { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer as usize == TRACKED_POINTER.load(Ordering::SeqCst)
            && layout.size() == TRACKED_BYTES.load(Ordering::SeqCst) {
            TRACKED_FREES.fetch_add(1, Ordering::SeqCst);
        }
        System.dealloc(pointer, layout)
    }
}
#[global_allocator] static ALLOCATOR: FaultAllocator = FaultAllocator;
extern "C" { fn hepta_refuse_next_pthread_create(); }

static GATE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static DEPENDENCY: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static FINISHED: AtomicUsize = AtomicUsize::new(0);

fn gate_reset(gate: &(Mutex<bool>, Condvar)) { *gate.0.lock().unwrap() = false; }
fn gate_open(gate: &(Mutex<bool>, Condvar)) { *gate.0.lock().unwrap() = true; gate.1.notify_all(); }
fn gate_wait(gate: &(Mutex<bool>, Condvar)) {
    let until = Instant::now() + Duration::from_secs(10);
    let mut open = gate.0.lock().unwrap();
    while !*open {
        let left = until.checked_duration_since(Instant::now()).expect("test gate timeout");
        open = gate.1.wait_timeout(open, left).unwrap().0;
    }
}
fn await_condition(test: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !test() { assert!(Instant::now() < until, "test synchronization timeout"); std::thread::yield_now(); }
}
fn wait_for_sender(group: &HeptaTaskGroup) {
    await_condition(|| group.shared.state.lock().unwrap().report.h_waiting_senders == 1);
}
fn record(shared: &HeptaGroupShared) -> H_GroupReport { shared.state.lock().unwrap().report }
fn aggregate(shared: &HeptaGroupShared) -> H_GroupTreeReport {
    let mut result = H_GroupTreeReport::default();
    result.h_depth = shared.tree.lock().unwrap().depth;
    __hepta_tree_accumulate(shared, &mut result); result
}
fn track(data: &Vec<u8>) {
    TRACKED_POINTER.store(data.as_ptr() as usize, Ordering::SeqCst);
    TRACKED_BYTES.store(data.capacity(), Ordering::SeqCst);
    TRACKED_FREES.store(0, Ordering::SeqCst);
}
fn untrack_once() {
    TRACKED_POINTER.store(0, Ordering::SeqCst);
    assert_eq!(TRACKED_FREES.load(Ordering::SeqCst), 1);
}
fn empty_pool(pool: &HeptaGroupBudget) {
    let b = pool.state.lock().unwrap();
    assert_eq!((b.h_attached_groups, b.h_reserved_threads, b.h_reserved_input_bytes,
                b.h_reserved_queue_slots, b.h_reserved_requested_stack_bytes), (0,0,0,0,0));
}
fn complete(data: Vec<u8>, _: &HeptaCancellation, _: &HeptaSender) -> u64 {
    let n = data.len() as u64; drop(data); FINISHED.fetch_add(1, Ordering::SeqCst); n
}
fn blocked(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    assert!(__hepta_group_send(out, 1));
    assert!(!__hepta_group_send(out, 2));
    assert!(cancel.flag.load(Ordering::Acquire));
    complete(data, cancel, out)
}
fn gated_complete(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    gate_wait(&GATE); complete(data, cancel, out)
}
fn gated_failure(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    gate_wait(&GATE); __hepta_group_fail(out, 77); complete(data, cancel, out)
}
fn late_failure(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    gate_wait(&DEPENDENCY); __hepta_group_fail(out, 79); complete(data, cancel, out)
}
fn dependent(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    assert!(__hepta_group_send(out, 1));
    gate_wait(&DEPENDENCY); complete(data, cancel, out)
}
fn producer(data: Vec<u8>, cancel: &HeptaCancellation, out: &HeptaSender) -> u64 {
    for i in 0..128 { assert!(__hepta_group_send(out, i)); }
    gate_open(&DEPENDENCY); complete(data, cancel, out)
}

fn interdependent_queues() {
    gate_reset(&DEPENDENCY); FINISHED.store(0, Ordering::SeqCst);
    let mut root = __hepta_group_new(1,1,1);
    let mut first = __hepta_group_new(1,1,1);
    let mut second = __hepta_group_new(0,0,1);
    let mut leaf = __hepta_group_new(1,1,1);
    assert!(__hepta_group_spawn(&mut root, dependent, vec![0]));
    assert!(__hepta_group_spawn(&mut first, dependent, vec![0]));
    assert!(__hepta_group_spawn(&mut leaf, producer, vec![0]));
    wait_for_sender(&leaf);
    assert!(__hepta_group_adopt(&mut second, leaf));
    assert!(__hepta_group_adopt(&mut root, first));
    assert!(__hepta_group_adopt(&mut root, second));
    let done = __hepta_group_tree_join(root, false);
    assert_eq!((done.h_groups,done.h_depth,done.h_joined_groups,done.h_completed_tasks,
                done.h_active_tasks,done.h_discarded,done.h_sum), (4,3,4,3,0,130,3));
    assert_eq!(FINISHED.load(Ordering::SeqCst), 3);
}
fn legacy_joins() -> usize {
    let mut cases = 0;
    for mode in 0..3 {
        gate_reset(&GATE); FINISHED.store(0, Ordering::SeqCst);
        let mut root = __hepta_group_new(0,0,1);
        let mut branch = __hepta_group_new(0,0,1);
        let mut leaf = __hepta_group_new(1,19,1);
        assert!(__hepta_group_budget_configure(&mut root,1,19,3,65536,65536));
        assert!(__hepta_group_budget_share(&mut branch,&root));
        assert!(__hepta_group_budget_share(&mut leaf,&root));
        let pool = Arc::clone(root.budget.as_ref().unwrap());
        let root_state = Arc::clone(&root.shared); let leaf_state = Arc::clone(&leaf.shared);
        let data = vec![0;19]; track(&data);
        assert!(__hepta_group_spawn(&mut leaf,gated_complete,data));
        assert!(__hepta_group_adopt(&mut branch,leaf));
        assert!(__hepta_group_adopt(&mut root,branch));
        let joining = std::thread::spawn(move || __hepta_group_join(root,mode));
        await_condition(|| root_state.tree.lock().unwrap().joining);
        assert_eq!(FINISHED.load(Ordering::SeqCst),0);
        assert!(!joining.is_finished());
        assert_eq!(TRACKED_FREES.load(Ordering::SeqCst),0);
        assert_eq!(pool.state.lock().unwrap().h_reserved_threads,1);
        gate_open(&GATE);
        let flat = joining.join().unwrap();
        assert!(flat.h_joined); assert_eq!(flat.h_accepted_tasks,0);
        let all = aggregate(&root_state);
        assert_eq!((all.h_groups,all.h_joined_groups,all.h_active_tasks,all.h_completed_tasks),(3,3,0,1));
        assert!(record(&leaf_state).h_joined);
        assert_eq!(FINISHED.load(Ordering::SeqCst),1); untrack_once(); empty_pool(&pool);
        cases += 1;
    }
    cases
}
fn explicit_parent_cancel() {
    FINISHED.store(0, Ordering::SeqCst);
    let mut root = __hepta_group_new(1,1,1);
    let mut branch = __hepta_group_new(0,0,1);
    let mut leaf = __hepta_group_new(1,7,1);
    assert!(__hepta_group_spawn(&mut leaf,blocked,vec![0;7])); wait_for_sender(&leaf);
    let child_state = Arc::clone(&leaf.shared);
    assert!(__hepta_group_adopt(&mut branch,leaf)); assert!(__hepta_group_adopt(&mut root,branch));
    __hepta_group_cancel(&mut root);
    assert!(child_state.cancel.load(Ordering::Acquire));
    assert!(!__hepta_group_spawn(&mut root,complete,vec![0]));
    let done = __hepta_group_tree_join(root,false);
    assert_eq!((done.h_groups,done.h_joined_groups,done.h_sum,done.h_discarded,done.h_active_tasks),(3,3,7,1,0));
    assert!(done.h_cancelled && !done.h_failed); assert_eq!(FINISHED.load(Ordering::SeqCst),1);
}
fn failures_both_directions() -> usize {
    let mut cases = 0;
    for from_leaf in [false,true] {
        gate_reset(&GATE); FINISHED.store(0,Ordering::SeqCst);
        let mut root = __hepta_group_new(1,1,1); let mut branch = __hepta_group_new(0,0,1);
        let mut leaf = __hepta_group_new(1,1,1); let mut sibling = __hepta_group_new(1,1,1);
        assert!(__hepta_group_spawn(&mut root,if from_leaf {blocked} else {gated_failure},vec![0]));
        assert!(__hepta_group_spawn(&mut leaf,if from_leaf {gated_failure} else {blocked},vec![0]));
        assert!(__hepta_group_spawn(&mut sibling,blocked,vec![0]));
        wait_for_sender(if from_leaf {&root} else {&leaf}); wait_for_sender(&sibling);
        let leaf_state=Arc::clone(&leaf.shared); let sibling_state=Arc::clone(&sibling.shared);
        assert!(__hepta_group_adopt(&mut branch,leaf)); assert!(__hepta_group_adopt(&mut root,branch));
        assert!(__hepta_group_adopt(&mut root,sibling));
        gate_open(&GATE);
        await_condition(|| record(&root.shared).h_failed && leaf_state.cancel.load(Ordering::Acquire)
                        && sibling_state.cancel.load(Ordering::Acquire));
        let done=__hepta_group_tree_join(root,false);
        assert!(done.h_failed && done.h_cancelled); assert_eq!(done.h_failure_code,77);
        assert_eq!((done.h_groups,done.h_joined_groups,done.h_completed_tasks,done.h_active_tasks,done.h_sum),(4,4,3,0,3));
        assert_eq!(done.h_discarded,2); assert_eq!(done.h_waiting_senders,0);
        for node in [&leaf_state,&sibling_state] { assert!(record(node).h_failed && record(node).h_joined); }
        assert_eq!(FINISHED.load(Ordering::SeqCst),3); cases+=1;
    }
    cases
}
fn adoption_allocation_refusal() {
    let mut root=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(0,0,1);
    let mut leaf=__hepta_group_new(1,11,1);
    assert!(__hepta_group_budget_configure(&mut root,1,11,3,65536,65536));
    assert!(__hepta_group_budget_share(&mut child,&root)); assert!(__hepta_group_budget_share(&mut leaf,&root));
    let pool=Arc::clone(root.budget.as_ref().unwrap()); let subtree=Arc::clone(&child.shared);
    let data=vec![0;11]; track(&data);
    assert!(__hepta_group_spawn(&mut leaf,blocked,data)); wait_for_sender(&leaf);
    assert!(__hepta_group_adopt(&mut child,leaf));
    REFUSE_ALLOC.store(true,Ordering::SeqCst);
    assert!(!__hepta_group_adopt(&mut root,child));
    assert!(!REFUSE_ALLOC.load(Ordering::SeqCst)); untrack_once();
    let refused=aggregate(&subtree); assert_eq!((refused.h_groups,refused.h_joined_groups,refused.h_active_tasks),(2,2,0));
    let unchanged=__hepta_group_tree_snapshot(&root);
    assert_eq!((unchanged.h_groups,unchanged.h_depth,unchanged.h_adopted_groups,unchanged.h_adoption_refusals),(1,1,0,1));
    let b=__hepta_group_budget_snapshot(&root);
    assert_eq!((b.h_attached_groups,b.h_reserved_threads,b.h_reserved_input_bytes,b.h_reserved_queue_slots),(1,0,0,1));
    let mut recovery=__hepta_group_new(1,11,1); assert!(__hepta_group_budget_share(&mut recovery,&root));
    assert!(__hepta_group_spawn(&mut recovery,complete,vec![0;11]));
    assert!(__hepta_group_adopt(&mut root,recovery));
    let done=__hepta_group_tree_join(root,false);
    assert_eq!((done.h_groups,done.h_joined_groups,done.h_completed_tasks,done.h_sum),(2,2,1,11));
    empty_pool(&pool);
}
fn native_spawn_refusal() {
    let mut root=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(0,0,1);
    let mut leaf=__hepta_group_new(1,17,1);
    assert!(__hepta_group_budget_configure(&mut root,1,17,3,65536,65536));
    assert!(__hepta_group_budget_share(&mut child,&root)); assert!(__hepta_group_budget_share(&mut leaf,&root));
    let pool=Arc::clone(root.budget.as_ref().unwrap()); let data=vec![0;17]; track(&data);
    unsafe { hepta_refuse_next_pthread_create(); }
    assert!(!__hepta_group_spawn(&mut leaf,complete,data)); untrack_once();
    let usage=__hepta_group_budget_snapshot(&root);
    assert_eq!((usage.h_reserved_threads,usage.h_reserved_input_bytes,usage.h_reserved_requested_stack_bytes,
                usage.h_spawn_failures),(0,0,0,1));
    assert!(__hepta_group_spawn(&mut leaf,complete,vec![0;17]));
    assert!(__hepta_group_adopt(&mut child,leaf)); assert!(__hepta_group_adopt(&mut root,child));
    let done=__hepta_group_tree_join(root,false);
    assert_eq!((done.h_groups,done.h_joined_groups,done.h_spawn_failures,done.h_completed_tasks,done.h_sum),(3,3,1,1,17));
    empty_pool(&pool);
}
fn bounds_and_budget_identity() -> usize {
    let mut cases=0;
    let mut chain=__hepta_group_new(0,0,1);
    for _ in 1..HEPTA_TREE_MAX_DEPTH {
        let mut parent=__hepta_group_new(0,0,1); assert!(__hepta_group_adopt(&mut parent,chain)); chain=parent;
    }
    assert_eq!(__hepta_group_tree_snapshot(&chain).h_depth,16);
    let old=Arc::clone(&chain.shared); let mut above=__hepta_group_new(0,0,1);
    assert!(!__hepta_group_adopt(&mut above,chain));
    assert_eq!(aggregate(&old).h_joined_groups,16);
    assert_eq!(__hepta_group_tree_join(above,false).h_groups,1); cases+=1;
    let mut root=__hepta_group_new(0,0,1);
    for _ in 1..HEPTA_TREE_MAX_GROUPS { assert!(__hepta_group_adopt(&mut root,__hepta_group_new(0,0,1))); }
    let overflow=__hepta_group_new(0,0,1); let old=Arc::clone(&overflow.shared);
    assert!(!__hepta_group_adopt(&mut root,overflow)); assert!(record(&old).h_joined);
    let done=__hepta_group_tree_join(root,false); assert_eq!((done.h_groups,done.h_joined_groups,done.h_depth),(256,256,2)); cases+=1;
    for (parent_pool,child_pool) in [(true,false),(false,true),(true,true)] {
        let mut parent=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(0,0,1);
        if parent_pool { assert!(__hepta_group_budget_configure(&mut parent,0,0,2,0,65536)); }
        if child_pool { assert!(__hepta_group_budget_configure(&mut child,0,0,2,0,65536)); }
        let old=Arc::clone(&child.shared); assert!(!__hepta_group_adopt(&mut parent,child));
        assert!(record(&old).h_joined); assert_eq!(__hepta_group_tree_snapshot(&parent).h_groups,1);
        __hepta_group_join(parent,0); cases+=1;
    }
    let mut parent=__hepta_group_new(0,0,1); let child=__hepta_group_new(0,0,1);
    assert!(__hepta_group_adopt(&mut parent,child));
    assert!(!__hepta_group_budget_configure(&mut parent,0,0,2,0,65536));
    let mut sponsor=__hepta_group_new(0,0,1); assert!(__hepta_group_budget_configure(&mut sponsor,0,0,4,0,65536));
    assert!(!__hepta_group_budget_share(&mut parent,&sponsor));
    __hepta_group_join(parent,0); __hepta_group_join(sponsor,0); cases+=1;
    let mut parent=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(0,0,1);
    __hepta_group_seal(&mut child); assert!(__hepta_group_adopt(&mut parent,child));
    __hepta_group_seal(&mut parent); let child=__hepta_group_new(0,0,1); let old=Arc::clone(&child.shared);
    assert!(!__hepta_group_adopt(&mut parent,child)); assert!(record(&old).h_joined);
    assert_eq!(__hepta_group_tree_join(parent,false).h_joined_groups,2); cases+=1;
    cases
}
fn deterministic_failure_orders() -> usize {
    let mut cases=0;
    for at_child in [false,true] { for before in [false,true] {
        let mut parent=__hepta_group_new(0,0,1); let child=__hepta_group_new(0,0,1);
        let child_state=Arc::clone(&child.shared);
        let sender=HeptaSender{shared:Arc::clone(if at_child {&child.shared} else {&parent.shared})};
        if before { __hepta_group_fail(&sender,91); }
        assert_eq!(__hepta_group_adopt(&mut parent,child),!before);
        if !before { __hepta_group_fail(&sender,91); }
        let done=__hepta_group_tree_join(parent,false);
        assert_eq!(done.h_groups,if before {1} else {2});
        assert_eq!(done.h_failed,!at_child || !before);
        assert!(record(&child_state).h_joined && record(&child_state).h_cancelled); cases+=1;
    } }
    cases
}
fn adoption_failure_races() -> usize {
    let mut cases=0;
    for at_child in [false,true] { for _ in 0..64 {
        let mut parent=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(0,0,1);
        assert!(__hepta_group_adopt(&mut child,__hepta_group_new(0,0,1)));
        let state=Arc::clone(&child.shared);
        let sender=HeptaSender{shared:Arc::clone(if at_child {&child.shared} else {&parent.shared})};
        let gate=Arc::new(Barrier::new(2)); let other=Arc::clone(&gate);
        let failing=std::thread::spawn(move || { other.wait(); __hepta_group_fail(&sender,92); });
        gate.wait(); let accepted=__hepta_group_adopt(&mut parent,child); failing.join().unwrap();
        let done=__hepta_group_tree_join(parent,false);
        assert_eq!(done.h_groups,if accepted {3} else {1});
        assert_eq!(done.h_joined_groups,done.h_groups);
        assert_eq!(done.h_failed,!at_child || accepted);
        assert_eq!(aggregate(&state).h_joined_groups,2); assert!(record(&state).h_cancelled);
        cases+=1;
    } }
    cases
}
fn spawn_close_races() -> usize {
    let mut cases=0;
    for _ in 0..64 {
        let mut root=__hepta_group_new(1,23,1);
        assert!(__hepta_group_budget_configure(&mut root,1,23,1,65536,65536));
        let pool=Arc::clone(root.budget.as_ref().unwrap());
        let sender=HeptaSender{shared:Arc::clone(&root.shared)};
        let barrier=Arc::new(Barrier::new(2)); let other=Arc::clone(&barrier);
        let failure=std::thread::spawn(move || { other.wait(); __hepta_group_fail(&sender,93); });
        let data=vec![0;23]; track(&data);
        barrier.wait(); let accepted=__hepta_group_spawn(&mut root,complete,data);
        failure.join().unwrap();
        assert!(!__hepta_group_spawn(&mut root,complete,vec![]));
        let done=__hepta_group_tree_join(root,false);
        assert_eq!(done.h_accepted_tasks,usize::from(accepted));
        assert_eq!(done.h_completed_tasks,done.h_accepted_tasks); assert_eq!(done.h_active_tasks,0);
        assert_eq!(done.h_sum,if accepted {23} else {0}); assert!(done.h_failed);
        untrack_once(); empty_pool(&pool); cases+=1;
    }
    cases
}
fn spurious_tree_wakes() {
    gate_reset(&GATE);
    let mut root=__hepta_group_new(0,0,1); let mut child=__hepta_group_new(1,1,1);
    assert!(__hepta_group_spawn(&mut child,gated_complete,vec![0]));
    assert!(__hepta_group_adopt(&mut root,child));
    let state=Arc::clone(&root.shared);
    let joined=std::thread::spawn(move || __hepta_group_tree_join(root,false));
    await_condition(|| state.tree.lock().unwrap().joining);
    let signal=Arc::clone(&state.state.lock().unwrap().tree_signal);
    for _ in 0..64 { signal.changed.notify_all(); }
    assert!(!joined.is_finished()); gate_open(&GATE);
    assert_eq!(joined.join().unwrap().h_joined_groups,2);
}
fn failure_during_child_join() {
    gate_reset(&GATE); gate_reset(&DEPENDENCY);
    let mut root=__hepta_group_new(0,0,1); let mut first=__hepta_group_new(1,1,1);
    let mut second=__hepta_group_new(1,1,1);
    assert!(__hepta_group_spawn(&mut first,gated_complete,vec![0]));
    assert!(__hepta_group_spawn(&mut second,late_failure,vec![0]));
    let first_state=Arc::clone(&first.shared); let root_state=Arc::clone(&root.shared);
    assert!(__hepta_group_adopt(&mut root,first)); assert!(__hepta_group_adopt(&mut root,second));
    let joining=std::thread::spawn(move || __hepta_group_tree_join(root,true));
    // The first child owner has left its slot for a blocking native join. The
    // retained shared link must still carry a later sibling failure into it.
    await_condition(|| root_state.tree.lock().unwrap().children[0].owner.is_none());
    assert!(!joining.is_finished()); gate_open(&DEPENDENCY);
    await_condition(|| record(&first_state).h_failed);
    assert_eq!(record(&first_state).h_failure_code,79);
    gate_open(&GATE);
    let done=joining.join().unwrap();
    assert_eq!((done.h_joined_groups,done.h_completed_tasks,done.h_failure_code),(3,2,79));
}
fn deepest_failure_on_minimum_requested_stack() {
    gate_reset(&GATE);
    let mut chain=__hepta_group_new(1,1,1);
    assert!(__hepta_group_budget_configure(&mut chain,1,1,16,65536,65536));
    let pool=Arc::clone(chain.budget.as_ref().unwrap());
    assert!(__hepta_group_spawn(&mut chain,gated_failure,vec![0]));
    for _ in 1..HEPTA_TREE_MAX_DEPTH {
        let mut above=__hepta_group_new(0,0,1);
        assert!(__hepta_group_budget_share(&mut above,&chain));
        assert!(__hepta_group_adopt(&mut above,chain)); chain=above;
    }
    gate_open(&GATE);
    let done=__hepta_group_tree_join(chain,false);
    assert_eq!((done.h_groups,done.h_depth,done.h_joined_groups,done.h_completed_tasks,done.h_active_tasks),(16,16,16,1,0));
    assert!(done.h_failed && done.h_cancelled); assert_eq!(done.h_failure_code,77);
    empty_pool(&pool);
}
fn main() {
    interdependent_queues();
    let legacy=legacy_joins(); explicit_parent_cancel(); let failures=failures_both_directions();
    adoption_allocation_refusal(); native_spawn_refusal();
    let bounds=bounds_and_budget_identity(); let orders=deterministic_failure_orders();
    let adoption=adoption_failure_races(); let spawn=spawn_close_races(); spurious_tree_wakes();
    failure_during_child_join(); deepest_failure_on_minimum_requested_stack();
    println!("{}",1); println!("{}",legacy); println!("{}",1); println!("{}",failures);
    println!("{}",2); println!("{}",2); println!("{}",bounds); println!("{}",orders);
    println!("{}",adoption); println!("{}",spawn); println!("{}",64); println!("{}",1); println!("{}",1); println!("{}",0);
}
