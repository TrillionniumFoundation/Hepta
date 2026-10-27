#![allow(dead_code,unused,non_camel_case_types)]

pub struct HeptaCancellation {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub struct HeptaTask {
    handle: std::thread::JoinHandle<u64>,
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
fn __hepta_rt_spawn(
    worker: fn(std::vec::Vec<u8>, &HeptaCancellation) -> u64,
    data: std::vec::Vec<u8>,
) -> HeptaTask {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancellation = HeptaCancellation { flag: std::sync::Arc::clone(&flag) };
    let handle = std::thread::spawn(move || worker(data, &cancellation));
    HeptaTask { handle, flag }
}
fn __hepta_rt_join(task: HeptaTask, cancel: bool) -> u64 {
    let HeptaTask { handle, flag } = task;
    if cancel { flag.store(true, std::sync::atomic::Ordering::Release); }
    handle.join().expect("Hepta task panicked")
}

#[derive(Clone, Copy)]
pub struct H_GroupReport {
    pub h_accepted_tasks: usize, pub h_rejected_tasks: usize,
    pub h_completed_tasks: usize, pub h_active_tasks: usize,
    pub h_spawn_failures: usize, pub h_input_bytes: usize,
    pub h_queued: usize, pub h_peak_queued: usize,
    pub h_send_waits: usize, pub h_waiting_senders: usize,
    pub h_send_timeouts: usize, pub h_receive_timeouts: usize,
    pub h_received: usize, pub h_discarded: usize,
    pub h_task_limit: usize, pub h_input_byte_limit: usize,
    pub h_queue_capacity: usize, pub h_sum: u64,
    pub h_failed: bool, pub h_failure_code: u64,
    pub h_cancelled: bool, pub h_joined: bool,
}
#[derive(Clone, Copy, Default)]
pub struct H_GroupBudgetReport {
    pub h_attached: bool, pub h_attached_groups: usize,
    pub h_thread_limit: usize, pub h_input_byte_limit: usize,
    pub h_queue_slot_limit: usize, pub h_requested_stack_byte_limit: usize,
    pub h_worker_stack_request: usize,
    pub h_reserved_threads: usize, pub h_reserved_input_bytes: usize,
    pub h_reserved_queue_slots: usize, pub h_reserved_requested_stack_bytes: usize,
    pub h_peak_threads: usize, pub h_peak_input_bytes: usize,
    pub h_peak_queue_slots: usize, pub h_peak_requested_stack_bytes: usize,
    pub h_rejected_admissions: usize, pub h_spawn_failures: usize,
    pub h_attachment_refusals: usize,
}
struct HeptaGroupBudget {
    state: std::sync::Mutex<H_GroupBudgetReport>,
    io: std::sync::Mutex<H_GroupIoReport>,
}
struct HeptaGroupState {
    report: H_GroupReport,
    // Fixed-size storage: send never grows the ring.
    ring: std::vec::Vec<u64>,
    head: usize, len: usize, sealed: bool, closed: bool,
    selectors: std::vec::Vec<std::sync::Weak<HeptaSelectSignal>>,
    tree_signal: std::sync::Arc<HeptaSelectSignal>,
    budget: Option<std::sync::Arc<HeptaGroupBudget>>,
    io_waiters: std::vec::Vec<std::sync::Weak<dyn HeptaGroupIoWake>>,
}
// A signal belongs to one select call or one consuming tree. Notification
// takes group state -> signal; waiters release the signal before polling.
struct HeptaSelectSignal {
    pending: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}
fn __hepta_select_notify(state: &mut HeptaGroupState) {
    *state.tree_signal.pending.lock().expect("Hepta tree wake poisoned") = true;
    state.tree_signal.changed.notify_all();
    state.selectors.retain(|weak| {
        if let Some(signal) = weak.upgrade() {
            *signal.pending.lock().expect("Hepta select state poisoned") = true;
            signal.changed.notify_all();
            true
        } else { false }
    });
}
struct HeptaGroupShared {
    tree: std::sync::Mutex<HeptaGroupTree>,
    state: std::sync::Mutex<HeptaGroupState>,
    readable: std::sync::Condvar,
    writable: std::sync::Condvar,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub struct HeptaSender { shared: std::sync::Arc<HeptaGroupShared> }
pub struct HeptaTaskGroup {
    shared: std::sync::Arc<HeptaGroupShared>,
    handles: std::vec::Vec<std::thread::JoinHandle<u64>>,
    budget: Option<std::sync::Arc<HeptaGroupBudget>>,
}
fn __hepta_group_new(tasks: usize, bytes: usize, slots: usize) -> HeptaTaskGroup {
    assert!(slots > 0, "Hepta group queue capacity must be positive");
    assert!(slots <= (isize::MAX as usize) / core::mem::size_of::<u64>(),
            "Hepta group queue storage exceeds the supported allocation size");
    let report = H_GroupReport {
        h_accepted_tasks: 0, h_rejected_tasks: 0, h_completed_tasks: 0,
        h_active_tasks: 0, h_spawn_failures: 0, h_input_bytes: 0,
        h_queued: 0, h_peak_queued: 0, h_send_waits: 0,
        h_send_timeouts: 0, h_receive_timeouts: 0,
        h_waiting_senders: 0, h_received: 0, h_discarded: 0,
        h_task_limit: tasks, h_input_byte_limit: bytes,
        h_queue_capacity: slots, h_sum: 0, h_failed: false,
        h_failure_code: 0, h_cancelled: false, h_joined: false,
    };
    HeptaTaskGroup {
        shared: std::sync::Arc::new(HeptaGroupShared {
            tree: std::sync::Mutex::new(__hepta_tree_new()),
            state: std::sync::Mutex::new(HeptaGroupState {
                report, ring: std::vec![0u64; slots], head: 0, len: 0,
                sealed: false, closed: false,
                selectors: std::vec::Vec::new(),
                tree_signal: std::sync::Arc::new(HeptaSelectSignal {
                    pending: std::sync::Mutex::new(false), changed: std::sync::Condvar::new(),
                }),
                budget: None, io_waiters: std::vec::Vec::new(),
            }),
            readable: std::sync::Condvar::new(),
            writable: std::sync::Condvar::new(),
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
        handles: std::vec::Vec::new(),
        budget: None,
    }
}
fn __hepta_group_budget_configure(
    group: &mut HeptaTaskGroup, threads: usize, bytes: usize, slots: usize,
    requested_stack_bytes: usize, worker_stack_request: usize,
) -> bool {
    let tree = group.shared.tree.lock().expect("Hepta group tree poisoned");
    if !tree.accepting || tree.cancelling || tree.joining || !tree.children.is_empty() { return false; }
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    if group.budget.is_some() || state.sealed || state.closed || state.report.h_accepted_tasks != 0
        || slots < state.ring.len() || worker_stack_request < 64 * 1024
        || worker_stack_request > 1024 * 1024 * 1024 {
        return false;
    }
    group.budget = Some(std::sync::Arc::new(HeptaGroupBudget {
        io: std::sync::Mutex::new(H_GroupIoReport::default()),
        state: std::sync::Mutex::new(H_GroupBudgetReport {
            h_attached: true, h_attached_groups: 1,
            h_thread_limit: threads, h_input_byte_limit: bytes,
            h_queue_slot_limit: slots, h_requested_stack_byte_limit: requested_stack_bytes,
            h_worker_stack_request: worker_stack_request,
            h_reserved_queue_slots: state.ring.len(), h_peak_queue_slots: state.ring.len(),
            ..H_GroupBudgetReport::default()
        }),
    }));
    state.budget = group.budget.clone();
    true
}
fn __hepta_group_budget_share(target: &mut HeptaTaskGroup, sponsor: &HeptaTaskGroup) -> bool {
    let budget = match &sponsor.budget { Some(value) => value, None => return false };
    let tree = target.shared.tree.lock().expect("Hepta group tree poisoned");
    if !tree.accepting || tree.cancelling || tree.joining || !tree.children.is_empty() { return false; }
    let mut state = target.shared.state.lock().expect("Hepta group state poisoned");
    if target.budget.is_some() || state.sealed || state.closed || state.report.h_accepted_tasks != 0 { return false; }
    let mut usage = budget.state.lock().expect("Hepta group budget poisoned");
    let slots = usage.h_reserved_queue_slots.checked_add(state.ring.len());
    let groups = usage.h_attached_groups.checked_add(1);
    if slots.is_none() || slots.unwrap() > usage.h_queue_slot_limit || groups.is_none() {
        usage.h_attachment_refusals = usage.h_attachment_refusals.saturating_add(1);
        return false;
    }
    usage.h_attached_groups = groups.unwrap();
    usage.h_reserved_queue_slots = slots.unwrap();
    usage.h_peak_queue_slots = core::cmp::max(usage.h_peak_queue_slots, slots.unwrap());
    target.budget = Some(std::sync::Arc::clone(budget));
    state.budget = target.budget.clone();
    true
}
fn __hepta_group_budget_snapshot(group: &HeptaTaskGroup) -> H_GroupBudgetReport {
    group.budget.as_ref().map(|budget| *budget.state.lock().expect("Hepta group budget poisoned"))
        .unwrap_or_default()
}
fn __hepta_budget_admit(group: &HeptaTaskGroup, bytes: usize) -> bool {
    let budget = match &group.budget { Some(value) => value, None => return true };
    let mut usage = budget.state.lock().expect("Hepta group budget poisoned");
    let threads = usage.h_reserved_threads.checked_add(1);
    let input = usage.h_reserved_input_bytes.checked_add(bytes);
    let stack = usage.h_reserved_requested_stack_bytes.checked_add(usage.h_worker_stack_request);
    if threads.is_none() || threads.unwrap() > usage.h_thread_limit
        || input.is_none() || input.unwrap() > usage.h_input_byte_limit
        || stack.is_none() || stack.unwrap() > usage.h_requested_stack_byte_limit {
        usage.h_rejected_admissions = usage.h_rejected_admissions.saturating_add(1);
        return false;
    }
    usage.h_reserved_threads = threads.unwrap();
    usage.h_reserved_input_bytes = input.unwrap();
    usage.h_reserved_requested_stack_bytes = stack.unwrap();
    usage.h_peak_threads = core::cmp::max(usage.h_peak_threads, threads.unwrap());
    usage.h_peak_input_bytes = core::cmp::max(usage.h_peak_input_bytes, input.unwrap());
    usage.h_peak_requested_stack_bytes = core::cmp::max(usage.h_peak_requested_stack_bytes, stack.unwrap());
    true
}
fn __hepta_budget_spawn_failure(group: &HeptaTaskGroup, bytes: usize, reserved: bool) {
    if let Some(budget) = &group.budget {
        let mut usage = budget.state.lock().expect("Hepta group budget poisoned");
        if reserved {
            usage.h_reserved_threads -= 1;
            usage.h_reserved_input_bytes -= bytes;
            usage.h_reserved_requested_stack_bytes -= usage.h_worker_stack_request;
        }
        usage.h_rejected_admissions = usage.h_rejected_admissions.saturating_add(1);
        usage.h_spawn_failures = usage.h_spawn_failures.saturating_add(1);
    }
}
fn __hepta_group_spawn(
    group: &mut HeptaTaskGroup,
    worker: fn(std::vec::Vec<u8>, &HeptaCancellation, &HeptaSender) -> u64,
    data: std::vec::Vec<u8>,
) -> bool {
    let bytes = data.len();
    // Keep the admission gate through handle publication/rollback. A racing
    // failure cannot close a group and miss an accepted native worker.
    let tree = group.shared.tree.lock().expect("Hepta group tree poisoned");
    {
        let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
        let new_bytes = state.report.h_input_bytes.checked_add(bytes);
        if !tree.accepting || tree.cancelling || tree.joining || state.sealed || state.closed
            || state.report.h_accepted_tasks >= state.report.h_task_limit
            || new_bytes.is_none() || new_bytes.unwrap() > state.report.h_input_byte_limit {
            state.report.h_rejected_tasks = state.report.h_rejected_tasks.saturating_add(1);
            // 'data' is owned by this call and released on rejection.
            return false;
        }
        // Reserve the join-handle slot before starting an OS thread. Failure
        // cannot leave an unrecorded running worker behind.
        if group.handles.try_reserve(1).is_err() {
            state.report.h_rejected_tasks = state.report.h_rejected_tasks.saturating_add(1);
            state.report.h_spawn_failures = state.report.h_spawn_failures.saturating_add(1);
            __hepta_budget_spawn_failure(group, bytes, false);
            return false;
        }
        if !__hepta_budget_admit(group, bytes) {
            state.report.h_rejected_tasks = state.report.h_rejected_tasks.saturating_add(1);
            return false;
        }
        state.report.h_accepted_tasks += 1;
        state.report.h_active_tasks += 1;
        state.report.h_input_bytes = new_bytes.unwrap();
    }
    let shared = std::sync::Arc::clone(&group.shared);
    let builder = match &group.budget {
        Some(budget) => std::thread::Builder::new().stack_size(
            budget.state.lock().expect("Hepta group budget poisoned").h_worker_stack_request),
        None => std::thread::Builder::new(),
    };
    let launched = builder.spawn(move || {
        let token = HeptaCancellation { flag: std::sync::Arc::clone(&shared.cancel) };
        let sender = HeptaSender { shared: std::sync::Arc::clone(&shared) };
        let value = worker(data, &token, &sender);
        let mut state = shared.state.lock().expect("Hepta group state poisoned");
        state.report.h_completed_tasks += 1;
        state.report.h_active_tasks -= 1;
        state.report.h_sum = state.report.h_sum.wrapping_add(value);
        if state.sealed && state.report.h_active_tasks == 0 {
            state.closed = true;
            shared.readable.notify_all();
            shared.writable.notify_all();
            __hepta_select_notify(&mut state);
        }
        value
    });
    match launched {
        Ok(handle) => { group.handles.push(handle); true }
        Err(_) => {
            let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
            state.report.h_accepted_tasks -= 1;
            state.report.h_active_tasks -= 1;
            state.report.h_input_bytes -= bytes;
            state.report.h_rejected_tasks = state.report.h_rejected_tasks.saturating_add(1);
            state.report.h_spawn_failures = state.report.h_spawn_failures.saturating_add(1);
            __hepta_budget_spawn_failure(group, bytes, true);
            false
        }
    }
}
fn __hepta_group_send_wait(
    sender: &HeptaSender, value: u64, deadline: Option<std::time::Instant>,
) -> core::result::Result<bool, u8> {
    let shared = &sender.shared;
    let mut state = shared.state.lock().expect("Hepta group state poisoned");
    while state.len == state.ring.len() && !state.closed {
        let remaining = if let Some(until) = deadline {
            let now = std::time::Instant::now();
            if now >= until {
                state.report.h_send_timeouts = state.report.h_send_timeouts.saturating_add(1);
                return Err(1);
            }
            Some(until.duration_since(now))
        } else { None };
        state.report.h_send_waits = state.report.h_send_waits.saturating_add(1);
        state.report.h_waiting_senders += 1;
        state = if let Some(remaining) = remaining {
            shared.writable.wait_timeout(state, remaining).expect("Hepta group state poisoned").0
        } else {
            shared.writable.wait(state).expect("Hepta group state poisoned")
        };
        state.report.h_waiting_senders -= 1;
    }
    if state.closed { return Ok(false); }
    let index = (state.head + state.len) % state.ring.len();
    state.ring[index] = value;
    state.len += 1;
    state.report.h_queued = state.len;
    state.report.h_peak_queued = core::cmp::max(state.report.h_peak_queued, state.len);
    shared.readable.notify_one();
    __hepta_select_notify(&mut state);
    Ok(true)
}
fn __hepta_group_send(sender: &HeptaSender, value: u64) -> bool {
    // No deadline means the wait operation cannot return a timeout error.
    __hepta_group_send_wait(sender, value, None).expect("Hepta untimed send failed")
}
fn __hepta_group_send_timeout(sender: &HeptaSender, value: u64, millis: u64)
    -> core::result::Result<bool, u8> {
    let until = std::time::Instant::now().checked_add(std::time::Duration::from_millis(millis)).ok_or(2u8)?;
    __hepta_group_send_wait(sender, value, Some(until))
}
fn __hepta_group_seal(group: &mut HeptaTaskGroup) {
    let mut tree = group.shared.tree.lock().expect("Hepta group tree poisoned");
    tree.accepting = false;
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    state.sealed = true;
    if state.report.h_active_tasks == 0 {
        state.closed = true;
        group.shared.readable.notify_all();
        group.shared.writable.notify_all();
        __hepta_select_notify(&mut state);
    }
}
fn __hepta_group_receive_wait(
    group: &HeptaTaskGroup, output: &mut u64, discard: bool,
    deadline: Option<std::time::Instant>,
) -> core::result::Result<bool, u8> {
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    assert!(state.sealed, "Hepta group_receive requires group_seal before consumption");
    while state.len == 0 && !state.closed {
        state = if let Some(until) = deadline {
            let now = std::time::Instant::now();
            if now >= until {
                state.report.h_receive_timeouts = state.report.h_receive_timeouts.saturating_add(1);
                return Err(1);
            }
            group.shared.readable.wait_timeout(state, until.duration_since(now))
                .expect("Hepta group state poisoned").0
        } else {
            group.shared.readable.wait(state).expect("Hepta group state poisoned")
        };
    }
    if state.len == 0 { return Ok(false); }
    *output = state.ring[state.head];
    state.head = (state.head + 1) % state.ring.len();
    state.len -= 1;
    state.report.h_queued = state.len;
    if discard { state.report.h_discarded = state.report.h_discarded.saturating_add(1); }
    else { state.report.h_received = state.report.h_received.saturating_add(1); }
    group.shared.writable.notify_one();
    Ok(true)
}
fn __hepta_group_receive_inner(group: &HeptaTaskGroup, output: &mut u64, discard: bool) -> bool {
    __hepta_group_receive_wait(group, output, discard, None).expect("Hepta untimed receive failed")
}
fn __hepta_group_receive(group: &HeptaTaskGroup, output: &mut u64) -> bool {
    __hepta_group_receive_inner(group, output, false)
}
fn __hepta_group_receive_timeout(group: &HeptaTaskGroup, output: &mut u64, millis: u64)
    -> core::result::Result<bool, u8> {
    let until = std::time::Instant::now().checked_add(std::time::Duration::from_millis(millis)).ok_or(2u8)?;
    __hepta_group_receive_wait(group, output, false, Some(until))
}
struct HeptaSelectRegistration {
    left: std::sync::Arc<HeptaGroupShared>,
    right: std::sync::Arc<HeptaGroupShared>,
    signal: std::sync::Arc<HeptaSelectSignal>,
}
impl Drop for HeptaSelectRegistration {
    fn drop(&mut self) {
        let signal = std::sync::Arc::downgrade(&self.signal);
        for shared in [&self.left, &self.right] {
            let mut state = shared.state.lock().expect("Hepta group state poisoned");
            state.selectors.retain(|weak| !weak.ptr_eq(&signal));
        }
    }
}
fn __hepta_select_register(shared: &HeptaGroupShared, signal: &std::sync::Arc<HeptaSelectSignal>)
    -> core::result::Result<(), u8> {
    let mut state = shared.state.lock().expect("Hepta group state poisoned");
    assert!(state.sealed, "Hepta group_select_receive requires group_seal on both groups");
    state.selectors.retain(|weak| weak.strong_count() != 0);
    // Bound the number of concurrent registered calls and retained vector
    // capacity. This limit is separate from channel queue capacity.
    if state.selectors.len() >= 64 || state.selectors.try_reserve_exact(1).is_err() {
        return Err(4);
    }
    state.selectors.push(std::sync::Arc::downgrade(signal));
    Ok(())
}
fn __hepta_select_poll(shared: &HeptaGroupShared, output: &mut u64) -> (bool, bool) {
    let mut state = shared.state.lock().expect("Hepta group state poisoned");
    if state.len == 0 { return (false, state.closed); }
    *output = state.ring[state.head];
    state.head = (state.head + 1) % state.ring.len();
    state.len -= 1;
    state.report.h_queued = state.len;
    state.report.h_received = state.report.h_received.saturating_add(1);
    shared.writable.notify_one();
    (true, false)
}
fn __hepta_group_select_receive(
    left: &HeptaTaskGroup, right: &HeptaTaskGroup, output: &mut u64,
    prefer_right: bool, millis: u64,
) -> core::result::Result<u8, u8> {
    if std::sync::Arc::ptr_eq(&left.shared, &right.shared) { return Err(3); }
    let until = std::time::Instant::now().checked_add(std::time::Duration::from_millis(millis)).ok_or(2u8)?;
    let registration = HeptaSelectRegistration {
        left: std::sync::Arc::clone(&left.shared), right: std::sync::Arc::clone(&right.shared),
        signal: std::sync::Arc::new(HeptaSelectSignal {
            pending: std::sync::Mutex::new(false), changed: std::sync::Condvar::new(),
        }),
    };
    // Drop unregisters both sides even if the second reservation is refused.
    __hepta_select_register(&registration.left, &registration.signal)?;
    __hepta_select_register(&registration.right, &registration.signal)?;
    loop {
        // Never hold the signal mutex while inspecting a group: notifications
        // take the opposite (group -> signal) order. Setting pending first and
        // then polling makes every racing notification either observable as a
        // queue state or retained until the following condition-variable wait.
        *registration.signal.pending.lock().expect("Hepta select state poisoned") = false;
        let (first, first_id, second, second_id) = if prefer_right {
            (&registration.right, 2u8, &registration.left, 1u8)
        } else { (&registration.left, 1u8, &registration.right, 2u8) };
        let (received, first_closed) = __hepta_select_poll(first, output);
        if received { return Ok(first_id); }
        let (received, second_closed) = __hepta_select_poll(second, output);
        if received { return Ok(second_id); }
        if first_closed && second_closed { return Ok(0); }
        let mut pending = registration.signal.pending.lock().expect("Hepta select state poisoned");
        let now = std::time::Instant::now();
        if now >= until { return Err(1); }
        if !*pending {
            pending = registration.signal.changed.wait_timeout(pending, until.duration_since(now))
                .expect("Hepta select state poisoned").0;
            // Poll after every wake, including timeout/spurious wake. The one
            // deadline is retained, and queued values/closed state win a zero
            // duration poll. The mutex, scheduler and workers are not timed.
        }
    }
}
fn __hepta_group_cancel(group: &mut HeptaTaskGroup) {
    __hepta_tree_stop(&group.shared, None, true);
}
fn __hepta_group_snapshot(group: &HeptaTaskGroup) -> H_GroupReport {
    group.shared.state.lock().expect("Hepta group state poisoned").report
}
fn __hepta_group_fail(sender: &HeptaSender, code: u64) {
    assert!(code != 0, "Hepta group_fail requires a nonzero error code");
    __hepta_tree_fail(&sender.shared, code);
}
fn __hepta_group_join(mut group: HeptaTaskGroup, mode: u8) -> H_GroupReport {
    __hepta_group_join_inner(&mut group, mode);
    __hepta_group_snapshot(&group)
}

#[derive(Clone, Copy, Default)]
pub struct H_GroupIoReport {
    pub h_configured:bool, pub h_reactor_limit:usize,
    pub h_port_slot_limit:usize, pub h_request_slot_limit:usize,
    pub h_byte_limit:usize, pub h_attached_reactors:usize,
    pub h_reserved_port_slots:usize, pub h_reserved_request_slots:usize,
    pub h_reserved_bytes:usize, pub h_peak_reactors:usize,
    pub h_peak_port_slots:usize, pub h_peak_request_slots:usize,
    pub h_peak_bytes:usize, pub h_attachment_refusals:usize,
    pub h_buffer_refusals:usize, pub h_wake_notifications:usize,
}
// Notification never shares a reactor or buffer. Implementations may not
// acquire topology or group-state locks: the caller holds group state.
trait HeptaGroupIoWake: Send + Sync { fn cancel(&self); }
fn __hepta_group_io_notify(state:&mut HeptaGroupState) {
    state.io_waiters.retain(|weak| {
        if let Some(wake)=weak.upgrade() {wake.cancel();true} else {false}
    });
}
fn __hepta_group_io_configure(
    group:&mut HeptaTaskGroup,reactors:usize,ports:usize,requests:usize,bytes:usize,
)->bool {
    let tree=group.shared.tree.lock().expect("Hepta group tree poisoned");
    if !tree.accepting || tree.cancelling || tree.joining || !tree.children.is_empty() {return false}
    let state=group.shared.state.lock().expect("Hepta group state poisoned");
    if state.sealed || state.closed || state.report.h_accepted_tasks!=0 || reactors>256 {return false}
    let Some(budget)=&group.budget else{return false};
    // Freeze one pool-wide configuration before native worker admission.
    let tasks=budget.state.lock().expect("Hepta group budget poisoned");
    if tasks.h_reserved_threads!=0 {return false}
    let mut io=budget.io.lock().expect("Hepta group I/O budget poisoned");
    if io.h_configured {return false}
    *io=H_GroupIoReport{h_configured:true,h_reactor_limit:reactors,
        h_port_slot_limit:ports,h_request_slot_limit:requests,h_byte_limit:bytes,
        ..H_GroupIoReport::default()};
    true
}
fn __hepta_group_io_snapshot(group:&HeptaTaskGroup)->H_GroupIoReport {
    group.budget.as_ref().map(|budget|*budget.io.lock().expect("Hepta group I/O budget poisoned"))
        .unwrap_or_default()
}

const HEPTA_TREE_MAX_GROUPS: usize = 256;
const HEPTA_TREE_MAX_DEPTH: usize = 16;
#[derive(Clone, Copy, Default)]
pub struct H_GroupTreeReport {
    pub h_groups: usize, pub h_depth: usize, pub h_adopted_groups: usize,
    pub h_adoption_refusals: usize, pub h_joined_groups: usize,
    pub h_accepted_tasks: usize, pub h_rejected_tasks: usize,
    pub h_completed_tasks: usize, pub h_active_tasks: usize,
    pub h_spawn_failures: usize, pub h_input_bytes: usize,
    pub h_queued: usize, pub h_received: usize, pub h_discarded: usize,
    pub h_waiting_senders: usize, pub h_sum: u64,
    pub h_failed: bool, pub h_failure_code: u64, pub h_cancelled: bool,
}
struct HeptaTreeChild {
    // Keep cancellation reachability even after join takes the linear owner.
    shared: std::sync::Arc<HeptaGroupShared>,
    owner: Option<HeptaTaskGroup>,
}
struct HeptaGroupTree {
    accepting: bool, cancelling: bool, joining: bool,
    parent: std::sync::Weak<HeptaGroupShared>,
    children: std::vec::Vec<HeptaTreeChild>,
    groups: usize, depth: usize, adoption_refusals: usize,
}
fn __hepta_tree_new() -> HeptaGroupTree {
    HeptaGroupTree {
        accepting: true, cancelling: false, joining: false,
        parent: std::sync::Weak::new(), children: std::vec::Vec::new(),
        groups: 1, depth: 1, adoption_refusals: 0,
    }
}
// Lock order: ancestor tree -> descendant tree -> group state -> budget or
// signal. A waiter holds only the signal mutex. No join holds any of these.
fn __hepta_tree_rebind_locked(
    shared: &HeptaGroupShared, tree: &HeptaGroupTree,
    signal: &std::sync::Arc<HeptaSelectSignal>,
) {
    shared.state.lock().expect("Hepta group state poisoned").tree_signal =
        std::sync::Arc::clone(signal);
    for child in &tree.children {
        let below = child.shared.tree.lock().expect("Hepta group tree poisoned");
        __hepta_tree_rebind_locked(&child.shared, &below, signal);
    }
}
fn __hepta_group_adopt(parent: &mut HeptaTaskGroup, child: HeptaTaskGroup) -> bool {
    let mut supplied = Some(child);
    let accepted = {
        let mut tree = parent.shared.tree.lock().expect("Hepta group tree poisoned");
        let candidate = supplied.as_ref().unwrap();
        let same_budget = match (&parent.budget, &candidate.budget) {
            (None, None) => true,
            (Some(left), Some(right)) => std::sync::Arc::ptr_eq(left, right),
            _ => false,
        };
        // Source ownership makes self/cycle adoption impossible. Retain an
        // identity check at the native boundary before locking the child.
        if !tree.accepting || tree.cancelling || tree.joining || !same_budget
            || std::sync::Arc::ptr_eq(&parent.shared, &candidate.shared) {
            tree.adoption_refusals = tree.adoption_refusals.saturating_add(1);
            false
        } else {
            let shared = std::sync::Arc::clone(&candidate.shared);
            let mut below = shared.tree.lock().expect("Hepta group tree poisoned");
            let groups = tree.groups.checked_add(below.groups);
            let depth = core::cmp::max(tree.depth, below.depth + 1);
            if below.cancelling || below.joining || below.parent.strong_count() != 0
                || groups.is_none() || groups.unwrap() > HEPTA_TREE_MAX_GROUPS
                || depth > HEPTA_TREE_MAX_DEPTH
                || tree.children.try_reserve_exact(1).is_err() {
                tree.adoption_refusals = tree.adoption_refusals.saturating_add(1);
                false
            } else {
                let signal = std::sync::Arc::clone(
                    &parent.shared.state.lock().expect("Hepta group state poisoned").tree_signal);
                below.parent = std::sync::Arc::downgrade(&parent.shared);
                __hepta_tree_rebind_locked(&shared, &below, &signal);
                tree.groups = groups.unwrap();
                tree.depth = depth;
                tree.children.push(HeptaTreeChild {
                    shared: std::sync::Arc::clone(&shared), owner: supplied.take(),
                });
                true
            }
        }
    };
    if let Some(refused) = supplied {
        // Refusal still consumes the child: stop and join its whole subtree.
        // This may block for cooperative worker cleanup, with no locks held.
        __hepta_group_join(refused, 2);
    }
    accepted
}
fn __hepta_tree_stop(shared: &HeptaGroupShared, failure: Option<u64>, discard: bool) {
    let mut tree = shared.tree.lock().expect("Hepta group tree poisoned");
    tree.accepting = false;
    tree.cancelling = true;
    {
        let mut state = shared.state.lock().expect("Hepta group state poisoned");
        state.sealed = true;
        state.closed = true;
        state.report.h_cancelled = true;
        if let Some(code) = failure {
            if !state.report.h_failed {
                state.report.h_failed = true;
                state.report.h_failure_code = code;
            }
        }
        shared.cancel.store(true, std::sync::atomic::Ordering::Release);
        __hepta_group_io_notify(&mut state);
        if discard {
            state.report.h_discarded = state.report.h_discarded.saturating_add(state.len);
            state.len = 0;
            state.report.h_queued = 0;
        }
        shared.readable.notify_all();
        shared.writable.notify_all();
        __hepta_select_notify(&mut state);
    }
    for child in &tree.children { __hepta_tree_stop(&child.shared, failure, discard); }
}
fn __hepta_tree_fail(origin: &std::sync::Arc<HeptaGroupShared>, code: u64) {
    let mut root = std::sync::Arc::clone(origin);
    loop {
        let parent = {
            let mut tree = root.tree.lock().expect("Hepta group tree poisoned");
            // Mark before observing the parent link. Adoption either precedes
            // this step and is visible, or refuses this failing subtree.
            tree.accepting = false;
            tree.cancelling = true;
            tree.parent.upgrade()
        };
        match parent { Some(parent) => root = parent, None => break }
    }
    // Failure preserves queued values, matching the existing flat protocol.
    // Any join that drains the tree discards the remaining values explicitly.
    __hepta_tree_stop(&root, Some(code), false);
}
fn __hepta_tree_begin_join(shared: &HeptaGroupShared) {
    let mut tree = shared.tree.lock().expect("Hepta group tree poisoned");
    tree.accepting = false;
    tree.joining = true;
    {
        let mut state = shared.state.lock().expect("Hepta group state poisoned");
        state.sealed = true;
        if state.report.h_active_tasks == 0 {
            state.closed = true;
            shared.readable.notify_all();
            shared.writable.notify_all();
            __hepta_select_notify(&mut state);
        }
    }
    for child in &tree.children { __hepta_tree_begin_join(&child.shared); }
}
fn __hepta_tree_drain_poll(shared: &HeptaGroupShared) -> bool {
    let tree = shared.tree.lock().expect("Hepta group tree poisoned");
    let mut closed = {
        let mut state = shared.state.lock().expect("Hepta group state poisoned");
        if state.len != 0 {
            state.report.h_discarded = state.report.h_discarded.saturating_add(state.len);
            state.len = 0;
            state.report.h_queued = 0;
            shared.writable.notify_all();
        }
        state.closed
    };
    // Poll every queue on each wake. Sequentially waiting for one child could
    // leave a sibling producer blocked behind a full queue indefinitely.
    for child in &tree.children { closed &= __hepta_tree_drain_poll(&child.shared); }
    closed
}
fn __hepta_tree_drain(shared: &HeptaGroupShared) {
    let signal = std::sync::Arc::clone(
        &shared.state.lock().expect("Hepta group state poisoned").tree_signal);
    loop {
        *signal.pending.lock().expect("Hepta tree wake poisoned") = false;
        if __hepta_tree_drain_poll(shared) { return; }
        let mut pending = signal.pending.lock().expect("Hepta tree wake poisoned");
        while !*pending {
            pending = signal.changed.wait(pending).expect("Hepta tree wake poisoned");
        }
    }
}
fn __hepta_tree_accumulate(shared: &HeptaGroupShared, output: &mut H_GroupTreeReport) {
    let tree = shared.tree.lock().expect("Hepta group tree poisoned");
    let report = shared.state.lock().expect("Hepta group state poisoned").report;
    macro_rules! add { ($field:ident, $value:expr) => {
        output.$field = output.$field.checked_add($value).expect("Hepta tree report counter overflow");
    } }
    add!(h_groups, 1); add!(h_adopted_groups, tree.children.len());
    add!(h_adoption_refusals, tree.adoption_refusals);
    add!(h_joined_groups, usize::from(report.h_joined));
    add!(h_accepted_tasks, report.h_accepted_tasks); add!(h_rejected_tasks, report.h_rejected_tasks);
    add!(h_completed_tasks, report.h_completed_tasks); add!(h_active_tasks, report.h_active_tasks);
    add!(h_spawn_failures, report.h_spawn_failures); add!(h_input_bytes, report.h_input_bytes);
    add!(h_queued, report.h_queued); add!(h_received, report.h_received);
    add!(h_discarded, report.h_discarded); add!(h_waiting_senders, report.h_waiting_senders);
    output.h_sum = output.h_sum.wrapping_add(report.h_sum);
    if !output.h_failed && report.h_failed {
        output.h_failed = true; output.h_failure_code = report.h_failure_code;
    }
    output.h_cancelled |= report.h_cancelled;
    for child in &tree.children { __hepta_tree_accumulate(&child.shared, output); }
}
fn __hepta_group_tree_snapshot(group: &HeptaTaskGroup) -> H_GroupTreeReport {
    let mut output = H_GroupTreeReport::default();
    output.h_depth = group.shared.tree.lock().expect("Hepta group tree poisoned").depth;
    __hepta_tree_accumulate(&group.shared, &mut output);
    output
}
fn __hepta_tree_finish(group: &mut HeptaTaskGroup) {
    let children = group.shared.tree.lock().expect("Hepta group tree poisoned").children.len();
    for index in 0..children {
        let child = group.shared.tree.lock().expect("Hepta group tree poisoned")
            .children[index].owner.take();
        if let Some(mut child) = child { __hepta_tree_finish(&mut child); }
    }
    for handle in group.handles.drain(..) {
        // panic=abort is the production profile; arbitrary worker termination
        // and panic containment are not promised by a structured join.
        handle.join().expect("Hepta group worker panicked");
    }
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    state.report.h_joined = true;
    let queue_slots = state.ring.len();
    state.ring = std::vec::Vec::new();
    if let Some(budget) = group.budget.take() {
        let mut usage = budget.state.lock().expect("Hepta group budget poisoned");
        usage.h_reserved_threads -= state.report.h_accepted_tasks;
        usage.h_reserved_input_bytes -= state.report.h_input_bytes;
        usage.h_reserved_requested_stack_bytes -= state.report.h_accepted_tasks * usage.h_worker_stack_request;
        usage.h_reserved_queue_slots -= queue_slots;
        usage.h_attached_groups -= 1;
    }
}
fn __hepta_group_join_inner(group: &mut HeptaTaskGroup, mode: u8) {
    assert!(mode <= 2, "Hepta group join mode is invalid");
    __hepta_tree_begin_join(&group.shared);
    if mode == 2 { __hepta_tree_stop(&group.shared, None, true); }
    if mode == 0 {
        let state = group.shared.state.lock().expect("Hepta group state poisoned");
        assert!(state.closed && state.len == 0,
            "Hepta group_join requires a drained channel at the root; use group_drain_and_join or group_cancel_and_join");
    }
    __hepta_tree_drain(&group.shared);
    __hepta_tree_finish(group);
}
fn __hepta_group_tree_join(mut group: HeptaTaskGroup, cancel: bool) -> H_GroupTreeReport {
    __hepta_group_join_inner(&mut group, if cancel { 2 } else { 1 });
    __hepta_group_tree_snapshot(&group)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", target_pointer_width = "64")))]
compile_error!("Hepta bounded I/O reactor requires the qualified x86_64-unknown-linux-gnu hosted profile");
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", target_pointer_width = "64"))]
mod __hepta_io_runtime {
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const IO_OK:u8=0;
const IO_CANCELLED:u8=1;
const IO_TIMEOUT:u8=2;
const IO_EOF:u8=3;
const IO_CLOSED:u8=4;
const IO_SYSTEM:u8=5;
const IO_INVALID:u8=6;
const IO_REQUEST_LIMIT:u8=7;
const IO_BYTE_LIMIT:u8=8;
const IO_BUSY:u8=9;
const IO_TICKET:u8=10;
const IO_PORT:u8=11;
const IO_ALLOCATION:u8=12;
const IO_IDENTITIES:u8=13;
const IO_PORT_LIMIT:u8=14;
const IO_BINDING:u8=15;
const IO_SHARED_LIMIT:u8=16;
const IO_REGISTRATION_LIMIT:u8=17;
const IO_PENDING:u8=255;
const IO_MAX_MILLIS:u64=86_400_000;
static IO_NEXT_ID:AtomicU64=AtomicU64::new(1);
fn io_ids(count:u64)->Option<u64> {
    IO_NEXT_ID.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|value|value.checked_add(count)).ok()
}

// Linux's pollfd is two-byte event fields after a signed C int descriptor;
// nfds_t is unsigned long on the qualified Linux 64-bit profile. Qualification
// compares these exact sizes/offsets against the native <poll.h> definitions.
#[repr(C)]
#[derive(Clone,Copy)]
struct IoPollFd { fd:i32, events:i16, revents:i16 }
extern "C" {
    #[link_name="poll"]
    fn __hepta_io_poll_sys(fds:*mut IoPollFd, count:usize, timeout:i32)->i32;
}
const IO_POLLIN:i16=0x0001;
const IO_POLLOUT:i16=0x0004;

#[derive(Clone,Copy)]
pub struct H_IoPair { pub h_left:u64, pub h_right:u64, pub h_status:u8 }
#[derive(Clone,Copy,Default)]
pub struct H_IoReport {
    pub h_status:u8, pub h_port_limit:usize, pub h_request_limit:usize,
    pub h_byte_limit:usize, pub h_open_ports:usize, pub h_occupied_requests:usize,
    pub h_pending_requests:usize, pub h_reserved_bytes:usize,
    pub h_peak_requests:usize, pub h_peak_bytes:usize,
    pub h_admitted:u64, pub h_refused:u64, pub h_completed:u64,
    pub h_cancelled:u64, pub h_timed_out:u64, pub h_abandoned:u64,
    pub h_poll_calls:u64, pub h_poll_interruptions:u64, pub h_poll_failures:u64,
    pub h_read_calls:u64, pub h_write_calls:u64, pub h_would_block:u64,
    pub h_read_bytes:u64, pub h_written_bytes:u64, pub h_last_os_error:i32,
    pub h_shutdown:bool,
}
struct IoPort { token:u64, socket:UnixStream, reading:bool, writing:bool }
struct IoOperation {
    token:u64, port:u64, writing:bool, data:Vec<u8>, requested:usize,
    transferred:usize, deadline:Instant, status:u8,
}
pub struct HeptaIoRequest {
    reactor:u64, token:u64,
    // A refused submission returns the caller's buffer without allocating a
    // slot or metadata; the linear ticket still has to be consumed.
    immediate:Option<(Vec<u8>,u8)>,
}
trait IoTaskBinding {
    fn cancelled(&self)->bool;
    fn wake_fd(&self)->i32;
    fn reserve_bytes(&self,bytes:usize)->bool;
    fn release_bytes(&self,bytes:usize);
}
pub struct HeptaIoReactor {
    identity:u64, ports:Vec<Option<IoPort>>, operations:Vec<Option<IoOperation>>,
    pollfds:Vec<IoPollFd>, report:H_IoReport, cursor:usize,
    task:Option<std::sync::Arc<dyn IoTaskBinding>>,
    // The native reactor is deliberately single-owner/single-thread. Source
    // callers borrow it mutably for every mutation; even raw Rust callers
    // cannot move/share it across threads through Send/Sync.
    thread_affinity:std::marker::PhantomData<std::rc::Rc<()>>,
}

pub fn __hepta_io_reactor(port_limit:usize,request_limit:usize,byte_limit:usize)->HeptaIoReactor {
    let mut result=HeptaIoReactor {
        identity:0,ports:Vec::new(),operations:Vec::new(),pollfds:Vec::new(),task:None,
        report:H_IoReport {h_port_limit:port_limit,h_request_limit:request_limit,h_byte_limit:byte_limit,
                          ..H_IoReport::default()},cursor:0,thread_affinity:std::marker::PhantomData,
    };
    if !(2..=256).contains(&port_limit) || !(1..=1024).contains(&request_limit) {
        result.report.h_status=IO_INVALID;return result;
    }
    let Some(identity)=io_ids(1) else {result.report.h_status=IO_IDENTITIES;return result};
    result.identity=identity;
    if result.ports.try_reserve_exact(port_limit).is_err()
        || result.operations.try_reserve_exact(request_limit).is_err()
        || result.pollfds.try_reserve_exact(request_limit).is_err() {
        result.report.h_status=IO_ALLOCATION;return result;
    }
    result.ports.resize_with(port_limit,||None);
    result.operations.resize_with(request_limit,||None);
    result
}
fn io_os_error(io:&mut HeptaIoReactor,error:std::io::Error) {
    io.report.h_last_os_error=error.raw_os_error().unwrap_or(0);
}
pub fn __hepta_io_local_pair(io:&mut HeptaIoReactor)->H_IoPair {
    let failed=|io:&mut HeptaIoReactor,status| {
        io.report.h_refused=io.report.h_refused.saturating_add(1);
        H_IoPair{h_left:0,h_right:0,h_status:status}
    };
    if io.report.h_status!=IO_OK{let status=io.report.h_status;return failed(io,status)}
    if io_task_cancelled(io){return failed(io,IO_CANCELLED)}
    let mut empty=io.ports.iter().enumerate().filter(|(_,p)|p.is_none()).map(|(i,_)|i);
    let (Some(left_index),Some(right_index))=(empty.next(),empty.next()) else {
        return failed(io,IO_PORT_LIMIT)
    };
    let Some(first)=io_ids(2) else{return failed(io,IO_IDENTITIES)};
    let (left,right)=match UnixStream::pair() {
        Ok(pair)=>pair, Err(error)=>{io_os_error(io,error);return failed(io,IO_SYSTEM)}
    };
    if let Err(error)=left.set_nonblocking(true).and_then(|_|right.set_nonblocking(true)) {
        io_os_error(io,error);return failed(io,IO_SYSTEM)
    }
    io.ports[left_index]=Some(IoPort{token:first,socket:left,reading:false,writing:false});
    io.ports[right_index]=Some(IoPort{token:first+1,socket:right,reading:false,writing:false});
    io.report.h_open_ports+=2;
    H_IoPair{h_left:first,h_right:first+1,h_status:IO_OK}
}
fn io_finish_slot(io:&mut HeptaIoReactor,index:usize,status:u8) {
    let Some(operation)=io.operations[index].as_mut() else{return};
    if operation.status!=IO_PENDING{return}
    operation.status=status;
    let port=operation.port; let writing=operation.writing;
    if let Some(endpoint)=io.ports.iter_mut().flatten().find(|p|p.token==port) {
        if writing {endpoint.writing=false}else{endpoint.reading=false}
    }
    io.report.h_pending_requests-=1;
    io.report.h_completed=io.report.h_completed.saturating_add(1);
    if status==IO_CANCELLED {io.report.h_cancelled=io.report.h_cancelled.saturating_add(1)}
    if status==IO_TIMEOUT {io.report.h_timed_out=io.report.h_timed_out.saturating_add(1)}
}
fn io_submit(io:&mut HeptaIoReactor,port:u64,data:Vec<u8>,requested:usize,millis:u64,writing:bool)->HeptaIoRequest {
    let rejected=|io:&mut HeptaIoReactor,data:Vec<u8>,status| {
        io.report.h_refused=io.report.h_refused.saturating_add(1);
        HeptaIoRequest{reactor:io.identity,token:0,immediate:Some((data,status))}
    };
    if io.report.h_status!=IO_OK {let status=io.report.h_status;return rejected(io,data,status)}
    if io_task_cancelled(io){return rejected(io,data,IO_CANCELLED)}
    if requested>data.len() || millis>IO_MAX_MILLIS {return rejected(io,data,IO_INVALID)}
    let Some(deadline)=Instant::now().checked_add(Duration::from_millis(millis)) else{return rejected(io,data,IO_INVALID)};
    let Some(port_index)=io.ports.iter().position(|p|p.as_ref().map_or(false,|p|p.token==port)) else{return rejected(io,data,IO_PORT)};
    let endpoint=io.ports[port_index].as_ref().unwrap();
    if if writing {endpoint.writing}else{endpoint.reading} {return rejected(io,data,IO_BUSY)}
    let Some(index)=io.operations.iter().position(Option::is_none) else{return rejected(io,data,IO_REQUEST_LIMIT)};
    let Some(reserved)=io.report.h_reserved_bytes.checked_add(data.capacity()) else{return rejected(io,data,IO_BYTE_LIMIT)};
    if reserved>io.report.h_byte_limit{return rejected(io,data,IO_BYTE_LIMIT)}
    let Some(token)=io_ids(1) else{return rejected(io,data,IO_IDENTITIES)};
    if io.task.as_ref().map_or(false,|task|!task.reserve_bytes(data.capacity())) {
        return rejected(io,data,IO_SHARED_LIMIT)
    }
    io.operations[index]=Some(IoOperation{token,port,writing,data,requested,transferred:0,deadline,status:IO_PENDING});
    let endpoint=io.ports[port_index].as_mut().unwrap();
    if writing {endpoint.writing=true}else{endpoint.reading=true}
    io.report.h_reserved_bytes=reserved;
    io.report.h_occupied_requests+=1;
    io.report.h_pending_requests+=1;
    io.report.h_admitted=io.report.h_admitted.saturating_add(1);
    io.report.h_peak_bytes=io.report.h_peak_bytes.max(reserved);
    io.report.h_peak_requests=io.report.h_peak_requests.max(io.report.h_occupied_requests);
    if requested==0 {io_finish_slot(io,index,IO_OK)} else if millis==0 {io_finish_slot(io,index,IO_TIMEOUT)}
    HeptaIoRequest{reactor:io.identity,token,immediate:None}
}
pub fn __hepta_io_read(io:&mut HeptaIoReactor,port:u64,data:Vec<u8>,requested:usize,millis:u64)->HeptaIoRequest {
    io_submit(io,port,data,requested,millis,false)
}
pub fn __hepta_io_write(io:&mut HeptaIoReactor,port:u64,data:Vec<u8>,requested:usize,millis:u64)->HeptaIoRequest {
    io_submit(io,port,data,requested,millis,true)
}
fn io_slot(io:&HeptaIoReactor,request:&HeptaIoRequest)->Option<usize> {
    if request.immediate.is_some() || request.reactor!=io.identity{return None}
    io.operations.iter().position(|entry|entry.as_ref().map_or(false,|op|op.token==request.token))
}
pub fn __hepta_io_request_status(io:&HeptaIoReactor,request:&HeptaIoRequest)->u8 {
    if let Some((_,status))=&request.immediate{return *status}
    io_slot(io,request).map_or(IO_TICKET,|index|io.operations[index].as_ref().unwrap().status)
}
pub fn __hepta_io_cancel(io:&mut HeptaIoReactor,request:&HeptaIoRequest)->bool {
    let Some(index)=io_slot(io,request) else{return false};
    if io.operations[index].as_ref().unwrap().status!=IO_PENDING{return false}
    io_finish_slot(io,index,IO_CANCELLED);true
}
// Each scan gives each pending request at most one nonblocking syscall.
// Descriptor ownership remains in ports for the whole call, and the exclusive
// reactor borrow prevents close/reuse while poll or Read/Write accesses it.
fn io_task_cancelled(io:&HeptaIoReactor)->bool {
    io.task.as_ref().map_or(false,|task|task.cancelled())
}
fn io_progress(io:&mut HeptaIoReactor) {
    let count=io.operations.len();
    if count==0{return}
    let start=io.cursor%count;
    io.cursor=(start+1)%count;
    for step in 0..count {
        let index=(start+step)%count;
        if io_task_cancelled(io) {io_finish_slot(io,index,IO_CANCELLED);continue}
        let Some(operation)=io.operations[index].as_mut() else{continue};
        if operation.status!=IO_PENDING{continue}
        if Instant::now()>=operation.deadline {io_finish_slot(io,index,IO_TIMEOUT);continue}
        let Some(endpoint)=io.ports.iter().flatten().find(|p|p.token==operation.port) else {
            io_finish_slot(io,index,IO_CLOSED);continue
        };
        let mut socket=&endpoint.socket;
        let range=operation.transferred..operation.requested;
        let result=if operation.writing {
            io.report.h_write_calls=io.report.h_write_calls.saturating_add(1);
            socket.write(&operation.data[range])
        } else {
            io.report.h_read_calls=io.report.h_read_calls.saturating_add(1);
            socket.read(&mut operation.data[range])
        };
        let mut finish=None;
        match result {
            Ok(0)=>finish=Some(if operation.writing{IO_SYSTEM}else{IO_EOF}),
            Ok(bytes)=>{
                operation.transferred+=bytes;
                if operation.writing {io.report.h_written_bytes=io.report.h_written_bytes.saturating_add(bytes as u64)}
                else {io.report.h_read_bytes=io.report.h_read_bytes.saturating_add(bytes as u64)}
                if operation.transferred==operation.requested{finish=Some(IO_OK)}
            },
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{
                io.report.h_would_block=io.report.h_would_block.saturating_add(1);
            },
            Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
            Err(error)=>{io.report.h_last_os_error=error.raw_os_error().unwrap_or(0);finish=Some(IO_SYSTEM)},
        }
        if let Some(status)=finish {io_finish_slot(io,index,status)}
    }
}
pub fn __hepta_io_poll(io:&mut HeptaIoReactor,millis:u64)->Result<usize,u8> {
    if io.report.h_status!=IO_OK{return Err(io.report.h_status)}
    if millis>IO_MAX_MILLIS{return Err(IO_INVALID)}
    let before=io.report.h_pending_requests;
    io_progress(io);
    if io.report.h_pending_requests!=before || io.report.h_pending_requests==0 {
        return Ok(before-io.report.h_pending_requests)
    }
    io.pollfds.clear();
    let now=Instant::now();
    let mut wait=Duration::from_millis(millis);
    for entry in &io.operations {
        let Some(operation)=entry else{continue};
        if operation.status!=IO_PENDING{continue}
        wait=wait.min(operation.deadline.saturating_duration_since(now));
        let endpoint=io.ports.iter().flatten().find(|p|p.token==operation.port).unwrap();
        io.pollfds.push(IoPollFd{fd:endpoint.socket.as_raw_fd(),events:if operation.writing{IO_POLLOUT}else{IO_POLLIN},revents:0});
    }
    if let Some(task)=&io.task {
        // Attach reserved this extra entry. The read endpoint outlives this
        // exclusive poll even if another thread closes its cancellation peer.
        io.pollfds.push(IoPollFd{fd:task.wake_fd(),events:IO_POLLIN,revents:0});
    }
    // Round up rather than repeatedly waking before a sub-millisecond deadline.
    let timeout=((wait.as_nanos()+999_999)/1_000_000).min(i32::MAX as u128) as i32;
    io.report.h_poll_calls=io.report.h_poll_calls.saturating_add(1);
    // SAFETY: all entries are initialized repr(C) pollfd records; the pointer
    // and exact length refer to the same Vec allocation, which is never resized
    // during this call. Every FD is held by a live UnixStream in this exclusively
    // borrowed reactor. poll writes only revents and retains neither pointer nor
    // FD ownership. The Linux 64-bit ABI is qualified separately.
    let ready=unsafe{__hepta_io_poll_sys(io.pollfds.as_mut_ptr(),io.pollfds.len(),timeout)};
    if ready<0 {
        let error=std::io::Error::last_os_error();
        if error.kind()==std::io::ErrorKind::Interrupted {
            io.report.h_poll_interruptions=io.report.h_poll_interruptions.saturating_add(1);
        } else if !io_task_cancelled(io) {
            io.report.h_poll_failures=io.report.h_poll_failures.saturating_add(1);
            io_os_error(io,error);
            for index in 0..io.operations.len(){io_finish_slot(io,index,IO_SYSTEM)}
        }
    }
    // A timeout or EINTR does not reset any operation's original deadline.
    // Nonblocking I/O also handles readiness racing with peer close.
    io_progress(io);
    Ok(before-io.report.h_pending_requests)
}
fn io_remove(io:&mut HeptaIoReactor,index:usize)->IoOperation {
    let operation=io.operations[index].take().unwrap();
    // deliberately omitted shared reservation release
    io.report.h_reserved_bytes-=operation.data.capacity();
    io.report.h_occupied_requests-=1;
    operation
}
pub fn __hepta_io_take(io:&mut HeptaIoReactor,request:HeptaIoRequest,transferred:&mut usize,status:&mut u8)->Vec<u8> {
    *transferred=0;
    if let Some((data,code))=request.immediate{*status=code;return data}
    let Some(index)=io_slot(io,&request) else{*status=IO_TICKET;return Vec::new()};
    io_finish_slot(io,index,IO_CANCELLED);
    let operation=io_remove(io,index);
    *transferred=operation.transferred;*status=operation.status;operation.data
}
pub fn __hepta_io_wait(io:&mut HeptaIoReactor,request:HeptaIoRequest,transferred:&mut usize,status:&mut u8)->Vec<u8> {
    if request.immediate.is_none() {
        while let Some(index)=io_slot(io,&request) {
            if io.operations[index].as_ref().unwrap().status!=IO_PENDING{break}
            if __hepta_io_poll(io,IO_MAX_MILLIS).is_err(){io_finish_slot(io,index,IO_CLOSED)}
        }
    }
    __hepta_io_take(io,request,transferred,status)
}
pub fn __hepta_io_close_port(io:&mut HeptaIoReactor,port:u64)->bool {
    let Some(index)=io.ports.iter().position(|entry|entry.as_ref().map_or(false,|entry|entry.token==port)) else{return false};
    for slot in 0..io.operations.len() {
        if io.operations[slot].as_ref().map_or(false,|op|op.port==port){io_finish_slot(io,slot,IO_CLOSED)}
    }
    io.ports[index]=None;io.report.h_open_ports-=1;true
}
pub fn __hepta_io_report(io:&HeptaIoReactor)->H_IoReport {io.report}
fn io_cleanup(io:&mut HeptaIoReactor) {
    if io.report.h_shutdown {return}
    for index in 0..io.operations.len() {
        io_finish_slot(io,index,IO_CANCELLED);
        if io.operations[index].is_some() {
            let _=io_remove(io,index);
            io.report.h_abandoned=io.report.h_abandoned.saturating_add(1);
        }
    }
    io.ports.clear();io.report.h_open_ports=0;io.pollfds.clear();
    io.task=None;io.report.h_shutdown=true;
}
impl Drop for HeptaIoReactor {fn drop(&mut self){io_cleanup(self)}}
pub fn __hepta_io_shutdown(mut io:HeptaIoReactor)->H_IoReport {
    io_cleanup(&mut io);io.report
}

// Inserted inside __hepta_io_runtime only if the checked program uses groups.
struct IoWorkerBinding {
    group:std::sync::Arc<super::HeptaGroupShared>,
    budget:std::sync::Arc<super::HeptaGroupBudget>,
    wake_read:Option<UnixStream>,
    wake_write:std::sync::Mutex<Option<UnixStream>>,
    ports:usize,requests:usize,
}
impl super::HeptaGroupIoWake for IoWorkerBinding {
    fn cancel(&self) {
        // A permanent one-shot cancellation closes the owned peer. HUP wakes
        // poll without a fallible write, timer loop, or externally supplied FD.
        let mut writer=self.wake_write.lock().expect("Hepta I/O wake poisoned");
        if let Some(socket)=writer.take() {
            drop(socket);
            let mut usage=self.budget.io.lock().expect("Hepta group I/O budget poisoned");
            usage.h_wake_notifications=usage.h_wake_notifications.saturating_add(1);
        }
    }
}
impl IoTaskBinding for IoWorkerBinding {
    fn cancelled(&self)->bool {self.group.cancel.load(Ordering::Acquire)}
    fn wake_fd(&self)->i32 {self.wake_read.as_ref().unwrap().as_raw_fd()}
    fn reserve_bytes(&self,bytes:usize)->bool {
        let mut usage=self.budget.io.lock().expect("Hepta group I/O budget poisoned");
        let total=usage.h_reserved_bytes.checked_add(bytes);
        if total.is_none() || total.unwrap()>usage.h_byte_limit {
            usage.h_buffer_refusals=usage.h_buffer_refusals.saturating_add(1);return false
        }
        usage.h_reserved_bytes=total.unwrap();
        usage.h_peak_bytes=usage.h_peak_bytes.max(total.unwrap());true
    }
    fn release_bytes(&self,bytes:usize) {
        let mut usage=self.budget.io.lock().expect("Hepta group I/O budget poisoned");
        usage.h_reserved_bytes-=bytes;
    }
}
impl Drop for IoWorkerBinding {
    fn drop(&mut self) {
        // A canceller may release its last upgraded Arc under group state.
        // Never take that lock here. Dead Weak entries are pruned at the next
        // attach/cancel or destroyed with the group; they own no FD or buffer.
        drop(self.wake_write.get_mut().expect("Hepta I/O wake poisoned").take());
        drop(self.wake_read.take());
        let mut usage=self.budget.io.lock().expect("Hepta group I/O budget poisoned");
        usage.h_attached_reactors-=1;
        usage.h_reserved_port_slots-=self.ports;
        usage.h_reserved_request_slots-=self.requests;
    }
}
pub fn __hepta_io_attach(io:&mut HeptaIoReactor,sender:&super::HeptaSender)->u8 {
    if io.report.h_status!=IO_OK {return io.report.h_status}
    if io.task.is_some() || io.report.h_open_ports!=0 || io.report.h_occupied_requests!=0
        || io.report.h_shutdown {return IO_BINDING}
    let group=&sender.shared;
    let mut state=group.state.lock().expect("Hepta group state poisoned");
    // Registration and cancellation publication share this mutex: cancellation
    // either rejects the attachment or observes its published wake descriptor.
    if group.cancel.load(Ordering::Acquire) {return IO_CANCELLED}
    if state.report.h_joined || state.report.h_active_tasks==0 {return IO_BINDING}
    let Some(budget)=state.budget.as_ref().cloned() else{return IO_BINDING};
    let mut usage=budget.io.lock().expect("Hepta group I/O budget poisoned");
    if !usage.h_configured {return IO_BINDING}
    let ports=io.report.h_port_limit+2;
    let requests=io.report.h_request_limit;
    let reactors=usage.h_attached_reactors.checked_add(1);
    let port_total=usage.h_reserved_port_slots.checked_add(ports);
    let request_total=usage.h_reserved_request_slots.checked_add(requests);
    state.io_waiters.retain(|weak|weak.strong_count()!=0);
    let fail=|usage:&mut super::H_GroupIoReport,code| {
        usage.h_attachment_refusals=usage.h_attachment_refusals.saturating_add(1);code
    };
    if reactors.is_none() || reactors.unwrap()>usage.h_reactor_limit
        || port_total.is_none() || port_total.unwrap()>usage.h_port_slot_limit
        || request_total.is_none() || request_total.unwrap()>usage.h_request_slot_limit {
        return fail(&mut usage,IO_SHARED_LIMIT)
    }
    if state.io_waiters.len()>=64 {return fail(&mut usage,IO_REGISTRATION_LIMIT)}
    if state.io_waiters.try_reserve_exact(1).is_err()
        || io.pollfds.try_reserve_exact(requests+1-io.pollfds.len()).is_err() {
        return fail(&mut usage,IO_ALLOCATION)
    }
    let (reader,writer)=match UnixStream::pair() {
        Ok(pair)=>pair,
        Err(error)=>{io_os_error(io,error);return fail(&mut usage,IO_SYSTEM)}
    };
    if let Err(error)=reader.set_nonblocking(true).and_then(|_|writer.set_nonblocking(true)) {
        io_os_error(io,error);return fail(&mut usage,IO_SYSTEM)
    }
    // Complete every recoverable setup operation before committing counters.
    // Ordinary Arc allocation failure, as elsewhere in groups, is still fatal.
    let binding=std::sync::Arc::new(IoWorkerBinding{group:std::sync::Arc::clone(group),
        budget:std::sync::Arc::clone(&budget),wake_read:Some(reader),
        wake_write:std::sync::Mutex::new(Some(writer)),ports,requests});
    usage.h_attached_reactors=reactors.unwrap();
    usage.h_reserved_port_slots=port_total.unwrap();
    usage.h_reserved_request_slots=request_total.unwrap();
    usage.h_peak_reactors=usage.h_peak_reactors.max(reactors.unwrap());
    usage.h_peak_port_slots=usage.h_peak_port_slots.max(port_total.unwrap());
    usage.h_peak_request_slots=usage.h_peak_request_slots.max(request_total.unwrap());
    let wake:std::sync::Arc<dyn super::HeptaGroupIoWake>=binding.clone();
    state.io_waiters.push(std::sync::Arc::downgrade(&wake));
    io.task=Some(binding);IO_OK
}

// Inserted inside the exact production I/O module, with its exact group/task
// runtime. Extra threads, allocator hooks and peer clones are test setup only.
mod task_io_controls {
use super::*;
use super::super::*;
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::{Arc,Barrier,Mutex};
use std::sync::atomic::{AtomicUsize,AtomicBool};

static FAIL_SIZE:AtomicUsize=AtomicUsize::new(0);
static REFUSALS:AtomicUsize=AtomicUsize::new(0);
static TRACKED:[AtomicUsize;512]=[const {AtomicUsize::new(0)};512];
static ALLOCATED:AtomicUsize=AtomicUsize::new(0);
static FREED:AtomicUsize=AtomicUsize::new(0);
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct AllocationObserver;
fn should_refuse(size:usize)->bool {
    if size!=0 && FAIL_SIZE.compare_exchange(size,0,Ordering::SeqCst,Ordering::SeqCst).is_ok() {
        REFUSALS.fetch_add(1,Ordering::SeqCst);true
    } else {false}
}
unsafe impl GlobalAlloc for AllocationObserver {
    unsafe fn alloc(&self,l:Layout)->*mut u8 {
        if should_refuse(l.size()){std::ptr::null_mut()}else{System.alloc(l)}
    }
    unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8 {
        if should_refuse(l.size()){std::ptr::null_mut()}else{System.alloc_zeroed(l)}
    }
    unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8 {
        if should_refuse(n){std::ptr::null_mut()}else{System.realloc(p,l,n)}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:Layout) {
        for entry in &TRACKED {
            if entry.compare_exchange(p as usize,0,Ordering::SeqCst,Ordering::SeqCst).is_ok() {
                FREED.fetch_add(1,Ordering::SeqCst);LIVE.fetch_sub(1,Ordering::SeqCst);break
            }
        }
        System.dealloc(p,l)
    }
}
#[global_allocator] static ALLOCATOR:AllocationObserver=AllocationObserver;
fn tracked(size:usize)->Vec<u8> {
    let data=vec![0xa5u8;size];assert!(size>0);
    let slot=TRACKED.iter().find(|entry|entry.compare_exchange(0,data.as_ptr() as usize,Ordering::SeqCst,Ordering::SeqCst).is_ok());
    assert!(slot.is_some());ALLOCATED.fetch_add(1,Ordering::SeqCst);LIVE.fetch_add(1,Ordering::SeqCst);data
}
extern "C" {
    fn hepta_task_io_poll_entries()->u32;
    fn hepta_task_io_fail_poll();
    fn hepta_task_io_fail_pair();
    fn hepta_task_io_pause_poll(enabled:i32);
    fn hepta_task_io_fd_open(fd:i32)->i32;
}
static MODE:AtomicUsize=AtomicUsize::new(0);
static READY:AtomicBool=AtomicBool::new(false);
static BARRIER:Mutex<Option<Arc<Barrier>>>=Mutex::new(None);
fn wait_for(predicate:impl Fn()->bool) {
    let until=Instant::now()+Duration::from_secs(3);
    while !predicate(){assert!(Instant::now()<until,"fixture handshake timed out");std::thread::yield_now();}
}
fn family(reactors:usize,ports:usize,requests:usize,bytes:usize)->(HeptaTaskGroup,HeptaTaskGroup) {
    let mut root=__hepta_group_new(2,0,1);
    assert!(__hepta_group_budget_configure(&mut root,2,0,8,131072,65536));
    assert!(__hepta_group_io_configure(&mut root,reactors,ports,requests,bytes));
    let mut observer=__hepta_group_new(0,0,1);
    assert!(__hepta_group_budget_share(&mut observer,&root));(root,observer)
}
fn empty(observer:&HeptaTaskGroup) {
    let io=__hepta_group_io_snapshot(observer);
    assert_eq!((io.h_attached_reactors,io.h_reserved_port_slots,io.h_reserved_request_slots,io.h_reserved_bytes),(0,0,0,0),"I/O reservation leak");
    let tasks=__hepta_group_budget_snapshot(observer);
    assert_eq!((tasks.h_reserved_threads,tasks.h_reserved_input_bytes,tasks.h_reserved_requested_stack_bytes),(0,0,0));
    assert_eq!(tasks.h_reserved_queue_slots,1);
    assert_eq!(LIVE.load(Ordering::SeqCst),0,"actual buffer leak");
}
fn finish(root:HeptaTaskGroup,observer:HeptaTaskGroup)->H_GroupTreeReport {
    let done=__hepta_group_tree_join(root,false);assert_eq!(done.h_active_tasks,0);
    empty(&observer);let pool=observer.budget.as_ref().unwrap().clone();
    __hepta_group_tree_join(observer,false);
    let usage=pool.state.lock().unwrap();assert_eq!(usage.h_reserved_queue_slots,0);assert_eq!(usage.h_attached_groups,0);done
}
fn waiting(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mode=MODE.load(Ordering::SeqCst);let mut io=__hepta_io_reactor(2,2,64);
    let attached=__hepta_io_attach(&mut io,sender);
    if attached==IO_CANCELLED {__hepta_io_shutdown(io);return 1}
    assert_eq!(attached,IO_OK);
    let pair=__hepta_io_local_pair(&mut io);
    if pair.h_status==IO_CANCELLED {__hepta_io_shutdown(io);return 1}
    assert_eq!(pair.h_status,IO_OK);
    let fds:Vec<i32>=io.ports.iter().flatten().map(|p|p.socket.as_raw_fd())
        .chain(std::iter::once(io.task.as_ref().unwrap().wake_fd())).collect();
    if mode==1 {let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.write_all(&[5,6,7]).unwrap();}
    let requested=if mode==5 {1}else{19};
    let request=__hepta_io_read(&mut io,pair.h_left,tracked(19),requested,if mode==2 {10}else{30000});
    if mode==1 {assert_eq!(__hepta_io_poll(&mut io,0),Ok(0));}
    if mode==3 {unsafe{hepta_task_io_fail_poll()};}
    if mode==4 {
        drop(request);drop(io);
        for fd in fds {assert_eq!(unsafe{hepta_task_io_fd_open(fd)},0);}
        return 4
    }
    if mode==5 {
        let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.write_all(&[7]).unwrap();
        assert_eq!(__hepta_io_poll(&mut io,0),Ok(1));
        __hepta_tree_stop(&sender.shared,None,true);
    }
    READY.store(true,Ordering::SeqCst);
    let (mut count,mut code)=(0,255);
    let returned=__hepta_io_wait(&mut io,request,&mut count,&mut code);
    let expected=match mode {2=>IO_TIMEOUT,3=>IO_SYSTEM,5=>IO_OK,_=>IO_CANCELLED};
    assert_eq!(code,expected,"wait completion status");
    if mode==1 {assert_eq!(count,3);assert_eq!(&returned[..3],&[5,6,7]);assert!(returned[3..].iter().all(|b|*b==0xa5));}
    else if mode==5 {assert_eq!(count,1);assert_eq!(returned[0],7);}
    else {assert_eq!(count,0);}
    drop(returned);
    if mode==2 || mode==3 {
        let retry=__hepta_io_read(&mut io,pair.h_left,tracked(19),0,0);
        let data=__hepta_io_wait(&mut io,retry,&mut count,&mut code);assert_eq!(code,IO_OK);drop(data);
    }
    let report=__hepta_io_shutdown(io);assert_eq!(report.h_reserved_bytes,0);
    for fd in fds {assert_eq!(unsafe{hepta_task_io_fd_open(fd)},0);}
    code as u64
}
fn run_wait(mode:usize,cancel:bool,hold:bool) {
    MODE.store(mode,Ordering::SeqCst);READY.store(false,Ordering::SeqCst);
    let (mut root,observer)=family(1,4,2,64);
    let before=unsafe{hepta_task_io_poll_entries()};
    if hold {unsafe{hepta_task_io_pause_poll(1)}}
    assert!(__hepta_group_spawn(&mut root,waiting,vec![]));
    if cancel {
        wait_for(||unsafe{hepta_task_io_poll_entries()}>before);
        if !hold {std::thread::sleep(Duration::from_millis(20));}
        __hepta_group_cancel(&mut root);
        if hold {unsafe{hepta_task_io_pause_poll(0)}}
    }
    finish(root,observer);
}
fn limits(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mode=MODE.load(Ordering::SeqCst);let mut first=__hepta_io_reactor(2,2,64);
    let mut second=__hepta_io_reactor(2,2,64);assert_eq!(__hepta_io_attach(&mut first,sender),0);
    if mode<3 {
        assert_eq!(__hepta_io_attach(&mut second,sender),IO_SHARED_LIMIT,"attachment budget ignored");
        __hepta_io_shutdown(first);assert_eq!(__hepta_io_attach(&mut second,sender),0);__hepta_io_shutdown(second);
    } else {
        __hepta_io_shutdown(second);let pair=__hepta_io_local_pair(&mut first);
        let a=__hepta_io_read(&mut first,pair.h_left,tracked(19),19,30000);
        let b=__hepta_io_write(&mut first,pair.h_right,tracked(1),1,30000);
        assert_eq!(__hepta_io_request_status(&first,&b),IO_SHARED_LIMIT,"shared byte budget ignored");
        let (mut n,mut s)=(0,255);drop(__hepta_io_take(&mut first,b,&mut n,&mut s));assert_eq!(s,16);
        drop(__hepta_io_take(&mut first,a,&mut n,&mut s));
        let c=__hepta_io_read(&mut first,pair.h_left,tracked(19),0,0);
        assert_eq!(__hepta_io_request_status(&first,&c),0);drop(__hepta_io_take(&mut first,c,&mut n,&mut s));
        __hepta_io_shutdown(first);
    }
    0
}
fn limit_case(mode:usize) {
    MODE.store(mode,Ordering::SeqCst);
    let args=match mode {0=>(1,8,4,64),1=>(2,4,4,64),2=>(2,8,2,64),_=>(1,4,2,19)};
    let (mut root,observer)=family(args.0,args.1,args.2,args.3);
    assert!(__hepta_group_spawn(&mut root,limits,vec![]));finish(root,observer);
}
fn setup_refusals(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mode=MODE.load(Ordering::SeqCst);let mut io=__hepta_io_reactor(2,2,64);
    if mode<2 {
        let size=if mode==0 {core::mem::size_of::<std::sync::Weak<dyn HeptaGroupIoWake>>()} else {3*core::mem::size_of::<IoPollFd>()};
        let before=REFUSALS.load(Ordering::SeqCst);FAIL_SIZE.store(size,Ordering::SeqCst);
        assert_eq!(__hepta_io_attach(&mut io,sender),IO_ALLOCATION);
        assert_eq!(REFUSALS.load(Ordering::SeqCst),before+1);assert_eq!(FAIL_SIZE.load(Ordering::SeqCst),0);
    } else {unsafe{hepta_task_io_fail_pair()};assert_eq!(__hepta_io_attach(&mut io,sender),IO_SYSTEM);}
    let pool=sender.shared.state.lock().unwrap().budget.as_ref().unwrap().clone();
    {let r=pool.io.lock().unwrap();assert_eq!((r.h_attached_reactors,r.h_reserved_port_slots,r.h_reserved_request_slots,r.h_reserved_bytes),(0,0,0,0));}
    assert_eq!(__hepta_io_attach(&mut io,sender),0);__hepta_io_shutdown(io);0
}
fn setup_case(mode:usize) {
    MODE.store(mode,Ordering::SeqCst);let (mut root,observer)=family(1,4,2,64);
    assert!(__hepta_group_spawn(&mut root,setup_refusals,vec![]));finish(root,observer);
}
fn registry(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mut reactors:Vec<HeptaIoReactor>=Vec::new();
    for _ in 0..64 {let mut io=__hepta_io_reactor(2,1,0);assert_eq!(__hepta_io_attach(&mut io,sender),0);reactors.push(io);}
    let mut retry=__hepta_io_reactor(2,1,0);assert_eq!(__hepta_io_attach(&mut retry,sender),IO_REGISTRATION_LIMIT);
    drop(reactors.pop().unwrap());assert_eq!(__hepta_io_attach(&mut retry,sender),0);
    drop(retry);drop(reactors);0
}
fn registration_limit() {
    let (mut root,observer)=family(65,260,65,0);assert!(__hepta_group_spawn(&mut root,registry,vec![]));finish(root,observer);
}
fn cancellation_races() {
    for _ in 0..64 {
        MODE.store(0,Ordering::SeqCst);let (mut root,observer)=family(1,4,2,64);
        let mut child=__hepta_group_new(1,0,1);assert!(__hepta_group_budget_share(&mut child,&root));
        let below=child.shared.clone();let above=root.shared.clone();let before=unsafe{hepta_task_io_poll_entries()};
        assert!(__hepta_group_spawn(&mut child,waiting,vec![]));assert!(__hepta_group_adopt(&mut root,child));
        wait_for(||unsafe{hepta_task_io_poll_entries()}>before);
        let a=std::thread::spawn(move||__hepta_tree_stop(&above,None,true));
        let b=std::thread::spawn(move||__hepta_tree_fail(&below,9));
        a.join().unwrap();b.join().unwrap();let done=finish(root,observer);assert_eq!(done.h_failure_code,9);assert_eq!(done.h_joined_groups,2);
    }
    for _ in 0..64 {
        let (mut root,observer)=family(1,4,2,64);assert!(__hepta_group_spawn(&mut root,waiting,vec![]));
        __hepta_group_cancel(&mut root);finish(root,observer);
    }
}
fn ready_race(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mut io=__hepta_io_reactor(2,1,19);assert_eq!(__hepta_io_attach(&mut io,sender),0);
    let pair=__hepta_io_local_pair(&mut io);let mut peer=io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket.try_clone().unwrap();
    let q=__hepta_io_read(&mut io,pair.h_left,tracked(19),1,30000);
    let signal=Arc::new(Barrier::new(2));let peer_signal=signal.clone();let cancel_signal=signal.clone();let group=sender.shared.clone();
    let writer=std::thread::spawn(move||{peer_signal.wait();let _=peer.write_all(&[7]);});
    let canceller=std::thread::spawn(move||{cancel_signal.wait();__hepta_tree_stop(&group,None,true);});
    let (mut n,mut s)=(0,255);let data=__hepta_io_wait(&mut io,q,&mut n,&mut s);
    assert!(s==0 || s==1);if s==0 {assert_eq!((n,data[0]),(1,7));}else{assert_eq!(n,0);assert_eq!(data[0],0xa5);}
    writer.join().unwrap();canceller.join().unwrap();drop(data);__hepta_io_shutdown(io);0
}
fn readiness_races() {
    for _ in 0..64 {let (mut root,observer)=family(1,4,1,19);assert!(__hepta_group_spawn(&mut root,ready_race,vec![]));finish(root,observer);}
}
fn budget_worker(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let barrier=BARRIER.lock().unwrap().as_ref().unwrap().clone();let mut io=__hepta_io_reactor(2,1,19);
    assert_eq!(__hepta_io_attach(&mut io,sender),0);let pair=__hepta_io_local_pair(&mut io);
    barrier.wait();let q=__hepta_io_read(&mut io,pair.h_left,tracked(19),19,30000);
    let status=__hepta_io_request_status(&io,&q);barrier.wait();assert!(status==IO_PENDING || status==IO_SHARED_LIMIT);
    let (mut n,mut s)=(0,255);drop(__hepta_io_take(&mut io,q,&mut n,&mut s));__hepta_io_shutdown(io);
    u64::from(status==IO_PENDING)
}
fn budget_races() {
    for _ in 0..32 {
        *BARRIER.lock().unwrap()=Some(Arc::new(Barrier::new(2)));
        let (mut root,observer)=family(2,8,2,19);
        assert!(__hepta_group_spawn(&mut root,budget_worker,vec![]));assert!(__hepta_group_spawn(&mut root,budget_worker,vec![]));
        let done=__hepta_group_tree_join(root,false);assert_eq!(done.h_sum,1);empty(&observer);
        let usage=__hepta_group_io_snapshot(&observer);assert_eq!(usage.h_peak_bytes,19);assert_eq!(usage.h_buffer_refusals,1);
        __hepta_group_tree_join(observer,false);
    }
    *BARRIER.lock().unwrap()=None;
}
pub fn run(which:&str) {
    match which {
        "lost_wakeup"=>{println!("waiting-for-real-cancellation");run_wait(0,true,false);},
        "budget_bypass"=>limit_case(3),
        "reservation_leak"=>run_wait(4,false,false),
        "buffer_leak"=>run_wait(4,false,false),
        "positive"=>{
            run_wait(0,true,false);run_wait(0,true,true);run_wait(1,true,false);
            run_wait(2,false,false);run_wait(3,false,false);run_wait(4,false,false);run_wait(5,false,false);
            for m in 0..4 {limit_case(m);}for m in 0..3 {setup_case(m);}registration_limit();
            cancellation_races();readiness_races();budget_races();
            assert_eq!(ALLOCATED.load(Ordering::SeqCst),FREED.load(Ordering::SeqCst));
            println!("{{\"blocking_cancel_cases\":2,\"partial_cancel_cases\":1,\"timeout_recovery_cases\":1,\"poll_error_recovery_cases\":1,\"native_drop_cases\":1,\"completed_before_cancel_cases\":1,\"budget_refusal_dimensions\":4,\"metadata_allocation_refusals\":2,\"wake_socket_refusals\":1,\"registration_limit_recovery_cases\":1,\"parent_child_cancel_failure_races\":64,\"attachment_cancel_races\":64,\"readiness_cancel_races\":64,\"shared_byte_admission_races\":32,\"tracked_allocations\":{},\"tracked_frees\":{},\"live_buffers\":{},\"real_poll_entries\":{}}}",ALLOCATED.load(Ordering::SeqCst),FREED.load(Ordering::SeqCst),LIVE.load(Ordering::SeqCst),unsafe{hepta_task_io_poll_entries()});
        },
        _=>panic!("unknown native qualification control"),
    }
}
}
pub fn __hepta_task_io_controls(which:&str){task_io_controls::run(which)}

}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", target_pointer_width = "64"))]
use __hepta_io_runtime::*;

fn main(){__hepta_task_io_controls("reservation_leak")}
