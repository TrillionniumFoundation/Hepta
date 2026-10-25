"""Bounded hosted concurrency profile, separate from syntax and code generation.

Local budgets belong to one TaskGroup instance. Explicitly attached groups can
also share a reservation pool. Neither profile bounds total process heap/RSS,
worker/FFI allocations, actual OS stack mappings, or CPU time.
"""
from .ast import Param, Struct, Type

GROUP_BUILTINS = {
    "task_group", "group_spawn", "group_send", "group_receive", "group_seal",
    "group_join", "group_drain_and_join", "group_cancel_and_join",
    "group_snapshot", "group_fail", "group_send_timeout", "group_receive_timeout",
    "group_cancel",
    "group_select_receive",
    "group_budget_configure", "group_budget_share", "group_budget_snapshot",
}
GROUP_TYPE_NAMES = {"TaskGroup", "Sender", "GroupReport", "GroupBudgetReport"}
GROUP = Type("TaskGroup")
SENDER = Type("Sender", (Type("u64"),))
REPORT = Type("GroupReport")
BUDGET_REPORT = Type("GroupBudgetReport")
REPORT_FIELDS = [
    ("accepted_tasks", "usize"), ("rejected_tasks", "usize"),
    ("completed_tasks", "usize"), ("active_tasks", "usize"),
    ("spawn_failures", "usize"), ("input_bytes", "usize"),
    ("queued", "usize"), ("peak_queued", "usize"),
    ("send_waits", "usize"), ("waiting_senders", "usize"),
    ("send_timeouts", "usize"), ("receive_timeouts", "usize"),
    ("received", "usize"), ("discarded", "usize"),
    ("task_limit", "usize"), ("input_byte_limit", "usize"),
    ("queue_capacity", "usize"), ("sum", "u64"),
    ("failed", "bool"), ("failure_code", "u64"),
    ("cancelled", "bool"), ("joined", "bool"),
]
BUDGET_REPORT_FIELDS = [
    ("attached", "bool"), ("attached_groups", "usize"),
    ("thread_limit", "usize"), ("input_byte_limit", "usize"),
    ("queue_slot_limit", "usize"), ("requested_stack_byte_limit", "usize"),
    ("worker_stack_request", "usize"),
    ("reserved_threads", "usize"), ("reserved_input_bytes", "usize"),
    ("reserved_queue_slots", "usize"), ("reserved_requested_stack_bytes", "usize"),
    ("peak_threads", "usize"), ("peak_input_bytes", "usize"),
    ("peak_queue_slots", "usize"), ("peak_requested_stack_bytes", "usize"),
    ("rejected_admissions", "usize"), ("spawn_failures", "usize"),
    ("attachment_refusals", "usize"),
]


def report_struct() -> Struct:
    return Struct("GroupReport", [Param(name, Type(typ)) for name, typ in REPORT_FIELDS])


def budget_report_struct() -> Struct:
    return Struct("GroupBudgetReport", [Param(name, Type(typ)) for name, typ in BUDGET_REPORT_FIELDS])


GROUP_RUNTIME = r'''
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
struct HeptaGroupBudget { state: std::sync::Mutex<H_GroupBudgetReport> }
struct HeptaGroupState {
    report: H_GroupReport,
    // Fixed-size storage: send never grows the ring.
    ring: std::vec::Vec<u64>,
    head: usize, len: usize, sealed: bool, closed: bool,
    selectors: std::vec::Vec<std::sync::Weak<HeptaSelectSignal>>,
}
// One signal belongs to one select call, so unrelated groups cannot cause
// repeated wakeups. Group state -> signal is the only nested lock order.
struct HeptaSelectSignal {
    pending: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}
fn __hepta_select_notify(state: &mut HeptaGroupState) {
    state.selectors.retain(|weak| {
        if let Some(signal) = weak.upgrade() {
            *signal.pending.lock().expect("Hepta select state poisoned") = true;
            signal.changed.notify_all();
            true
        } else { false }
    });
}
struct HeptaGroupShared {
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
            state: std::sync::Mutex::new(HeptaGroupState {
                report, ring: std::vec![0u64; slots], head: 0, len: 0,
                sealed: false, closed: false,
                selectors: std::vec::Vec::new(),
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
    let state = group.shared.state.lock().expect("Hepta group state poisoned");
    if group.budget.is_some() || state.sealed || state.closed || state.report.h_accepted_tasks != 0
        || slots < state.ring.len() || worker_stack_request < 64 * 1024
        || worker_stack_request > 1024 * 1024 * 1024 {
        return false;
    }
    group.budget = Some(std::sync::Arc::new(HeptaGroupBudget {
        state: std::sync::Mutex::new(H_GroupBudgetReport {
            h_attached: true, h_attached_groups: 1,
            h_thread_limit: threads, h_input_byte_limit: bytes,
            h_queue_slot_limit: slots, h_requested_stack_byte_limit: requested_stack_bytes,
            h_worker_stack_request: worker_stack_request,
            h_reserved_queue_slots: state.ring.len(), h_peak_queue_slots: state.ring.len(),
            ..H_GroupBudgetReport::default()
        }),
    }));
    true
}
fn __hepta_group_budget_share(target: &mut HeptaTaskGroup, sponsor: &HeptaTaskGroup) -> bool {
    let budget = match &sponsor.budget { Some(value) => value, None => return false };
    let state = target.shared.state.lock().expect("Hepta group state poisoned");
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
    {
        let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
        let new_bytes = state.report.h_input_bytes.checked_add(bytes);
        if state.sealed || state.closed
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
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    state.sealed = true;
    state.report.h_cancelled = true;
    state.closed = true;
    group.shared.cancel.store(true, std::sync::atomic::Ordering::Release);
    state.report.h_discarded = state.report.h_discarded.saturating_add(state.len);
    state.len = 0;
    state.report.h_queued = 0;
    group.shared.readable.notify_all();
    group.shared.writable.notify_all();
    __hepta_select_notify(&mut state);
}
fn __hepta_group_snapshot(group: &HeptaTaskGroup) -> H_GroupReport {
    group.shared.state.lock().expect("Hepta group state poisoned").report
}
fn __hepta_group_fail(sender: &HeptaSender, code: u64) {
    assert!(code != 0, "Hepta group_fail requires a nonzero error code");
    let mut state = sender.shared.state.lock().expect("Hepta group state poisoned");
    if !state.report.h_failed {
        state.report.h_failed = true;
        state.report.h_failure_code = code;
    }
    state.report.h_cancelled = true;
    state.closed = true;
    sender.shared.cancel.store(true, std::sync::atomic::Ordering::Release);
    sender.shared.readable.notify_all();
    sender.shared.writable.notify_all();
    __hepta_select_notify(&mut state);
}
fn __hepta_group_join(mut group: HeptaTaskGroup, mode: u8) -> H_GroupReport {
    // mode 0: already drained; 1: explicitly drain and discard; 2: cancel.
    __hepta_group_seal(&mut group);
    if mode == 1 {
        let mut ignored = 0u64;
        while __hepta_group_receive_inner(&group, &mut ignored, true) {}
    } else if mode == 2 {
        __hepta_group_cancel(&mut group);
    } else {
        let state = group.shared.state.lock().expect("Hepta group state poisoned");
        assert!(state.closed && state.len == 0,
                "Hepta group_join requires a drained channel; use group_drain_and_join or group_cancel_and_join");
    }
    for handle in group.handles.drain(..) {
        // The production bootstrap profile uses panic=abort. This is not a
        // promise of panic containment or termination of arbitrary workers.
        handle.join().expect("Hepta group worker panicked");
    }
    let mut state = group.shared.state.lock().expect("Hepta group state poisoned");
    state.report.h_joined = true;
    if let Some(budget) = group.budget.take() {
        let mut usage = budget.state.lock().expect("Hepta group budget poisoned");
        usage.h_reserved_threads -= state.report.h_accepted_tasks;
        usage.h_reserved_input_bytes -= state.report.h_input_bytes;
        usage.h_reserved_requested_stack_bytes -= state.report.h_accepted_tasks * usage.h_worker_stack_request;
        usage.h_reserved_queue_slots -= state.ring.len();
        usage.h_attached_groups -= 1;
    }
    state.report
}
'''
