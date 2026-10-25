"""Bounded hosted concurrency profile, separate from syntax and code generation.

Budgets belong to one TaskGroup instance. They constrain admissions and logical
queue storage, not total process heap/RSS, worker allocations, or CPU time.
"""
from .ast import Param, Struct, Type

GROUP_BUILTINS = {
    "task_group", "group_spawn", "group_send", "group_receive", "group_seal",
    "group_join", "group_drain_and_join", "group_cancel_and_join",
    "group_snapshot", "group_fail", "group_send_timeout", "group_receive_timeout",
    "group_cancel",
}
GROUP_TYPE_NAMES = {"TaskGroup", "Sender", "GroupReport"}
GROUP = Type("TaskGroup")
SENDER = Type("Sender", (Type("u64"),))
REPORT = Type("GroupReport")
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


def report_struct() -> Struct:
    return Struct("GroupReport", [Param(name, Type(typ)) for name, typ in REPORT_FIELDS])


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
struct HeptaGroupState {
    report: H_GroupReport,
    // Fixed-size storage: send never grows the ring.
    ring: std::vec::Vec<u64>,
    head: usize, len: usize, sealed: bool, closed: bool,
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
            }),
            readable: std::sync::Condvar::new(),
            writable: std::sync::Condvar::new(),
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
        handles: std::vec::Vec::new(),
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
        state.report.h_accepted_tasks += 1;
        state.report.h_active_tasks += 1;
        state.report.h_input_bytes = new_bytes.unwrap();
    }
    let shared = std::sync::Arc::clone(&group.shared);
    let launched = std::thread::Builder::new().spawn(move || {
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
    state.report
}
'''
