"""Consuming, bounded task-group trees for the hosted Rust runtime.

Adoption transfers the actual child owner, not only its budget identity. The
finite dynamic protocol is qualified separately from normal-exit IR checking.
"""
from .ast import Param, Struct, Type

TREE_REPORT = Type("GroupTreeReport")
TREE_REPORT_FIELDS = [
    ("groups", "usize"), ("depth", "usize"), ("adopted_groups", "usize"),
    ("adoption_refusals", "usize"), ("joined_groups", "usize"),
    ("accepted_tasks", "usize"), ("rejected_tasks", "usize"),
    ("completed_tasks", "usize"), ("active_tasks", "usize"),
    ("spawn_failures", "usize"), ("input_bytes", "usize"),
    ("queued", "usize"), ("received", "usize"), ("discarded", "usize"),
    ("waiting_senders", "usize"), ("sum", "u64"),
    ("failed", "bool"), ("failure_code", "u64"), ("cancelled", "bool"),
]


def tree_report_struct() -> Struct:
    return Struct("GroupTreeReport", [Param(name, Type(typ)) for name, typ in TREE_REPORT_FIELDS])


TREE_RUNTIME = r'''
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
'''
