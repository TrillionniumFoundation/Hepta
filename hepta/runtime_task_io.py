"""Worker-owned local reactors on the existing explicit task reservation pool.

The portable group metadata and Linux attachment reuse the original runtime.
There is no second frontend or ownership checker in this composition.
"""
from .ast import Param, Struct, Type

GROUP_IO_REPORT = Type("GroupIoReport")
GROUP_IO_FIELDS = [
    ("configured", "bool"), ("reactor_limit", "usize"),
    ("port_slot_limit", "usize"), ("request_slot_limit", "usize"),
    ("byte_limit", "usize"), ("attached_reactors", "usize"),
    ("reserved_port_slots", "usize"), ("reserved_request_slots", "usize"),
    ("reserved_bytes", "usize"), ("peak_reactors", "usize"),
    ("peak_port_slots", "usize"), ("peak_request_slots", "usize"),
    ("peak_bytes", "usize"), ("attachment_refusals", "usize"),
    ("buffer_refusals", "usize"), ("wake_notifications", "usize"),
]


def group_io_struct():
    return Struct("GroupIoReport", [Param(name, Type(typ)) for name, typ in GROUP_IO_FIELDS])


TASK_IO_GROUP_RUNTIME = r'''
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
'''


TASK_IO_RUNTIME = r'''
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
'''
