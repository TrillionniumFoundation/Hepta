"""Linux hosted, bounded, caller-driven nonblocking local-stream reactor.

The reactor owns every admitted descriptor and buffer. Requests are linear
completion tickets; cancellation is serialized between pump calls. The sole
unsafe production operation is poll(2) on a live Rust-owned pollfd array.
"""
from dataclasses import fields, is_dataclass

from .ast import Expr, Param, Struct, Type

IO_OWNER_TYPES = {"IoReactor", "IoRequest"}
IO_TYPE_NAMES = IO_OWNER_TYPES | {"IoPair", "IoReport", "GroupIoReport"}
IO_BUILTINS = {
    "io_reactor", "io_local_pair", "io_read", "io_write", "io_poll",
    "io_cancel", "io_request_status", "io_take", "io_wait", "io_close_port",
    "io_report", "io_shutdown",
    "io_attach", "group_io_configure", "group_io_snapshot",
}
IO_REACTOR = Type("IoReactor")
IO_REQUEST = Type("IoRequest")
IO_PAIR = Type("IoPair")
IO_REPORT = Type("IoReport")
IO_PAIR_FIELDS = [("left", "u64"), ("right", "u64"), ("status", "u8")]
IO_REPORT_FIELDS = [
    ("status", "u8"), ("port_limit", "usize"), ("request_limit", "usize"),
    ("byte_limit", "usize"), ("open_ports", "usize"), ("occupied_requests", "usize"),
    ("pending_requests", "usize"), ("reserved_bytes", "usize"),
    ("peak_requests", "usize"), ("peak_bytes", "usize"),
    ("admitted", "u64"), ("refused", "u64"), ("completed", "u64"),
    ("cancelled", "u64"), ("timed_out", "u64"), ("abandoned", "u64"),
    ("poll_calls", "u64"), ("poll_interruptions", "u64"), ("poll_failures", "u64"),
    ("read_calls", "u64"), ("write_calls", "u64"), ("would_block", "u64"),
    ("read_bytes", "u64"), ("written_bytes", "u64"), ("last_os_error", "i32"),
    ("shutdown", "bool"),
]


def io_structs():
    return [Struct(name, [Param(field, Type(typ)) for field, typ in fields])
            for name, fields in (("IoPair", IO_PAIR_FIELDS), ("IoReport", IO_REPORT_FIELDS))]


def has_io_profile(program):
    """Include unused declarations when an independent lowerer lacks this profile."""
    pending = [program]
    while pending:
        item = pending.pop()
        if isinstance(item, Type):
            if item.name in IO_TYPE_NAMES:
                return True
            pending.extend(item.args)
        elif is_dataclass(item):
            if isinstance(item, Expr) and item.kind == "call" and item.value in IO_BUILTINS:
                return True
            pending.extend(getattr(item, field.name) for field in fields(item))
        elif isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (tuple, list)):
            pending.extend(item)
    return False


IO_RUNTIME = r'''
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
    if let Some(task)=&io.task {task.release_bytes(operation.data.capacity())}
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
// HEPTA_IO_GROUP_INSERTION
// HEPTA_IO_TEST_INSERTION
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", target_pointer_width = "64"))]
use __hepta_io_runtime::*;
'''
