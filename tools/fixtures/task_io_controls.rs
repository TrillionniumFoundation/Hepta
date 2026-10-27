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
    fn hepta_task_io_fail_nonblocking(ordinal:u32);
    fn hepta_task_io_nonblocking_failures()->u32;
    fn hepta_task_io_last_pair_fd(index:u32)->i32;
    fn hepta_task_io_pause_poll(enabled:i32);
    fn hepta_task_io_fd_open(fd:i32)->i32;
}
static MODE:AtomicUsize=AtomicUsize::new(0);
static READY:AtomicBool=AtomicBool::new(false);
static DROP_GO:AtomicBool=AtomicBool::new(false);
static DROP_DONE:AtomicBool=AtomicBool::new(false);
static DROP_WAKE_FD:AtomicUsize=AtomicUsize::new(0);
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
    } else if mode==2 {unsafe{hepta_task_io_fail_pair()};assert_eq!(__hepta_io_attach(&mut io,sender),IO_SYSTEM);}
    else {
        let before=unsafe{hepta_task_io_nonblocking_failures()};
        unsafe{hepta_task_io_fail_nonblocking((mode-2) as u32)};
        assert_eq!(__hepta_io_attach(&mut io,sender),IO_SYSTEM);
        assert_eq!(unsafe{hepta_task_io_nonblocking_failures()},before+1);
        // Failure occurs after the actual socketpair creates both endpoints.
        // Check kernel FD closure before a retry can reuse either number.
        for index in 0..2 {
            let fd=unsafe{hepta_task_io_last_pair_fd(index)};assert!(fd>=0);
            assert_eq!(unsafe{hepta_task_io_fd_open(fd)},0,"failed wake setup leaked an endpoint");
        }
    }
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
fn final_arc_worker(_:Vec<u8>,_:&HeptaCancellation,sender:&HeptaSender)->u64 {
    let mut io=__hepta_io_reactor(2,1,19);assert_eq!(__hepta_io_attach(&mut io,sender),0);
    DROP_WAKE_FD.store(io.task.as_ref().unwrap().wake_fd() as usize,Ordering::SeqCst);
    let pair=__hepta_io_local_pair(&mut io);assert_eq!(pair.h_status,0);
    let q=__hepta_io_read(&mut io,pair.h_left,tracked(19),19,30000);
    READY.store(true,Ordering::SeqCst);wait_for(||DROP_GO.load(Ordering::SeqCst));
    drop(q);drop(io);DROP_DONE.store(true,Ordering::SeqCst);0
}
fn final_canceller_arc_cleanup() {
    READY.store(false,Ordering::SeqCst);DROP_GO.store(false,Ordering::SeqCst);DROP_DONE.store(false,Ordering::SeqCst);
    let (mut root,observer)=family(1,4,1,19);
    assert!(__hepta_group_spawn(&mut root,final_arc_worker,vec![]));
    wait_for(||READY.load(Ordering::SeqCst));
    let mut state=root.shared.state.lock().unwrap();
    let retained=state.io_waiters[0].upgrade().unwrap();
    DROP_GO.store(true,Ordering::SeqCst);
    // The worker drops its local owner while the canceller still holds state
    // and a temporary wake Arc, exactly the ownership hazard under review.
    wait_for(||DROP_DONE.load(Ordering::SeqCst));
    let usage=__hepta_group_io_snapshot(&observer);
    assert_eq!((usage.h_attached_reactors,usage.h_reserved_bytes),(1,0));
    let wake_fd=DROP_WAKE_FD.load(Ordering::SeqCst) as i32;
    assert_eq!(unsafe{hepta_task_io_fd_open(wake_fd)},1);
    root.shared.cancel.store(true,Ordering::Release);
    __hepta_group_io_notify(&mut state);
    drop(retained); // The final strong reference is released under group state.
    let released=__hepta_group_io_snapshot(&observer);
    assert_eq!((released.h_attached_reactors,released.h_reserved_port_slots,released.h_reserved_request_slots,released.h_reserved_bytes),(0,0,0,0));
    assert_eq!(unsafe{hepta_task_io_fd_open(wake_fd)},0,"final canceller Arc leaked the wake reader");
    drop(state);finish(root,observer);
}
fn refused_subtree_recovery() {
    MODE.store(0,Ordering::SeqCst);
    let (mut root,observer)=family(1,4,2,64);
    let mut child=__hepta_group_new(1,0,1);
    assert!(__hepta_group_budget_share(&mut child,&root));
    let before=unsafe{hepta_task_io_poll_entries()};
    assert!(__hepta_group_spawn(&mut child,waiting,vec![]));
    wait_for(||unsafe{hepta_task_io_poll_entries()}>before);
    // Refusal consumes the child and synchronously cancels/joins it. Its
    // worker is already in the production poll path, with a resident buffer.
    __hepta_group_seal(&mut root);
    assert!(!__hepta_group_adopt(&mut root,child));
    let done=__hepta_group_tree_join(root,false);
    assert_eq!((done.h_adoption_refusals,done.h_joined_groups),(1,1));
    empty(&observer);
    // Keep the same explicit pool alive through the observer and admit a new
    // group. It must perform a timeout, recover and release the same charges.
    MODE.store(2,Ordering::SeqCst);
    let mut retry=__hepta_group_new(1,0,1);
    assert!(__hepta_group_budget_share(&mut retry,&observer));
    assert!(__hepta_group_spawn(&mut retry,waiting,vec![]));
    let recovered=finish(retry,observer);assert_eq!(recovered.h_joined_groups,1);
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
        let mut left=__hepta_group_new(1,0,1);let mut right=__hepta_group_new(1,0,1);
        assert!(__hepta_group_budget_share(&mut left,&root));assert!(__hepta_group_budget_share(&mut right,&root));
        assert!(__hepta_group_spawn(&mut left,budget_worker,vec![]));assert!(__hepta_group_spawn(&mut right,budget_worker,vec![]));
        assert!(__hepta_group_adopt(&mut root,left));assert!(__hepta_group_adopt(&mut root,right));
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
        "drop_lock_inversion"=>{println!("waiting-for-canceller-owned-drop");final_canceller_arc_cleanup();},
        "positive"=>{
            run_wait(0,true,false);run_wait(0,true,true);run_wait(1,true,false);
            run_wait(2,false,false);run_wait(3,false,false);run_wait(4,false,false);run_wait(5,false,false);
            for m in 0..4 {limit_case(m);}for m in 0..5 {setup_case(m);}registration_limit();refused_subtree_recovery();
            final_canceller_arc_cleanup();
            cancellation_races();readiness_races();budget_races();
            assert_eq!(ALLOCATED.load(Ordering::SeqCst),FREED.load(Ordering::SeqCst));
            println!("{{\"blocking_cancel_cases\":2,\"partial_cancel_cases\":1,\"timeout_recovery_cases\":1,\"poll_error_recovery_cases\":1,\"native_drop_cases\":1,\"completed_before_cancel_cases\":1,\"budget_refusal_dimensions\":4,\"metadata_allocation_refusals\":2,\"wake_socket_refusals\":1,\"wake_nonblocking_refusals\":{},\"final_canceller_arc_cleanup_cases\":1,\"registration_limit_recovery_cases\":1,\"refused_subtree_cleanup_recovery_cases\":1,\"parent_child_cancel_failure_races\":64,\"attachment_cancel_races\":64,\"readiness_cancel_races\":64,\"shared_byte_admission_races\":32,\"tracked_allocations\":{},\"tracked_frees\":{},\"live_buffers\":{},\"real_poll_entries\":{}}}",unsafe{hepta_task_io_nonblocking_failures()},ALLOCATED.load(Ordering::SeqCst),FREED.load(Ordering::SeqCst),LIVE.load(Ordering::SeqCst),unsafe{hepta_task_io_poll_entries()});
        },
        _=>panic!("unknown native qualification control"),
    }
}
}
pub fn __hepta_task_io_controls(which:&str){task_io_controls::run(which)}
