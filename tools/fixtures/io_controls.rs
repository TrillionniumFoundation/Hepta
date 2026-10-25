extern "C" {
    fn hepta_io_test_cpu_ns()->u64;
    fn hepta_io_test_blocked_ns()->u64;
    fn hepta_io_test_real_polls()->u64;
    fn hepta_io_test_final_timeout()->i32;
    fn hepta_io_test_reset();
    fn hepta_io_test_interrupt(count:u32,delay_ms:u32);
    fn hepta_io_test_fail_poll();
    fn hepta_io_test_exhaust_fds()->i32;
    fn hepta_io_test_restore_fds()->i32;
    fn hepta_io_test_pollfd_size()->usize;
    fn hepta_io_test_pollfd_align()->usize;
    fn hepta_io_test_pollfd_events()->usize;
    fn hepta_io_test_pollfd_revents()->usize;
    fn hepta_io_test_nfds_size()->usize;
    fn hepta_io_test_fd_open(fd:i32)->i32;
    fn hepta_io_test_wait_readable(fd:i32)->i32;
}
struct IoCounting;
static IO_TRACK:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static IO_REFUSE_NTH:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static IO_ATTEMPTS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static IO_ALLOCS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static IO_FREES:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static IO_LIVE:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
static IO_BUFFER_TRACK:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static IO_BUFFER_LIVE:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for IoCounting {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        let track=IO_TRACK.load(Ordering::SeqCst);
        if track {
            let number=IO_ATTEMPTS.fetch_add(1,Ordering::SeqCst)+1;
            if IO_REFUSE_NTH.load(Ordering::SeqCst)==number {return core::ptr::null_mut()}
        }
        let pointer=std::alloc::GlobalAlloc::alloc(&std::alloc::System,layout);
        if !pointer.is_null() {
            if track {IO_ALLOCS.fetch_add(1,Ordering::SeqCst);IO_LIVE.fetch_add(layout.size() as isize,Ordering::SeqCst);}
            if IO_BUFFER_TRACK.load(Ordering::SeqCst) && layout.size()==4093 {
                IO_BUFFER_LIVE.fetch_add(4093,Ordering::SeqCst);
            }
        }
        pointer
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout) {
        if IO_TRACK.load(Ordering::SeqCst) {
            IO_FREES.fetch_add(1,Ordering::SeqCst);IO_LIVE.fetch_sub(layout.size() as isize,Ordering::SeqCst);
        }
        if IO_BUFFER_TRACK.load(Ordering::SeqCst) && layout.size()==4093 {
            IO_BUFFER_LIVE.fetch_sub(4093,Ordering::SeqCst);
        }
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System,pointer,layout);
    }
}
#[global_allocator] static IO_ALLOCATOR:IoCounting=IoCounting;
fn io_track(nth:usize) {
    assert_eq!(IO_LIVE.load(Ordering::SeqCst),0);
    IO_ATTEMPTS.store(0,Ordering::SeqCst);IO_ALLOCS.store(0,Ordering::SeqCst);IO_FREES.store(0,Ordering::SeqCst);
    IO_REFUSE_NTH.store(nth,Ordering::SeqCst);IO_TRACK.store(true,Ordering::SeqCst);
}
fn io_untrack()->(usize,usize,usize,isize) {
    IO_TRACK.store(false,Ordering::SeqCst);
    (IO_ATTEMPTS.load(Ordering::SeqCst),IO_ALLOCS.load(Ordering::SeqCst),IO_FREES.load(Ordering::SeqCst),IO_LIVE.load(Ordering::SeqCst))
}
fn io_test_pair(io:&mut HeptaIoReactor)->H_IoPair {
    let pair=__hepta_io_local_pair(io);assert_eq!(pair.h_status,IO_OK);pair
}
fn io_test_take(io:&mut HeptaIoReactor,request:HeptaIoRequest,expected:u8,bytes:usize)->Vec<u8> {
    let mut count=usize::MAX;let mut status=IO_PENDING;
    let data=__hepta_io_wait(io,request,&mut count,&mut status);
    assert_eq!((status,count),(expected,bytes));data
}
fn io_test_close(io:HeptaIoReactor)->H_IoReport {
    let report=__hepta_io_shutdown(io);
    assert!(report.h_shutdown);
    assert_eq!((report.h_open_ports,report.h_pending_requests,report.h_occupied_requests,report.h_reserved_bytes),(0,0,0,0));
    report
}
pub(crate) fn io_control_main() {
    unsafe {
        assert_eq!(core::mem::size_of::<IoPollFd>(),hepta_io_test_pollfd_size());
        assert_eq!(core::mem::align_of::<IoPollFd>(),hepta_io_test_pollfd_align());
        assert_eq!(core::mem::offset_of!(IoPollFd,events),hepta_io_test_pollfd_events());
        assert_eq!(core::mem::offset_of!(IoPollFd,revents),hepta_io_test_pollfd_revents());
        assert_eq!(core::mem::size_of::<usize>(),hepta_io_test_nfds_size());
        hepta_io_test_reset();
    }
    // Real delayed readiness: only the peer is on another thread; all I/O
    // requests and poll execution stay in the single-owner reactor thread.
    let mut io=__hepta_io_reactor(2,2,128);let pair=io_test_pair(&mut io);
    let mut peer=io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket.try_clone().unwrap();
    let request=__hepta_io_read(&mut io,pair.h_left,vec![0;64],64,2000);
    let handle=std::thread::spawn(move||{std::thread::sleep(Duration::from_millis(25));peer.write_all(&[37;64]).unwrap();});
    let cpu_start=unsafe{hepta_io_test_cpu_ns()};assert!(cpu_start>0);
    let start=Instant::now();
    let received=io_test_take(&mut io,request,IO_OK,64);
    let elapsed=start.elapsed().as_nanos() as u64;
    let cpu_end=unsafe{hepta_io_test_cpu_ns()};assert!(cpu_end>=cpu_start);
    let cpu=cpu_end-cpu_start;
    let blocked=unsafe{hepta_io_test_blocked_ns()};
    let real_polls=unsafe{hepta_io_test_real_polls()};
    assert_eq!(received,vec![37;64]);handle.join().unwrap();drop(received);
    assert!(elapsed>=15_000_000 && blocked>=10_000_000);
    assert!(cpu<elapsed/2+5_000_000 && real_polls>=1 && real_polls<=4);
    let report=io_test_close(io);assert!(report.h_poll_calls>=1 && report.h_poll_calls<=4);

    // Partial read preserves its initialized tail and reports EOF rather than
    // pretending that the requested length was completely filled.
    let mut io=__hepta_io_reactor(2,2,128);let pair=io_test_pair(&mut io);
    let request=__hepta_io_read(&mut io,pair.h_left,vec![99;16],16,2000);
    {let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.write_all(&[1,2,3]).unwrap();}
    assert!(__hepta_io_close_port(&mut io,pair.h_right));
    let data=io_test_take(&mut io,request,IO_EOF,3);
    assert_eq!(&data[..3],&[1,2,3]);assert!(data[3..].iter().all(|v|*v==99));drop(data);
    let broken=__hepta_io_write(&mut io,pair.h_left,vec![7;8],8,2000);
    drop(io_test_take(&mut io,broken,IO_SYSTEM,0));
    assert_ne!(__hepta_io_report(&io).h_last_os_error,0);io_test_close(io);

    let mut io=__hepta_io_reactor(2,1,16);let pair=io_test_pair(&mut io);
    let request=__hepta_io_read(&mut io,pair.h_left,vec![99;16],16,2000);
    {let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.write_all(&[4,5,6]).unwrap();}
    assert_eq!(__hepta_io_poll(&mut io,0),Ok(0));assert!(__hepta_io_cancel(&mut io,&request));
    let data=io_test_take(&mut io,request,IO_CANCELLED,3);
    assert_eq!(&data[..3],&[4,5,6]);assert!(data[3..].iter().all(|v|*v==99));drop(data);io_test_close(io);

    // Force a real partial write by filling a local stream while its peer does
    // not read. Cancellation preserves the already delivered prefix.
    let size=2*1024*1024;
    let mut io=__hepta_io_reactor(2,2,size);let pair=io_test_pair(&mut io);
    let request=__hepta_io_write(&mut io,pair.h_left,vec![71;size],size,2000);
    assert_eq!(__hepta_io_poll(&mut io,0),Ok(0));
    let index=io_slot(&io,&request).unwrap();
    let partial=io.operations[index].as_ref().unwrap().transferred;
    assert!(partial>0 && partial<size);
    assert!(__hepta_io_cancel(&mut io,&request));assert!(!__hepta_io_cancel(&mut io,&request));
    let buffer=io_test_take(&mut io,request,IO_CANCELLED,partial);assert!(buffer.iter().all(|v|*v==71));drop(buffer);
    let mut delivered=vec![0;partial];
    {let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.read_exact(&mut delivered).unwrap();}
    assert!(delivered.iter().all(|v|*v==71));drop(delivered);
    io_test_close(io);

    // A real write-readiness wait: fill the stream, then an independently
    // scheduled peer drains it. Both descriptors stay nonblocking; the fixture
    // peer also uses a real event wait when it needs more bytes.
    let mut io=__hepta_io_reactor(2,1,size);let pair=io_test_pair(&mut io);
    let mut peer=io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket.try_clone().unwrap();
    let writing=__hepta_io_write(&mut io,pair.h_left,vec![41;size],size,2000);
    assert_eq!(__hepta_io_poll(&mut io,0),Ok(0));
    let already=io.operations[io_slot(&io,&writing).unwrap()].as_ref().unwrap().transferred;
    assert!(already>0 && already<size);
    unsafe{hepta_io_test_reset();}
    let worker=std::thread::spawn(move||{
        std::thread::sleep(Duration::from_millis(25));
        let mut received=0;let mut chunk=[0;4096];
        while received<size {
            match peer.read(&mut chunk) {
                Ok(0)=>panic!("peer reached early EOF"),
                Ok(count)=>{assert!(chunk[..count].iter().all(|value|*value==41));received+=count;},
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{
                    unsafe{assert!(hepta_io_test_wait_readable(peer.as_raw_fd())>0);}
                },
                Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
                Err(error)=>panic!("peer read failed: {error}"),
            }
        }
        received
    });
    let start=Instant::now();drop(io_test_take(&mut io,writing,IO_OK,size));
    let write_elapsed=start.elapsed().as_nanos() as u64;
    let write_blocked=unsafe{hepta_io_test_blocked_ns()};
    let write_polls=unsafe{hepta_io_test_real_polls()};
    assert_eq!(worker.join().unwrap(),size);
    assert!(write_elapsed>=15_000_000 && write_blocked>=10_000_000 && write_polls>=1 && write_polls<=256);
    let report=io_test_close(io);assert_eq!(report.h_written_bytes,size as u64);

    // Kernel readiness can arrive before cancellation; a queued cancellation
    // still prevents the reactor's first read, so bytes remain in the socket.
    let mut io=__hepta_io_reactor(2,2,64);let pair=io_test_pair(&mut io);
    let cancelled=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    {let mut peer=&io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket;peer.write_all(&[83;8]).unwrap();}
    assert!(__hepta_io_cancel(&mut io,&cancelled));drop(io_test_take(&mut io,cancelled,IO_CANCELLED,0));
    let next=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    let read=io_test_take(&mut io,next,IO_OK,8);assert_eq!(read,vec![83;8]);drop(read);io_test_close(io);

    // A peer thread and cancellation race at a barrier. Regardless of which
    // reaches the kernel first, cancelled requests never run a later read.
    // This is a readiness/cancel race, not concurrent access to the reactor.
    for value in 0..64u8 {
        let mut io=__hepta_io_reactor(2,1,8);let pair=io_test_pair(&mut io);
        let mut peer=io.ports.iter().flatten().find(|p|p.token==pair.h_right).unwrap().socket.try_clone().unwrap();
        let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
        let other=std::sync::Arc::clone(&barrier);
        let request=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
        let worker=std::thread::spawn(move||{other.wait();peer.write_all(&[value;8]).unwrap();});
        barrier.wait();assert!(__hepta_io_cancel(&mut io,&request));
        drop(io_test_take(&mut io,request,IO_CANCELLED,0));worker.join().unwrap();
        let next=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
        let bytes=io_test_take(&mut io,next,IO_OK,8);assert_eq!(bytes,vec![value;8]);
        drop(bytes);io_test_close(io);
    }

    // Five actually intercepted EINTR returns consume time. The final real
    // poll receives only the remaining original deadline, not a fresh period.
    unsafe{hepta_io_test_reset();hepta_io_test_interrupt(5,20);}
    let mut io=__hepta_io_reactor(2,1,8);let pair=io_test_pair(&mut io);
    let request=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,250);
    drop(io_test_take(&mut io,request,IO_TIMEOUT,0));
    let remaining=unsafe{hepta_io_test_final_timeout()};
    assert!(remaining>=0 && remaining<=200);
    let report=io_test_close(io);assert_eq!(report.h_poll_interruptions,5);assert_eq!(report.h_timed_out,1);

    // An actual poll-boundary EIO completes all in-flight operations as errors,
    // followed by a successful transfer through the same native descriptors.
    unsafe{hepta_io_test_reset();hepta_io_test_fail_poll();}
    let mut io=__hepta_io_reactor(2,4,64);let pair=io_test_pair(&mut io);
    let a=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    let b=__hepta_io_read(&mut io,pair.h_right,vec![0;8],8,2000);
    drop(io_test_take(&mut io,a,IO_SYSTEM,0));drop(io_test_take(&mut io,b,IO_SYSTEM,0));
    assert_eq!(__hepta_io_report(&io).h_poll_failures,1);
    let a=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    let b=__hepta_io_write(&mut io,pair.h_right,vec![3;8],8,2000);
    let data=io_test_take(&mut io,a,IO_OK,8);assert_eq!(data,vec![3;8]);drop(data);drop(io_test_take(&mut io,b,IO_OK,8));
    io_test_close(io);

    // Distinct slot, byte-capacity, direction and port budgets; each refusal
    // returns its original buffer and does not allocate a resident request.
    let mut io=__hepta_io_reactor(2,2,16);let pair=io_test_pair(&mut io);
    let a=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    let b=__hepta_io_read(&mut io,pair.h_right,vec![0;8],8,2000);
    let busy=__hepta_io_read(&mut io,pair.h_left,vec![1;4],4,2000);assert_eq!(io_test_take(&mut io,busy,IO_BUSY,0),vec![1;4]);
    let full=__hepta_io_write(&mut io,pair.h_left,vec![2;4],4,2000);assert_eq!(io_test_take(&mut io,full,IO_REQUEST_LIMIT,0),vec![2;4]);
    assert_eq!(__hepta_io_local_pair(&mut io).h_status,IO_PORT_LIMIT);
    assert!(__hepta_io_cancel(&mut io,&a));drop(io_test_take(&mut io,a,IO_CANCELLED,0));
    let mut capacity=Vec::with_capacity(16);capacity.resize(8,0);
    let bytes=__hepta_io_write(&mut io,pair.h_left,capacity,8,2000);
    let returned=io_test_take(&mut io,bytes,IO_BYTE_LIMIT,0);assert_eq!((returned.len(),returned.capacity()),(8,16));drop(returned);
    assert!(__hepta_io_cancel(&mut io,&b));drop(io_test_take(&mut io,b,IO_CANCELLED,0));
    let zero=__hepta_io_read(&mut io,pair.h_left,Vec::new(),0,0);assert!(io_test_take(&mut io,zero,IO_OK,0).is_empty());
    let report=io_test_close(io);assert_eq!((report.h_peak_bytes,report.h_peak_requests),(16,2));

    let mut io=__hepta_io_reactor(2,1,8);let pair=io_test_pair(&mut io);
    let sent=__hepta_io_write(&mut io,pair.h_left,vec![5;8],8,2000);
    assert_eq!(__hepta_io_poll(&mut io,0),Ok(1));
    assert!(!__hepta_io_cancel(&mut io,&sent));
    let full=__hepta_io_read(&mut io,pair.h_right,vec![0;8],8,2000);drop(io_test_take(&mut io,full,IO_REQUEST_LIMIT,0));
    assert_eq!(__hepta_io_report(&io).h_reserved_bytes,8);
    drop(io_test_take(&mut io,sent,IO_OK,8));
    let received=__hepta_io_read(&mut io,pair.h_right,vec![0;8],8,2000);
    let bytes=io_test_take(&mut io,received,IO_OK,8);assert_eq!(bytes,vec![5;8]);drop(bytes);io_test_close(io);

    // Close an endpoint with an outstanding read, then obtain the very same
    // numeric Linux FD for a different port identity. Old IDs cannot touch it.
    let mut io=__hepta_io_reactor(2,4,64);let pair=io_test_pair(&mut io);
    let old_fd=io.ports.iter().flatten().find(|p|p.token==pair.h_left).unwrap().socket.as_raw_fd();
    let old=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    assert!(__hepta_io_close_port(&mut io,pair.h_left));assert!(__hepta_io_close_port(&mut io,pair.h_right));
    let new_pair=io_test_pair(&mut io);
    let reused=io.ports.iter().flatten().any(|p|p.socket.as_raw_fd()==old_fd);assert!(reused);
    assert_ne!(new_pair.h_left,pair.h_left);
    let invalid=__hepta_io_read(&mut io,pair.h_left,vec![6;8],8,2000);assert_eq!(io_test_take(&mut io,invalid,IO_PORT,0),vec![6;8]);
    assert!(!__hepta_io_close_port(&mut io,pair.h_left));
    drop(io_test_take(&mut io,old,IO_CLOSED,0));
    let a=__hepta_io_read(&mut io,new_pair.h_left,vec![0;8],8,2000);
    let b=__hepta_io_write(&mut io,new_pair.h_right,vec![67;8],8,2000);
    let read=io_test_take(&mut io,a,IO_OK,8);assert_eq!(read,vec![67;8]);drop(read);drop(io_test_take(&mut io,b,IO_OK,8));
    io_test_close(io);

    // Cross-reactor misuse never polls another reactor's FD. A wrongly
    // consumed ticket loses its claim, while its original owner still reports
    // and reclaims that bounded allocation at shutdown.
    IO_BUFFER_TRACK.store(true,Ordering::SeqCst);
    let mut a=__hepta_io_reactor(2,2,8192);let pa=io_test_pair(&mut a);
    let mut b=__hepta_io_reactor(2,2,8192);let _pb=io_test_pair(&mut b);
    let request=__hepta_io_read(&mut a,pa.h_left,vec![0;4093],4093,2000);
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),4093);
    assert_eq!(__hepta_io_request_status(&b,&request),IO_TICKET);assert!(!__hepta_io_cancel(&mut b,&request));
    let foreign_port=__hepta_io_read(&mut b,pa.h_left,vec![2;8],8,2000);drop(io_test_take(&mut b,foreign_port,IO_PORT,0));
    assert!(io_test_take(&mut b,request,IO_TICKET,0).is_empty());
    assert_eq!(__hepta_io_report(&a).h_reserved_bytes,4093);
    assert_eq!(__hepta_io_report(&b).h_poll_calls,0);
    let report=io_test_close(a);assert_eq!(report.h_abandoned,1);io_test_close(b);
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),0);IO_BUFFER_TRACK.store(false,Ordering::SeqCst);

    // A stale request identity is reconstructed only by this trusted native
    // control; safe Hepta itself rejects copying or reusing its linear ticket.
    let mut io=__hepta_io_reactor(2,1,8);let pair=io_test_pair(&mut io);
    let first=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    let stale=HeptaIoRequest{reactor:first.reactor,token:first.token,immediate:None};
    assert!(__hepta_io_cancel(&mut io,&first));drop(io_test_take(&mut io,first,IO_CANCELLED,0));
    let next=__hepta_io_read(&mut io,pair.h_left,vec![0;8],8,2000);
    assert_eq!(__hepta_io_request_status(&io,&stale),IO_TICKET);assert!(!__hepta_io_cancel(&mut io,&stale));
    assert!(io_test_take(&mut io,stale,IO_TICKET,0).is_empty());
    assert_eq!(__hepta_io_request_status(&io,&next),IO_PENDING);
    assert!(__hepta_io_cancel(&mut io,&next));drop(io_test_take(&mut io,next,IO_CANCELLED,0));io_test_close(io);

    // A real Linux soft RLIMIT_NOFILE exhaustion, then restoration and reuse.
    let mut io=__hepta_io_reactor(2,1,8);
    unsafe{assert_eq!(hepta_io_test_exhaust_fds(),0);}
    let refused=__hepta_io_local_pair(&mut io);
    unsafe{assert_eq!(hepta_io_test_restore_fds(),0);}
    assert_eq!(refused.h_status,IO_SYSTEM);assert_eq!(__hepta_io_report(&io).h_open_ports,0);
    let _recovered=io_test_pair(&mut io);io_test_close(io);

    // Shutdown must really close descriptors and free admitted buffers, not
    // merely zero report counters. There are no open/close calls between the
    // drop and fcntl, so an unrelated descriptor cannot mask the observation.
    IO_BUFFER_TRACK.store(true,Ordering::SeqCst);
    let mut io=__hepta_io_reactor(2,2,8186);let pair=io_test_pair(&mut io);
    let fds:Vec<_>=io.ports.iter().flatten().map(|port|port.socket.as_raw_fd()).collect();
    for &fd in &fds{unsafe{assert_eq!(hepta_io_test_fd_open(fd),1);}}
    let a=__hepta_io_read(&mut io,pair.h_left,vec![0;4093],4093,2000);
    let b=__hepta_io_write(&mut io,pair.h_right,vec![0;4093],4093,2000);
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),8186);
    let report=io_test_close(io);assert_eq!((report.h_cancelled,report.h_abandoned),(2,2));
    for &fd in &fds{unsafe{assert_eq!(hepta_io_test_fd_open(fd),0);}}
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),0);drop((a,b));
    let mut io=__hepta_io_reactor(2,1,4093);let pair=io_test_pair(&mut io);
    let fd=io.ports.iter().flatten().next().unwrap().socket.as_raw_fd();
    let ticket=__hepta_io_read(&mut io,pair.h_left,vec![0;4093],4093,2000);
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),4093);
    drop(io);unsafe{assert_eq!(hepta_io_test_fd_open(fd),0);}
    assert_eq!(IO_BUFFER_LIVE.load(Ordering::SeqCst),0);drop(ticket);
    IO_BUFFER_TRACK.store(false,Ordering::SeqCst);

    // Refuse every distinct fixed-metadata allocation in turn. Partial setup
    // allocations are actually freed and the next construction recovers.
    for nth in 1..=3 {
        io_track(nth);
        let io=__hepta_io_reactor(4,8,128);let report=__hepta_io_shutdown(io);
        let observed=io_untrack();
        assert_eq!(report.h_status,IO_ALLOCATION);assert_eq!(observed.0,nth);
        assert_eq!(observed.1,observed.2);assert_eq!(observed.3,0);
    }
    io_track(0);
    let io=__hepta_io_reactor(4,8,128);let report=__hepta_io_shutdown(io);
    let observed=io_untrack();assert_eq!(report.h_status,0);assert_eq!((observed.0,observed.1,observed.2,observed.3),(3,3,3,0));

    // No hidden metadata growth on ordinary submission, ready progression and
    // completion collection: the native allocation entry point observes zero.
    let mut io=__hepta_io_reactor(2,2,16);let pair=io_test_pair(&mut io);
    let input=vec![0;8];let output=vec![31;8];
    io_track(0);
    let a=__hepta_io_read(&mut io,pair.h_left,input,8,2000);
    let b=__hepta_io_write(&mut io,pair.h_right,output,8,2000);
    let mut n=0;let mut status=0;
    let input=__hepta_io_wait(&mut io,a,&mut n,&mut status);assert_eq!((n,status),(8,0));
    let output=__hepta_io_wait(&mut io,b,&mut n,&mut status);assert_eq!((n,status),(8,0));
    let hot=io_untrack();assert_eq!(hot.0,0);assert_eq!(hot.1,0);assert_eq!(hot.3,0);
    assert_eq!(input,vec![31;8]);drop((input,output));io_test_close(io);

    // The production allocator never wraps identifiers. Only this isolated
    // control process writes the counter to reach otherwise impractical edges.
    let before=IO_NEXT_ID.load(Ordering::Relaxed);
    let mut io=__hepta_io_reactor(2,1,8);
    IO_NEXT_ID.store(u64::MAX-1,Ordering::Relaxed);
    assert_eq!(__hepta_io_local_pair(&mut io).h_status,IO_IDENTITIES);
    assert_eq!(io.report.h_open_ports,0);
    IO_NEXT_ID.store(u64::MAX,Ordering::Relaxed);
    let failed=__hepta_io_reactor(2,1,8);assert_eq!(io_test_close(failed).h_status,IO_IDENTITIES);
    io_test_close(io);IO_NEXT_ID.store(before,Ordering::Relaxed);
    let mut io=__hepta_io_reactor(2,1,8);let _pair=io_test_pair(&mut io);io_test_close(io);

    println!("{{\"schema\":\"hepta.io-native-controls.v1\",\"delayed_readiness_cases\":1,\"partial_read_eof_cases\":1,\"broken_peer_cases\":1,\"partial_write_cancel_cases\":1,\"partial_read_cancel_cases\":1,\"delayed_write_readiness_cases\":1,\"ready_before_cancel_cases\":1,\"readiness_cancel_races\":64,\"deadline_interruptions\":5,\"poll_failure_recovery_cases\":1,\"admission_refusal_cases\":5,\"completed_slot_reservation_cases\":1,\"fd_reuse_cases\":1,\"stale_port_cases\":1,\"stale_request_cases\":1,\"foreign_reactor_cases\":1,\"actual_fd_limit_refusals\":1,\"metadata_refusal_sites\":3,\"identifier_exhaustion_cases\":2,\"shutdown_fd_close_cases\":1,\"native_drop_cleanup_cases\":1,\"queued_shutdown_cancellations\":2,\"hot_path_allocations\":{},\"final_tracked_buffer_bytes\":{},\"blocking_elapsed_ns\":{},\"blocking_poll_ns\":{},\"blocking_thread_cpu_ns\":{},\"blocking_real_poll_calls\":{},\"partial_write_bytes\":{},\"final_deadline_poll_millis\":{},\"write_blocking_elapsed_ns\":{},\"write_blocking_poll_ns\":{},\"write_real_poll_calls\":{}}}",
        hot.0,IO_BUFFER_LIVE.load(Ordering::SeqCst),elapsed,blocked,cpu,real_polls,partial,remaining,write_elapsed,write_blocked,write_polls);
}
