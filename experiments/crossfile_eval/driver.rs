// A fixed transport/instrumentation driver. No expected outputs or private
// cases are compiled into it; hidden inputs arrive from the parent on stdin.
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
// Candidate code is an independently compiled dependency crate. It has no
// Rust namespace access to these trusted allocator/control statics.
static TRACK: AtomicUsize = AtomicUsize::new(0);
static REFUSE: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
static REFUSALS: AtomicUsize = AtomicUsize::new(0);
struct ObservedAllocator;
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let tracked = layout.align() == 1 && layout.size() == TRACK.load(Ordering::SeqCst) && layout.size() != 0;
        if tracked && REFUSE.load(Ordering::SeqCst) {
            REFUSALS.fetch_add(1, Ordering::SeqCst);
            return std::ptr::null_mut();
        }
        let pointer = System.alloc(layout);
        if tracked && !pointer.is_null() { ALLOCS.fetch_add(1, Ordering::SeqCst); }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if layout.align() == 1 && layout.size() != 0 && layout.size() == TRACK.load(Ordering::SeqCst) {
            FREES.fetch_add(1, Ordering::SeqCst);
        }
        System.dealloc(pointer, layout);
    }
}
#[global_allocator] static ALLOCATOR: ObservedAllocator = ObservedAllocator;
extern "C" {
    fn cf_threads_reset(); fn cf_threads() -> u64; fn cf_joins() -> u64;
    fn cf_native_reset(); fn cf_c_calls() -> u64; fn cf_cpp_calls() -> u64;
}
fn main() {
    // __TRACK_BUFFER__ is substituted by the trusted evaluator.
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut fields = line.split_whitespace();
        let id: usize = fields.next().unwrap().parse().unwrap();
        let a: i64 = fields.next().unwrap().parse().unwrap();
        let b: i64 = fields.next().unwrap().parse().unwrap();
        let refuse: u8 = fields.next().unwrap().parse().unwrap();
        assert!(fields.next().is_none());
        unsafe { cf_threads_reset(); cf_native_reset(); }
        ALLOCS.store(0, Ordering::SeqCst); FREES.store(0, Ordering::SeqCst); REFUSALS.store(0, Ordering::SeqCst);
        REFUSE.store(refuse != 0, Ordering::SeqCst);
        TRACK.store(if __TRACK_BUFFER__ { a.max(0) as usize } else { 0 }, Ordering::SeqCst);
        let value = cf_submission::evaluate(a, b);
        TRACK.store(0, Ordering::SeqCst); REFUSE.store(false, Ordering::SeqCst);
        println!("{{\"id\":{},\"result\":{},\"allocations\":{},\"frees\":{},\"refusals\":{},\"threads\":{},\"joins\":{},\"c_calls\":{},\"cpp_calls\":{}}}",
                 id, value, ALLOCS.load(Ordering::SeqCst), FREES.load(Ordering::SeqCst), REFUSALS.load(Ordering::SeqCst),
                 unsafe { cf_threads() }, unsafe { cf_joins() }, unsafe { cf_c_calls() }, unsafe { cf_cpp_calls() });
    }
}
