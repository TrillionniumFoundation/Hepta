use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
struct ObservedAllocator;
static OBSERVED_TRACKING: AtomicBool = AtomicBool::new(false);
static OBSERVED_REFUSE: AtomicBool = AtomicBool::new(false);
static OBSERVED_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_FREED: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_REFUSALS: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if OBSERVED_TRACKING.load(Ordering::SeqCst) {
            OBSERVED_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
            if OBSERVED_REFUSE.load(Ordering::SeqCst) {
                OBSERVED_REFUSALS.fetch_add(1, Ordering::SeqCst);
                return core::ptr::null_mut();
            }
        }
        let pointer = std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout);
        if OBSERVED_TRACKING.load(Ordering::SeqCst) && !pointer.is_null() {
            OBSERVED_ALLOCATED.fetch_add(1, Ordering::SeqCst);
            OBSERVED_LIVE.fetch_add(1, Ordering::SeqCst);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        if OBSERVED_TRACKING.load(Ordering::SeqCst) {
            OBSERVED_FREED.fetch_add(1, Ordering::SeqCst);
            OBSERVED_LIVE.fetch_sub(1, Ordering::SeqCst);
        }
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout);
    }
}
#[global_allocator]
static OBSERVED_ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observe_word(mut state: u64, word: u64) -> u64 {
    for shift in (0..64).step_by(8) {
        state ^= (word >> shift) & 255;
        state = state.wrapping_mul(1099511628211);
    }
    state
}

fn main() {
    let mut digest = 14695981039346656037u64;
    let (mut total_allocations, mut total_frees, mut total_refusals) = (0usize, 0usize, 0usize);
    for (index, current) in OWNED_CASES.iter().enumerate() {
        OBSERVED_ALLOCATED.store(0, Ordering::SeqCst);
        OBSERVED_FREED.store(0, Ordering::SeqCst);
        OBSERVED_REFUSALS.store(0, Ordering::SeqCst);
        OBSERVED_ATTEMPTS.store(0, Ordering::SeqCst);
        OBSERVED_LIVE.store(0, Ordering::SeqCst);
        OBSERVED_REFUSE.store(current.5 != 0, Ordering::SeqCst);
        OBSERVED_TRACKING.store(true, Ordering::SeqCst);
        let actual = h_owned_case(current.0, current.1, current.2, current.3, current.4);
        OBSERVED_TRACKING.store(false, Ordering::SeqCst);
        let allocated = OBSERVED_ALLOCATED.load(Ordering::SeqCst);
        let freed = OBSERVED_FREED.load(Ordering::SeqCst);
        let refusals = OBSERVED_REFUSALS.load(Ordering::SeqCst);
        let attempts = OBSERVED_ATTEMPTS.load(Ordering::SeqCst);
        let live = OBSERVED_LIVE.load(Ordering::SeqCst);
        if actual != current.6 {
            println!("{{\"ok\":false,\"failure\":\"value\",\"case\":{},\"expected\":{},\"actual\":{}}}", index, current.6, actual);
            std::process::exit(2);
        }
        if allocated != current.7 || freed != current.7 || live != 0 || refusals != current.8 || attempts != current.7 + current.8 {
            println!("{{\"ok\":false,\"failure\":\"lifecycle\",\"case\":{},\"allocated\":{},\"freed\":{},\"live\":{},\"refusals\":{},\"attempts\":{}}}", index, allocated, freed, live, refusals, attempts);
            std::process::exit(3);
        }
        total_allocations += allocated;
        total_frees += freed;
        total_refusals += refusals;
        for value in [index as u64, actual, allocated as u64, freed as u64, refusals as u64] {
            digest = observe_word(digest, value);
        }
    }
    println!("{{\"ok\":true,\"cases\":{},\"observations_fnv64\":\"{:016x}\",\"allocations\":{},\"frees\":{},\"refusals\":{},\"live\":0}}", OWNED_CASES.len(), digest, total_allocations, total_frees, total_refusals);
}
