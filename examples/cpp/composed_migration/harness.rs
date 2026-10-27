use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, AtomicU64, Ordering};
struct ObservedAllocator;
static TRACKING: AtomicBool = AtomicBool::new(false);
static REFUSE_AT: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);
static REFUSALS: AtomicUsize = AtomicUsize::new(0);
static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static TRACE: AtomicU64 = AtomicU64::new(0);
static POINTERS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
static SIZES: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

fn observe_word(mut state: u64, word: u64) -> u64 {
    for shift in (0..64).step_by(8) { state ^= (word >> shift) & 255; state = state.wrapping_mul(1099511628211); }
    state
}
fn observe_event(kind: u64, identity: usize, size: usize) {
    TRACE.store(observe_word(observe_word(observe_word(TRACE.load(Ordering::SeqCst), kind), identity as u64), size as u64), Ordering::SeqCst);
}
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if TRACKING.load(Ordering::SeqCst) {
            let attempt = ATTEMPTS.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == REFUSE_AT.load(Ordering::SeqCst) {
                REFUSALS.fetch_add(1, Ordering::SeqCst); observe_event(3, attempt, layout.size());
                return core::ptr::null_mut();
            }
        }
        let pointer = std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout);
        if TRACKING.load(Ordering::SeqCst) && !pointer.is_null() {
            let position = ALLOCATED.fetch_add(1, Ordering::SeqCst);
            if position >= 8 { std::process::abort(); }
            POINTERS[position].store(pointer as usize, Ordering::SeqCst);
            SIZES[position].store(layout.size(), Ordering::SeqCst);
            LIVE.fetch_add(1, Ordering::SeqCst); observe_event(1, position + 1, layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        if TRACKING.load(Ordering::SeqCst) {
            let mut found = false;
            for i in 0..ALLOCATED.load(Ordering::SeqCst) {
                if POINTERS[i].load(Ordering::SeqCst) == pointer as usize {
                    POINTERS[i].store(0, Ordering::SeqCst);
                    FREED.fetch_add(1, Ordering::SeqCst); LIVE.fetch_sub(1, Ordering::SeqCst);
                    observe_event(2, i + 1, SIZES[i].load(Ordering::SeqCst)); found = true; break;
                }
            }
            if !found { std::process::abort(); }
        }
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout);
    }
}
#[global_allocator]
static OBSERVER: ObservedAllocator = ObservedAllocator;

fn main() {
    let mut digest = 14695981039346656037u64;
    let (mut total_allocations, mut total_frees, mut total_refusals) = (0usize, 0usize, 0usize);
    for (index, current) in COMPOSED_CASES.iter().enumerate() {
        for item in [&ALLOCATED, &FREED, &REFUSALS, &ATTEMPTS] { item.store(0, Ordering::SeqCst); }
        LIVE.store(0, Ordering::SeqCst); TRACE.store(14695981039346656037, Ordering::SeqCst);
        for i in 0..8 { POINTERS[i].store(0, Ordering::SeqCst); SIZES[i].store(0, Ordering::SeqCst); }
        REFUSE_AT.store(current.6, Ordering::SeqCst); TRACKING.store(true, Ordering::SeqCst);
        let actual = h_composed_case(current.0, current.1, current.2, current.3, current.4, current.5);
        TRACKING.store(false, Ordering::SeqCst);
        let allocated = ALLOCATED.load(Ordering::SeqCst); let freed = FREED.load(Ordering::SeqCst);
        let refusals = REFUSALS.load(Ordering::SeqCst); let attempts = ATTEMPTS.load(Ordering::SeqCst);
        let live = LIVE.load(Ordering::SeqCst); let trace = TRACE.load(Ordering::SeqCst);
        if actual != current.7 {
            println!("{{\"ok\":false,\"failure\":\"value\",\"case\":{},\"expected\":{},\"actual\":{}}}", index, current.7, actual);
            std::process::exit(2);
        }
        if allocated != current.8 || freed != current.8 || refusals != current.9 || attempts != current.8 + current.9 || live != 0 || trace != current.10 {
            println!("{{\"ok\":false,\"failure\":\"lifecycle\",\"case\":{},\"allocated\":{},\"freed\":{},\"live\":{},\"refusals\":{},\"trace\":\"{:016x}\",\"expected_trace\":\"{:016x}\"}}", index, allocated, freed, live, refusals, trace, current.10);
            std::process::exit(3);
        }
        total_allocations += allocated; total_frees += freed; total_refusals += refusals;
        for value in [index as u64, actual, trace, allocated as u64, freed as u64, refusals as u64] { digest = observe_word(digest, value); }
    }
    println!("{{\"ok\":true,\"cases\":{},\"observations_fnv64\":\"{:016x}\",\"allocations\":{},\"frees\":{},\"refusals\":{},\"live\":0}}", COMPOSED_CASES.len(), digest, total_allocations, total_frees, total_refusals);
}
