// Appended only to the Rust differential reference, never LLVM/C codegen.
struct LocalViewAllocator;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
static LV_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static LV_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static LV_RELEASES: AtomicUsize = AtomicUsize::new(0);
static LV_REFUSALS: AtomicUsize = AtomicUsize::new(0);
static LV_REJECT: AtomicUsize = AtomicUsize::new(0);
static LV_LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for LocalViewAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let attempt = LV_ATTEMPTS.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == LV_REJECT.load(Ordering::SeqCst) {
            LV_REFUSALS.fetch_add(1, Ordering::SeqCst); return core::ptr::null_mut();
        }
        let pointer = std::alloc::System.alloc(layout);
        if !pointer.is_null() {
            LV_ALLOCATIONS.fetch_add(1, Ordering::SeqCst); LV_LIVE.fetch_add(1, Ordering::SeqCst);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(pointer, layout);
        LV_RELEASES.fetch_add(1, Ordering::SeqCst); LV_LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}
#[global_allocator] static LOCAL_VIEW_ALLOCATOR: LocalViewAllocator = LocalViewAllocator;
#[no_mangle] pub extern "C" fn lv_reset(reject: usize) {
    assert_eq!(LV_LIVE.load(Ordering::SeqCst), 0);
    LV_ATTEMPTS.store(0, Ordering::SeqCst); LV_ALLOCATIONS.store(0, Ordering::SeqCst);
    LV_RELEASES.store(0, Ordering::SeqCst); LV_REFUSALS.store(0, Ordering::SeqCst);
    LV_REJECT.store(reject, Ordering::SeqCst);
}
#[no_mangle] pub extern "C" fn lv_attempts() -> usize { LV_ATTEMPTS.load(Ordering::SeqCst) }
#[no_mangle] pub extern "C" fn lv_allocations() -> usize { LV_ALLOCATIONS.load(Ordering::SeqCst) }
#[no_mangle] pub extern "C" fn lv_releases() -> usize { LV_RELEASES.load(Ordering::SeqCst) }
#[no_mangle] pub extern "C" fn lv_refusals() -> usize { LV_REFUSALS.load(Ordering::SeqCst) }
#[no_mangle] pub extern "C" fn lv_live() -> isize { LV_LIVE.load(Ordering::SeqCst) }
