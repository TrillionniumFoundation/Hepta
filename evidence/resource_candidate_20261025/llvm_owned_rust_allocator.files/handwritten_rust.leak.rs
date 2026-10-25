// Independent handwritten Rust baseline. The resource implementation uses
// safe Vec/slice operations; no Hepta-generated Rust is included here.
struct OwnedBytes { data: Vec<u8> }

fn try_bytes(size: usize) -> Result<Vec<u8>, u8> {
    let mut data = Vec::new();
    data.try_reserve_exact(size).map_err(|_| 1u8)?;
    data.resize(size, 0);
    Ok(data)
}

impl OwnedBytes {
    fn new(size: usize, reject: bool) -> Result<Self, u8> {
        let data = try_bytes(size)?;
        if reject { drop(data); Err(2) } else { Ok(Self { data }) }
    }
    fn view(&self) -> &[u8] { &self.data }
}

fn forward<T>(value: T) -> T { value }

#[no_mangle]
pub extern "C" fn full_lifecycle(size: usize, seed: u32) -> u64 {
    let mut owner = match OwnedBytes::new(size, false) {
        Err(code) => return 1000 + u64::from(code), Ok(value) => value,
    };
    for (index, byte) in owner.data.iter_mut().enumerate() {
        *byte = (index as u32).wrapping_add(seed) as u8;
    }
    let moved = forward(owner);
    let checksum = moved.view().iter().map(|&byte| u64::from(byte)).sum();
    drop(moved);
    checksum
}

#[no_mangle]
pub extern "C" fn constructor_error(size: usize, seed: u32) -> u64 {
    match OwnedBytes::new(size, true) {
        Err(code) => 1000 + u64::from(code) + u64::from(seed),
        Ok(unexpected) => { drop(unexpected); 9000 },
    }
}

#[no_mangle]
pub extern "C" fn two_stage(size: usize, seed: u32) -> u64 {
    let mut first = match OwnedBytes::new(size, false) {
        Err(code) => return 1000 + u64::from(code), Ok(value) => value,
    };
    first.data.fill(seed as u8);
    let mut second = match try_bytes(size + 17) {
        Err(code) => { drop(first); return 1000 + u64::from(code); },
        Ok(value) => value,
    };
    for (destination, &source) in second.iter_mut().zip(first.view()) {
        *destination = source ^ 90;
    }
    let checksum = second.iter().map(|&byte| u64::from(byte)).sum();
    drop(second);
    drop(first);
    checksum
}

#[no_mangle]
pub extern "C" fn two_alloc(second: usize, refuse: u32) -> u64 {
    let mut first = match try_bytes(7) {
        Err(code) => return 100 + u64::from(code), Ok(value) => value,
    };
    first[0] = 19;
    let moved = match try_bytes(second) {
        Err(code) => { drop(first); return u64::from(code); }, Ok(value) => forward(value),
    };
    if refuse != 0 { drop(moved); drop(first); return 2; }
    let result = moved.len() as u64 + u64::from(first[0]);
    drop(moved);
    drop(first);
    result
}

// Appended to an unchanged Rust baseline solely for untimed observation.
// The allocator is measurement infrastructure, not application code. Counts
// are observations: the producer must fail if optimization removes calls.
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

const HEPTA_OBSERVER_BACKEND: &str = "handwritten_rust";
const HEPTA_OBSERVER_LEAK: bool = true;
struct HeptaObservedAllocator;
static HEPTA_TRACKING: AtomicBool = AtomicBool::new(false);
static HEPTA_REFUSE_SIZE: AtomicUsize = AtomicUsize::new(0);
static HEPTA_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static HEPTA_FREES: AtomicUsize = AtomicUsize::new(0);
static HEPTA_LIVE: AtomicIsize = AtomicIsize::new(0);
static HEPTA_REFUSALS: AtomicUsize = AtomicUsize::new(0);
static HEPTA_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static HEPTA_SYSTEM_REFUSALS: AtomicUsize = AtomicUsize::new(0);

unsafe impl std::alloc::GlobalAlloc for HeptaObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let tracking = HEPTA_TRACKING.load(Ordering::SeqCst);
        if tracking {
            HEPTA_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
            if layout.size() == HEPTA_REFUSE_SIZE.load(Ordering::SeqCst) {
                HEPTA_REFUSALS.fetch_add(1, Ordering::SeqCst);
                return core::ptr::null_mut();
            }
        }
        let pointer = std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout);
        if tracking {
            if pointer.is_null() {
                HEPTA_SYSTEM_REFUSALS.fetch_add(1, Ordering::SeqCst);
            } else {
                HEPTA_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
                HEPTA_LIVE.fetch_add(1, Ordering::SeqCst);
            }
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        let tracking = HEPTA_TRACKING.load(Ordering::SeqCst);
        // Deliberately compiled negative control: omit actual System release.
        // Application source and its Drop calls remain unchanged.
        if tracking && HEPTA_OBSERVER_LEAK { return; }
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout);
        if tracking {
            HEPTA_FREES.fetch_add(1, Ordering::SeqCst);
            HEPTA_LIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[global_allocator]
static HEPTA_ALLOCATOR: HeptaObservedAllocator = HeptaObservedAllocator;

// Use the same public scalar C symbol on both baselines. Generated Rust uses
// an internal h_two_alloc identifier with export_name="two_alloc"; the
// observer must not rewrite that application or depend on its private name.
extern "C" {
    #[link_name = "two_alloc"]
    fn hepta_observer_export(second: usize, refuse: u32) -> u64;
}

fn hepta_observer_call(second: usize, refuse: u32) -> u64 {
    // This declaration is linked to the unchanged definition in this crate.
    unsafe { hepta_observer_export(second, refuse) }
}

fn hepta_observe(phase: &str, actual: &[u64], expected: &[u64], allocations: usize,
                 refusals: usize) -> bool {
    // Tracking is disabled before formatting or printing. Rust startup and
    // observation-output allocations are outside the application denominator.
    let allocated = HEPTA_ALLOCATIONS.load(Ordering::SeqCst);
    let freed = HEPTA_FREES.load(Ordering::SeqCst);
    let live = HEPTA_LIVE.load(Ordering::SeqCst);
    let refused = HEPTA_REFUSALS.load(Ordering::SeqCst);
    let attempts = HEPTA_ATTEMPTS.load(Ordering::SeqCst);
    let system_refusals = HEPTA_SYSTEM_REFUSALS.load(Ordering::SeqCst);
    let ok = actual == expected && allocated == allocations && freed == allocations
        && live == 0 && refused == refusals && attempts == allocations + refusals
        && system_refusals == 0;
    println!("{{\"backend\":\"{}\",\"negative_control\":{},\"phase\":\"{}\",\"calls\":{:?},\"allocations\":{},\"frees\":{},\"live\":{},\"refusals\":{},\"attempts\":{},\"system_refusals\":{},\"ok\":{}}}",
        HEPTA_OBSERVER_BACKEND, HEPTA_OBSERVER_LEAK, phase, actual, allocated,
        freed, live, refused, attempts, system_refusals, ok);
    ok
}

fn main() {
    HEPTA_TRACKING.store(true, Ordering::SeqCst);
    let first = [hepta_observer_call(3, 0), hepta_observer_call(5, 1), hepta_observer_call(0, 0)];
    HEPTA_REFUSE_SIZE.store(12281, Ordering::SeqCst);
    let refused = hepta_observer_call(12281, 0);
    let capacity = hepta_observer_call(usize::MAX, 0);
    HEPTA_TRACKING.store(false, Ordering::SeqCst);
    if !hepta_observe("fixed_five", &[first[0], first[1], first[2], refused, capacity],
                       &[22, 2, 19, 1, 1], 7, 1) {
        std::process::exit(86);
    }
    // A leak control that unexpectedly passes is also a qualification failure.
    if HEPTA_OBSERVER_LEAK { std::process::exit(87); }

    HEPTA_REFUSE_SIZE.store(0, Ordering::SeqCst);
    HEPTA_TRACKING.store(true, Ordering::SeqCst);
    let recovered = hepta_observer_call(3, 0);
    HEPTA_TRACKING.store(false, Ordering::SeqCst);
    if !hepta_observe("second_refusal_recovery", &[recovered], &[22], 9, 1) {
        std::process::exit(86);
    }

    // Reset only after all previous tracked owners have been released.
    HEPTA_ALLOCATIONS.store(0, Ordering::SeqCst);
    HEPTA_FREES.store(0, Ordering::SeqCst);
    HEPTA_REFUSALS.store(0, Ordering::SeqCst);
    HEPTA_ATTEMPTS.store(0, Ordering::SeqCst);
    HEPTA_SYSTEM_REFUSALS.store(0, Ordering::SeqCst);
    HEPTA_REFUSE_SIZE.store(7, Ordering::SeqCst);
    HEPTA_TRACKING.store(true, Ordering::SeqCst);
    let first_refused = hepta_observer_call(3, 0);
    HEPTA_TRACKING.store(false, Ordering::SeqCst);
    if !hepta_observe("first_refusal", &[first_refused], &[101], 0, 1) {
        std::process::exit(86);
    }

    HEPTA_REFUSE_SIZE.store(0, Ordering::SeqCst);
    HEPTA_TRACKING.store(true, Ordering::SeqCst);
    let first_recovered = hepta_observer_call(3, 0);
    HEPTA_TRACKING.store(false, Ordering::SeqCst);
    if !hepta_observe("first_refusal_recovery", &[first_recovered], &[22], 2, 1) {
        std::process::exit(86);
    }
}
