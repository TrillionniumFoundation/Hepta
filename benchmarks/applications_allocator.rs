// Shared benchmark instrumentation only. Appended unchanged to both Rust
// library builds. Production Hepta binaries do not install this allocator.
mod application_instrumentation {
    use std::alloc::{GlobalAlloc,Layout};
    extern "C" {
        fn app_measure_alloc(size:usize,alignment:usize,zeroed:i32)->*mut u8;
        fn app_measure_dealloc(pointer:*mut u8);
        fn app_measure_realloc(pointer:*mut u8,size:usize,alignment:usize)->*mut u8;
    }
    struct Measured;
    unsafe impl GlobalAlloc for Measured {
        unsafe fn alloc(&self,layout:Layout)->*mut u8{app_measure_alloc(layout.size(),layout.align(),0)}
        unsafe fn alloc_zeroed(&self,layout:Layout)->*mut u8{app_measure_alloc(layout.size(),layout.align(),1)}
        unsafe fn dealloc(&self,pointer:*mut u8,_:Layout){app_measure_dealloc(pointer)}
        unsafe fn realloc(&self,pointer:*mut u8,layout:Layout,size:usize)->*mut u8{
            app_measure_realloc(pointer,size,layout.align())
        }
    }
    #[global_allocator] static MEASURED:Measured=Measured;
}
