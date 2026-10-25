#![no_std]
#![no_main]

// Original minimal BSP for the QEMU 8.2.2 MPS2 AN386 model. Hardware addresses,
// CPU exception entry, linker layout, barriers and semihosted EXIT are trusted
// boundary code. There is no allocator, OS, external crate, or host-side IRQ
// injection. Hepta supplies the UART and timer register operations.
extern crate hepta_program;
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU32, Ordering};

global_asm!(r#"
    .syntax unified
    .cpu cortex-m4
    .thumb
    .section .vector_table,"a",%progbits
    .long __stack_top
    .long Reset
    .long Default_Handler
    .long Default_Handler
    .long Default_Handler
    .long Default_Handler
    .long Default_Handler
    .long 0,0,0,0
    .long Default_Handler
    .long Default_Handler
    .long 0
    .long Default_Handler
    .long SysTick_Handler
    .rept 8
    .long Default_Handler
    .endr
    .long Timer0_Handler
    .rept 23
    .long Default_Handler
    .endr
    .section .text.Reset,"ax",%progbits
    .global Reset
    .thumb_func
Reset:
    cpsid i
    ldr r0, =__data_load
    ldr r1, =__data_start
    ldr r2, =__data_end
1:
    cmp r1, r2
    bhs 2f
    ldr r3, [r0], #4
    str r3, [r1], #4
    b 1b
2:
    ldr r1, =__bss_start
    ldr r2, =__bss_end
    movs r3, #0
3:
    cmp r1, r2
    bhs 4f
    str r3, [r1], #4
    b 3b
4:
    bl board_main
    b .
"#);

// Keep a genuinely writable externally visible .data word. A private unused
// store target can be folded to an immediate and would not exercise copying.
#[used]
#[no_mangle]
pub static DATA_MARKER: AtomicU32 = AtomicU32::new(0x1357_9bdf);
static IRQ_COUNT: AtomicU32 = AtomicU32::new(0);
static CHECKSUM: AtomicU32 = AtomicU32::new(0);
static WATCHDOG: AtomicU32 = AtomicU32::new(0);
static BAD_IRQ: AtomicU32 = AtomicU32::new(0);

fn uart() -> *mut u32 { core::ptr::without_provenance_mut(0x4000_4000) }
fn timer() -> *mut u32 { core::ptr::without_provenance_mut(0x4000_0000) }

// Only the non-Rust-allocation peripheral register addresses in board.json are
// passed here; all are aligned u32 registers with valid integer bit patterns.
unsafe fn register_write(address: usize, value: u32) {
    core::ptr::write_volatile(core::ptr::without_provenance_mut(address), value);
}

fn exit(code: u32) -> ! {
    // ARM semihosting SYS_EXIT_EXTENDED: reason ADP_Stopped_ApplicationExit.
    // No semihosted file, network, input, or output services are used.
    let parameters = [0x20026u32, code];
    unsafe { asm!("bkpt 0xab", in("r0") 0x20u32, in("r1") parameters.as_ptr()); }
    loop { core::hint::spin_loop(); }
}

fn put(bytes: &[u8]) {
    for byte in bytes {
        if unsafe { hepta_program::h_uart_putc(uart(), *byte) } != 1 { exit(90); }
    }
}
fn decimal(mut value: u32) {
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 { break; }
    }
    put(&digits[start..]);
}
fn finish(code: u32, data: u32, stopped: bool) -> ! {
    unsafe { asm!("cpsid i", options(nomem, nostack, preserves_flags)); }
    put(b"HEPTA_BOARD {\"status\":\"");
    put(if code == 0 { b"passed" } else { b"rejected" });
    put(b"\",\"code\":"); decimal(code);
    put(b",\"data_marker\":"); decimal(data);
    put(b",\"irq_count\":"); decimal(IRQ_COUNT.load(Ordering::SeqCst));
    put(b",\"checksum\":"); decimal(CHECKSUM.load(Ordering::SeqCst));
    put(b",\"watchdog_ticks\":"); decimal(WATCHDOG.load(Ordering::SeqCst));
    put(b",\"bad_irq\":"); decimal(BAD_IRQ.load(Ordering::SeqCst));
    put(b",\"timer_stopped\":"); put(if stopped { b"true" } else { b"false" });
    put(b"}\n");
    // UART TX must drain before QEMU exits; observation uses the device output.
    unsafe {
        let mut spins = 0u32;
        while core::ptr::read_volatile(uart().wrapping_add(1)) & 1 != 0 {
            spins += 1;
            if spins == 1_000_000 { exit(91); }
        }
    }
    exit(code)
}

#[no_mangle]
pub extern "C" fn Timer0_Handler() {
    let ordinal = IRQ_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    let value = unsafe { hepta_program::h_timer_irq(timer(), ordinal) };
    if value == 0 || ordinal > 5 { BAD_IRQ.fetch_add(1, Ordering::SeqCst); }
    CHECKSUM.fetch_add(value, Ordering::SeqCst);
}
#[no_mangle]
pub extern "C" fn SysTick_Handler() { WATCHDOG.fetch_add(1, Ordering::SeqCst); }
#[no_mangle]
pub extern "C" fn Default_Handler() -> ! { exit(92) }
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { exit(93) }

#[no_mangle]
pub extern "C" fn board_main() -> ! {
    unsafe { hepta_program::h_uart_init(uart()); }
    let data = DATA_MARKER.load(Ordering::SeqCst);
    if data != 0x1357_9bdf || IRQ_COUNT.load(Ordering::SeqCst) != 0
        || CHECKSUM.load(Ordering::SeqCst) != 0 || WATCHDOG.load(Ordering::SeqCst) != 0
        || BAD_IRQ.load(Ordering::SeqCst) != 0 { finish(41, data, false); }
    unsafe {
        register_write(0xe000_ed08, 0); // VTOR: vector table at FLASH start.
        register_write(0xe000_e280, 1 << 8); // NVIC: clear timer0 pending.
        if !cfg!(disable_timer_irq) { register_write(0xe000_e100, 1 << 8); }
        register_write(0xe000_e014, 24999); // SysTick 25 MHz / 25000 = 1 kHz.
        register_write(0xe000_e018, 0);
        register_write(0xe000_e010, 7);
        hepta_program::h_timer_start(timer());
        asm!("dsb", "isb", "cpsie i", options(nostack, preserves_flags));
    }
    while IRQ_COUNT.load(Ordering::SeqCst) < 5 && WATCHDOG.load(Ordering::SeqCst) < 20 {
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)); }
    }
    unsafe {
        asm!("cpsid i", options(nomem, nostack, preserves_flags));
        register_write(0xe000_e010, 0);
        register_write(0xe000_e180, 1 << 8);
        asm!("dsb", "isb", options(nostack, preserves_flags));
    }
    let stopped = unsafe { hepta_program::h_timer_stopped(timer()) } == 1;
    let code = if IRQ_COUNT.load(Ordering::SeqCst) != 5 { 42 }
        else if CHECKSUM.load(Ordering::SeqCst) != 55 || BAD_IRQ.load(Ordering::SeqCst) != 0 { 43 }
        else if !stopped { 44 } else { 0 };
    finish(code, data, stopped)
}
