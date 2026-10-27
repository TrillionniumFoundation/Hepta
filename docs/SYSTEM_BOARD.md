# Volatile access and an executable Cortex-M4 board profile

This increment executes a real linked `thumbv7em-none-eabi` image in the QEMU
8.2.2 **system** model `mps2-an386`. It advances board bring-up beyond building an
object or running a Linux process under user-mode emulation. It does not qualify
a physical board, DMA, GPU, device timing, or a general interrupt ownership model.

## Language surface and external contract

```hepta
export "C" fn acknowledge(timer: raw mut u32) -> Unit
effects {unsafe, io, write}
resources {heap_allocations=0; may_block=false; may_suspend=false; may_spawn=false;}
{
    unsafe { volatile_store(timer, 3, 1); }
}
```

`volatile_load(pointer, index)` and `volatile_store(pointer, index, value)` take an
element index. Both require an `unsafe` block and the `unsafe, io` effects; store
also requires `write` and a mutable raw pointer. The admitted element types are
the fixed-width signed/unsigned integers through 64 bits and `usize/isize`.
Boolean, floating point, 128-bit and aggregate registers are rejected. The
caller must establish that the particular target and device support the chosen
width and alignment; the frontend does not infer that every admitted width is a
single bus transaction on every processor.

The Rust backend emits `core::ptr::{read_volatile,write_volatile}` with
`wrapping_add` for pointer calculation. It does not impose Rust's in-allocation
`add` precondition on an externally supplied MMIO address. For ordinary allocated
memory, normal validity, initialization, aliasing and provenance obligations
still apply. For memory outside Rust allocations, the caller supplies the actual
hardware mapping, access width/alignment, valid value representation and a
nontrapping device access with the conditions documented by Rust's volatile API.
Hepta does not introduce an integer-to-pointer cast or treat arbitrary integers
as safe device capabilities.

The C backend emits an explicitly volatile, correctly qualified element access.
Its execution test uses valid allocated register arrays under GCC/UBSan. This
does not qualify portable C MMIO semantics or a C freestanding board backend;
`--backend c --no-std` is still rejected.

Volatile access is not an atomic operation, a CPU/device fence, cache maintenance,
DMA buffer handoff, lifetime proof or concurrent synchronization. A target may
also split a wide access into multiple instructions. This profile uses 32-bit
registers. The BSP supplies explicit CPU barriers and uses Rust atomic variables
for communication between the ISR and main code. It does not share ordinary
mutable RAM through volatile accesses.

HSIR and the descriptive CFG retain each operation, type, source span and its
undischarged obligations in `volatile_accesses`. These descriptive exports do not
upgrade any proof claims. The independent resource/concurrent IR verifiers reject
this raw-pointer/foreign board profile.

`io` describes an observable effect, not a dependency on the hosted standard
library. A `no_std` library may use these operations or explicit BSP foreign
calls. Hosted printing, allocation, task runtimes and hosted I/O reactors retain
their own rejection checks. Bare-metal `--crate-type bin` is not a general Hepta
entrypoint: the explicit BSP links a Hepta `no_std` library.

## Public Rust ABI obligation preservation

An exported or `pub` Hepta function declaring `unsafe` or `ffi` now generates a
Rust `pub unsafe fn` (with `extern "C"` when applicable). Its C ABI is unchanged.
This matters when a Rust application consumes the generated `rlib`: a safe Rust
signature must not hide caller-side raw-memory or foreign-library obligations.
Tests compile a valid-array consumer without an unsafe block and require Rust
`E0133`; only the explicitly acknowledged valid-array caller is executed. A
binary's private generated process-entry shim acknowledges its source program's
unsafe root. It does not create a reusable safe exported wrapper.

## Actual board execution

Files are in `examples/boards/mps2_an386/`:

| File | Executed responsibility |
| --- | --- |
| `kernel.hepta` | UART setup/output, timer configuration, pending-bit read, IRQ acknowledgement, stop after five events, checksum |
| `startup.rs` | Vector table, reset assembly, data copy, BSS zeroing, exception entry, atomics, watchdog, independent result oracle and semihosted exit |
| `link.ld` | FLASH/RAM layout, stack, load/run addresses and section assertions |
| `board.json` | Fixed board/model/target, register map, source references and explicit external assumptions |

QEMU loads the ELF and the Cortex-M4 follows its reset vector. The reset code
copies a nonempty `.data` segment and zeros `.bss`. A public, retained atomic
canary prevents the compiler from replacing the data-copy check with a constant.
ELF validation independently requires the actual RAM canary and its FLASH load
segment. The ordinary BSS zero state is checked; this is not a claim that all
possible power-on RAM patterns have been explored.

Hepta configures the CMSDK APB timer at `0x40000000`. NVIC IRQ 8 reaches vector
slot 24 and calls the generated Hepta handler, which reads and acknowledges the
peripheral pending bit. After five timer interrupts, the Hepta code disables the
timer. The expected independent checksum is `1²+2²+3²+4²+5²=55`. A separate
SysTick watchdog makes a missing external IRQ terminate with a specific failure
instead of allowing an unfinished execution to count as success.

The observed JSON is transmitted by the emulated CMSDK UART at `0x40004000` using
Hepta's volatile stores. It is not host-generated output. Semihosting is used
only for `SYS_EXIT_EXTENDED`; the guest performs no semihosted file/network/input
operations. The native model's disconnected NIC warning is retained.

Qualification builds four distinct ARM ELF images and executes six cold boots:

| Compiled case | Runs | Required result |
| --- | ---: | --- |
| Correct source/BSP | 3 | Exit 0; actual data marker; five IRQs; checksum 55; timer stopped and acknowledged |
| Wrong Hepta IRQ calculation | 1 | Exit 43; five IRQs; observed checksum 60 |
| NVIC IRQ not enabled | 1 | Exit 42; zero external IRQs; 20 SysTick watchdog events |
| Reset data copy replaced with clearing | 1 | Exit 41; actual RAM data marker observed as zero |

The report retains complete ELF bytes as bounded base64, parsed sections,
symbols, all 48 vector entries, source/generated-code identities, native library
builds, link commands, device transcripts and negative-control exit codes. Its
validator reparses the retained ELF and binds summaries to raw observations. It
is not a signature or an independent proof of compiler correctness.

## Reproduce

Install the repository's pinned Rust 1.90.0 toolchain with the
`thumbv7em-none-eabi` target, and the QEMU 8.2.2 `qemu-system-arm` executable.

```sh
python tools/validate_board.py --output artifacts/system-board.json
python -m unittest tests.test_volatile tests.test_system_board
```

Missing QEMU, a different model version, target libraries, native compilation or
execution failures are failures. There is no object-only or skipped-test pass.

## Primary references

- [QEMU 8.2.2 MPS2 machine and memory map](https://github.com/qemu/qemu/blob/v8.2.2/hw/arm/mps2.c).
- [QEMU 8.2.2 CMSDK UART model](https://github.com/qemu/qemu/blob/v8.2.2/hw/char/cmsdk-apb-uart.c).
- [QEMU 8.2.2 CMSDK timer model](https://github.com/qemu/qemu/blob/v8.2.2/hw/timer/cmsdk-apb-timer.c).
- [ARM CMSIS 5.9.0 Cortex-M4 core register definitions](https://github.com/ARM-software/CMSIS_5/blob/5.9.0/CMSIS/Core/Include/core_cm4.h).
- [Rust volatile read contract](https://doc.rust-lang.org/core/ptr/fn.read_volatile.html) and [write contract](https://doc.rust-lang.org/core/ptr/fn.write_volatile.html).

The example is original BSP code; it does not vendor the emulator implementation.
