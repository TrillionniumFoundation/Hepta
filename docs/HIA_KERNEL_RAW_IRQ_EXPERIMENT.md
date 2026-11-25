# Experimental raw CPL0 integer interrupt entry

The isolated selfhost kernel profile adds a terminal operation
`x86.irq.dispatch_kernel_frame()` with effects privilege, read, write and trap.
It admits only a single exported zero-argument, zero-result function with one
block, one operation and trap-user terminator. The ELF export starts directly
with fifteen GPR pushes, before any ordinary function prologue. Hardware supplies
the five-word no-error-code long-mode frame. The experimental contract requires
a caller-owned CPL0 interrupt gate, mapped aligned low-half stack, CS=0x18,
SS=0x10 and a caller-owned per-CPU GS_BASE descriptor containing a SysV callback
pointer. It validates the original 160-byte frame and live IF/segments before
reading the descriptor; the callback receives the frame and returns a selected
frame. The existing guarded native integer restore validates that frame and
executes real IRETQ. The emitter is part of the native compiler, not a linked
assembly entry stub. GNU as is used independently to verify emitted bytes.

Local isolated parent-native reconstruction used #959 exact compiler, two
empty-PATH self-rebuilds, twenty malformed source refusals and twenty independent
PC/Q35 hardware-model cases. The observer installs an IDT gate directly to the
ELF export, executes actual INT with two different register/flags patterns,
checks every GPR in the saved frame and on return, and deliberately clobbers
caller-saved registers in the callback. Null descriptor, null/high callback,
live IF, forbidden saved DF, null returned frame, wrong R15 save and deleted
IRETQ are independent negative controls. Previous initial local candidate
without the pre-dispatch guard passed sixteen cases; the final candidate adds
the guard and two cases on both platforms. A preliminary local rebuild command
failed because its output executable path was relative; the failure is retained,
and the final run used an absolute path. This is not an external APIC interrupt
or arbitrary task/CPU, exception error-code, user entry, FPU/SIMD, GS ownership,
callback authority, or production scheduler proof. No production lock or
full-acceptance gate changes. The prior tests remain enabled.
