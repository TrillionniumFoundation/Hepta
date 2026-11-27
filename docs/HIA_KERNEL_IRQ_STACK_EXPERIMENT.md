# Experimental native raw IRQ scheduler stack (HOLD)

The isolated kernel profile adds terminal x86.irq.dispatch_on_stack() with
explicit privilege, atomic, read, write and trap effects. The previous
dispatch_kernel_frame operation and byte-level qualification remain unchanged.
The new operation admits exactly one exported zero-argument/zero-result
function, one block, one operation and trap-user terminator. Native code saves
all fifteen GPRs on the interrupted task stack, validates its hardware frame
and reads a caller-owned GS_BASE descriptor (callback, lower bound, top, busy
word; four u64s). It requires a mapped low-half aligned fixed 16 KiB scheduler
stack disjoint from the descriptor and original 160-byte frame; acquires the
busy word by locked CAS, checks a 512-byte bottom canary, and switches actual
RSP before calling the callback. The callback receives the original frame,
must honor SysV callee-saved registers, and must not mutate the descriptor or
enable interrupts. Native code rejects a returned frame inside the transient
stack/descriptor, rechecks RSP, descriptor, canary, selected frame and live
IF/segments while the lease is held, releases by locked CAS, and executes the
terminal pop/IRETQ tail directly without stack use after release. Invalid and
partially committed paths trap, not retry.

Local #960-parent compilation and two empty-PATH self-rebuilds produced
compiler 434d32e6e7117796b0540cf635820dca9df10de012c60f7057f47aaffaa2f645,
source 8a4e5ca4b28cf2c0af4d2199b0ec7a0d32fea25ab6c13710c6c8cd1052a9e2f9.
Independent full-sequence GNU as oracle and 21 malformed source controls
(including missing atomic) passed; old raw IRQ object is byte-identical.
The same native subject was linked in the independent HeptaKernel APIC
periodic three-task/idle fixture: 56/56 PC/Q35 cases. Upstream CI retains
all original hardware suites and adds the new compiler/oracle controls;
kernel CI separately qualifies the complete path. All evidence is specific
to the exact experimental candidates, not main.

Caller-owned descriptor/mapping/callback are not CPU or page capability.
This is a fixed non-nested BSP fixture, not arbitrary SMP, NMI/error-code/CPL3,
FPU, arbitrary callback bounds, alias freedom or guard-page mapping.
No production lock, main or original service budget changes.
