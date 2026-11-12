# Exact original impact timing diagnostic

This work measures the original near-8 MiB impact failure. It does not replace the original semantic qualification or change its outcome.

## Bound inputs and execution

The new CI first reads every member of original run43189935529 artifact13930443158: 3,090 files and150,697,441 raw bytes, including all original sources, images, process streams and compressed full expected buffers. The existing published reader preserves every original byte and mode and checks its full index and input before/after identities.

The builder binds all63 original semantic HIA sources and images, reproduces the entire old mechanical prefix and original ELF, then adds only four before/after timing hooks to the mechanical executor. Removing those calls and the timing block must recover the complete original assembly. The retained63 HIA images are never recompiled or changed.

One new HIA packer is compiled by exact35ee B3 under the original10CPU/20wall/256MiB and1MiB source/output/work limits. Its actual native entry must produce the entire expected instrumented ELF and preserve all input/work bytes and canaries. This is one new packer entry, not a new semantic qualification.

The capture executes exactly three ELF processes:

1. The exact original ELF on the complete original semantic case0001, requiring return code, stdout and stderr to equal the original streams byte-for-byte.
2. The instrumented ELF on that same input, requiring the same full original result.
3. The instrumented ELF on the exact8,370,475B large-valid input, SHA2568672352b719ab283e2efd48e0f0c753c194cda9fce5cb990660106875e285f05. Its complete original expected output is8,371,538B, SHA2569e3c7056f89a954cefff8affe8430a3f1988579d8bb74b9579bf4a17101ee2b9.

The original uninstrumented large-valid process is not rerun by this diagnostic. Its recorded90,058,572,023ns/-9 failure and original whole-group CPU failure remain unchanged. A captured diagnostic process killed at its smaller remaining CPU allocation is a measurement boundary, not a successful semantic case.

## Budget and descriptor handling

Build, capture and read-only analysis are separately identified diagnostic phases, each limited to90CPU/180wall/1GiB. Capture measures the complete parent-plus-child CPU cost. Each child receives at most the remaining whole90 seconds minus four seconds reserved for final byte verification and evidence handling; the calibration children additionally cap at12CPU seconds. Final measured budgets remain hard assertions. This split must never be used to exempt evidence or reference work from an original semantic qualification budget.

FD198 is reserved with an owned /dev/null descriptor before opening input/output/error/trace files. None of those streams may acquire198. The owned slot is then replaced with the trace output and passed only to the child; ownership is consumed before closing, and child termination/reaping proceeds independently on every failure path. Cleanup evidence failures are attached to an existing primary exception.

Every trace frame has16 little-endian u64 words: magic, phase, thread-CPU seconds/nanoseconds, monotonic seconds/nanoseconds, current controller role/kind/lease/sequence, event operation/role, input size, second capacity, work capacity, and original or returned RAX. Hooks preserve all general registers and flags and write only their own stack plus the dedicated trace FD. Full original and captured stdin/stdout/stderr, raw128B timing frames, source/image pins, full packer operands and all failures are retained.

## Interpretation

The separate reader streams every raw timing frame, validates order and paired context, checks full file identities before/after, and reports complete pair totals and the32 largest complete intervals. The underlying raw trace remains complete; the32-row ranking is a derived index, not a substitute for that trace. Every u64 frame projection uses decimal strings.

Before-to-after differences include before-hook sampling and trace-write overhead. Adding the hooks also changes layout and resource use. An unmatched before frame does not prove the exact HIA call was still running: it may have returned before the after record was fully written. The difference from child rusage is approximate and includes uninstrumented code.

The three independent narrow reviews cover hook preservation, FD lifecycle and final budget/error handling. They executed no AST, assembler, B3 or native program. They do not certify the63-image system.

All new source here is unexecuted at submission. Actual CI must establish syntax, original reproduction, packer output, calibration and trace integrity. Any performance change suggested by these measurements still needs the complete original uninstrumented13-group/329-case impact gate under its unchanged budgets before replacing production behavior. Whole-stack closure, installation and production activation remain false.
