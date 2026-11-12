# IR PGO trial: independent static review and strengthened checks

The reviewed starting point was
`83a75793ae462ba3bb6357f88704b0c3aa4e23bb`. This increment closes four
implementation gaps before the next formal performance qualification. It
does not change the eleven registered arms, the prospectively selected
`hia_native_irpgo` arm, the training/held-out inputs, or the acceptance ratios.

## Corrections

The old counter check established that the module had positive counters and
that a target name appeared. Another function's activity could therefore
rescue a target whose counters were all zero. The new check requires exactly
one target section, exactly one declared counter length and list, matching
lengths, unsigned 64-bit decimal values, and at least one positive counter in
the target itself. The complete target block-counter list is retained. The
observed LLVM output has `entry_first = 0`, so neither its first element nor
their sum is presented as an entry invocation count.

The captured canonical Core and LLVM files now have explicit identities bound
to fresh emission from the verified Core. Every research HIA compilation
checks them before and after the compiler command; final artifact validation
checks them again before sampling and at completion. The stable bounded
reader rejects nonregular or changed files and never allocates from an
unbounded replacement. These are trusted-host file checks, not sealed compiler
input, arbitrary-host integrity, or native-refinement proofs.

The allocation-refusal observer now uses `-O3`, full LTO and native CPU
optimization at both object compilation and final link. It retains the
allocation wrappers and `-fno-builtin`. This is a separate observer binary
from the same LLVM/profile, not an injection into the exact performance DSO.
Its registered 96 rows require a new run. Earlier successful rows linked at
`-O2` retain that older scope and source.

Initialization now records source hashing, upstream verification, directory
preparation and project copying. `whole_qualification_wall_ns` is the sum of
that initialization and `run_wall_ns`; it excludes idle time between object
construction and starting the run. HIA research build totals include their
Core/LLVM checks and binary inventory; compiler command duration is retained
separately where appropriate. Per-sample process timings and the fixed gate
are unchanged. Acquisition, human labor and the final report write remain
outside these measured work intervals.

## Other reviewed controls

- The original Core is captured once and reused for default, LTO and IR-PGO
  HIA builds. No original C implementation is linked into the HIA arm.
- C and C++ retain both frontend PGO and LLVM IR PGO alternatives, full LTO,
  native CPU optimization and ordinary compiler optimization freedoms. Rust
  retains its safe implementation, fat LTO, one codegen unit, native CPU
  optimization, panic-abort mode, and actual profile-generate/profile-use arm.
- Training calls use only `training.bin`, once for each named algorithm. The
  held-out seed and larger input are distinct and fixed before sampling.
- The HIA comparison arm is fixed in advance. The strongest reference is
  selected by the registered minimum median process time rule. No HIA arm is
  selected after inspecting samples; every registered sample is retained.
- Functional checks, allocation-refusal observations and named maintenance
  oracles precede sampling. The previous maintenance-oracle failure remains
  separate evidence; algorithm names replace dictionary-order assumptions.
- Compiler, protocol, source, image and input identities are retained and
  checked. The common fork/exec supervisor reports child wait4 peak RSS with
  its pre-exec floor; this does not establish a process memory upper bound.

`tests.test_hia_legacy_irpgo` checks fabricated target activity, duplicate or
missing sections, malformed/oversized counters, and changed Core/LLVM bytes
before and after the research compile boundary. It emits LLVM but invokes no
native compiler, training process, model or performance sample. Parsing the
three previously retained counter reports is a format replay, not a rerun or
requalification of their old native binaries.

The next frozen-source qualification must establish the actual new resource
and performance results. This review does not predict them and does not
prove compiler correctness, general resource safety or universal speedup.
