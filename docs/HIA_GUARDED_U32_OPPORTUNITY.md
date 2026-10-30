# A separate two-u32 native opportunity gate

The previous checksum studies sometimes supplied different Core candidates that
compiled to identical native bytes. Such a bank cannot establish a useful
specialization opportunity, much less an NDU controller advantage. This lane
adds a small independently qualified native workload before another controller
comparison. It does not change `PreparedArtifactSession` or its
`full_lifecycle(usize,u32)->u64` ABI.

## Frozen scope and demand

[`protocol_v1.json`](../experiments/hia_guarded_opportunity/protocol_v1.json) is
fixed at SHA-256
`1b4d1818d7fa9aff079bf7b27220d9f4df2bc0668a52b827e8a0adbd1b8cebbf`.
The original registration was published before any performance campaign in
[commit 18be73e4](https://github.com/TrillionniumFoundation/Hepta/commit/18be73e4bb42063d3f78c506cd2ec6c37226b47d).
The qualifier refuses changed protocol bytes; an experiment with a different
horizon requires a new explicit registration, not a post-observation edit.

The single native ABI is `calculate(u32 x, u32 denominator) -> u32`, computing
`(x / denominator + x % denominator) mod 2^32`. Division by zero is a defined
Core trap. The three actions are the generic function and existing executable
equality-guarded clones for denominators 8 and 10. A guard miss executes the
generic path. The two synthetic modules have separate 90% hot-denominator
distributions, with deterministic varying generic denominators and numerators.
Each module has seven training and seven disjoint validation seeds; every seed
executes all three candidates in a preregistered rotated/reversed order.

The horizon is **100 million calls per module**, registered as a research
scenario. It is not a captured application trace or a claim about production
demand. There are 200,000 calls and 10,000 warmup calls per measured batch, for
84 measured batches. No sample is dropped, replaced or automatically retried.
The prospective selection has one specialized-module slot. The complete bank
is built during qualification; this is not a claim that only one candidate was
compiled or that a one-compilation online budget was met.

## Independent evidence before native timing

For every candidate, including the baseline, the lane recomputes:

1. The actual canonical Core verifier and the closed two-u32 ABI/profile check.
2. The existing `validate_translation` all-input value and first-trap query.
3. The existing selected Core-to-LLVM body check on the actual emitted LLVM.
4. The existing compiler's exact Core/LLVM/tool identities and ELF ABI check.
5. An independent arithmetic formula against the interpreter, followed by 14
   real interpreter/native cases, including two zero-denominator traps.

Unknown/refuted proofs prevent compilation. No imported JSON receipt can stand
in for a proof. Actual exported `calculate` instruction bytes are extracted
from the checked ELF dynamic symbol and executable segment, so an unrelated
ELF metadata difference cannot count as a code-changing specialization.

All candidates use the same 10-second per-query SMT limit. During development,
the denominator-10 first-trap query exhausted an initial 5-second limit; a
30-second diagnostic limit obtained UNSAT after about 5.587 seconds. The
initial unknown remains a refusal, not a proved result. This concrete
diagnosis motivated the uniform 10-second profile before the performance
campaign. The generic checker and its default policies were not changed.
Both actual solving costs remain charged, and a future unknown still refuses.

## Native execution and ownership

The compiled fixed C driver and each internally built shared object are copied
into sealed Linux memfds. Each image is checked against its build SHA-256.
Execution uses the held parent descriptor paths, not the mutable publication
paths. The synchronous bounded runner completes owned process-group cleanup
before any descriptor is released. Descriptor release is attempted once;
uncertainty produces failure and cannot certify successful cleanup.

The C driver calls the exact two-u32 function type and uses kernel CPU,
address-space, file-size and core-dump limits. Child wall time and output bytes
are bounded separately. The returned record must have exact fields, exact
integer types, canonical JSON bytes and an independently recomputed checksum.
Load, loop, CPU, unload and parent-observed outer time are retained. A very
short correctness control may report zero CPU nanoseconds at host clock
resolution; that raw observation is preserved. Loop times are diagnostics.
Economic comparison uses the outer wall time of the complete fresh-child
batch, including launch, load, loop, output and owned cleanup.

No native function executes in the Python controller. This does not establish
a general malicious-code sandbox. The compiler, linker, libc, loader, host
environment and operating system remain trusted; native checked-trap cases
observe silent SIGABRT without proving its root cause. The Core proof, selected
LLVM body proof, finite native observations and final machine-code refinement
remain distinct claims.

## Cost gate and next controller experiment

The measured search cost conservatively begins at the qualification function
entry, including preflight/protocol validation and the initial source hashing
before the registered protocol-write start. It then includes generation,
every proof and build, baseline work, native correctness checks, pinning,
Python checksum generation, all training/validation samples, descriptor
release, the complete opportunity analysis and final source hashing. These
cost stages are retained separately. Unsuccessful attempts remain charged on
failed runs. Tool installation, outer Python startup/imports and the final
cost-field rebinding/report decoration/JSON serialization are explicitly
outside that boundary. The 60-second study wall budget is checked between
bounded stages and after all measured work; each solver, compiler and child
also has its own finite timeout. It is not a process-wide instantaneous
deadline, and an over-budget final stage cannot become a completed negative
qualification.

For each module and both phases, the gate uses

`(minimum baseline outer batch - maximum selected-candidate outer batch) * horizon / batch_calls - entire measured search cost`.

The future deployment unit is the same complete fresh-child batch used for
qualification: the fixed horizon requires 500 batches per module. Counting
load/startup/cleanup once in training is not payment for those 500 future
batches. A retained review counterexample has a 4 ms baseline kernel in a
5 ms complete batch and a 1 ms candidate kernel in a 6 ms complete batch.
With a 600 ms complete search cost, the old inner-only calculation would have
claimed +900 ms; the complete-batch calculation correctly gives -1,100 ms.
The new regression requires refusal. This implementation correction occurred
before the registered performance campaign and did not change its horizon,
seeds, candidates or protocol bytes.

This is an observed conservative envelope, not a statistical confidence
interval. Each prospective specialization is charged the entire common search
cost. At least two code-distinct modules must remain positive in both phases,
within the study budget, before a separate constrained NDU/control study has
the registered opportunity. A diagnostic break-even call count never changes
the registered horizon. Incomplete evidence is `failed`; completed evidence
with no sufficient opportunity is `no-economic-opportunity`.

A positive gate alone would establish neither NDU advantage nor a production
deployment. The next study must compare the same finite candidate bank and
information against fixed and complete-enumeration/DP controls, account for
actual controller/build costs, and retain independent holdout outcomes.
Equal choices to a complete finite optimum are not an incremental gain.

## Run

```sh
python tools/qualify_hia_guarded_opportunity.py \
  --clang /path/to/clang-20 \
  --expected-source FULL_40_CHARACTER_SOURCE_COMMIT \
  --workdir /new/path/outside/the/source/tree
```

The output directory retains the frozen protocol, Core/LLVM sources, compiled
artifacts, driver and `RESULT.json` with raw records, proofs, source hashes,
compiler identities, cleanup receipts, costs and claims. Exit zero means the
finite qualification completed, including a completed negative opportunity
result. A proof/ABI/native/budget/source error exits nonzero and retains the
failure. No result from this lane closes arbitrary C/C++ migration, persistent
resource hot replacement, Rust-wide performance superiority or global
instruction optimality.

The full expected commit is required. Before any native work and after the
campaign, the existing integrated source checker verifies HEAD, tree, every
tracked raw file blob and mode, and clean working-tree status. These complete
inventories are retained separately from the selected Python dependency
hashes. Both checks are charged. The output directory must be outside the
source tree; a dirty tree cannot be attributed to the last commit merely
because `git rev-parse HEAD` has not changed.
