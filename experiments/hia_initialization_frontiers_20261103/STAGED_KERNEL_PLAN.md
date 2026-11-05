# Proposed bounded staged kernel verification

Design only after PR #603 head a7ea688e002298dd3dc9c965ea0506a3349d30d1.
The third actual positive process reached its existing 60-second timeout and
returned no complete positive receipt. No component acceptance is inferred from
that attempt. This plan neither changes the predicates nor marks a proof passed.
All twelve global obligations remain unproved, all production/admission flags
false, and DENY_ALL. No new native target execution or artifact upload is proposed.

## Constraint and useful distinction

One long positive file can repeat expensive computation and reach the process
limit even if smaller certified components might fit individually. That is a
hypothesis, not an established cause of the third failure. Stage only reviewed
proof-producing Lean sources; do not cache Python booleans as propositions or
replace the complete raw document with a selected slice.

Retain the existing limits: at most eleven Lean process launches per run,
60 seconds per process, no new process starting after 540 seconds, 600 seconds
external command wall time, 15-minute job, 2 MiB per generated proof source and
8 MiB aggregate generated proof sources. The 32 KiB/4096-node/depth32 transport
bounds, scalar semantics and rejection propositions remain unchanged. No process
retry inside the run bypasses the invocation/time counters. If a single stage
still cannot finish, the run fails; this plan does not authorize raising a limit.

## Proposed ten-stage DAG, including every negative

The implementation must freeze the actual dependency/source/theorem manifests
before execution. The following arrangement fits the existing eleven-launch cap;
it does not add eleven positive processes on top of ten negative processes.

1. Baseline: exact accepted #600 model and its 56 declarations, without the new
   syntax model. Produce one checked baseline module.
2. Transport/data: import Baseline; add the exact transport prefix of the
   reviewed syntax model (three generic transport theorems) and full literal
   Raw/bytes definitions for real linear, parallel-arm and three actual-Core
   mutants. Do not include the extraction suffix or Hint definitions yet.
   Independent byte numerals remain checked before execution; no concrete
   transport result is presumed here.
3. Real linear transport: import Syntax/data; prove its five bounded components
   and assemble the same checkedEncode equality.
4. Parallel-arm transport: the same construction for its full distinct byte input.
5. Wrong-phi transport: the same construction for its freshly verified mutant.
6. Literal-two transport: the same construction for its freshly verified mutant.
7. Wrong-condition transport: the same construction for its freshly verified mutant.
8. Connections and syntax rejection: import the five checked transport modules;
   append the exact original extraction suffix and locator definitions. Prove
   the two concrete extraction equalities and real structural relation, and prove
   the exact negations of stale-descriptor/wrong-phi/literal-two/wrong-condition
   claims. The three mutants' transport premises come from stages 5-7, never from
   Python re-verification alone. Print the full positive 66-name axiom inventory
   and the four precisely named rejection certificates.
9. Transport rejection: import real transport; prove the exact original five
   transport negatives (changed byte, duplicate keys, key order, byte256 alias,
   leading-zero spelling). The changed-byte proof may rewrite the cached exact
   positive encoding before showing the byte inequality; it must not recompute
   or silently replace the original wrong-byte input. Print five rejection names.
10. Wrong-arm isolated leaf: import the checked parallel transport module, not
    stage 8's original extraction suffix. Append only the extraction suffix with
    the existing single reconstruction mutation and the parallel locator; prove
    the unchanged wrong-arm negation. The transport declarations and exact
    parallel fixture are shared, not regenerated or recomputed. The original and
    mutated extractors live in separate import graphs, so their same-named
    constants cannot conflict or shadow one another. Never import stage 8 into
    this leaf or this leaf into stage 8. Print its precise rejection inventory.

Split the existing model at its existing transport/extraction namespace boundary,
not at an inferred semantic boundary. Require exact prefix+suffix reconstruction
of the reviewed model bytes; bind full-model, prefix, suffix and the unique
mutation position. No field, predicate, declaration or dependency may be dropped.
The five generic theorems are three transport plus two original extraction
results; the full original positive inventory remains 66.

This is an execution partition, not permission to weaken or rename a proposition
without traceability. If namespace qualification is needed to put mutant inputs
in one data module, retain an explicit mapping from each original proposition to
its fully qualified statement and exact raw/byte definitions. Structural tests
must check alpha-equivalence and the same original input bytes; resolving a short
name to a different fixture must fail. Each original negative remains a kernel
proof of not P, not an expected compilation error.

A positive receipt requires every stage, all full-byte transport and all ten
rejection certificates. Successful stages alone are partial evidence; no final
flag becomes true before the complete DAG, identities and inventories pass.

## Precise import and generated-module boundary

Lean's module loader is a trust boundary. Importing an olean at the ordinary
trust level must not be described as rerunning kernel checking of every imported
proof. Accept only modules produced by a successful prior pinned Lean invocation
in this same fresh run. No old CI artifact, repository-supplied olean, arbitrary
filesystem module or saved result can enter the DAG.

Use a newly created empty module root and one fixed, dedicated module-name prefix.
Only the frozen DAG's exact direct imports are permitted. The support inventory
continues to bind the repository-pinned standard library and imported tactic
modules. LEAN_PATH may contain only this fresh module root; LEAN_SYSROOT is the
verified pinned checker root, and LEAN_SRC_PATH is cleared. Do not inherit user
search paths or find a similarly named module elsewhere. Verify the fresh prefix
cannot shadow an existing standard-library module. No package/plugin/native
library discovery or additional import is permitted.

For each stage, bind in a manifest:

- exact source bytes/hash, module name and ordered direct import list;
- exact parent module source and olean hashes, with successful stage receipt IDs;
- pinned Lean executable and existing support identities;
- command arguments, isolated search path and current working directory;
- expected positive/rejection theorem names and permitted axiom inventory;
- return code, completion/timeout status, bounded diagnostic hashes;
- exact newly produced olean path/hash and byte count.

Invoke only the pinned Lean CLI with explicit input/root/output paths:
`lean --root=<fresh-root> -o <fresh-root>/<prefix>/<module>.olean <fresh-root>/<prefix>/<module>.lean`.
Do not add -c/-b/--run/--plugin or change trust level. The exact v4.19 implementation
sources are [shell.cpp](https://github.com/leanprover/lean4/blob/v4.19.0/src/util/shell.cpp),
[Path.lean](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Util/Path.lean),
and [Import.lean](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/Import.lean).
The --deps option lists direct dependencies only and would consume another Lean
invocation; do not run it per stage and silently exceed the cap. Validate the
fixed headers, complete fresh-root file inventory and transitive DAG against the
verified module-resolution rule instead.
The output module is admitted to the next stage only after exit zero, absence of
errors/placeholders, exact named inventory, unchanged inputs/support/dependencies,
and an existing nonempty regular output file. A failed process may leave a file;
that file is never admitted, even if it looks structurally valid.

Reject symlinks, hardlinks, unexpected filenames/module prefixes, missing parents,
reordered/replaced imports and extra output code/shared libraries. Bound retained
generated module outputs separately (proposed: 32 MiB per olean, 128 MiB total),
so the new cache is finite rather than an unbounded side channel. These new caps
are ceilings, not a reason to enlarge any existing input/time limit. No modules
are uploaded. Verify all source/module/support hashes before and after each stage
and again before final acceptance. This is trusted-host change detection, not an
atomic snapshot or protection from an adversarial concurrent ABA replacement.

## Timeout and interruption evidence

Persist a stage-start receipt before launching, including input/dependency hashes
and remaining invocation/deadline budget. On timeout or launch/parse failure,
retain bounded available stdout/stderr with byte count, SHA-256, truncation and
partial/incomplete indicators. TimeoutExpired may hold partial captured bytes;
these are diagnostics, never accepted theorem inventories. Keep at most the
existing 1 MiB diagnostic output allowance per process, without claiming it is a
hard streaming allocation bound unless a bounded capture mechanism enforces it.
Record which process timed out, returncode/null, and terminal failed status.

Terminate the timed-out process using the existing supported subprocess cleanup;
no downstream stage may start. A process killed by the external deadline/host loss
may leave only a running receipt. Missing/unfinished receipt is failed/unknown,
never success. The wrapper must not claim that arbitrary host interruption always
produces a final RESULT. Job logs may retain completed stage summaries; no full
raw-directory upload is introduced.

## Required adversarial tests before another CI run

- Valid mocked DAG and exact command/source/import inventory; actual proof status
  remains unchecked in mocks.
- Substitute an old or externally supplied olean; alter a parent after its check;
  skip a failed parent; return exit zero without producing the expected file.
- Shadow a module via search path, wrong prefix, undeclared import, symlink,
  hardlink, unexpected executable/shared-library output or oversized module.
- Alter one byte/raw input or namespace resolution; swap the wrong-arm leaf with
  the normal model; preserve every original not-P target and full transport.
- Missing/duplicate/unexpected axioms, error/sorryAx, missing rejection certificate,
  absent final positive inventory and a true flag on partial completion.
- Timeout with stdout bytes, text, undecodable bytes, overlong output and no output;
  retain bounded marked diagnostics, no downstream execution.
- Expired 540-second launch deadline, eleventh/twelfth process boundary, 600-second
  outer interruption and per-source/aggregate proof-byte budgets.

Independent design review comes before implementation. Independent implementation
review and actual pinned exact-head CI still precede any claim of this narrow
syntax connection. If stages cannot fit the unchanged limits, report that concrete
blocker and design a genuinely smaller/compositional proof, not a weaker contract.

## Implementation pending real kernel verification

The staged source builder and executor implement the ten-module DAG above.
Each source has explicit import metadata plus the implicit `Init` dependency.
The generated package is the only permitted package in a freshly created root;
unknown files/directories, symbolic links, multi-link files and pinned-support
package collisions are rejected. Before and after every invocation the executor
rechecks source, Lean executable, support identities and all admitted parent
module bytes. A module is admitted only after exit zero, complete diagnostics,
its exact theorem/axiom inventory, and ordinary-file/size checks. The final
receipt requires all ten stages, the original 66 positive declarations, and all
ten exact-negation certificates. Imported modules remain trusted successful
same-run kernel outputs, not independently rechecked proofs.

Each launch first writes a start receipt. Python timeouts retain bounded partial
stdout/stderr with hashes and byte counts, mark the stage incomplete, and block
all successors. Retained diagnostic text shares a 1 MiB UTF-8 byte allowance;
truncation cannot pass verification. A later log-only diagnostic command reads
only fixed receipt/log names with no-follow file descriptors. External kills or
host loss can still leave only a running receipt. These are trusted-host change
checks, not protection against arbitrary concurrent ABA replacement.

Local mocked process tests validate the orchestration and rejection boundaries,
not Lean elaboration, kernel reduction or actual proof acceptance. Until the
exact published head passes the pinned Lean lane, the full Core-syntax connection
remains UNCHECKED. Production zero-initialization, all twelve unproved global
obligations and DENY_ALL are unchanged. No generated files are uploaded by this
lane; its bounded diagnostics are printed to the Actions job log.
