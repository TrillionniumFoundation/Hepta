> Historical Core implementation observations, not a current release plan.

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.
> High-level/source migration components and their gates have been removed.
> Current scope: [Core-only product](HIA_CORE_ONLY_SCOPE.md).

# Semantic advance after the 0742fde checkpoint

This increment continues the same standalone HIA implementation from
`0742fde5058b6583fcbdef782c879639ed5c1aed`. It selectively integrates the
partial-record, constexpr and incremental-checking work from PR #338, adapts
it to the existing v8 resource contracts, and repairs independently reproduced
source, Rust admission and native-child cleanup gaps. A feature description
or an earlier commit's passing report does not qualify this new revision.

## Execution and analysis responsibilities

| Representation or consumer | Responsibility and boundary |
| --- | --- |
| Composite v1/v2/v3 | A nominal frontend over products, enums and cooperative tasks. v1 normalizes to primitive v6; v2 and v3 to v7. v3 adds explicit partial-record states and linear tokens. Nominal metadata never bypasses primitive admission. |
| Primitive Core v1–v8 | The versioned, independently rechecked SSA/type/resource contract consumed by the standalone Python VM and direct LLVM backend. Existing versions retain their original operation semantics. v8 supports parameter-bound returned loans. |
| Incremental verifier | Reuses a body only inside a live fully checked session under the v2 closed-body/callee-interface contract. Global shape checks still run. Callee parameter identities and v8 return origins are cache dependencies; caller-supplied hashes and receipts cannot authorize reuse. |
| Rust checker and Machine | Independently admit and execute declared primitive resource profiles, including chains, bulk operations and v8 returned loans. Raw input tests exercise Rust's own parser. Rust remains a shadow; production authority is not switched by this increment. |
| Resource bounds, SMT and Lean | Each result has its own quantity, admitted subset and assumptions. A call-depth bound is not a heap, native-stack, wall-time or termination bound. Existing selected proofs do not prove the whole compiler. |

## Concrete changes and their acceptance conditions

### Partial record states

Composite v3 has `record.begin`, `record.insert`, `record.finish`,
`record.take` and `record.abandon`. An initialized-field set is part of the
type; reading an absent field, inserting twice, finishing early or abandoning
a nonempty state rejects. Even an empty or scalar-only partial state carries
a real zero-byte owner token after normalization. The token has logical move
and destruction semantics without an allocator attempt or `free(NULL)`.

The fixed partial-record corpus includes two simultaneously live payloads in
pending, running and completed cooperative tasks. Normal and injected first/
second allocation failures are checked against a separately specified reverse
release order. A deliberately wrong-order native candidate retains the correct
scalar value and free count but is rejected by its actual release sequence.

See [partial-record semantics](HIA_PARTIAL_RECORDS_V3.md). General uninitialized addresses, stored loans inside partial records,
arbitrary recursive heap ADTs and asynchronous cancellation remain separate
obligations.

### Rust parser and native lifecycle repairs

Rust's bounded duplicate-safe decoder now treats the raw JSON integer token
`-0` as integer zero, consistently with Python's Core decoder. Float tokens,
malformed numbers, quoted numbers, duplicate keys and excessive nesting retain
their rejection rules. Tests send original bytes directly to the Rust process;
Python normalization cannot hide a raw-parser difference.

The native scalar observer retains a child owner until `wait` positively
confirms the direct child's reap. A bounded process-local quarantine survives
a discarded exception. Pending cleanup blocks new observers, and the total
in-flight reservation count is capped. Retries only reap the original child;
they do not signal a potentially reused process group, execute the candidate
again or turn a failed observation into a pass. This does not provide cleanup
after host-process crashes or force an uninterruptible kernel wait to finish.

See [raw Rust admission](HIA_RUST_RAW_INTEGER_ADMISSION.md),
[native cleanup ownership](HIA_NATIVE_CLEANUP_OWNERSHIP_20261028.md).

## Qualification and remaining P0–P7 obligations

Freeze a clean combined commit before running `retired harness qualify-hia-integrated`.
Its complete Python discovery is one test denominator; critical groups are
subsets of that run. Cargo results are counted separately. The 37-gate unified
plan adds actual partial-record and constexpr producers with retained-evidence
replay. It also extends Rust parity and Agent mechanism groups for raw parsing,
returned-loan execution and v8 incremental invalidation. Neither gate inventory
nor the presence of a test is an execution result.

The broader roadmap still requires the following separate closure evidence:

| Stage | Remaining obligation |
| --- | --- |
| P0 | Convergence of all promised source/frontends, analyses and backends on their declared versioned execution contracts, including legacy hosted routes. |
| P1 | General typed memory/provenance, broader returned and stored borrows, arbitrary recursive ADTs, uninitialized memory and asynchronous cancellation, with stable illegal-alias/resource refusals. |
| P2 | Qualification before any Rust production-authority switch; complete claimed value, failure, cleanup and resource correspondence for each native subset. |
| P3 | Actual bidirectional ABI, callbacks and foreign lifetimes on each claimed compiler/OS/architecture. Scalar export checks and emulation do not establish aggregate or callback ABI. |
| P4 | Representative complete project/configuration inventories, ownership contracts and real migration cost. Finite constexpr/template success is not general C++ or STL translation. |
| P5 | Prespecified independent real-task/model success and cost results. Incremental work counts and atomic edit mechanisms do not establish model productivity. |
| P6 | Current-source workload throughput, tail latency, memory ceilings and physical device/protocol evidence. Neither prior timings nor QEMU establish these. |
| P7 | Rules/refinement tied to the actual implementation, transformations and foreign assumptions; source/toolchain/platform-specific reproducible release evidence. |

All whole-project completion and universal performance/soundness claims remain
false until those corresponding obligations have been independently met.
