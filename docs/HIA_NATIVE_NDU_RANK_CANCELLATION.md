# Live cancellation for the native NDU rank engine

This checkpoint connects the existing private interrupt word to the running normalizer, proof process and NDU evaluator. It preserves the original absolute deadlines, cleanup bounds, process and stream capacities, source and binary custody checks, and the complete result/cost semantics. The original engine captured a value once; it could not observe a later change while a child was running.

## Control and lifetime contract

The mechanical engine validates its existing six input/output/work views before writing the actual control-buffer base to control offset 120. It introduces no new public input field. The trusted HIA task policy derives the live interrupt word at that base plus 104. The context entry timestamp remains at START 4096, and the context active ticket at 3504–3559 and ordered-report frame at 7040–7087 are untouched.

For the evaluator, the task policy supplies the private tag HIANCN01 at owner workspace 2256 and the actual word address at 2264. Existing source-root, captured integer policy and snapshot-cancel fields retain their meanings. The owner reads the same-process word through getpid and process_vm_readv, including while a nested path resolver or bounded pump is suspended. Failed or short reads and nonzero samples set the existing sticky cancellation word. The sampler saves and restores the original syscall feedback; it does not consume nested feedback or change its continuation. A fresh owner begin takes precedence over poisoned prior sampler state. The original binary digest at 2304–2335 is preserved.

Cancellation uses the original owned-process cleanup and reap path, and reaches the existing status 2 / kind 2 BaseException outcome. An empty BaseException body is valid. Context finish still copies the result into an independent immutable payload, consumes the active reference exactly once, and leaves the caller responsible for unmapping the engine arena on every outcome.

## Versioned process compatibility

HIANPS01 retains its original alignment requirement, cancellation token comparison, validation order, fixed image roles and all capacities. HIANPS02 adds a kernel-checked live read for possibly unaligned addresses. It has the same 128-byte header, 20 MiB workspace, original 8/16 MiB role image bounds and original 64 MiB stream limits. Both the original and new profile preserve token value 2 as the existing committed/non-cancelled state; only token value 1 cancels this process role.

The new profile checks nonzero pointers for unsigned extent wrap, then reads through process_vm_readv. Short or failed kernel reads take the existing failure/cleanup path. EINTR retry checks the original absolute clock. No arbitrary caller pointer is directly dereferenced. A zero pointer keeps the original no-cancellation behavior. The mechanical process bridge is unchanged.

This versioning is necessary: an intermediate implementation sent an unaligned control address to the old aligned-only process profile. Actual old/new tests identified that regression. The final implementation restores all eight original control alignments without disabling cancellation.

## Actual qualification

The adjacent JSON records actual source, native compiler, packer, image, report and input-role digests. All successful results use the final unchanged cancellation source.

| Scope | Actual checks |
|---|---:|
| Owner sampler and fresh/poisoned state | 82 |
| Original owner effect faults / private ABI / combined cases / live custody | 41 / 228 / 73 / 18 |
| Original HIANPS01 process / private guards / image bounds / native pack guards | 57 / 52 / 7 / 5 |
| HIANPS02 using the same process cases / guards / image bounds / native pack guards | 57 / 52 / 7 / 5 |
| New unaligned, live, protected, partial, noncanonical and overflowing word cases | 32 |
| Native engine pack, atomic rejection and six-view guards | 74 |
| Original full engine with retained context results | 17 |
| Actual old/new control alignments | 16 |
| Real running-child cancellation and preexisting interrupt | 4 |
| Two simultaneous native rank entries, isolated cancellation in each of three child families | 3 pairs / 6 entries |
| Native pack with independently qualified public dictionary order | 74 |
| Combined original ordered end-to-end cases | 44 |
| Combined actual running-child cancellation | 4 |

The concurrent cases stop an actual owned kernel fork event solely to deterministically set A's private interrupt word, detach the child before the native parent continues, and let the product own exec, capture, kill and reap. B's word remains zero and B completes its actual proofs/evaluation and selects the valid candidate. Both contexts settle, their retained results survive arena unmap, the exact FD set is unchanged, and no owned child remains. Separate live-child tests identify an already running normalizer, proof or evaluator, observe an actual WSTOPPED state, then update only the live word. Neither harness is part of the production chain.

The combined image uses the main/report inputs from commit 55bc211d5c242ed6ecae47ef513dcc25df030f29. That implementation is a separate dependency; this commit does not rewrite its sources or private hash inputs.

## Native construction

The five changed HIA policies/packers were compiled by the captured and sealed native source compiler. The owner is produced by HIANOP02 with the original six source-bound flats. The engine is produced by HIANEP02 with the original 21 roles and original per-role/total limits. The readable assembly is a mechanical pointer/syscall/relative-call adapter; independent assembly comparisons do not replace the native HIA packer outputs. No host-language effect dispatcher is used by the actual engine cases.

The production increment consists of the five HIA files and two readable mechanical assembly files listed in the JSON runtime_sources. Python author/qualification scripts are development provenance and are not required at runtime.

## Limits of this checkpoint

This is a rank-engine cancellation and composition checkpoint. It does not claim a new full-source cold qualification, final public façade or BG lifecycle composition, installed aggregate, production registration, or cleanup/activation. Existing V9/P3 evidence remains bound to its original frozen source. Public SIGINT/TERM-to-private-word wiring must be validated with its final caller. Ordinary BG Future.cancel does not acquire a new authority to interrupt rank.

All earlier failed candidates and fixture failures remain in the custody tree. The JSON distinguishes the actual intermediate unaligned regression from fixture failures (ptrace observation permissions, a transient proc-FD snapshot, and an expected raw ABI refusal mistaken for a structured process result). None is counted as a passing run, and none changed a product limit or deadline.
