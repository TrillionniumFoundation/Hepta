# Resumable native general scalar CNF

`examples/hia_bootstrap/general_cnf.hepta` implements a separate general scalar
proof role. It does not invoke Python, Rust, Z3, an external solver, or the old
bounded CNF role. The old 256-word / 4096-variable fast role is unchanged.

The caller must first admit the actual Core programs, select the functions,
check their exact signatures and qualified scalar operations, and produce the
`HIABVP01` graph. This role then captures and hashes that graph, constructs a
word DAG and a 32-bit CNF, searches it, and independently checks a SAT word
witness. The service must still replay SAT arguments through its independent
Core VM. A serialized receipt is not execution authority.

## Scope

The general structural profile is 128 blocks and 2048 operations per function,
32 function parameters, and 16 user returns. Block parameters do not acquire a
32-parameter or 256-slot limit. Translation uses 18 observation pairs to retain
all user returns, normal completion, and the first trap. Typed SSA entries use
`type << 32 | node`; word-node indices and all Boolean literals are independent
32-bit fields. Calls and the `HIABVP02` summary tail are outside this primitive
role. The owner handles call qualification separately; no call support is
inferred from integer operation numbers.

Mode 1 asks whether an admitted function can fail to return normally. Mode 2
asks whether the admitted functions differ in return values or first trap.
Mode 4 is the separate Boolean bound-marker query: incomplete execution or a
normal `true` return is a witness; an explicit trap is not a true marker. It is
not a totality proof. The public primitive service uses modes 1 and 2.

Finite storage exhaustion returns Unknown only when actual construction or
search reaches the declared allocation. It does not prove the query, and it is
not a substitute for attempting the general profile. Search time is controlled
by the caller's original absolute deadline, including time already spent in
admission and the fast role. No new deadline is created for this fallback.

## Six-word interface

The flat entry has the existing borrowed-view ABI:

```
f0(input_pointer, input_bytes, output_pointer, output_capacity,
   workspace_pointer, workspace_bytes) -> u32
```

Input, output, and the private workspace must be disjoint. The caller supplies
at least 512 MiB of private workspace and an output capacity of 64 MiB. All
runtime state is in that private workspace; the code has no mutable global
query state. The role neither allocates nor calls a host syscall.

### Request

A request starts with exactly 128 bytes. All fields below are little-endian
unsigned 64-bit words except the magic and digest.

| Offset | Value |
| --- | --- |
| 0 | Eight bytes `HIAGCN01` |
| 8 | Operation: 0 begin, 1 advance |
| 16 | Graph byte count: begin payload size; zero on advance |
| 24 | Remaining milliseconds, 1 through 60000 |
| 32 | Step quantum, 1 through 16384 |
| 40, 48, 56 | Zero |
| 64 | Expected graph SHA-256, raw 32 bytes |
| 96 through 127 | Zero |

Begin carries the exact graph immediately after the header, with no trailing
bytes. The graph is bounded by 16 MiB and captured once before hashing. The
expected digest is compared with the actual captured bytes. Advance carries no
payload and must retain the same graph digest and a nonincreasing remaining
budget. The caller normally uses quantum 1024.

The role has no clock. The owner checks the same absolute deadline before and
after every call, including a call that returns SAT or UNSAT. Deadline expiry
must override that result with Unknown. A word bitblast and a word-witness
step force a yield even if the requested quantum is larger. Each valid reply
reports exactly the number of completed primitive transitions. Begin's bounded
capture is part of elapsed time, not a new time allowance.

### Reply

| Offset | Value |
| --- | --- |
| 0 | Eight bytes `HIAGCR01` |
| 8 | 0 Unknown, 1 SAT, 2 UNSAT, 3 running, 4 invalid |
| 16 | Current phase, described below |
| 24 | Reason: 0 none, 1 malformed, 2 actual capacity, 3 reserved for budget, 4 graph digest mismatch, 5 bad continuation, 6 witness/invariant failure |
| 32 | Declared private work extent, 536870912 bytes; not an RSS measurement |
| 40 | Current Boolean variable count |
| 48 | Current clause count, including learned clauses |
| 56 | Cumulative primitive steps |
| 64 | Actual captured graph SHA-256, raw 32 bytes |
| 96 | SAT argument count, otherwise zero |
| 104 | SAT model byte count, otherwise zero |
| 112 | Steps in this call, at most the requested quantum |
| 120 | Zero |

Phases are 1 graph hashing, 2 word projection, 3 validation and marking,
4 bitblast and initial formula hashing, 5 CDCL, 6 clause and word witness,
7 completed SAT or UNSAT. A valid continuation has nondecreasing phase and
`new cumulative - old cumulative == call steps`. A running phase-1 reply has a
zero actual digest. From phase 2 onward it must match the captured graph.
Unknown from actual capacity retains the phase in which it occurred.

Malformed request headers and invalid continuations return phase 0 and clear
all diagnostic counts and digests. An invalid graph or witness detected after
capture can retain its actual phase and diagnostic digest. A graph digest
mismatch is invalid in phase 1 and can return the computed unequal digest.
No invalid or Unknown result carries a model or a proof claim.

Only SAT appends data: first one 64-bit word per declared parameter, including
unit parameters, then `ceil(variables / 8)` bytes of Boolean model. Arguments
retain the original parameter order. Unit words are zero; other words are
masked to their type width. The VM adapter performs signed conversion. Model
bit zero represents variable 1 and low bits come first. Unused high bits of the
last byte are zero. All other replies are exactly 128 bytes. An output view
shorter than 128 bytes returns `0xffffffff` without writing it.

## Initial formula identity

The graph digest is never labeled as a CNF digest. The separately computed
initial CNF identity is available in the private work header:

| Offset | Value |
| --- | --- |
| 1024 | Ready flag; only 1 after the complete initial formula has been hashed |
| 1032 | Initial variable count |
| 1040 | Initial clause count |
| 1048 | Initial 32-bit token count, including every zero clause terminator |
| 1056 | Initial formula SHA-256, raw 32 bytes |
| 1088 | Canonical serialized byte count, `32 + 4 * initial token count` |

The hashed bytes are `HIAF3201`, the three initial counts as 64-bit words, then
all initial tokens as little-endian 32-bit words. A literal is `2*variable` for
positive and `2*variable+1` for negative, with variables numbered from 1. Zero
terminates a clause. Variable 1 is the true constant; literal 2 is true and 3
is false. The initial formula is fully constructed and hashed before search.
Learned clauses append after its immutable prefix. The ready flag and initial
digest are not rewritten by learning. If construction stops earlier, the
formula digest remains unavailable and the owner must record null.

## Private allocation

MiB means 1048576 bytes. No allocation overlaps another live allocation.

| Base | Extent | Purpose |
| --- | --- | --- |
| 0 | 4096 B | Continuation and formula metadata |
| 8192 | 1184 B | Private SHA state |
| 16384 | 288 B | Eighteen observation pairs |
| 65536 | Up to 16 MiB | Captured graph |
| 17 MiB | 1 MiB | Projection state, 128 block offsets and dynamic phi starts |
| 18 MiB | 8 MiB | Typed SSA locals |
| 26 MiB | 8 MiB | Dynamic phi slots, reused for word witness values after projection |
| 34 MiB | 40 MiB | 1048576 word nodes, 40 bytes each |
| 74 MiB | 8 MiB | Bounded exact-key word-node table |
| 82 MiB | 256 MiB | 64 32-bit Boolean tokens per word node |
| 338 MiB | 64 MiB | Up to 16777216 32-bit CNF tokens |
| 402 MiB | 32 MiB | Up to 1048576 32-byte clause records |
| 434 MiB | 16 MiB | Watched-literal list heads |
| 450 MiB | 2 MiB | Assignments |
| 452 MiB | 8 MiB | Trail |
| 460 MiB | 8 MiB | Decision levels |
| 468 MiB | 8 MiB | Trail limits |
| 476 MiB | 8 MiB | Reasons |
| 484 MiB | 2 MiB | Conflict-analysis marks |
| 486 MiB | 8 MiB | Learned-clause scratch |
| 494 MiB | 16 MiB | Bounded exact-key Boolean gate table |
| 510 MiB | 1 MiB | Observed-word marks |
| 511 MiB | 1 MiB | Bounded word-operation scratch |

The Boolean variable bound is 2097151. Cache collisions can lose sharing but
cannot change a clause: keys are checked completely before reuse. Pure
commutative word operations normalize their two operands after the original
folding rules. This changes no ordered trap projection. The implementation
uses watched literals and first-UIP conflict analysis. Every SAT result checks
all clauses, reconstructs all observed word values independently of bitblast,
and requires an actual observation mismatch before publishing its model.

## Construction and qualification

The final native source is 375940 bytes; the flat is 444161 bytes. Exact hashes
and evidence digests are in `HIA_GENERAL_CNF_NATIVE.json`. Actual construction
ran the qualified HIA assembly frontend, HIA reference-wire projector, and
independent HIA endian seed backend as three sealed native executables with an
empty PATH. All Core, wire, and final flat bytes matched the separately built
development reference. No target or successor compiler was used.

The component evidence includes:

- All 95 distinct original graph packets representing the original 113 calls,
  under their original 2-second budgets; every result matched fresh pinned Z3
  4.15.4 reference encoding, and SAT arguments were replayed through Core VM.
- General boundaries including 32 parameters with unit and signed values,
  16 returns, 128 blocks, 2048 operations, 45000 block parameters, 92009 word
  nodes, and a real 188592-variable formula. Pigeonhole queries exercised
  actual conflict learning and UNSAT search.
- 69 request, continuation, poison, real allocation exhaustion, and same-deadline
  controls. The valid 2048-add case reached the actual 1048576-clause capacity
  and returned Unknown without a completed formula digest.
- 128 deterministic random Core pairs. Native results all finished within the
  original 2 seconds. 127 have direct whole-query Z3 confirmation. The remaining
  case's whole-query Z3 result stayed Unknown at both 2 and 60 seconds; those
  failures remain preserved. Its equivalence was independently proved by exact
  Core-structure induction using 74 solver-proved pure primitive commutations.
  This is a distinct proof method, not a relabeled whole-query result.
- 35 universal word commutation proofs, 134 actual graph-SHA boundary cases,
  16 concurrent queries sharing the same code with independent workspaces,
  and six separate Boolean bound-marker queries.

These are component qualifications. They do not claim that every general
query will be decided within its time or allocation budget, that the complete
service is installed, that implementation soundness is machine-proved, or that
the separate 60-phase cold run has passed its 180-second gate. The preserved
cold V7 failure remains open.
