# Guarded HIA reductions with independent inductive validation

This increment implements an executable fast path for a narrow, useful case:
unsigned byte reductions whose original source traps on integer overflow.
It preserves the complete checked implementation as the fallback. A proposed
loop invariant is untrusted input; only discharged obligations authorize native
publication. Neither an optimizer's confidence nor an NDU recommendation grants
that authority.

The modules are `hepta/hia_guarded_optimization.py` (proposal, structural
contract, guarded composition and artifact publication) and
`hepta/hia_inductive.py` (independent edge/check verification). They complement
the existing exact scalar-segment checker rather than widen its assumptions.

## Why the guard is necessary

For a byte reduction with an initially zero unsigned 64-bit accumulator, a
useful invariant is

\[
0 \le i \le n,\qquad 0 \le s \le 255i.
\]

A successful byte load supplies `0 <= b <= 255` by its Core type. If the loop
continues only while `i < n` and the runtime entry guard establishes

\[
n \le \left\lfloor\frac{2^{64}-1}{255}\right\rfloor,
\]

then the accumulator update cannot overflow. Replacing that specific checked
addition with wrapping addition has the same value and trap behavior on this
guarded path. This argument does not assume a particular allocation size or
allocator policy. Inputs outside the guard execute the complete original Core.
A smaller guard is allowed and makes both paths directly testable with small
ordinary inputs.

The default proposer recognizes a finite counted-loop pattern and suggests the
guard and invariants. Recognition is not a proof. For example, a producer that
asserts the accumulator began at zero when the actual Core initializes it to one
fails the independently checked initialization obligation.

## Exact supported change

A proposal has schema `hepta.hia.guarded-reduction-proposal.v1` and contains:

- `base_sha256`, binding the original standalone program;
- `fast_core`, the actual candidate operations;
- `guards`, identifying the actual function argument and unsigned maximum;
- `invariants`, bounded typed predicates at each block entry;
- `changes`, the exact function/block/instruction inventory.

Only listed unsigned `int.add.checked` instructions may become `int.add.wrap`.
Function signatures, effects, resource operations, calls, block structure,
successors and all other instruction attributes must remain identical. A
declared change that differs from the actual code rejects before solving.

The supported predicate vocabulary is deliberately small: unsigned order,
equality, constant bounds and bounded scaled inequalities. The independent
encoding widens scaled expressions to 128 bits; it does not let modular
overflow make a false invariant appear true. Metadata, instructions,
constraints, obligations and solver time are bounded.

## Independently discharged obligations

The verifier checks each of the following against the actual original Core:

1. The runtime guard and function inputs establish the entry invariants.
2. Each actual jump and each branch arm preserves the destination block's
   invariant under that edge's condition.
3. Every removed overflow check is unreachable as a trap when execution reaches
   that exact instruction under the block invariant and successful original
   instruction prefix.

Resource/effect instructions remain in place. Their successful scalar outputs
are fresh typed unconstrained values. The proof assumes no additional buffer
contents, length relationship, alias fact or allocator success. The existing
first-trap model prevents a later value equivalence argument from silently
removing an earlier observable trap.

All obligations must be `unsat` when queried for a counterexample. `sat`,
`unknown`, timeout, exhausted budget, unsupported predicate, malformed inventory
and implementation identity drift fail closed. Every complete SMT query and
its digest is retained. Z3 is fixed to the admitted version and each request
uses its own solver context.

## Composition and final artifact identity

The implementation first freezes the producer's input. It independently
reconstructs a single guarded function containing a guard block, the fast CFG
and the original checked CFG. Exactly one branch runs. Owner values enter one
body, so resources are neither duplicated nor replayed. There is no additional
native call frame for the fallback dispatch.

The composed standalone Core passes the same `verify_program` authority as all
other admitted inputs. Native output uses the existing direct LLVM backend.
The receipt binds original Core, fast Core, composed Core, guards/invariants,
proof obligations, solver, checker, compiler, target and final native bytes.
Compilation occurs in private staging, with identity checks before publication.
Changing a producer dictionary after proof cannot change the frozen program;
changing checker source while compiling refuses publication.

Runtime consumers must load the receipt-matched sealed image. A mutable output
path by itself is not a permanent identity guarantee.

## Command line

```sh
hepta hia lower input.hepta --output baseline.core.json
hepta hia optimize-guarded baseline.core.json --output reduction.proposal.json
hepta hia verify-guarded baseline.core.json --candidate reduction.proposal.json
hepta hia build-guarded baseline.core.json --candidate reduction.proposal.json \
  --clang clang-20 --output candidate.so
```

`optimize-guarded --maximum 32` exercises a smaller guard with a full fallback.
A rejected or timed-out proposal is not published by that action. Native build
performs its own admission again; a prior JSON receipt cannot substitute for
the actual candidate.

## Qualification and boundaries

The tests include genuine SMT induction, forged invariants and guard bounds,
unlisted semantic changes, budget/timeout/unknown refusal, actual VM fast and
slow paths, allocation failures, actual sealed native execution and source
identity drift during build. The unchanged unguarded fast candidate remains
rejected by the original equivalence checker.

This is not a proof of the whole compiler, arbitrary memory optimization,
general CFG rewriting or native LLVM correctness. The Core semantics and
verification implementation, SMT encoding and solver, native backend, loader,
OS and hardware remain part of the trust boundary. A valid proof also says
nothing about whether the added dispatch or compilation cost is profitable.
Those claims require the separately retained native performance measurements.

Unsupported naming patterns or structures may conservatively reject, including
a candidate whose generated CFG prefix would collide with an existing SSA
name. Rejection is explicit; no unchecked fallback backend is selected.
