# Captured C post-test loops

The captured project translator now accepts a finite `do { body } while (condition)`
subset through the same checked Hepta source and HIA Core routes as its existing
`while` and `for` support. The declaration inventory, compiler-owned original
types, captured flags/dependency identity, pointer contracts and publication
rules remain mandatory.

## Execution and scope

A fresh first-iteration Boolean, initialized to `true`, short-circuits the
condition of one ordinary Hepta `while` loop. The body resets it to `false`;
subsequent loop headers evaluate the original postcondition. Only one body is emitted.
The translation neither duplicates cursor movement nor reorders condition reads
before the first body. The existing independent Core verifier, interpreter and
LLVM backend consume the resulting program.

The P0 convergence retains the newer shared structured-control lowerer from
the eight-track candidate. Braced and single-statement bodies, local declarations,
nested structured loops, nearest-loop `break`/`continue`, and returns use that
one path. A return or break skips the postcondition; a continue reaches it.
`goto`, labels, `switch`, and mutating post-test conditions remain refused.
Generated names use a separate namespace. This is not a complete C control-flow
implementation. The earlier round8 exclusions are historical and do not describe
the converged implementation.

For the captured value translator, the separate definite-assignment pass
checks the first body using the incoming state, keeping normal, break and
continue exits separate, then checks the condition and successor using only
assignments established on every reaching path. An
outer `while` or `for` can still execute zero times. Missing branch assignments,
self-reads before first assignment and assignments made only by a possibly
empty nested loop remain rejected. The record-view translator retains its more
restrictive existing rule for deferred local declarations.

The loop does not introduce a resource cleanup rule. Successful calls retain
the existing owner and loan accounting. A specified trap or finite VM budget
stop reports the actual live state; it does not report destructors that did not
run. A zero-length cursor input cannot avoid its first dereference merely
because the eventual condition would be false.

## Actual application qualification

`tools/qualify_hia_c_posttest.py` uses the existing Ring-Buffer and musl comparison
application. All locked upstream source files remain unchanged. One already
authored checksum translation unit receives a maintenance edit from an
eight-iteration `for` to an equivalent post-test loop. This distinction is
recorded in the protocol and before/after source hashes.

The captured four-unit project contains eleven upstream function bodies and
one authored checksum body, with one separately authored Hepta client. The
qualification retains the original inputs and contracts, exact consumed Clang
ASTs, generated Hepta/HIA/LLVM, original and generated native artifacts, build
receipts, bounded child process logs and every observed result. Original C
objects are not linked into the HIA target. The HIA public ABI remains scalar;
borrowed buffer capabilities stay internal.

The fixed protocol has 48 input cases, each compared against two original C
compiler routes, the HIA native route, the HIA interpreter and an independent
checksum recurrence. Sixteen resource scenarios cover empty, successful and
rejected lengths with allocation refusal at attempts 1, 2 and 3, plus normal
allocation. C and HIA native allocation/free observations are compared against
the interpreter. These are separate, overlapping cohorts, not a total of
unique tests.

The command requires a full expected source commit and a clean source tree. It
checks every tracked source byte and executable mode against that commit both
before and after execution using the existing integrated identity reader.
Evidence must go outside the source inventory. Failures retain their artifacts
and produce a nonzero CLI exit.

```sh
python tools/qualify_hia_c_posttest.py \
  --expected-source "$(git rev-parse HEAD)" \
  --clang /path/to/clang-20 --cc gcc \
  --output /absolute/new/evidence-directory
```

This qualification targets actual Linux x86-64 LP64 execution. It does not
establish additional host coverage, C source equivalence for all inputs,
arbitrary C/C++ migration, native refinement proofs, foreign pointer provenance
inference, or a performance advantage. The existing broad goals and prior
evidence retain their own scope and source identities.

## Regression contract

`tests/test_c_project_do_while.py` exercises the first-iteration rule, deferred
assignment, direct C/Rust/HIA execution, stable syntax/effect refusals, native
abort before a false condition can hide a body trap, real stopped-resource
ledgers and the captured upstream application maintenance case. The separate
qualification command produces durable per-run artifacts; temporary unit test
directories alone are not presented as a complete migration evidence archive.
