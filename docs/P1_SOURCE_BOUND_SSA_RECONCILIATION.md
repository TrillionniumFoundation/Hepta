# P1 — source-bound HSIR to independently checked scalar CFG/SSA

This is a strict source-revalidation bridge from PR #14 source_bound_v0
into PR #37 frozen HSIR -> CFG -> SSA -> independent verifier. It does
not make every PR #14 program compatible and does not prove backend semantics.

## Actual producer and consumer commands

On the PR #14-derived compiler, capture the v1 JSON from stdout:

    python -m hepta hsir-v1 file.hepta > /tmp/pr14-export.json

On the PR #37-derived compiler, keep the exact same source bytes:

    python -m hepta ssa-v1-reconcile file.hepta \
      --envelope /tmp/pr14-export.json --rustc /path/to/pinned/rustc

The consumer accepts the versioned PR #14 CLI envelope or its inner
hepta.hsir.integration.v1 object. Malformed/duplicate/unbounded JSON
and large source files reject. There is no frontend-only flag on this
new command.

## Mandatory gates

1. Verify source-bound v1/v0 digests, source SHA, and unproved claims.
2. Reject imports, nominal types, all owned/borrrowed/lifetime/generic
   parameters, external assumptions, FFI, volatile operations, unsafe
   effects, nonempty resource contracts and unsupported control flow.
3. Convert only typed, by-value, pure-or-panic scalar expressions to
   the PR #36 frozen structural expression profile.
4. Independently parse and check the exact original source with the
   PR #37 compiler; require actual rustc validation and status
   rust_borrows_types=rustc_checked.
5. Compare ordered function signatures, parameter ownership/type, ABI
   direction, declared/inferred effects, resource contracts, and all
   normalized scalar expression/statement operations. A rehashed v0
   semantic mutation is rejected even if source SHA remains unchanged.
6. Invoke the existing CFG, pruned scalar SSA and independent verifier.
   Report the original v1/v0 and new target HSIR/CFG/SSA identities.

The report says external project identity is not independently verified.
It does not assert memory/resource safety for generic PR #14 programs,
source-to-IR semantic equivalence, native codegen permission, or foreign
C/C++ library safety. Anything requiring resource/memory SSA, general
borrow/provenance semantics or full project imports deliberately rejects.

## Tests and scope

Implemented files:
- hepta/source_bound_reconcile.py
- hepta/cli.py
- tests/test_source_bound_reconcile.py
- tests/test_source_bound_reconcile_native.py

Local Python 3.13.5 isolated tests: **11/11 passing**. The tests cover
typed scalar mapping, source/semantic divergence, invalid/hash mismatched
source, FFI/Owned/resource refusal, borrows/generics, incomplete native
state and malicious unhashable AST fields. Native calls in these eleven
isolated unit tests are mocked and do not qualify rustc or LLVM.

Two additional real-rustc/CFG/SSA tests are committed, including a
semantically different but rehashed PR #14 function body. They have not
been run here: a complete PR #37 checkout and pinned rustc were unavailable
in the container. Running them is a remaining acceptance condition.

P0 integration, ownership/provenance-aware SSA, source-to-backend
refinement, P2–P7 and original P01–P12 remain open.
