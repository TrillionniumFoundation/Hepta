# Independent Rust parameter-bound returned loans

`--owned-run` admits the finite primitive v8 byte-owner subset with profile
`bounded-cfg-byte-owner-loan-returns-v4`. The existing Rust parser, ownership
flow checker, scalar `Machine` and byte storage implement this extension;
neither Python-generated receipts nor a second execution engine grant admission.
Canonical Python Core remains the production authority.

## Static contract and dynamic identity

Rust independently parses optional, arity-matched `return_loans`. Borrowed
results name an original borrowed input with sufficient permission; scalar
and owner result positions are null. Missing annotations cannot authorize
borrowed results. Old versions still reject borrowed results and the new field.

Capabilities carry the original parameter identity independently of SSA root
and parent names. CFG transfers rename graph nodes while preserving that
identity. This extra join restriction applies only to functions returning
loans, so the existing scalar/owner/nonreturning-loan CFG grammar is unchanged.
Return validates every result before consuming it: its origin must match the
declared parameter, it must be that external parameter or its direct child,
and it must have no active children. Duplicate handles, local owner escape,
deeper descendants, wrong origin, mutable aliasing and permission escalation
reject. Calls instantiate each result as a child of its declared actual input.

The same execution Machine retains original actual bindings through loops,
CFG renaming and recursion. Forwarding an input creates a distinct child loan
and one started-loan event. Returning a callee-created direct child transfers
its handle without another event. Distinct shared formals may alias one caller
view; returned shared handles remain separately consumable. Independent mutable
origins may swap only under their declared ordering. Parent access and ending,
owner move/drop, and subsequent calls remain subject to the original graph.

All frames share the existing step, root-inclusive 32-frame and 16 MiB live-byte
limits and allocation-failure counter. Successful scalar entry returns must
have a clean ledger. Trap, allocation failure and budget stops retain the
resources actually live at the stop; no synthetic unwinding is reported.

## Wire profiles and unchanged boundaries

| Input | Independent static receipt | Byte-owner execution profile |
| --- | --- | --- |
| Primitive v1–v7 without chain signatures/operations | `hepta.hia.rust-owner-shadow.v1` | `bounded-cfg-byte-owner-bulk-v3` |
| Primitive v8 without chain signatures/operations | `hepta.hia.rust-owner-shadow.v2` | `bounded-cfg-byte-owner-loan-returns-v4` |
| Primitive v7/v8 with chain signatures/operations | Same version-specific static receipt | `bounded-cfg-owned-memory-v5` |

The v8 static receipt adds exactly
`v8_parameter_bound_loan_returns_checked=true`. The Python executable-pinned
crosscheck reconstructs the expected receipt and claims from canonical input;
an old envelope, missing/false/integer claim or a v8 claim on an older program
rejects. Scalar-only checking/execution remains v1–v7 and does not silently
inherit v8. This crosscheck corroborates a pinned development executable; it
does not make that executable or its self-reported claims a production proof.

Static chain owner/loan checking includes v8 inherited chain operations.
The separately versioned [v5 execution profile](HIA_RUST_RETURNED_CHAINS_V8.md)
composes these operations with parameter-bound returned loans in the same
Machine. The whole module still rejects unknown operations and illegal loan
graphs, including unused helpers behind an immediate trap or failure. Direct
nominal input, public resource handles, arbitrary lifetime parameters, self-reference,
asynchronous cancellation and external lifetimes are not qualified. The
extension does not prove native refinement, whole-language safety or Rust
performance superiority and does not close P2 as a whole.

## Reproducible execution and retained evidence

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_returned_loans tests.test_hia_rust_crosscheck -v
python tools/qualify_hia_rust_owned_cfg.py --returned-loans --output /tmp/hia-returned-loans.json
```

The v8 qualifier requires a clean unchanged Git commit and source inventory.
It retains actual programs, each complete Python/Rust execution pair, binary
identity, policy limits, raw method logs, and independent negative input bytes
with both Rust shadow and execution refusals. The corpus exercises forwarded
and created children, CFG renaming, recursion, loop-carried parents, shared
actual aliases, mutable origin ordering, read-only results from mutable input,
each executed step cut, heap/allocation failure and partially-created results.

Its observations are distinct from the existing CFG/bulk v3 corpus and are
never added to the number of unit test methods. Historical counts belong to
their recorded source identities; final integrated qualification must run on
the combined clean commit.
