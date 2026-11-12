# Executed Rust shadow integration and global JSON budget

This change is based on PR #319, exact parent
`209fa298127adf41b24d128d0291dcb4a0649c73`. It closes two reproduced
integration defects in the existing opt-in Rust shadow path. The canonical
Python HIA verifier remains the production admission authority.

## Real producer/consumer disagreement

The Rust scalar producer already emits `v7_scalar_only_checked` and
`v7_chain_resources_supported`. The Owner/Loan producer already emits
`v7_chain_owner_loan_cfg_checked` and `v7_chain_native_semantics_proved`.
The Python crosscheck consumer still required the older exact claim sets and
allowed only Core v1-v6. Actual compiled producer output therefore failed:

| Canonical input and explicit profile | Baseline result |
| --- | --- |
| v1 scalar | `shadow safety claims: unexpected, missing or duplicated fields` |
| v1 owned | The same claim-shape rejection |
| v7 scalar | `the pinned Rust shadow profiles support only primitive v1..v6` |
| v7 owned | The same version rejection |

These outcomes were reproduced with the old consumer loaded from the exact
parent and the actual locally compiled Rust executable. The old mocked
protocol tests passed because their fake reports repeated the same stale
claim shape.

The consumer now accepts the current producer's exact fields and primitive
v1-v7 grammar. Version-dependent claims must be strict Booleans equal to the
canonical Core version. Missing fields, extra fields, an integer used as a
Boolean, a wrong version claim, a changed digest and upgraded safety claims
still reject. Scalar mode continues to refuse resource programs; no automatic
Owner/Loan mode selection is introduced.

The new real-executable regression builds the locked crate, obtains its path
from Cargo's compiler-artifact records, pins its SHA-256, and exercises the
whole existing byte-pinned crosscheck runner. It covers scalar and owned inputs
under every version v1-v7, the real nine-function recursive-chain module, and
canonical normalization of generic records/enums, stored loans, cooperative
tasks and the eleven-function composite-v2 chain module.

## Global budget before visiting the next JSON value

The previous Serde visitor counted each subtree only after its child was
fully decoded. A large prefix plus a nested suffix could therefore decode
additional values after the whole document's 262,144-node limit was reached.
On a bounded adversarial array containing a floating value in that suffix,
Python refused with `E_HIA_LIMIT` before allocation, while the old Rust visitor
reached the forbidden suffix and returned its floating-value `E_HIA_FORMAT`.

The existing visitor now carries one shared node counter through Serde's
`DeserializeSeed`. Each value consumes its budget before it is deserialized;
depth is also checked before visiting that value. The same strict duplicate
key and integer-only decoder is retained, as is the post-parse structure
check. This is a budget fix in the existing decoder, not a new HIA grammar.

Executed controls cover the inclusive node limit, the next nested array or
object value, depth 64 versus 65, and duplicate-key rejection before its
unvisited value. Both scalar and owned entrypoints agree with the Python
predecode boundary. The input-byte cap remains 8 MiB.

## Executed validation

Toolchain: Rust 1.90.0, Cargo 1.90.0 and native Linux `/usr/bin/python3`
3.12.3. Cargo dependencies were fetched against the committed lockfile;
the following executions were offline. Build products used a
`CARGO_TARGET_DIR` outside the source tree.

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
/usr/bin/python3 -m unittest \
  tests.test_hia_rust_shadow \
  tests.test_hia_rust_owned_shadow \
  tests.test_hia_rust_calls_shadow \
  tests.test_hia_rust_chain_shadow \
  tests.test_hia_rust_scalar_vm \
  tests.test_hia_rust_crosscheck \
  tests.test_hia_rust_crosscheck_cli -v
```

- Rust: **47 tests passed**, zero failures, zero ignored.
- Python: **35 tests passed**, zero failures/errors/skips.

The suites exercise real Rust verification and scalar execution, scalar type
and overflow behavior, explicit exports, internal-call effects, recursion and
step-budget parity, Owner/Loan CFG joins, conflicting aliases, consumed owners,
versioned byte operations and v7 chains. Protocol tests using deliberately fake
executables remain separately labeled in the same suite. These counts are test
methods, not a new combined count of unique semantic cases or native HIA runs.

The executed source increments are bound by SHA-256:

| File | SHA-256 |
| --- | --- |
| `hepta/hia_rust_crosscheck.py` | `32ed8d1302cb30c3fbb1d6ee5fd178b44cf713c97434c4c9278d00872e38a6d4` |
| `rust/hia-core-shadow/src/lib.rs` | `8196c04bee513f22056abeed7b196f95edc45cf71f9dbb9d2bdda528394e9628` |
| `rust/hia-core-shadow/tests/json_budget.rs` | `5d6e44a7a8b12a3b84eb970ed4bb536bf163b040753e15e69d5fbdeddf1ca457` |
| `tests/test_hia_rust_crosscheck.py` | `56a30dbd0fb0e750e657efd99ca14143b843a5130aef2788cd8f665e7ae00bc6` |

No new HIA operation, ABI, LLVM backend, ownership rule or production authority
is introduced. These finite tests do not prove general memory provenance,
allocator semantics, frontend/backend refinement, native resource execution,
concurrency, physical hardware, performance or Agent productivity.
`whole_project_blockers_closed=false`.
