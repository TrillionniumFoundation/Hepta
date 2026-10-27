# HIA P7: early JSON node/depth admission on canonical v7 stack

## Exact code lineage

- Recipient PR #282 exact HEAD `0dd3d212a3d01a1f69b075dddc1519d987219e7d`.
- Donor PR #274 exact `fbf6abdc7156187c962544c3261a577ab81b3c30`.
- The existing bounded syntax-only scanner and its two source test modules
  were transplanted as exact unchanged Git blobs. The recipient's existing
  `hepta.hia_program._decode` was changed at ONE reviewed call boundary
  only; its v7/composite schema registry, immutable normalization, owner/loan
  verifier, interpreter and LLVM backend remain unchanged.
- The new v7-specific test verifies canonical Core identity, composite-v2
  syntax preservation, over-budget dense JSON refusal before full decode,
  excess depth refusal and decoded-key duplication rejection.

## Security invariant

Before constructing a full Python JSON Value graph, reject an encoded
standalone HIA input exceeding 262144 structural nodes or depth 64. The
syntax preflight counts value nodes, not object keys, and decodes individual
keys only to enforce equality of escaped spellings. The accepted syntax
subset is integers, bool, string and null, as already required by the Core.
The existing `json.loads` with duplicate-key hook and the canonical
`verify_program` still independently parse and validate the complete
program after this preflight; untrusted producer hashes/claims confer no
permissions.

A valid v7 or composite-v2 input must NOT be incorrectly interpreted under
the older primitive-v6 profile. The scanner never examines or grants schema
permissions. It is *not* a general-purpose process RSS limit for caller-
constructed Python objects or native processes.

## Executable checks

```sh
python -m unittest tests.test_hia_json_preflight \
    tests.test_hia_json_predecode tests.test_hia_p7_v7_json_predecode -v
python -m unittest tests.test_hia_program tests.test_hia_program_composite \
    tests.test_hia_program_llvm -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

The donor standalone scanner previously reported isolated 6/6 CPython
tests, but that is **not** a test of this new combined exact HEAD. The
current shell has no complete GitHub checkout (DNS unavailable) or pinned
Rust/Cargo; these in-repository Python/LLVM/Rust tests have NOT run against
this source revision. CI queue state is irrelevant to engineering progress
but never counted as a passing test.

P0–P7 complete native/ABI/migration/Agent/hardware/formal blockers remain
open. `whole_project_blockers_closed=false`.
