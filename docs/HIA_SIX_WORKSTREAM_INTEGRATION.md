# Integrated HIA implementation baseline

This work selects `63971f5fbf992be0ace9c1949ec0dd9c3ede7a21` (#346) as its
starting implementation. It ports source deltas rather than merging unrelated
experiment histories or treating comparison summaries as a complete file
inventory. A GitHub comparison can truncate its changed-file list; complete
Git tree and local `git diff --no-renames` comparisons are required here.

## Source provenance

| Source | Compared from | Integrated scope |
| --- | --- | --- |
| #325, `0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997` | `d5a0bf0e42611309cbc6461b1a414b9f8ece254f` | Certified modular and guarded narrowing, prepared internal proof reuse, unique-owner C++ project capture, explicit routes and CLI, associated regression tests and required benchmark protocol/driver |
| #329, `fc5c155c47a7920519ed79a9953f8e415b0a7863` | `739e84a402a800d51abefc6007118c887db7d91a` | C++ upstream host/toolchain capture, actual bad-signature controls, nested record-field returned loans, loaded-mapping observation and pinning cleanup repair |
| #342, `f9e1ad206e38bd97ba6747e8ece725d1eba2c78e` | `1739484bbda1a49a39b05714e2017d35b5c2c7e9` | C contract identity resolved by ABI argument position, including slice extents and record initialization sources |

NDU graph/session/cache code is reconciled separately with the same selected
source heads. Historical experiment results remain evidence about their own
recorded source, toolchain and inputs. They do not qualify this combination.
The round-three benchmark protocol and C driver are required source fixtures;
their presence does not report a newly executed performance result.

## Conflict decisions that preserve the stronger contracts

- Primitive v8 continues to use only `return_loans`. The older donor spelling
  `return_origins` is not an executable alias. Stable nested field projection
  chooses the actual scalarized leaf and binds it using the canonical field.
  Existing multiple-result alias checks and public-entry restrictions remain.
- Composite v3 continues to normalize to primitive v7. It does not silently
  acquire v8 returned-loan semantics.
- `hia optimize` retains finite NDU proposal/ranking semantics; constant folding
  remains `hia fold-constants`. Narrowing receives separate explicit commands.
- Prepared admission publishes an image and its internal proof transactionally.
  Interrupted unpublished images retire through the existing release ledger;
  a fully committed image stays owned if interruption occurs before return.
  Unknown loader/descriptor release outcomes remain quarantined, consume the
  admission budget and are never retried by numeric identity. Public function
  references are revoked before attempted unload.
- C++ capture keeps bounded process-tree handling and exact raw captured bytes.
  Added host qualification does not weaken existing platform refusal paths.
- C declaration agreement compares validated contracts at argument positions,
  including fixed-versus-parameter extents. Parameter spelling cannot hide a
  conflicting extent or initializer source in another translation unit.
- Existing independent Rust shadow, byte-budget, native-retirement and pinned
  NDU transport profiles remain separate. No observed result or external
  ranking receipt becomes checker, publication or deployment authority.

## Existing ports retained from the baseline

#333 contract snapshotting, #334 typed owner/chain roots and call-formal scope,
#335 uncertain cleanup ownership, and #338 partial-record/constexpr/impact
changes were selectively reconciled in #346; those PR heads are not its Git
ancestors. Their earlier files must not replace the reconciled implementation.
#344/#345 Cargo environment changes are already superseded by the tested
runner-time environment setup in #346. #342's argument-position defect was
still absent and is therefore added explicitly.

The standalone verifier and direct LLVM route are not claims of whole-language
soundness, full source/backend refinement, unrestricted C/C++ translation,
Rust performance superiority, or globally optimal instruction generation.
Fresh integrated qualification must retain failures, skips, source identities
and native tool identities instead of inheriting another branch's green result.

## Reproducible inventory on the unified source

[HIA_INTEGRATION_SOURCES.json](HIA_INTEGRATION_SOURCES.json) records selected
heads, their actual delta bases, retained/reconciled/unintegrated decisions and
original experiment identity fields. After committing the complete integrated
tree, run:

```sh
python tools/inspect_hia_integration.py --expected-head ACTUAL_COMMITTED_SHA --output /tmp/hia-integration-inventory.json
python tools/qualify_hia_safety_contract.py --output /tmp/hia-safety-contract.json
```

The inventory rejects a dirty or different source and inspects complete Git
trees. Missing/unchanged donor paths are failures unless explicitly excluded.
An identical donor blob is mechanically retained. A changed selected blob is
identified as reconciliation requiring semantic review; file presence itself
does not prove that all behavior survived. The conflict decisions above and
fresh source-bound tests supply that separate review and evidence.

The round-three benchmark/graph/stateful registrations record Git base
`4fcc2c3735f3637932edd13ded814880743723f5` with working-tree/source bindings.
The production source checkpoint later archived by #325 is
`5b66f96af480d6f599d8646cff6ef7e542de1072`; the final evidence archive head is
`0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997`. These are different identities.
The matched-agent registration contains source SHA-256 maps without a clean
Git source commit, which is recorded as missing instead of invented. The JSON
inventory retains exact registration-file SHA-256 and original identity field
paths; none of these old records qualifies the new integrated source.
