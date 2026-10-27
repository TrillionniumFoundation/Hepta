# HIA Rust decoder incremental node/depth budget hardening

**Scope:** P7 hostile-input resource safety on the existing HIA Rust shadow
verifier/execution frontend. This changes no HIA ISA, Python semantic
authority, Owner/Loan checker, LLVM emitter, C/C++ translator or ABI profile.

## Defect and correction

Previously the Rust `UniqueJson` serde visitor rejected duplicate object
keys, floating values and input documents above 8 MiB, but its
262,144-node / 64-edge structural traversal only ran **after** allocating
the complete nested `serde_json::Value` object graph. A short JSON document
containing many tiny values could spend substantial memory and parsing time
before being rejected.

The existing visitor now carries subtree node counts and maximum child depth
while parsing arrays/maps. Each completed child is added with overflow-safe
arithmetic; the parser refuses a composite as soon as it crosses the existing
limit, before appending the over-budget subtree. Duplicate object keys are
refused *before* parsing the duplicate value. This preserves the known
`E_HIA_LIMIT` versus malformed `E_HIA_FORMAT` diagnostic distinction, and
retains the post-parse structural validator as defense in depth.

The subtree path metric is the number of edges from composite root to its
deepest leaf. A leaf has depth zero and counts as one node; object member
keys are not value nodes. This matches the existing post-parse walker.

## Regressions committed

`rust/hia-core-shadow/tests/decode_budgets.rs` exercises:
- 262,144 scalar array entries plus one root: node-budget rejection by the
  real Rust scalar, owned and execution entrypoints under the 8 MiB text cap;
- depth 64 accepted by the decoder (later schema rejection), depth 65 rejected
  during decoding;
- oversized byte input and duplicate object field rejection;
- an ordinary malformed finite program produces `E_HIA_FORMAT`, not a false
  resource-limit diagnostic.

Real acceptance requires Cargo build and test execution on this exact
source commit, together with Python↔Rust scalar/owned differential and the
existing native/source gate regressions:

    cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
    python -m unittest tests.test_hia_rust_scalar_vm \
        tests.test_hia_rust_owned_shadow tests.test_hia_rust_shadow -v

No CI status is a development prerequisite. The file-size limit is still a
finite 8 MiB cap, not a kernel-enforced RSS/CPU quota and not proof that
arbitrary malicious JSON deserialization consumes constant resources.

General executable provenance, source-to-native formal refinement,
arbitrary C++ L2/L3, full target ABI, Agent-model A/B, physical DMA/GPU,
long-run production p99 and all-project soundness remain OPEN.
`whole_project_blockers_closed=false`.
