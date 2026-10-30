# Rust raw Copy-record normalization candidate

Rust can now read a declared subset of **raw `hepta.hia.composite.v1`** input,
check nominal identities before erasure, normalize it to the existing
`hepta.hia.program.v6`, and execute it through the existing Rust checker and
Machine. The native child does not invoke the Python normalizer or evaluator.
This is an explicit finite candidate input path. It does not replace production
`verify_program`, `execute_core`, `hia run`, route admission or LLVM admission;
those still use the Python authority.

Previously the Rust Machine received primitive bytes after Python had already
performed every nominal check. Merely wrapping that process in another Python
execution API would retain the same semantic dependency. This increment adds
the missing native nominal front pass for one stated subset. P2.1 and P2.2
still require the remaining production input domain and deployment gates.

## Exact accepted input and rejection boundary

The new commands accept the existing composite-v1 object shape with `schema`,
`module`, `types` and `functions`. Type declarations must be `record` with
`params: []`. Fields may be machine scalars or other acyclic Copy records;
nested and empty records are included. Both a declared record's string name
and its concrete `{"name":"Record","args":[]}` reference are accepted.

Supported nominal operations are `record.make`, `record.get` and
`record.unpack`. Calls, branches, jumps, loops, scalar arithmetic, returns,
explicit traps and the existing primitive-v6 byte-owner/view operations are
available. Primitive byte resources may occur inside functions and internal
signatures; they may not be fields of these Copy records. Function results
cannot carry loans, preserving composite-v1's original rule.

Resource-bearing or stored-loan records, generic declarations/instantiations,
enums and `match`, cooperative tasks, partial records, `record.borrow`, later
composite schemas, primitive chain operations and legacy nominal-v2 input are
outside this candidate. Their presence anywhere in the submitted module,
including an unused declaration or function, refuses the whole input. The
candidate does not erase an unsupported declaration, import an alternate
producer profile or fall back to Python. Existing primitive Rust entrypoints
continue to reject raw nominal input.

All source nominal identities are checked before flattening. Two distinct
records with identical machine layouts remain different types at construction,
calls, results and CFG edges. Empty records still have SSA names and nominal
types even though they contribute zero primitive slots. Duplicate definitions,
undefined values, incompatible function entry parameters and invalid unused
functions cannot disappear through erasure. A primitive instruction cannot
reinterpret a nominal value as a scalar or discard an extra empty argument.

The public `exports` list is derived from original signatures: every parameter
and result must originally be a primitive scalar. A record helper does not
become public when flattening leaves one scalar or no slots. Native execution
checks these actual Core exports before entering the Machine.

## Native commands and identity

```sh
hia-core-shadow --composite-record-normalize < raw-composite-v1.json
hia-core-shadow --composite-record-run-bound-v1 FUNCTION JSON_ARGS JSON_POLICY < raw-composite-v1.json
```

The normalization report uses
`hepta.hia.rust-copy-record-normalization.v1`, profile
`monomorphic-copy-records-over-primitive-v6-v1`, canonical nominal
`input_sha256`, actual primitive `program_sha256`, the normalized `core` and
explicit finite/non-authority claims. Returning this JSON grants no admission
token; there is no report-import shortcut. Normalization and execution both
start with actual raw input and the existing bounded, duplicate-safe Rust
decoder, then recheck the full generated Core with `verify_owned`.

Execution uses a separate
`hepta.hia.rust-copy-record-bound-execution.v1` envelope. Its request binds the
canonical original nominal input digest, actual Core digest, selected input
profile, function, ordered scalar arguments and complete bound-v4 policy.
The execution payload is the existing bound-v4 Machine's report. Renaming a
record or field can leave the primitive Core unchanged, but it changes the
original-input identity and bound request. The raw source byte stream is
retained separately by the collector, including noncanonical JSON spelling.

No Core schema, primitive opcode, evaluator, ownership checker, ABI, default
backend or production-switch flag is introduced. The normalizer is a native
implementation of this nominal input subset; the primitive resource and
execution semantics remain those of the existing checker and Machine.

## Bounds before expansion

The candidate uses the existing input limits of 8 MiB, 262,144 JSON nodes and
JSON depth 64, together with the existing 1,024-function and 4,096-block limits.
It retains the nominal budgets: 128 declarations/monomorphic instantiations,
64 fields per record, 32 layout depth, 512 flattened fields, 8,192 generated
names and 32,768 elaborated value slots. Every declared layout is checked,
including unused layouts; this is an explicit conservative candidate boundary.

Repeated Copy aliases can amplify a small source into many erased scalar
arguments or result types. Binding lookups retain references while original
types are checked. Checked width sums must fit the remaining Core-node quota
before scalar-name vectors are cloned, collected or extended. Function result
types and emitted parameters/outputs use the same pre-materialization check.
Each counted scalar reference occupies at least one final Core JSON node, so
this guard is a necessary existing Core limit; full Core structure, byte,
type, effect and resource checks still run afterward. The guard is not a
whole-process RSS theorem or a claim that all verifier allocations are covered
by the logical payload budget.

The bound-v4 execution policy remains unchanged: up to 256 root-inclusive
frames, ten million allowed ticks and 1 GiB of logical payload/node bytes;
the complete policy is at most 1,024 bytes and uses exact canonical positive
hex failure indices. Public scalar transport remains at most 8,192 arguments
and 128 KiB. A trap or budget stop retains its actual stopped ledger; no
destructor cleanup or cancellation is invented.

## Required finite qualification

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python tools/qualify_hia_rust_copy_records.py --expected-head COMMIT --output-directory /tmp/new-raw-records
python tools/qualify_hia_rust_api_v4.py --expected-head COMMIT --output-directory /tmp/new-bound-v4
python tools/qualify_hia_composite_returned_loans.py --expected-head COMMIT --output-directory /tmp/new-composite-v4
python -m unittest tests.test_hia_safety_protocol tests.test_hia_integrated_inputs tests.test_hia_integrated_workflow -v
```

The raw-record collector fixes nine methods and requires zero failures, errors,
skips, expected failures and unexpected successes. It retains actual raw native
inputs/process streams, exact Rust/Python Core bytes and source-derived exports,
complete execution reports and stopped resource ledgers, refusals, source/tool
identities and executable bytes' before/after hashes. The native child runs
from a temporary directory with no Python on its PATH; Python admission,
elaboration and Machine functions are disabled during each launch. Python is
used afterward as a separate oracle in the collector. These controls establish
the observed code path, not a hostile-host sandbox or transitive runtime proof.

Controls include nested/empty records, heterogeneous exact scalar values,
record loops, internal primitive allocation/refusal/loan handling, traps and
stopped prefixes; same-layout nominal mismatches; zero-width SSA and public
entry restrictions; unused malformed/unsupported declarations; strict raw
JSON; the exact layout/name/value-slot boundaries; and small raw inputs whose
erased argument/result width exceeds the Core node limit. The original draft's
pre-charge cloning defect and its corrected source are retained in the external
development evidence, without labeling that draft as qualified.

The branch is registered additively in the existing full-gate and both host
matrix push allowlists. Workflow registration and queued runs are not passes.
Current public-source execution records must qualify their own commit.

Production authority remains Python; optimization policy remains `no_change`.
General nominal resource normalization, the complete Python API domain,
deployment eligibility, refinement and all P0–P7 closure claims remain open.
