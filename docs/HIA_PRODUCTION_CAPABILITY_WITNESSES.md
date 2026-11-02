# Production CFG capability witnesses

`tools/verify_hia_capabilities.py --production-output-directory ...` connects
the existing generic Lean model to finite observations of the actual Python CFG
verifier and independent Rust raw-byte-DAG admission. It does not add a compiler,
resource checker or execution authority.

The fixed cohort uses `stored_loan_record.hia`, normalized through the existing
nominal adapter, and `returned_views.hepta`, lowered through the explicit v8
source adapter. The resulting canonical Core bytes are reverified. A current
thread profile callback observes genuine `rename_capabilities` calls and their
inputs/results without replacing the helper or its verifier binding. An
existing callable profile callback is chained and restored on success or
failure; opaque profilers refuse, and other threads are not observed.

Trace coverage is checked against an independent inventory read from the
immutable Core's declared functions, blocks and terminators. Each
`(function, block, jump/then/else)` occurrence must appear exactly once, with
the real `_BlockCheck.transfer` caller, original edge, exact target parameters
and statically derived resource-name map. The two arms count separately even
when they have identical destinations and arguments. Missing, duplicated,
foreign and rebound rows refuse. The inventory does not call the production
`_edges` helper; a regression deliberately makes that producer omit an arm
while keeping the joined block reachable and confirms qualification refuses.

For each observed edge, the exporter retains the full graph, actual remap,
actual result and separately listed forgotten external capabilities. The
selected input must contain every local capability, its roots and parents.
Duplicate names, missing roots and parent cycles refuse the witness profile.
This exporter restriction is not a proof that the whole verifier excludes
every possible malformed graph.

The concrete certificate gives selected source names consecutive natural
codes. Target names get the corresponding source code plus the selected count.
These are explicitly separate before/after SSA namespaces, including when a
target spelling happens to equal an old name. Target codes are derived from
the supplied injective map, independently of observed output fields. Original
parameter origins use a separate retained name table and are never renamed.
The total natural-number map `n ↦ n + count` is injective for all naturals.

Lean checks four concrete obligations for every captured edge: injectivity,
selected input closure, equality of the **observed output** with the model
renaming, and closure of that observed output. The existing fourteen generic
renaming theorems remain distinct from these finite witnesses. The exporter
does not silently regenerate an expected output in place of the captured one.
Mutating its root, parent, kind, external flag or parameter origin must fail
the intended concrete equality theorem. The four existing generic model
mutations are also checked independently.

The same saved primitive Core bytes enter the existing Rust raw-byte-DAG mode,
which performs its own whole-module admission before execution. Five fixed
invocations cover both branch choices and a zero-length bounds stop. The
existing complete execution/ledger comparator checks Python observations
against the Rust result. Ending a parent before its child and forging a v8
formal return origin are separate bad-Core controls; both established checkers
must reject the same changed bytes. These are finite program observations,
not a proof of the Rust `forward` implementation.

```sh
python tools/verify_hia_capabilities.py \
  --lean /absolute/pinned/lean-4.19.0/bin/lean \
  --production-output-directory /absolute/new/evidence-directory \
  --rust-shadow /absolute/hia-core-shadow \
  --rust-shadow-sha256 EXACT_EXECUTABLE_SHA256
```

## Explicit primitive Core invocation

The same qualifier also accepts one caller-selected artifact:

```sh
python tools/verify_hia_capabilities.py \
  --lean /absolute/pinned/lean-4.19.0/bin/lean \
  --production-output-directory /absolute/new/program-evidence \
  --rust-shadow /absolute/hia-core-shadow \
  --rust-shadow-sha256 EXACT_EXECUTABLE_SHA256 \
  --program /absolute/program.hia.json --function entry --arguments '[1,true]'
```

All three invocation options are required together. Input is a bounded regular
file of at most 8 MiB, parsed through the existing strict Core gate. Only
explicit primitive v1–v8 is admitted here; source and nominal adapters are not
selected by this mode. Original input bytes and the canonical Core sent to
Rust are retained with separate hashes. Arguments use the existing bounded
Rust scalar wire profile. At least one static CFG edge and one nonempty
selected capability graph are required; a zero-edge scalar program or only
empty capability graphs cannot produce a vacuous pass.

Every static edge in the whole module is observed, including private
functions. The existing Rust raw-byte-DAG route must independently admit that
same entire canonical Core before executing the named scalar export. Loops,
recursive calls, non-byte profiles or other unsupported Rust shapes refuse.
The fixed policies allow at most 64 structural allocator interactions, 4,096
structural VM ticks and call depth 32; execution has 4,096 ticks, 4,096 logical
heap bytes and call depth 32. A matched trap or quota stop is an observation,
not a normal-return guarantee.

The default two-fixture campaign remains unchanged. In explicit-program mode,
every applicable observed-result mutation must be rejected by Lean. Kind and
external-flag controls are mandatory; absent parent/origin/root-alias cases
are recorded as not applicable, never as passed controls. A separately changed
edge names an absent capability and must be rejected independently by both
whole-Core checkers. That negative is an undefined-resource argument control,
not a theorem of complete ownership soundness.

Qualification requires a clean source commit. It retains canonical Core,
captured graphs, namespace tables, generated positive/negative Lean inputs,
kernel output and dependencies, Rust/Python observations, bad-Core refusals,
source/tool/support identities and a byte manifest. Unknown or failed work
leaves `passed=false`; it cannot be replaced by an old saved receipt.

The mathematical `ExclusiveAlias` predicate is a relation that renaming
preserves. It can be true for a legal suspended mutable parent and shared
child; this is **not a theorem that all aliases are absent**. Likewise `Closed`
alone does not rule out synthetic parent cycles. External projection is
recorded before the selected-graph theorem and remains unproved. The Python
exporter/checker correspondence, every instruction transition, complete type
and ownership soundness, Rust implementation refinement, native lowering,
ABI, concurrency and external memory remain outside this qualification.
