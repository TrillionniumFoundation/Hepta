# Combined Core and evidence review on frozen `93b1c80`

The reviewed source is **`93b1c8002c2a41573080cca41a279a0a0fa4e915`**, tree
`5224a89507c257ec23092eba7ffc41aee1d496ed`. This review found one CI wiring
omission in that snapshot. The independently prepared follow-up
`1468550226bfe199b97b9d845f2983829d105936` closes that omission; its diff was
inspected without relabelling this review as a run on the follow-up commit.
No further source-composition or compact-evidence provenance blocker was found
within the scope below. No scientific acceptance gate changes.

The review used a separate sparse checkout, kept clean until both checks
completed. It did not modify the shared root checkout. Native builds, native
application measurements, model requests and the scalar solver matrix were not
rerun. Existing producer observations retain their original source identity.

## Checks actually performed

| Check | Observed result |
| --- | --- |
| Lightweight combined regressions | **152 passed, zero failures/errors/skips**, 20 explicitly selected suites/classes, 3.102292631 seconds |
| Subprocess observation during those regressions | Three Git metadata commands; no native compiler or model process |
| Independently reconstructed JSON datasets | **12/12**, from 7,973 fragment records, with no duplicate/unreachable nodes or unused string fragments |
| Original JSON comparison | All 12 original files were present; original byte length/SHA-256 and reconstructed canonical values matched |
| Retained indexed files | **772 distinct files**, 14,329,335 bytes, all size/hash bindings matched |
| Historical source binding declarations | **1,455 checks across 15 evidence groups**, including repeated dependencies, all matching their original Git blobs |
| Explicit public same-tree aliases | Both retained `ccd423bc` → `e629d92` mappings have tree `26695834a49be88dae42a41a2954954f721c7066` |
| Historical audit donor import | Nine selected files are byte-identical at their documented import commit; later fixes are separate |
| Existing scalar proof record inventory | 449 retained obligation records, checked as evidence without invoking the solver |
| Existing Rust shadow record inventory | 96 concatenated records, exact combined digest and record count |
| Agent v4 transport text | Eleven original request/response UTF-8 strings reconstruct their recorded byte hashes |
| Agent v5 compact inventory | All 418 files marked as included were checked; 606 source/native files are explicitly inventoried but not duplicated in this compact directory |

The full command, interpreter identity, source identity, file inventory digest,
per-dataset reconstruction details and source differences are retained in
[EVIDENCE_AUDIT.json](../experiments/hia_next_convergence_review_20261029/EVIDENCE_AUDIT.json).
The independent reader is retained byte-for-byte as
[audit_evidence.py](../experiments/hia_next_convergence_review_20261029/audit_evidence.py).
The separate [regression receipt](../experiments/hia_next_convergence_review_20261029/LIGHT_REGRESSION.json)
and [raw unittest log](../experiments/hia_next_convergence_review_20261029/LIGHT_REGRESSION.log)
identify exactly which suites ran.

An initial loader attempt failed before tests ran because the reviewer sparse
view omitted the existing `experiments/hia_filecheck` protocol imported by the
IR PGO runner. Adding that tracked directory fixed the review environment;
repository source was unchanged. The initial harness, empty unittest log and
explicit unqualified failure record are retained. The original exception was
reported by the tool, but its stderr was not separately saved as a raw file.
This attempt is not counted as a passing test run or as a product-code defect.

## Core/schema/resource composition inspected

The canonical primitive verifier, runtime, schema registry, JSON preflight,
existing static-budget analysis, private prepared-proof issuer and LLVM emitter
are byte-identical to the round's public base `2f49151ab9d8812eeb02ac2056f224f140099d76`.
Their exact hashes are in the audit receipt. The new adapters and analyses were
reviewed as consumers of those boundaries, and the selected regression suite
also exercises their shared entry points.

The C project adapter runs the existing structural translator, parses the
generated source together with the separately accounted authored client, calls
the canonical Core lowering/verifier, and rechecks the captured input. It retains
the actual consumed Clang AST text. Its public result still excludes arbitrary
foreign-pointer admission and automatic C record-layout equivalence. The cursor
helpers use the existing checked scalar vocabulary; they do not create a new
schema or unchecked resource descriptor.

The entry payload analysis reverifies the actual complete primitive v1 program
and keeps a separate closed operation/type inventory. Its call-DAG and CFG
analysis permit loops only when their repeated closure allocates no payload.
It does not feed a report back into native or runtime admission. Regression
coverage includes failure/trap prefixes, owner returns, transitive allocations,
unknown/future operations and continued refusal by historical budget gates.

The prepared-artifact consumer still requires its own successful proof/build,
internally issued proof records, exact Core/state/policy/artifact identity and
bounded leases. Adding the guarded proof's explicit policy hash satisfies the
existing issuer check rather than widening that check. The independently
reviewed runtime, pinning, issuer, implementation-identity and test files are
unchanged from their original review's source bindings. This static comparison
and the lightweight reservation regression do not replace the producer's
24-test actual-native run; that run remains attributed to `3c547848`.

No old schema label is reinterpreted, no historical proof receipt becomes an
import authority, and no new native resource admission was found in the examined
changes. These are scoped source-review findings, not a whole-language
soundness theorem or a fresh unified machine-code qualification.

## Cross-result attribution

The legacy native application qualification, its later IR PGO qualification,
the independent Rust shadow and the static payload analysis all name the same
143,935-byte captured Core, SHA-256
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`.
The retained payload report's deterministic analysis digest also recomputes
exactly. Its three requests and 32-byte bound remain a bound on fresh Core
invocation payload, with the existing exclusions for metadata, stack, RSS,
termination and native-code refinement.

Every common NDU summary/result field, apart from its intentionally different
report schema, matches the reconstructed original value. The original 27/324
activation episode/output count and the later 24/618 prepared-reuse count
reconcile independently. Activation is still not a net-benefit claim. The
negative warm/full-cost, profitable-opportunity and qualified cold-benefit
outcomes retain their original values; no observations were rerun here.

Agent v5 plan hashes, result hashes, source bindings and recorded costs were
checked independently. Its formal 15 requests / 15,594 tokens and all-runs
28 requests / 27,609 tokens reconcile exactly, including the failed and
development attempts. The recorded formal and all-runs experiment durations
remain 1,350.885819202 and 1,612.593904963 seconds respectively. The main
language comparison still has zero started cells and zero model requests at
this frozen snapshot. This review does not include the later v6 model run.

Historical snapshots differ from later integrated code in expected places.
Those paths are listed separately for each of the 15 groups. A later commit
having the same relevant implementation bytes is not described as having
executed an old experiment. Only the explicitly checked `ccd423bc`/`e629d92`
pair is called a whole-tree alias.

## Confirmed omission and its correction

At frozen `93b1c80`, the new payload tests were absent from the six-outcome
workflow and verified-increment module list. The six-outcome paths and retained
qualification did not include the standalone payload CLI/fixture either.
Follow-up `1468550` adds the 19-test module to both suites, the fixture to the
verified source inventory, the relevant workflow trigger paths, and the actual
clean-source CLI invocation against the retained migration Core.

That correction is verified by reading its exact Git blobs. This review does
not claim to have run that later workflow or executed remote CI. Its later
source-bound CLI result belongs to the root's separate evidence.

## Practical limits and replay

The evidence audit proves byte consistency under the local Git and filesystem
view. Hashes do not authenticate a producer, establish compiler correctness,
or independently reproduce the old experiments. Model weights, installed
toolchains, full raw native archives and external CI are outside this compact
check. The environment is the available shared cloud host, without a verified
user-dot identity or a performance qualification.

The retained reader deliberately pins `93b1c80`. Replay it from outside a clean
checkout of that commit with the original source objects available:

```sh
python /path/to/audit_evidence.py \
  --root /path/to/clean-93b1c80-checkout \
  --output /tmp/new-convergence-audit.json
```

The output must not already exist. It records when original absolute raw JSON
files are unavailable instead of pretending they were compared. The retained
run had all 12 present. No executable admission, performance claim, whole-language
proof or other scientific gate is issued by this reader.
