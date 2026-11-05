# Suppress executable code generation for inert certificate data

This is a **source-only proposal and nonaccepting diagnostic**, based on PR 603
commit `958d47577dce36994f5f9e1484ac50d34d36b65b`. It does not change the existing
relocated acceptance runner or any resource limit. No production, native,
initialization-elision, quota-equivalence, or performance authority is granted.
All twelve wider Core obligations remain unproved.

## Exact change

`tools/core_seven_nocode_sources.py` prefixes the 7,685 transport-data `def`
headers with `noncomputable `. The namespace-qualified definition inventory is
derived from the actual previously validated relocated sources, not a serialized
name list supplied by the candidate. No definition body, type, theorem statement,
proof term, import, input byte, stage order, theorem-print order, or rejection
coordinate changes. The noncomputable environment metadata intentionally differs.

In the pinned Lean 4.19 implementation, `shouldGenCodeFor` requires a declaration
to be neither a theorem nor explicitly noncomputable. An enclosing
`noncomputable section` alone is insufficient for this purpose. See
[Lean 4.19.0 PreDefinition/Basic.lean](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/PreDefinition/Basic.lean).
The existing kernel-reduction proofs still check the same data and propositions;
this change does not substitute an external evaluator, `native_decide`, a new
axiom, or a proof placeholder.

The candidate validator removes exactly the allowed prefixes from **actual
candidate bytes** and requires the complete original relocated source bytes to
be recovered. The recovered proposal is then passed through the unchanged
relocation validator and its unchanged earlier inverse validators. Unexpected
source changes, missing/duplicate markers, changed theorem inventories, forged
manifest fields, and omitted retained source copies are rejected.

The prefix adds 107,590 UTF-8 bytes. Candidate sources occupy 3,300,562 bytes;
the 22 original-plus-candidate source files occupy 5,700,944 bytes, within the
existing 8 MiB aggregate cap. The source manifest is
`7af1ff3c61192f86e2cb5585eddec4fd80993fb7ad830da567db9ab4886880f7`.

| Stage | Theorem-print subjects | Marked data definitions |
| --- | ---: | ---: |
| Baseline | 56 | 0 |
| SyntaxData | 547 | 1257 |
| CertPart01 | 271 | 236 |
| CertPart02 | 54 | 42 |
| CertPart03 | 1655 | 1301 |
| CertPart04 | 807 | 1416 |
| CertPart05 | 1297 | 1416 |
| CertPart06 | 1297 | 1413 |
| CertPart07 | 1297 | 604 |
| ConnectionsTransportRejections | 75 | 0 |
| WrongArm | 1 | 0 |

## Validation and retained failures

`python -m unittest tests.test_core_seven_nocode_sources -v` executes the real
complete input generation and inverse validator, then exercises namespace,
marker, body, theorem, inventory, manifest, and retained-copy mutations. The
2026-11-04 desktop run completed **9 tests in 91.770 seconds, all passing**. No
mocked successful Lean process is used in these tests.

The unchanged baseline acceptance runner was also executed against the exact
PR 603 source before modifying any identity-bound file. Baseline passed its 56
subjects. SyntaxData reached 60.000263301 seconds, then failed to establish
cleanup completion within 2 seconds. Its terminal result remains
`cleanup_failed`, with no positive targets or exact-negation claims. The original
failed evidence is retained at
`/home/qian-qi/work/hia-safe-core-baseline-20261104-r1`; result SHA-256 is
`7048d56b8f36bfb478754b5ebcda7155bf13cf27248529d65792a7128d2afe22`.
This local failure does not replace the earlier GitHub CertPart03 timeout.

## Timing diagnostic boundary

`tools/diagnose_core_seven_nocode.py` measures the actual kernel checks of an
already materialized candidate. Its report explicitly says
`preparation_time_included=false` and `source_inverse_replayed_here=false`.
It is **not** the full acceptance protocol and cannot be used as one, even if
every Lean invocation succeeds. The materialized bytes must separately pass the
source inverse validator; the diagnostic checks their source-manifest hashes,
the exact theorem-print inventories, the pinned Lean executable, and fresh
module/log creation.

The unchanged acceptance capture implementation supplies the 60-second process
limit, 2-second cleanup limit, bounded raw logs, and no retry. The diagnostic
retains at most eleven invocations, uses the unchanged 540-second launch window,
and must be invoked under an outer 600-second timeout. It never reads old
`.olean` files or upgrades an incomplete capture. Its root must initially contain
only the eleven materialized sources and their source-only manifest.

For an already materialized fresh directory:

```sh
timeout 600s python -m tools.diagnose_core_seven_nocode \
  --lean /absolute/path/to/lean-4.19.0/bin/lean \
  --directory /absolute/path/to/fresh-candidate
```

The pinned executable SHA-256 is
`92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023`.
The 2026-11-04 timing evidence is retained at
`/home/qian-qi/work/hia-safe-core-nocode-20261104-r1`. The diagnostic **failed** at
CertPart02 with `process_timeout`; later stages were not launched. Individual
process receipts and complete bounded raw stdout/stderr remain alongside
`diagnostic.result.json`.

| Stage | Actual subjects checked | Elapsed seconds | Outcome |
| --- | ---: | ---: | --- |
| Baseline | 56 | 10.198269614 | Passed |
| SyntaxData | 547 | 57.250211488 | Passed |
| CertPart01 | 271 | 33.164108724 | Passed |
| CertPart02 | 0 | 60.000357517 | Timeout, no inventory admitted |
| Remaining seven stages | 0 | — | Not launched |

The entire diagnostic took 162.597262187 seconds, excluding the separately
measured 91.492-second source preparation. It retained 59,381 raw log bytes and
6,100,136 bytes of freshly emitted, inventory-checked parent modules. This is
**not a closed timeout fix**:
explicitly suppressing data code generation is insufficient by itself. Background
workloads also make the run unsuitable for a quantitative performance comparison.
No target or exact-negation success is claimed.

The diagnostic runner used for this first measurement had SHA-256
`410ff902b598b25060ccc1309c53a13e78d14d3268c0f503d8030ec285e41249`.
Afterward, inventory receipts were compacted to their validated commitment so a
future eleven-stage report cannot exceed the metadata cap merely by duplicating
all subject names. The preserved first-run evidence still contains its original
full inventory maps; no outcome or source is rewritten.

## Remaining work

The full acceptance protocol must explicitly bind this new transformation,
source identities, and manifest; include preparation in its launch deadline;
and independently replay the complete frozen evidence before claiming even the
narrow syntax connection. This patch deliberately leaves that consumer boundary
closed. Passing a source inverse, a subset of kernel checks, or a diagnostic run
does not establish whole-Core refinement, memory/resource safety, or backend
correctness.
