# Scalar PHI edge evidence — original and repaired

This bundle records a concrete repair to the selected scalar LLVM checker.
It preserves both observer revisions and both source revisions; a later run
does not overwrite the earlier observation. The runtime change and its bounds
are described in [HIA_SCALAR_PHI_EDGES.md](../../docs/HIA_SCALAR_PHI_EDGES.md).
The broader proof matrix is in
HIA_SEQUENTIAL_CORE_PROOF_CHAIN.md (retired from this product).

## Fixed identities

| Role | Git identity |
| --- | --- |
| Original runtime | `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` |
| Regression-only RED commit, original runtime unchanged | `50a2c11ce9f7895736bd1a77d79ab9b3d327b68c` |
| RED tree | `ba68321b80d10fec6fb98ce30900c2f284d58b6b` |
| Repaired runtime commit | `a3d7a1273adb45a5f9ca9121a49057b603f6eb64` |
| Repaired tree | `342314f662d7cd197bd5c9fc12f7c6425d8eb739` |

The old checker file SHA-256 is
`aa1d475a764f127098f41b52ab719a67d8907fe3125ce3cc0e46999bc22c72c9`;
the repaired file SHA-256 is
`6d570a4cad497ad8b49e7d8853ff165eb253ba9b2bc0a45b87465b1687436269`.
All four runs recorded clean source status before and after, unchanged exact
source/tree identities, unchanged measured tools, and CPU affinity `[10]`.
The documents/evidence commit carrying this bundle is not the measured source
commit and does not inherit a complete composition qualification.

## Results and protocol correction

| Run | Protocol | Invalid variants actually reported `verified` by checker | New regression tests / full suite | LLVM oracle expectations | Legitimate native calls |
| --- | --- | --- | --- | --- | --- |
| `original` | v1 | 2: `earlier_phi`, `parallel_cfg_edge` | 11 run, 12 failure events including subtests | 12/12 | 384/384 |
| `repaired` | v1 | 0; all 8 invalid variants structurally `rejected` | 103/103 pass | 12/12 | 384/384 |
| `original-v2` | v2 | 3: `earlier_phi`, `false_edge_phi`, `parallel_cfg_edge` | 11 run, 12 failure events including subtests | 12/12 | 384/384 |
| `repaired-v2` | v2 | 0; all 8 invalid variants structurally `rejected` | 103/103 pass | 12/12 | 384/384 |

The v1 `false_edge_phi` fixture made the LLVM condition constant while leaving
the Core condition variable. This created an additional semantic mismatch.
The original checker therefore reported **`refuted`**, not `verified`, for
that case. The v1 console field `invalid_accepted` grouped every result that
was not structurally `rejected`; its label was too broad. The retained v1
`RESULT.json` correctly records `checker_status: refuted`. It must not be read
as a third old-checker verification failure.

V2 makes the same branch condition constant in both Core and LLVM, leaving
the illegal PHI on a branch that is semantically unexecuted. This isolates
the structural-validation defect: the original checker now truly reports
`verified`, whereas LLVM rejects the bytes. The v2 console summary separates
`invalid_verified` from `invalid_not_structurally_rejected`. Both source
revisions were rerun with the same v2 observer. V1 receipts remain unchanged.
This is a correction to the negative control, not a selection of benchmark
results. V1 and v2 are distinct protocols and must not be combined into one run.

LLVM 20 `opt -passes=verify -disable-output` accepts each of the four legitimate
variants and rejects each of the eight malformed variants in every run. An
`opt` nonzero exit for a malformed fixture is the expected oracle outcome.
Only legitimate LLVM is compiled with Clang 20 and called natively; each result
is compared against the Core interpreter and an independent wrapping-arithmetic
expectation. The 384 observations are finite calls, not exhaustive native proof.

The repaired 103-test inventory includes the 11 new PHI tests plus the existing
lowering, lowering-budget, sequential-Core, scalar-totality, scalar-call and
translation-validation suites. There are no errors, skips, expected failures
or unexpected successes. The original RED run intentionally contains only the
11 new tests; the unequal inventories are not a comparative productivity or
performance experiment. Test IDs and their digest are retained per run.

## Bundle and verification

evidence-a3d7a12.tar.gz (retired from this product) is **170,683 bytes** with SHA-256:

```text
faa65bdde2cb88b1510b3bee6736be0d30c3acbc7011b97de53c305898b0a0f5
```

[MANIFEST.json](MANIFEST.json) records source commits/trees, observer hashes,
run result hashes, member-manifest hashes, exact outcomes and explicit claim
limits. Each of the four run manifests covers 105 files. All **420 covered
files were reread from this exact archive and checked for byte length and
SHA-256** before committing the bundle. The archive also retains both observer
scripts, emitted Core/LLVM, checker JSON, `opt` logs, compiler logs, shared
libraries, native-call rows and tool identities. The manifest is an integrity
record, not execution or publication authority.

| Run | `RESULT.json` SHA-256 |
| --- | --- |
| `original` | `d1948d420d0576536386e820e9fadf8c8ed34f9dd13acf9635de15397ee503f4` |
| `repaired` | `ad12806df99e67d7c17311f11e92016b435fba0f79d0529fa68c1d049f2adf32` |
| `original-v2` | `3f3fe6a3ad8616afc5fb5283e4cdb5bc49b8ccd263672d134d6b8df38e6c6fe1` |
| `repaired-v2` | `76232d8d21f286407195c7bf5d12c443032df785370929728ca23c31d7ea8a87` |

Inspect or extract the archive into a new directory; it contains the prefix
`safe-core-phi/`. The observer scripts retain the exact fixture construction,
commands, tests and original tool paths. Reproduction requires the recorded
Python/Z3 and LLVM 20 environment, the selected exact source revision, and a
fresh output directory; adjusting machine-local paths creates a new observation
whose identities must be recorded. The retained native libraries are evidence
of these runs, not trusted binaries for another host.

For example, after extracting and creating a clean checkout of `a3d7a12`, run
the v2 observer with `--full-tests`; omit that flag for the RED inventory at
`50a2c11`. Replace the checkout, extracted-bundle and fresh-output paths below:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONOPTIMIZE=0 \
taskset -c 10 /data/hepta-hia-round2-20261104/toolchains/venv/bin/python -B \
  /path/to/extracted/safe-core-phi/observe_phi_edges_v2.py \
  --root /path/to/clean-checkout --output /path/to/new-output \
  --opt /data/hepta-hia-round2-20261104/toolchains/clang20/usr/bin/opt-20 \
  --clang /data/hepta-hia-round2-20261104/toolchains/clang20/usr/bin/clang-20 \
  --full-tests
```

The final repaired-v2 durable job was `1a1a9f85ea1-fc05-3a8e`, succeeded with exit
0 and complete durable output. The original-v2 job was
`1a1a9f6f604-fc05-3a76`, exit 1 as expected for RED. A printed inner result alone
would not establish successful process completion.

## Claim boundary / 结论边界

此证据关闭的是固定标量 checker 中的 PHI 同步绑定、所有 incoming 的支配检查、
以及重复 CFG 边被集合化遗漏的具体缺陷。它保留了 RED、实际 LLVM 拒绝 oracle、
合法变体、负例和原生有限回归，未扩大支持的 LLVM profile。

It does not prove the parser/encoder correct for all programs, complete LLVM
verification, whole-language Safe Core soundness, ownership/resource safety,
machine-code or C-ABI refinement, concurrency/hardware behavior, dynamic HIA
performance, or a unified build/execute/refuse/cancel/recover qualification.
Those claims remain false in the manifest. A final combined source revision
must be qualified again with its own complete evidence and unchanged budgets.
