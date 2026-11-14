# Namespace CI evidence readback and R20 diagnostic handoff

This is static review and authoring only: zero product imports/executions, zero
new benchmark measurements, and zero Git publications. Original evidence is
unchanged. Complete source identities, raw counters, CPU flags and supporting
records are in `harness/inputs/DIAGNOSTIC-HISTORY.json`.

## Existing phase evidence

Original diagnostic run 43475015584 used CPython 3.14.4, product abeef212 / tree
f2bc61c / 3,055 files. Its report and three case reports are under
`v94-native-namespace-budget-r1/ci-phase-r1/actual/raw/evidence`.

| Original case | Outcome | Whole test s | Fresh scans | file_digests s | _admitted_code s | Publication effects | Publication s | NamespaceState.call s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| expired evaluation | FAIL | 10.320282347 | 116 | 5.122012419 | 5.469173003 | 329 | 1.516398013 | 0.107763501 |
| reference loop | FAIL | 7.473435627 | 116 | 5.156175863 | 5.509675402 | 327 | 0.516228779 | 0.101452910 |
| native timeout | PASS | 17.526473931 | 277 | 12.270625338 | 13.051223670 | 670 | 1.280752871 | 0.217904049 |

These are nested inclusive totals, not additive costs. Whole-test timing includes
setup/teardown. State-call totals around 0.1 seconds do not justify prioritizing
Namespace state copies over the repeated multi-second source admissions.

Both short-context cases failed at the second emit, whereas R20's original
failures reached only the first baseline emit. The old timeout diagnostic's
evaluate call was 4.668248533 seconds and passed its original five-second check;
R20's corresponding original observation was 6.143223637 seconds and failed.
Fresh single-case processes differ from the original 35-method sequence.

All original reads/hashes remained. Two diagnostic SELECT reads observe context
timestamps without resetting them; their cost remains inside enclosing budgets.
Timers add overhead, and process CPU excludes subprocess CPU.

The raw Store counter 2,422 is double instrumentation, not distinct machine
entries. The original receipt observer remained single: mode 1 = 1,090 and mode
2 = 120 per case. The immutable STORE-OBSERVER-ADDENDUM is included unchanged.

## Existing SHA and scan components

Source: `ci-components-r1/actual/raw/evidence/REPORT.json`, run 43479122450.
All eight maps matched: 1,429 paths / 51,971,962 bytes. Full snapshots and two
warmup scans precede these fixed-order measurements.

| Pure hash order | Actual provider | Wall ms | Process CPU ms |
|---:|---|---:|---:|
| 1 | OpenSSL hashlib.sha256 | 33.949958 | 33.941395 |
| 2 | _sha2.sha256 | 204.066488 | 204.028079 |
| 3 | _sha2.sha256 | 204.262637 | 204.228011 |
| 4 | OpenSSL hashlib.sha256 | 34.181133 | 34.175011 |

OpenSSL averaged about 34.066 ms; _sha2 about 204.165 ms, roughly six times slower.
Owned-byte hashing does not authorize changing production read/close/hash/provider
ordering, and this fixed sample is not a general platform speedup guarantee.

| Full scan order | Kind | Wall ms | Process CPU ms |
|---:|---|---:|---:|
| 1 | original | 98.390416 | 98.380880 |
| 2 | instrumented | 96.852693 | 96.834475 |
| 3 | instrumented | 96.719333 | 96.703641 |
| 4 | original | 67.801852 | 67.794585 |

| Inclusive component | Calls per scan | Scan 2 ms / share | Scan 3 ms / share |
|---|---:|---:|---:|
| digest | 1,429 | 37.725185 / 38.95% | 37.800699 / 39.08% |
| guard | 1,687 | 18.588263 / 19.19% | 19.261677 / 19.91% |
| lexical | 1,429 | 51.878297 / 53.56% | 51.995115 / 53.76% |
| open | 1,429 | 12.458810 / 12.86% | 12.270481 / 12.69% |
| read | 1,429 | 10.658821 / 11.01% | 10.608878 / 10.97% |

The shares overlap; do not sum them. Lexical residuals 12.528461 / 12.170896 ms
include close/context management, dispatch, allocation and timer overhead; they
are not close timers. The differing original scans do not isolate observer cost.

Hardware was AMD EPYC 7763 / AuthenticAMD, four CPUs [0,1,2,3], measured on CPU 0
with affinity restored. OPENSSL_ia32cap was null/unset. OpenSSL was 3.0.13
(30 Jan 2024); hashlib.sha256 was _hashlib.openssl_sha256 returning _hashlib.HASH.
Mapped libcrypto.so.3: 5,309,400 bytes, SHA-256
6866ed711dab8927e1bf82bf1cd30e828bdfc34f3cc1e83b1c9eb01ce6c37d9a.
Recorded flags include sha_ni, avx2, aes, pclmulqdq, bmi1, bmi2, adx, vaes and
vpclmulqdq; the full original flag list is in the history JSON. Neither flags nor
provider identity prove the actual OpenSSL assembly dispatch. No dispatch trace
or capability-override experiment was observed.

## Guard and memo limits

Guard-R2 observed 91 mechanism + 2 foreign-key + 9 original freshness controls
passing on 3.14.4. ABBAABBA guard mean changed 3244.8327 → 2769.9950375 ns
(14.633656%), but complete fresh-map mean only 42.905882 → 41.92983775 ms
(2.2748495%). No business deadline method ran. Static readback confirms its two
guard definitions are not present in R20; lexical read/file_digests are equal.

Memo R1/R2/R3 all remain NOT_ADOPTED. R1 changed a foreign SHA argument refcount;
R2 changed refcounts visible to sys.monitoring; R3 allowed mid-open monitoring
to observe an extra dict.pop and raise MemoryError where the original returned.
The first incomplete observer and corrected failure both remain preserved. No
cached digest or shortened manifest is proposed.

## Frozen successor scope

Sixteen harness files produce locally computed tree
2bc8b7c0bf4489a43ccde370e8c60bfd374f8e30. Fixed source is commit
26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d / tree
84df4b42f1e20fd7d0c7229e658cf3b458984ffb, all 3,177 paths. Its fresh map is
1,551 files / 58,637,295 bytes, plus the support contract in current_sources.

The original expired method keeps 3000/1000 ms and the exact 42,759-byte module
016621eacf28492569b7332ac84a6d0775060311. The complete observer execution try
block is AST-identical, including all five selectors' use, poisons, SELECTs,
receipt checks, original loader and result assertions. Both helper files are
byte-identical. Only exact Store bypasses its duplicate generic diagnostic
wrapper. This changes diagnostic overhead and sample ordinals, so an old/new
wall-time comparison is not a qualified optimization result.

Five parts carry sixteen exact R20 ZIP members / 2,284,725 raw bytes: nine old
byte/mode identities and seven original R20 source-bound records. No fixture
compilation or cold replay is planned; original business builds remain enabled.

The old workflow did not install Clang 20 or Z3 explicitly. This successor uses
the exact production installation blocks and pip pins. The original qualifier's
_prerequisites adds two real version subprocesses, clang and ld, each with a
30-second bound, BEFORE the observed 1800-second group begins. This is extra
bounded preparation, not zero processes and not part of that 1800 seconds. The
observed original case runs in a fresh child afterward.

Job 40 minutes, group 1800 seconds, cleanup 3 seconds and all original inner
budgets remain. The inherited owner checks exit and process-group absence, not
an unimplemented ECHILD/subreaper claim. OBSERVATIONS_COMPLETE does not mean
business PASS or complete Native qualification.

The first authoring attempt rejected its inherited four-part assumption. Its
original output and failure remain. R2 changes only transport count/wording.
All reported Git IDs are locally computed until separately published/read back.
No branch or run has been created. The old 78-member local plan was not executed.
