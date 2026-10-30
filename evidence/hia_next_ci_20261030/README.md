# Independent CI artifact audit

The latest exact source, `44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`, and both
historical CI artifacts passed independent offline readback. The final
`VERIFY.json` records both `passed=true` and
`latest_required_source_verified=true`. All official source identities, raw
method and footer counts, manifests and scope checks below match. No archive
contents were extracted or executed. Historical results retain their own
source and denominators and do not substitute for the latest source.

| Source | Official Actions run | Python full run | Rust tests / result footers | Critical coverage: groups / modules / unique methods | Canonical safety selectors / capabilities |
|---|---:|---:|---:|---:|---:|
| `73922c1a3971125dfb9703555e50e5cf6444e842` | 41056856811 | 4,183 | 109 / 20 | 72 / 179 / 1,763 | 364 / 39 |
| `f7cc87218a101b4b2c715e3fdd2e9d42a7f7fd8b` | 41059399079 | 4,259 | 116 / 21 | 77 / 187 / 1,839 | 440 / 45 |
| **`44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`** | **41061115481** | **4,266** | **116 / 21** | **77 / 187 / 1,846** | **447 / 45** |

All listed methods passed without skip/error/failure. The critical coverage is
a subset of its own full Python run, not an additional test denominator. The
canonical matrix was a separate execution of selected methods; its selectors
also map back to the corresponding full-run methods. Matrix and full-suite
counts must not be combined as unique coverage. Rust result footers include
zero-test executable/doc-test harnesses; the count of result blocks is not the
number of tests.

The verifier checks each retained official API artifact digest, size, artifact
ID and workflow-run source against a single bounded read of the ZIP. It also
matches the official run's completed/success state, exact commit and tree, and
the declared repository. Those API JSON files are retained observations, not
new authentication or a signature supplied by an offline checker.

Each ZIP contains 46 ordinary members: respectively 6,990,666, 7,125,999 and
7,136,616 uncompressed bytes, totaling 138 members and 21,253,281 bytes. The separately pinned manifest binds every member's path, size and
SHA-256. ZIP compressed size, total expanded bytes, individual size, member
count and compression methods are bounded. Symlinks, special entries,
duplicates, unsafe paths and encryption are refused. The checker reads ZIP
members in memory and never extracts files or executes archived code.

The independent semantic checks cover:

- Exact workflow head, immutable commit/tree, all recorded source and external
  inventories before/after, initial clean state, and the frozen command plan.
- All eight integrated gates, each against its separate retained report.
- Every full-suite method header, terminal status and final stderr footer,
  including multiline docstrings and expected CLI diagnostic output.
- Every Rust harness's running count, unique successful methods and complete
  footer, with zero failed/ignored/measured/filtered-out tests.
- Every critical coverage module rebuilt as an exact subset of the full log.
- Canonical safety contract hash, every capability-to-selector binding, every
  selector's actual status and positive duration, final matrix log footer,
  and source stability against the full source inventory.
- Recorded real tool and Linux sealing observations, the four distinct pinned
  NDU source profiles, and their archived build-receipt identities.

The ranking probe remains `ADVISORY_ONLY`; recursive, finite and stream probes
remain `DENY_ALL`. These are synthetic identity/protocol checks. They do not
establish economic gain or program safety. The contract and report retain all
false whole-language soundness, source/native refinement, general concurrency,
absolute resource safety, global optimality, native process memory bound and
Rust performance superiority claims. Source/tool inventories are compared as
recorded evidence; the ZIP does not bundle the entire source and toolchain for
rehashing local installations.

**The original f7 economic experiment remains failed.** Its later successful CI
run does not promote it to a successful experiment, and neither CI result
changes any model qualification or performance result.

## Retained audit attempts

`history-readback-attempt-01` failed in the newly written offline checker because
it compared a complete tool-probe wrapper to only the nested `execution`
object. Its source snapshot, traceback and 0.096463515 s cost remain unchanged.
The correction compares the complete wrapper (tool path, SHA, invocation and
execution) to the corresponding gate record. `history-readback-attempt-02`
then passed in 0.250686459 s. Combined retained outer readback cost is
0.347149974 s. Manifest construction separately measured 0.053191137 s of
inner work. These are audit observations, not complete human/development costs.
No test/native/model run was performed by the audit.

The final three-run audit (`final-readback-attempt-01`) passed in 0.334101744 s,
with peak child RSS 40,644 KiB. All retained readback attempts, including the
initial offline-checker failure, total 0.681251718 s. Final manifest construction
separately measured 0.027381085 s of inner work. Download costs remain in each
original acquisition receipt. These costs are not native experiments and are
not a complete measure of implementation effort.

`VERIFY.json` is the complete final result. `SUMMARY.json` provides the latest
and historical counts, nested timing boundaries and acquisition costs.
`STATIC_REVIEW.json` retains a second agent's read-only checker review. Every
checker snapshot, stdout/stderr and outer execution receipt remains under its
attempt directory. The original `CI_PINS.history.json`, `MANIFEST.history.json`,
`VERIFY_HISTORY.json`, `SUMMARY.history.json` and `README.history.md` remain
unchanged as the checkpoint before the final artifact arrived. The intermediate
`api-run-44e34b7.json` remains in progress as originally observed; the separate
`final-api-run-44e34b7.json` records its later completed/success state.

The current artifact is 1,318,884 bytes, ID 12982148935, official digest
`fd29bbd98ac293e51e1c2acc234d5ef0157333c634b6f390e2e95a6a356c8c6e`.
Its official tree and both source inventories bind
`835555fb35dbdcf867724ef7a0bb1a6616270217`; 6,685 tracked files and 440 external
inputs were unchanged. The current canonical contract digest is
`bd58291c3bc3470840a6b22b9f712fe1766629e3cbae8bd83291da16c911f018`.

## Independent offline command

```sh
python verify_ci.py --root . \
  --pins CI_PINS.json \
  --pins-sha256 1095dc2596424c76bab4fc99cda4bcee50c70f0c415a7e54bf23327cf28b1a5e \
  --manifest MANIFEST.json \
  --manifest-sha256 1ee9fea8cffc424cfcd3e12a3a4416682ddbfb5ad1d6ac246eb007113dfe3069 \
  --output NEW_INDEPENDENT_FINAL_REVIEW.json
```

The output path must not already exist. A future historical-only invocation
may legitimately return `passed=true` with
`latest_required_source_verified=false`; it cannot be used as current CI
qualification. The recorded final invocation above verifies all three exact
artifacts and the latest-source flag is true.
