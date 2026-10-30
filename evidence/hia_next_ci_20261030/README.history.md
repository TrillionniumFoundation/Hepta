# Independent CI artifact audit

The two historical CI artifacts were independently read back without extracting
or executing their contents. They pass the checks described below. The latest
required source is `44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`; its final artifact
is still pending in this checkpoint. Neither historical result substitutes for
that source's CI qualification.

| Source | Official Actions run | Python full run | Rust tests / result footers | Critical coverage: groups / modules / unique methods | Canonical safety selectors / capabilities |
|---|---:|---:|---:|---:|---:|
| `73922c1a3971125dfb9703555e50e5cf6444e842` | 41056856811 | 4,183 | 109 / 20 | 72 / 179 / 1,763 | 364 / 39 |
| `f7cc87218a101b4b2c715e3fdd2e9d42a7f7fd8b` | 41059399079 | 4,259 | 116 / 21 | 77 / 187 / 1,839 | 440 / 45 |

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

Each ZIP contains 46 ordinary members (6,990,666 and 7,125,999 uncompressed
bytes). The separately pinned manifest binds every member's path, size and
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

The full independent result is `VERIFY_HISTORY.json`; summary and acquisition
costs are in `SUMMARY.history.json`. The exact checker snapshots and outer
execution receipts are under the attempt directories. `CI_PINS.history.json`
and `MANIFEST.history.json` are frozen historical inputs; a later final
three-run set will use separate filenames and preserve these bytes.

```sh
python verify_ci.py --root . \
  --pins CI_PINS.history.json \
  --pins-sha256 71d653f5379121849bd728de98033e1164548462c7bc0f86cf3d670a091ea677 \
  --manifest MANIFEST.history.json \
  --manifest-sha256 2ef414ddaeed3e4314757ddeb61acd461728458bb06b88f6e4982dcd0a0c152e \
  --output NEW_INDEPENDENT_HISTORY_REVIEW.json
```

The output path must not already exist. A successful historical-only audit
still records `latest_required_source_verified=false` until the exact latest
source's final artifact is supplied and independently checked.
