# Official hosted evidence for Hepta source 699de39

This is a read-only audit of original GitHub Actions evidence for public source
`699de39a8e92e0f083df316ecc5333fb3ecf8571`, tree
`592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`. All 18 available official ZIPs were
downloaded, checked against GitHub's original byte counts and SHA-256 digests,
CRC-checked, and retained without editing their bytes. All 3,068 ZIP members
received independent byte-count/SHA-256 inventory entries. Selected original
source, report, process-stream, and generated-artifact bindings were checked
against those retained bytes and the explicit Git source.

**Six runs succeeded; the separate full-release run was still in progress at the
last observation.** The completed content audit has explicit retention and scope
limits below. It does not turn this set of results into closure of all P0–P7
blockers.

## Official observations and content-audit status

Snapshot 03 was collected from **2026-10-29 11:24:23 through 11:24:34 UTC**.
Its original run, job, and artifact JSON files are unchanged. It contains seven
runs and 19 jobs: 18 jobs succeeded and the full-release job remained in progress.

| Official run | Scope | Official snapshot-03 status | Artifact content audit |
| --- | --- | --- | --- |
| [40862645159](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645159) | Actual-host ABI and declared stb_divide component | Success, 7/7 hosts | 7/7 ZIPs audited; temporary ABI matrix binary bytes are not retained by the workflow |
| [40862645199](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645199) | Actual-host C++ upstream reuse | Success, 7/7 hosts | 7/7 ZIPs audited, including native objects/executables and original streams |
| [40862645202](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645202) | Six outcomes, push | Success | Original ZIP, source maps, safety results, prepare-only application artifacts, and controls audited |
| [40862658213](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862658213) | Six outcomes, pull request | Success | Independently retained original ZIP audited to the same declared scope |
| [40862645459](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645459) | Verified optimization / NDU, push | Success | Original ZIP, current Hepta inputs, separately pinned native receipts, native binaries, and original command streams audited |
| [40862658216](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862658216) | Verified optimization / NDU, pull request | Success | Independently retained original ZIP audited to the same declared scope |
| [40862645318](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645318) | Full release | In progress | No available artifact; no artifact-content qualification claimed |

`summary.json` supplies the exact per-run/per-artifact mapping. Each
`content-audits/<artifact-id>.json` records its complete ZIP inventory, every
selected source map, every checked retained-file reference, explicit unavailable
references, and its remaining limits. `content-audit-index.json` records
18 `passed_with_explicit_scope_limits` results. The status means these original
records satisfy the stated offline audit; it is not a new native execution.

The final separate full-release observation was collected at **11:41:27 UTC**.
Job `123409464501` was still executing **Run all current native and experiment
qualification gates**. The standalone, verified-NDU, and integrated-eight-gate
steps had not completed. There were zero published artifacts and no reported
failed step. These later facts are retained in
`full-release-final-observation.json`; snapshot 03 is not rewritten.

## Source and actual-artifact bindings

### Seven actual ABI hosts

The actual matrix covers Linux x86-64 GCC/Clang, Linux AArch64 GCC/Clang,
macOS AArch64 Clang, and Windows x86-64 MSVC/Clang. Each original native-host
report records two optimization profiles, 181 foreign calls per profile,
three ill-typed declaration controls, and a compiled wrong-code control.

The exact current-source `validate_native_host.validate_report` was used only for
its read-only report/frontend reconstruction with `native=False`. Process
creation was prohibited during that check. The current compiler identity was
independently reconstructed from Git's original Python blobs; the local Python
audit dependencies were checked against those blobs before and after the audit.
No native compiler, host program, test suite, or workflow was run locally.

The ABI tool creates its matrix object and executables in temporary directories.
The official workflow uploads `native-host.json`, rather than those temporary
binary files. Their reported binary hashes therefore remain original hosted
receipts; **this audit does not claim to have recomputed those hashes from the
missing matrix binaries**. The finite report and original commands were checked.
The same ZIP's separately retained stb_divide binaries and migration records
were independently hashed: each host binds 273 implementation files and six
frozen fixture files before and after execution to the exact public commit/tree.
All 92 retained stb files were checked, or 94 for the Windows MSVC artifact.

These are finite frontend-to-Rust-object host qualifications. They do not qualify
general callbacks, reentrancy, external lifetimes, all ABI features, physical
boards, or general direct-LLVM exported resource interfaces.

### Seven actual C++ hosts

Each host reused the two locked nlohmann/json versions **3.11.3 and 3.12.0**.
For each version the retained observations include 98 direct/Hepta comparison
cases, 32 finite lifecycle cases, and 1,024 finite concurrent calls. Actual native
object and executable bytes, their machine/file format, generated input hashes,
original stdout/stderr bytes and base64 copies, and the actual wrong-code and
bad-signature controls were checked. The original hosted `audit.json` and its
eight rejected evidence-tampering controls remain intact.

Linux/macOS reports bind all 157 declared source inputs to exact Git blob bytes.
Each Windows report binds **150 exact Git blobs plus seven explicitly documented
CRLF checkout reconstructions**. Those seven example texts are precisely the
Git LF bytes with each LF changed to CRLF; both their Git and checkout hashes are
retained. They are not mislabeled as identical original Git bytes. Python files
are fixed to LF by `.gitattributes`; the locked upstream fixture bytes use
`-text` and remain unchanged. The actual retained Windows caller bytes were
checked against the recorded CRLF checkout.

The C++ evidence covers the declared finite reuse contract. It does not prove
foreign memory safety, general borrow retention, arbitrary asynchronous
cancellation, all allocation failures, or total human migration cost. Remote
compiler/sysroot binaries are described by the hosted receipts but were not
independently reacquired and rehashed here.

### Source/application workflows

Both original runs record **95 passed safety methods across 16 capabilities**, a
separate **183-test regression result with zero failures/errors/skips**, and a
successful `prepared_not_measured` filecheck run. The safety before/after maps
contain 909 source files and the application map contains 152; their Git blob
hashes, exact source head, and unchanged-source receipts were checked.

Filecheck records 768 native differential calls across eight routes and 96 cases,
48 resource cases, four maintenance cases, and two maintenance application
observations. Its actual libraries, input files, process ledger, validation
context, and other retained referenced artifacts were checked. The report has
`prepare_only: true` and an empty `samples` list. This does not qualify the current
version's representative throughput or tail latency.

The 35 passing deterministic agent controls have **zero model requests** and
`model_answer: false`. They establish those controls' observed behavior; they do
not establish independent real-task agent efficiency. Results from the push and
pull-request events are separate observations of overlapping suites, not twice
as many unique methods or tasks.

### Verified optimization and NDU workflows

Each original run records 595 regression tests with zero failures, errors, or
skips, and 30 completed finite NDU-loop episodes whose actual output/budget
checks passed. The audit checks the current Hepta maps (144 loop inputs and 360
regression inputs), loop protocol and calibration-bank digests, all original
episode records against their aggregate, the retained driver and generated
native artifacts, and native build command manifests with their original
stdout/stderr files. Four external identities remain separate:

| Native dependency | Exact original upstream pin |
| --- | --- |
| Recursive evaluator | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| Finite graph evaluator | `4b6391e116949af0c7e59776baead67271856bdb` |
| Persistent stream evaluator | `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` |
| Ranking adapter upstream | `d3c2d760eca5065fc966820379c35c6e8d56e855` |

The first three pins match the public 699de39 workflow. The ranking pin matches
`rust/hia-ndu-bridge/upstream.json`; its four current adapter inputs and builder
hash were checked. Original before/after upstream admission maps, native/bridge
source maps, and retained binaries were checked for consistency. **The external
upstream raw source blobs were not independently reacquired in this audit.**
The native admission receipts do not relabel any dependency as Hepta 699de39.

The adaptive negative control deliberately overwrites the candidate publication
path with the 23 bytes `not the loaded artifact`. The original admitted binary is
retained separately under `native-snapshots/candidate.so`, from the sealed file
descriptor before tampering. The audit checks that snapshot against both the
build and admission digests, checks the exact 23-byte final malicious path, and
checks the earlier `changed.so` negative control against original bytes plus
`changed`. `declared_negative_path_mutations` records these two different byte
identities explicitly. It does not pretend that the final malicious path is the
original executable.

The authority remains `DENY_ALL`, production activation remains false, and no
general performance superiority or safety derived from NDU is claimed. Python
production authority and the existing optimization policy are unchanged.

## Exact retention and publication

All 18 original archives total **79,211,552 bytes**. Their 3,068 members total
**342,675,778 decoded bytes**. Original ZIP bytes were published in commit
[`5c9875c14f12a676beef70da0674c1701c99f92c`](https://github.com/TrillionniumFoundation/Hepta/commit/5c9875c14f12a676beef70da0674c1701c99f92c)
under `evidence/hia_core_closure_20261029/ci-699de39/`. The official commit response
is preserved in `raw-zip-publication-commit.json`.

`publication-payloads.json` fixes 28 payloads: 16 whole ZIPs no larger than
12,000,000 bytes, and six ordered parts for each of the two larger source/app
ZIPs. Every part is at most 4 MiB. Concatenate each artifact's `payloads` in its
listed `index` order; the resulting bytes must equal that artifact's original
byte count and SHA-256. All parts and whole files were read back and verified,
and concatenated parts were compared byte-for-byte with the original ZIPs.
The map's SHA-256 is
`54bb41503f8ae316a6d650dd458ae2272007e3172b8c704ab4086ed9ff63da23`.

The metadata archive delivered with this report includes the official snapshots,
selected original raw reports, complete per-member inventories, audit code,
download receipts without transport secrets, source Git hashes, and local audit
development failures. It does not duplicate the already-published ZIP payloads.
The two large original local ZIP copies are represented publicly by their exact
ordered parts. `PUBLIC_FILES.json`, `MANIFEST.json`, and `freeze-receipt.json`
define the selected public set and its readback identities.

The first five local audit revisions rejected records because of assumptions in
the new offline auditor: Windows path separators/CRLF checkouts, list-shaped
maintenance records, independently pinned external source maps, relative command
manifest paths, the intentional adaptive path-tamper control, or a source blob
not yet included in the auditor's Git input set. Their scripts, failed audit JSON,
and stdout/stderr logs are retained. These are **offline auditor development
failures**, not newly failed hosted tests. Attempt 06 first passed all 18; attempt
07 additionally resolves relative stb artifact references explicitly.

A ten-pattern credential scan covers the public candidates and every decoded
original ZIP member. No findings were observed. Private signed download
references were used only for transport outside this directory and are excluded
from the public selection; the scanner does not read them. Previous snapshot 02,
snapshot 03, the frozen component archive, original hosted failures on source
1669ddc, and all source/test files were not modified by this audit.
