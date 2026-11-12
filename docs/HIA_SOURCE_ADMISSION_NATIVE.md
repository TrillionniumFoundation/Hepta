# Explicit native checkout source admission

## Status and ownership

This component is an explicit HIA implementation of one fresh checkout
`file_digests` operation. It is **not the default** source-admission path.
It does not change `ExecutionContext`, a public deadline, the source contract,
the worker, a release selection, or installed production state. No old stack is
deleted. Whole-product cold/full qualification and whole-input equivalence
remain separate requirements.

The canonical HIA asset is byte-for-byte revision three of the previously
executed isolated prototype:

- `examples/hia_bootstrap/source_admission.hiaasm`: 89,056 bytes,
  SHA256 `e7e0bdf576dd721c36d98a2b1855bcd34a2ab480094c322a3629ddc26de192f6`.
- The independent original HIA reference is retained at
  `tests/fixtures/hia_source_admission_reference.hiaasm`: 75,196 bytes,
  SHA256 `55097a1db37eb9c2771e6988c6299ac90b87a02b437f1c48527e9e64ee408298`.
  It is not regenerated from the optimized authoring module.
- The canonical packaging, loader, builder and permanent fixture are new source.
  The historical prototype's passes do not qualify those new paths.

HIA owns the fresh declared/dynamic path union, ordering, deduplication, each
read preclaim, its nonce and sequence, SHA-256 state, lowercase hexadecimal
serialization, and complete-map admission. Python performs the fixed
`Path` enumeration, `read_bytes`/close, memory allocation and object/byte
transport. It resolves native output handles back to retained exact strings
and checks the typed receipt. Python does not hash the admitted file contents.

The retained native state belongs to one invocation. It is a cooperative-host
protocol, not a security boundary against code that can rewrite the process's
private buffers or machine entry point. It provides neither a durable journal
nor a filesystem-wide atomic snapshot.

## Explicit interfaces

The runtime imports no authoring tools and has no environment-driven default
selector. The caller chooses the manifest and supplies its exact source list:

```python
from hepta.hia_source_admission_native import (
    installed_source_admission,
    native_file_digests,
)

image = installed_source_admission("/operator/selected/manifest.json")
result = native_file_digests(checkout, image, source_files=declared_sources)
```

`declared_sources` is the checkout profile's iterable of exact `str` values.
The dynamic set comes from the original
`(root / "hepta").rglob("*.py")` boundary and `relative_to(root).as_posix()`.
No alternate path normalization, content cache, mtime cache, or Python digest
fallback is used. There is no additional 8 MiB admitted-file limit. Allocation
and filesystem failures remain observable.

One image can create independent invocations, including concurrent calls.
`image.create().run(root, declared_sources)` is single-use. A failed invocation
cannot be resumed, retried, or turned into a partial map. A newly created
independent invocation makes its own fresh filesystem observations.

`source_files` is mandatory on the convenience function. In particular, the
runtime does not import `tools.hia_selfhost_contract` to discover it. This keeps
installed operation independent of authoring files and avoids a recursive
`current_sources → native source admission → current_sources` dependency.

## Code selection and installed custody

The explicit manifest has exactly five fields:

```json
{
  "schema": "hepta.hia.source-admission-native.v1",
  "source_sha256": "<64 lowercase hexadecimal characters>",
  "image_path": "source-admission.image.bin",
  "image_sha256": "<64 lowercase hexadecimal characters>",
  "compiler_sha256": "<64 lowercase hexadecimal characters>"
}
```

Duplicate fields, additional fields, malformed hashes and non-sibling image
paths are rejected before mapping. The existing native executable limit is
1 MiB, and the manifest transport limit is 16 KiB; neither is a limit on a file
whose contents are being admitted.

Every `installed_source_admission` call freshly reads and binds the manifest,
the source-owned HIA resource, and the selected executable. It rechecks those
bytes before returning. Only the immutable executable mapping can be cached.
A warm mapping therefore does not hide changed or missing source, executable,
or manifest bytes. An already returned image keeps its original immutable
code; a later failed selection neither replaces it nor resumes an invocation.

In a checkout the source comes from the source root. In an installed wheel it
comes from the package's
`hepta/_data/examples/hia_bootstrap/source_admission.hiaasm`. A missing
installed resource does not fall back to cwd, HOME, an old checkout, or a warm
mapping. The wheel test performs real native admission with an empty PATH and
blocks every `tools` import.

The local manifest selects trusted machine code. Its hashes are not an
all-input refinement proof, and the manifest alone makes no cold/full claim.

## Production builder and separate development builder

`tools/build_hia_source_admission.py` has two explicit entries. Production
`build(output, compiler, cold_report)` admits a **completed current-source cold
report** using the shared `admit_cold_build`. Every canonical component source,
test and independent reference fixture must be present with its exact digest
in that complete admitted source map before the output directory is created.

```console
python -B tools/build_hia_source_admission.py \
  --compiler /qualified/cold/B3.image.bin \
  --cold-report /qualified/cold/report.json \
  --output /new/source-admission
```

The fixed compiler call retains its original 20-second child timeout, 1 MiB
output/workspace profile and existing HIA function/block/instruction/parameter
limits. The builder checks the actual in-memory and recorded native compile
receipt through the shared strict receipt validator. Compiler, HIA source,
complete source map, cold report, executable and receipt are read back before
publication. The manifest and build record are created exclusively and read
back again. An existing output or publication is never overwritten. A failed
build leaves its observations available; it does not activate a route.

A development experiment must be selected separately:

```console
python -B tools/build_hia_source_admission.py \
  --development \
  --compiler /explicitly/retained/B3.image.bin \
  --output /new/source-admission-development
```

`build_development` still checks exact compilation receipts and all consumed
component bytes. It writes `development-manifest.json` and
`development-build.json`, with
`EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT` scope. It never calls a missing-cold
fallback and never fabricates a complete-source cold receipt.
`--development` and `--cold-report` are mutually exclusive.

## Native protocol and uncertainty

Each invocation retains a nonzero u64 nonce, a monotonically increasing read
sequence, an integrity-checked native state, and a transport preclaim. The
six-u64 reply contains status, action, nonce, sequence, item/count and extent.
The operation families initialize, claim the next read, accept its bytes,
record a foreign failure, or expose a bounded status observation.

Initialization validates the complete packet and zero destination state before
writing. HIA sorts and deduplicates retained path handles. State/output growth
is admitted only through the native no-effect capacity replies. A read request
is issued before the filesystem operation. File bytes are submitted only after
the original `read_bytes` context manager has completed its close.

A successful map is returned only after the native owner has consumed every
admitted unique input and issued its complete-map result. The fixed bridge
checks completion count against both the initialized unique count and the
confirmed sequence, the exact result extent, valid handles, unique keys and
canonical hexadecimal bytes.

Native entry is preclaimed before control crosses into machine code. Lost
return/receipt publication leaves that claim retained and refuses replay.
Filesystem exceptions retain the original exception object; failure to record
the diagnostic native outcome cannot replace it or authorize another read.
Sequence exhaustion, stale/foreign outcomes, malformed packets, state
corruption and inconsistent completion receipts refuse without returning a
partial map.

## Permanent controls

Source-only controls run without a selected compiler:

```console
python -B -m unittest tests.test_hia_source_admission_native.SourceAdmissionSourceTests
```

Native controls require exactly one explicit authority:

- `HEPTA_HIA_SOURCE_ADMISSION_COLD_REPORT`: the fixture takes the compiler from
  that actual cold report and uses the production builder.
- `HEPTA_HIA_SOURCE_ADMISSION_DEVELOPMENT_COMPILER`: the fixture uses the
  separate development builder and labels all observations accordingly.

Neither present means an explicit native-fixture skip, not a native pass.
Both present is an error. The full qualification harness must supply a
current-source cold report and reject unintended skips.

Optional `HEPTA_HIA_SOURCE_ADMISSION_EVIDENCE` selects the evidence parent.
The fixture creates an exclusive `source-admission` child and keeps original
compile receipts, inputs, outputs, controls and wheel logs there. No fixture
contains a machine-specific source or compiler path.

The permanent module contains 25 unittest methods, including the original
13 machine/VM methods and one method that executes all 11 original ordered
filesystem controls. The additional source/build/custody/wheel methods cover
the permanent integration boundary. The original controls retain:

- SHA padding boundaries, randomized vectors and a file larger than 8 MiB.
- Union/order/deduplication, Unicode/surrogate names, long names and empty maps.
- Stale/foreign nonce outcomes, malformed state, canaries, no-effect capacity
  replies, sequence exhaustion, and both completion-receipt regression cases.
- Lost native acknowledgements before and after entry, exact filesystem
  exception identity, diagnostic failure, reentrancy and independent concurrency.
- Independent Core VM comparison of **every output/state byte**, with the
  unchanged 2,000,000-step VM limit.
- Sixteen deterministic randomized path sets comparing every transition and
  every state byte against the separately compiled retained original HIA source.

The 11 ordered controls compare the current complete declared/dynamic source
closure with the original Python oracle. The number is derived from the actual
current closure; it is not frozen to an obsolete 821-file manifest. They check
the full open/enter/read/close/hash/hex event sequence, changed bytes with the
old mtime, a newly added dynamic Python source, its removal, two missing inputs'
first sorted error, replacement by a directory, read/close/hash/hex failures,
and an earlier hash failure before a later missing read. On the native side,
hash/hex event labels identify native transition boundaries. The "hex fault"
is a lost outcome after the HIA digest transition, not a claim to have injected
a fault inside HIA hexadecimal serialization.

Installation and build integration additionally check fresh source/executable
binding on warm hits, missing resources, changed admission readback, malformed
manifest refusal before mapping, strict actual compile-receipt fields, receipt
readback drift, changed source after compile, exclusive publication, and the
actual wheel without authoring tools or a checkout fallback.

## Historical evidence and limits

The frozen r3 prototype ran on Python 3.12.14 with explicitly retained compiler
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`.
It passed the original 13 machine/VM methods and 11 differential controls.
Its full 821-file, 23,219,411-byte map and read order matched the original
oracle. This is historical prototype evidence, not execution of the new
permanent loader/builder/wheel controls.

The complete original r1–r3 evidence archive has SHA256
`76187ecb326927f232aa4af5f437cc8c140306bdd029f3722cae9ac35a667c09`
(143 members). Its immutable UTF-8 transport wrapper is Git blob
`5e4abfaece6e4083fc9c8ad0cdd65c9330fa53d2`. The separate r1 archive is
SHA256 `c441bcb0e3a9d79e56ddfcd0d818ff4c940d0c1c8f9ad64f12228c62831450ae`,
wrapper blob `422a0af9c8617fb0ee15a9e7c26f82f151202b69`.
These archives retain the initial over-large VM-return fixture failure and the
r2 completion-count transport defect, as well as their corrected observations.

The scalar HIA SHA/state implementation remains slower than the hosted digest
path. Original full-map observations were approximately 24.8 seconds for r1,
5.62 seconds for r2, and 11.19 seconds for r3 under varying shared load. These
are not interchangeable timing qualifications or a stable speedup claim.
The original three-second product deadline has not been passed or changed
by this work. Performance, complete source qualification, installed wiring and
whole-product closure must be evaluated on their actual new candidate.
