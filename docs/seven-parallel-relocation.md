# Source-only parallel byte-fact relocation

This is a separate, nonaccepting layout experiment. It does not launch Lean,
reuse compiled modules or receipts, change an existing runner, or establish
performance. All twelve wider obligations remain unproved; authority remains
`DENY_ALL`.

## Why this candidate

The original seven-layout diagnostic on commit
`6b71086dfd012bc87d5828d8d4c3c58d78875f04` reported its sixth marker, immediately
after `parallel_parsed`, at 57.160616 seconds. The process then reached its
unchanged 60-second deadline without reporting the marker after 595 parallel
byte-fact theorems. These are asynchronous reporting frontiers, not individual
theorem timings. Complete parent elapsed-time receipts are not available in
the public log projection, so no parent-stage headroom is assumed.

Source inspection establishes a smaller dependency boundary: the byte
variables and earlier child facts needed by `parallel_bf0000` through
`parallel_bf0490` are already available by the end of `CertPart03`. The last
104 facts first become available in `CertPart04`.

The candidate moves only those first 491 exact declarations, in order, from
`CertPart04` to the end of `CertPart03`, immediately after the original
`parallel_pl113_0` declaration and before its print inventory. The moved
proof bodies total 100,165 UTF-8 bytes. No proposition, proof body, byte
input, original nonauxiliary declaration order, or import edge is changed.
The last 104 facts remain in their original Part04 position.

The per-module theorem inventories become:

- Baseline: 56; SyntaxData: 547.
- CertPart01: 271; CertPart02: 54; CertPart03: 1,655.
- CertPart04: 807; CertPart05: 1,297; CertPart06: 1,297;
  CertPart07: 1,297.
- ConnectionsTransportRejections: 75; WrongArm: 1.

These are source counts, not predictions of elapsed time. Part03 may exceed
its deadline after relocation. A different layout could distribute linear
facts into earlier stages, but those stages also have no established spare
time. That broader change is deferred rather than bundled into this one.

## Independent recovery and limits

The new source type and protocol are distinct from the existing seven-layout
acceptance and diagnostic types. Validation first authenticates the old seven
proposal using its unchanged full validator. It then parses actual candidate
declarations and checks fixed stage metadata, canonical import/namespace/print
framing, exact moved-name order, global uniqueness, and dependencies against
actual module ancestry.

Recovery removes the actual 491-declaration tail from Part03 and inserts those
same bytes before the actual `parallel_bf0491` declaration in Part04. The full
reconstructed stages must equal the authenticated old seven proposal, and that
reconstructed proposal must pass the unchanged validator. That validator in
turn reconstructs the original eleven source files and verifies all five byte
inputs. Manifest hashes and relocation descriptions do not substitute for
recovery from actual candidate bytes.

The retained-source budget covers the original eleven files and candidate
eleven files, plus any explicitly supplied additional serialized copies:
2 MiB per source, 8 MiB total, and a 32,768-byte manifest. Keeping a further full
old layout as an artifact must be charged explicitly; it is not a free copy.

There is no new process or execution budget in this source-only experiment.
Any later execution plan must independently preserve eleven stages, 60 seconds
per process, the 540-second new-launch deadline, 600-second outer command,
2-second cleanup, and 15-minute CI job. It must freshly authenticate all
candidate sources, binary/support identity, and every required ancestor. Old
module or receipt commitments cannot be carried over into the candidate run.
Full narrow acceptance would still require all 66 positive targets and ten
exact negative proofs. Source validation alone leaves every acceptance gate
closed.

## Local source checks

The dedicated test module is
`tests.test_core_seven_parallel_relocation_sources`. Run it with the project's
pinned Python dependencies under a 180-second outer test limit, for example:

```sh
timeout 180s python -m unittest tests.test_core_seven_parallel_relocation_sources -v
```

This command performs Python source/inverse checks only. It does not launch
Lean. Existing CI workflows are intentionally unchanged by this source-only
candidate. A passing Python test is not a candidate proof run or kernel
acceptance.
