# R6: a separate witness contract for two successful verifier observations

## Decision and scope

This is a separately versioned authoring successor. It changes one expected
list in the additional CLI witness test. The original R5 test file, its
singleton assertion, its reported failure, and the suffix that the failed
method never reached remain immutable. This package does not change or
activate product code, a default selector, a compiler, an image, or a budget.
It has not run a binder, a test, a Native/VM call, or CI.

The complete R5 test is 29,331 bytes, Git
`98582224513d486f706459183e3b5cd7a089bf0c`, SHA-256
`292657b99d1296661f3942c5054e8db6223b9d55ab50c7b38c80529c4b84cc73`.
Its exact full bytes are retained under `before/`. The new full test is under
`r6/`, with independent pins in `SOURCE-PACKET.json` and `STATIC-PROOF.json`.
It keeps the same twelve method IDs. The version is recorded in the external
contract and execution blueprint, not by silently rewriting the old file.

## Why the successful segment observes two refusals

The successful executed-pending segment in
`test_entry_error_busy_unknown_no_retry` directly prepares an actual Inspect
frame and calls the actual owner's `finish(frame)`. That segment does not
enter a CLI session wrapper. Its current verifier is temporarily replaced by
the test's `reenter` observer for the full synchronous `finish` call.

The preserved complete `inspect_program` policy first imports and invokes
`verify_program(document)`. The observer checks the refused `frame.drive()`
attempt, checks that the physical entry count did not change, checks
`frame.executed and not frame.completed`, appends its marker, and calls the
real verifier. Later the policy evaluates `normalization_report`. That
property resolves the real module-global verifier again and invokes it on
the verified value. The same observer runs all three state assertions,
appends another marker, and calls the real verifier again. With the preserved
primitive fixture, current providers, and both effects returning normally,
the successful segment therefore records two markers.

The R6 change is exactly:

```diff
-        self.assertEqual(reentries, ['refused-without-machine-entry'])
+        self.assertEqual(reentries, ['refused-without-machine-entry', 'refused-without-machine-entry'])
```

It neither removes the second verification nor memoizes its result. It does
not suppress, deduplicate, or filter either callback. The complete callback
body and all three assertions are byte-identical. The surrounding
`assertIsNone(error)` and real Native-entry assertion are also unchanged.
The original normalization property and the complete HIA policy are not
edited. `reference/SOURCE-REVIEW.json` includes the complete source excerpts
and the independently reconstructed call sequence.

## Why the first exception segment remains one

The first segment installs `refusing`, whose first verifier call raises its
specific `ForeignFailure`. The policy cannot reach the subsequent
normalization property on that path. Its exact exception-identity assertion,
`self.assertEqual(len(calls), 1)`, and actual Native-entry assertion remain
byte-identical. The change is restricted to the successful segment's
`reentries` oracle; it is not a rule that all errors or all inspect inputs
must cause two verifier observations.

## Original R5 result remains a failure

Before reset, Root and the peer reported session 63905 exiting 1 after
69.814360769 seconds: the first thirteen groups passed, and group fourteen
had one assertion failure with no test errors. The singleton-marker
assertion was that failure. The lost-claim and unknown-frame suffix beneath
that assertion, witness-11, witness-12, retained3 and original CLI43 were not
established by that run.

The old raw frame archive and the former detailed diagnosis were not fully
published before reset. The earlier source review explicitly records this
gap and the old hash-only diagnosis identities. This R6 package restores
source and authoring records from their complete published payloads; it does
not claim to recover the lost runtime frames or to replay the old failure.
The count contradiction follows independently from the preserved source.

The original source-only analysis is mounted by recipe
`9bfd18a239e19a6ec34da765f7e9a62e9e00e01c`; its previous proposal remains a
proposal in that archived package. Root has now expressly authorized this
separate R6 authoring decision. No original R5 report is changed to PASS.

## Preserved product and witness scope

The product view remains the complete R5 3,191-path map and tree
`d5e3ca6576607e3bfaad4bae09058a6c9fcfd1a5`. The additional witness is an
external qualification source, not a removed or substituted product path.
All product source pins remain identical. In particular, the actual R5
operand-position repair and records `import copy` fix remain required:

| Product source | Required Git identity |
| --- | --- |
| `hepta/hia_inspect_cli_operand.py` | `e2738c9ea58362f31eaddd1e6ac194317e80e367` |
| `hepta/hia_inspect_cli_records.py` | `4669e99e773538efa862ab2101f42e76b7cdbe00` |
| `hepta/hia_cli_inspect_native.py` | `cbd5621e19aab82007f4d4f36dbd6035c8181b10` |
| `hepta/hia_inspect_program_native.py` | `714247cd3d821339575983a70a804c9a69471b1e` |

This R6 decision does not alter op35/op10 import count, provider capture,
permission order, alias handling, dynamic reverify, or error semantics. It
does not adopt the independent op13 PatchResult adapter or borrow that
adapter's projected 3,210-path view. No new HIA generation is needed for the
one-line witness contract change.

## Required new evidence

`GROUPS.json` preserves all eighteen original groups, their order, complete
IDs, and group records. The new version must obtain its own results, including
the unchanged lost-claim suffix in witness-10, both witness-11 and witness-12,
retained3 and all original CLI43 IDs. A failure stops the sequence and remains
a failure; no later group is inferred. Actual complete before/after machine
buffers must still come from the original observer and actual HIA entries.
Foreign fallback or a mock owner cannot satisfy a positive control.

The old execution blueprint has historical paths and runtime records, and
the unmodified old runner admits 64,615 original ordered predecessor rows.
Some of those payloads are not recovered. Consequently the R6 blueprint is
explicitly not executable or bound. It retains that full history descriptor
and does not remove its gate. A later, separately reviewed post-reset binding
must either recover every required original payload or explicitly decide a
new execution-admission contract; it may not fill missing bytes from hashes
or silently replace the missing history with previous PASS metadata.

All eighteen groups retain each original 180+3-second owner. The six report
compilations and one Inspect compilation retain their 20-second, 10-CPU-
second and 1 MiB bounds. The 1 GiB entry and per-group storage floor remains.
Original CLI43 still uses `-B`, while the other group children use `-I -B`.
No Native/VM, cold, default, whole-runtime or new installed-source authority
is established by this authoring package.
