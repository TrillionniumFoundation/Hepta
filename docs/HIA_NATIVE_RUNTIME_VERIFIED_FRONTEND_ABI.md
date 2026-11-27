# Native Runtime verification and typed rejection

This component extends the fixed Runtime frontend with actual native `HIAProgramRejected` values. It preserves the original frontend product and request domains as a separate retained profile.

## Actual qualified product

The new native root has 46 logical roles and 15,439,935 bytes of text, within the original 16 MiB limit. Its sole Value code and arena, original Runtime/Lease carrier, original native frontend binding and installed-resource custody remain shared. The compiled HIA packers produced bytes identical to independent construction, and the original native linker produced the installed ELF.

The fixed frontend exports remain bind, options and verify. Capsule offsets are bind 0, options 1056 and verify 1552. The verify export contains a fixed mechanical dispatch: `HIARTVQ1` uses the retained fresh verifier; `HIARTXQ1` uses the native rejection owner. Both receive the same actual `HIARTVC1` 8192-byte verification context initialized by the native frontend binder. No consumer may populate that prefix or substitute a callback.

The fixed parent-capsule imports resolve the sole root, sole Value and installed-global entries. This capsule is not an independently initialized alternate Value arena.

## Typed rejection request

The six-argument entry uses immutable input/output/work pointer-and-extent pairs.

| Field | Meaning |
| --- | --- |
| Input length | Exactly 128 bytes |
| 0 | `HIARTXQ1` |
| 8 | 0 convert; 1 retry retained cleanup |
| 16 | For conversion, the actual `HIARTVR1` format 1 or 2 |
| 24, 32, 40 | For conversion, caller-owned immutable error payload capability |
| Remaining input | Zero |
| Output | At least 65,536 bytes |
| Work | Actual native frontend verification context, exactly 8,192 bytes |

Retry has zero format and capability fields. The payload is borrowed: the owner obtains a real payload clone, reads it through the fixed payload owner, imports the actual JSON into the sole Value arena and releases its own clone. The caller retains its original payload reference.

Format 1 is the actual normalizer driver diagnostic envelope. Its `E_DRIVER` transport code is not substituted for the HIA rejection code. The policy checks the envelope and obtains the HIA code from the actual message prefix before the first colon and space. Format 2 is the verifier's local descriptor; the declared class, HIA code and full message must agree.

The policy creates actual native strings, namespace dictionary, argument tuple, canonical class 42 and exception instance. Its namespace holds the real `code` Value and its arguments contain the full original rejection message. All temporary Value ownership is released by the deferred native protocols. No error instance is represented by a JSON shadow.

## Reply and failure custody

The 128-byte `HIARTXR1` header has status at 8, disposition at 16, independently owned primary exception capability at 24/32/40, pending at 80, known at 88, delivered at 96, quarantine kind at 104 and detail at 112. Disposition 2 means a real exception was delivered.

A primary exception already created remains delivered when subsequent temporary-resource cleanup fails. The response never hides that capability. A failed actual `munmap` retains the actual mapping and continuation in the existing verification context. Context words 152/160 retain pending/quarantine facts; word 184 is `HIARTXC1` only while this rejection continuation remains pending. The older verifier refuses this private retained continuation, and the native frontend binder refuses to retire the enclosing context. Only a successful native retry clears the retained mapping and marker. Retry never hands the primary exception out a second time.

A malformed or unknown dependency receipt preserves quarantine; no status is treated as proof of consumption. Queue pending is distinguished from the adapter's own retained continuation, and an actual successful retry does not retain a stale pending flag.

## Actual evidence and limits

The same installed root passed the original seven frontend groups and nine rejection groups. The rejection groups include missing schema, malformed JSON, invalid UTF-8, text input, actual VerifiedProgram structured-field revalidation, actual exception class/code/arguments compared with the original `verify_program`, real `mmap` ENOMEM before publication, and real `munmap` EIO after the exception was published. The latter test observed the retained mapping, rejected cross-profile cleanup and frontend retirement, then executed native retry and verified single delivery, unchanged exception and full Value/payload/FD/parent-guard retirement.

These are component qualifications. The full public Runtime constructor, scalar/totality-before-directory sequence, automatic Runtime terminal resource ledger and whole runtime qualification remain pending. Underlying rejection causes, traceback and normalizer capture attachment are not qualified by this component. The primary class/code/arguments qualification must not be used to claim those additional Python exception semantics.

Production source capture contains HIA and actual mechanical assembly; Python authors and oracle drivers remain development provenance only.
