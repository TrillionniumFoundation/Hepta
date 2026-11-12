# Exact Core53 original cold-failure readback

This is an independent, zero-target evidence reader for commit
8f27671ad748dc7c081a1eaad897b057d8d9f42e, tree
e76b4fe1237414ae3d30ba475bc19ea66d966f6c.

The actual Core run 43237029270 / native job 131247009417 failed. Its full
41,874-byte console log reports 6 of 11 cold checks, empty generation lists and
exit 1. This does not identify the cause or establish that no native work ran.
The previous Core52 and Core52a passes do not qualify this failure.

## Exact producer artifact

Artifact 13954345082 is
hia-core-native-8f27671ad748dc7c081a1eaad897b057d8d9f42e-1.
The producer and API agree on 54,205,895 ZIP bytes and SHA-256
4e6c28c249f27ec2dc05d7dcd7775c9aeb4d64b2a5dd18830c26af481624915b.
The producer uploaded 3,881 files. The original ZIP root is the temporary
directory, with hia-cold.json and hia-cold.cold/.

The transport independently verifies run, head, artifact ID/name, size and
digest before streaming the complete archive. The repository token is never
forwarded to the signed storage request. Transport limits are 90 CPU seconds,
180 wall seconds and 1 GiB address space, including output and its final gate.

## Reader scope

The reader copies and verifies the whole original ZIP, streams every outer
member through its CRC check, hashes complete bytes, records exact ZIP modes,
and checks the expected producer file count. Every outer member ending in .zip
is read as a complete embedded ZIP; every member of those ZIPs is streamed,
hashed and checked. Declared HIA lossless manifests and publication receipts
are compared against those full members. This does not promise recursive
interpretation of arbitrary ZIP members inside those embedded archives.

The original source export is bound to the original 53 Git tree and cold
source manifest. The cold/request/owner/phase/generation records and failure
streams are preserved as original bytes. Bounded base64 console frames permit
lossless root readback; console omissions remain available in the complete
artifact. No original JSON is parsed and reserialized in place of original
bytes. Derived JSON observations are separately named.

The only original-source AST operation is a standard-library literal read of
the pinned QUALIFICATION_FAMILIES assignment. Original project code is never
imported or executed. There is no compiler, B3, VM, native, old test, cold
qualification, backend or namespace execution in this job.

The old Core48 reader's readback logic is preserved by a complete exact text
inverse. New changes bind Core53 identities and protect the first failure
through finalization. All successfully copied original files and both inputs
are checked again on success and failure. Primary report writes, stdout
flushes and the post-output receipt are included before strict final aggregate
90 CPU / 180 wall checks. A later failure attempts a final FAIL rewrite and
cannot return success. An unwritable output remains an execution failure.

The producer's separate cold qualification limit remains 180 seconds with
3 seconds of cleanup. Nothing here changes that policy or assumes the cause
of the original failure.

## Current status

Source-only. Full Git blob bytes and exact forward/reverse text identity were
checked by the author. This new reader has not passed AST parsing, downloaded
the artifact or read any of its members yet. Its future PASS would establish
readback only. Core53's original FAIL remains retained, and whole native
production replacement remains OPEN.
