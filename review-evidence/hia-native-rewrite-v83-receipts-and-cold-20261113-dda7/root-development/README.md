# HIA receipt-loop development and exact source union

This archive preserves 322 logical originals, including all native observations,
failed diagnostic attempts, six original/candidate compiler outputs, the frozen
nine-path source delta, complete source inventories, and exact recovery records.
Its 14 fragments have actual Git create acknowledgements and complete byte
readbacks. Every fragment reassembles to the original 12,056,628-byte archive,
SHA256 `528a8015856d8976812d904f5f2a2f056d2e9b3f61c343611dbdcc82d4ab53d8`.

## Source and observed behavior

The initial six-path HIA candidate is based on published source `1cd416ab028a4c59ac76bf4b8e2c4018fb552d9d`.
It moves one invariant extent read outside each of the existing checksum payload
loops in Artifact namespace, request journal, and slot ledger. Header read order,
checksum arithmetic, payload read order, receipt contents, and guards are preserved.
The reviewed domain is serialized calls with privately owned workspace, as used
by the existing adapters; unrestricted concurrent external workspace mutation is
not claimed equivalent.

All six original/candidate images were built with the same retained development
compiler under the original 20-second compile-child limit. Local CPython is
3.12.14. The successful observation run has 82 diagnostic controls, 778 paired
calls and 1556 actual native entries. Complete inputs, outputs, workspaces and
both-end canaries agree, including real independent VM observations, protocol
lifecycles, corruption, short buffers and maximum 8 MiB payloads. This diagnostic
count is not an execution count for the original full suite.

The first two diagnostic attempts incorrectly expected empty response and empty
ABI acceptance. Both images instead returned the same original refusal, status
1 and 20 respectively. Those attempts and their complete available observations
remain preserved. The third attempt terminated with exit 137 while recording a
large textual trace; 762 complete records are recoverable, and its truncated
original gzip remains intact. Exit status alone does not establish the cause.
The successful fourth attempt uses bounded binary framing, preserving every
observed byte without constructing a large hexadecimal JSON record.

The 18 fixed-CPU, same-process alternating measurements compare read-only event
90 receipt calls. At 1 MiB the original/candidate median wall times are
110.98/19.95 ms (namespace), 121.74/22.92 ms (request), and 121.44/24.53 ms (ledger).
Each batch verifies the full output, unchanged input/workspace, return count and
canaries. These measurements do not replace original business budget gates.

## Frozen union

The final 3324-file union has tree `bc276bc832a7d6f04a21d63f55645859b75a01ee`,
relative to published parent `936aee286e30ee271b8d09235aba57d6ba76cd9e`.
Its nine changed paths are the six HIA authoring/generated paths, the precise
Evaluation integration inventory repair, four missing Artifact evidence upload
directories in the existing normal workflow, and regenerated support metadata.
The language coverage JSON is byte-identical. All three HIA regeneration outputs
equal the independently observed candidate bytes.

The original Artifact 45 source controls and the three checksum owners' original
21 source controls pass locally. The complete 973 ordered test IDs are preserved
and loaded, with zero full-inventory bodies executed by the loader. All source,
compiler and original harness input identities remain unchanged during controls.
Actual 3.14/3.11 CI and current-source cold results are separate qualifications.

## Recovery and limits

The archive includes the actual bytes of all 121 unique source changes retained
from seven inactive exports. Only 21,879 files exactly equal to the published
`4b19af89a766593f7d5f1cc2db256e81aba7afcb` base were reclaimed; the complete
recovery plan and scripts preserve each original Git tree. Frozen raw-file
deduplication preserves all pathnames, bytes and modes and retains every original
ZIP. Derived transport encodings remain exactly reconstructible from rooted Git
objects. This maintenance does not remove old production.

`restore_originals.py` verifies downloaded fragments and optionally restores the
complete logical evidence files into a new directory. Original failures are not
overwritten by successors. `whole_native=false`, `current_source_cold=false`, and
`production_files_deleted=0` remain explicit.
