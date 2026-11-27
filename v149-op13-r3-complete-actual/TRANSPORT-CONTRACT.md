# Original op13 R3 evidence transport

This is a custody-only transport of the already sealed original R3 archive.
It performs no product run, Native or VM call, compilation, binder, CI, source
mutation, budget change, archive resealing, ref update, or PR update.

The original 51,879,965-byte gzip is represented by 212 ordered archive parts.
Seventeen complete original metadata files are represented by 54 ordered
metadata parts. The fixed index and seven original/control leaves bring the
initial publication to 275 immutable Git blobs. Each had an actual POST SHA
acknowledgement and a complete GET compared with the original UTF-8 bytes,
then an independent on-disk readback. Local full API envelopes are retained.

The actual-GET verifier reconstructs the complete gzip and metadata streams.
It checks the gzip footer/CRC and exact archive identity; it decodes all 36,048
CAS objects and compares each of the 40,990 logical originals independently.
All 236,321,241 logical bytes, POSIX modes, original seven-stat identities,
366 directories, and original path sets matched. Repeated logical references
are fully read, not accepted from a digest or payload cache. No new full
uncompressed copy is produced. The original archive and every original remain.

The metadata includes the full INPUT-PLAN, AUTHOR-REVIEW, INTENT, MANIFEST,
REPORT, original sealer, Root custody EXEC/RETURN, and nine original Root
author/admission/observer/reader tools. Additional published transport proofs
retain the R1 verifier/preparer before-images, exact R3 diffs and byte inverses,
actual receipts, transport code, and execution observations.

The original qualification remains FAIL at native-11. The following Native
group was not started. No semantic VM was run. all_frames_retired remains
false, and compile_full_workspace_observed remains false. Successful custody
is not a passing qualification, cold admission, whole-program qualification,
or permission to replace an original failed record.

The gzip's Git identity is an identity of the reconstructed binary, not a claim
that the entire large binary was separately POSTed as one blob. The mount recipe
names the actually POSTed and fully GET-verified UTF-8 leaves. Its final proof
leaves describe the transport of the original archive rather than revising it.
