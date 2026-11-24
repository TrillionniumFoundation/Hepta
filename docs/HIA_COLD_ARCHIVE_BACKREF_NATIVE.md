# Immutable phase-journal capture and AZ03 archive replay

The native archive accepts AZ01, AZ02 and the 40-byte AZ03 backward-reference
record. It retains the complete logical journal and every actual published
file. Execution, observations, node counting, source/file custody, archive
readback and the original 180+3 second limits are unchanged.

Before journal parsing, the archive completes its existing hash of the actual
original journal against the sealed driver receipt. It then creates a private
memfd with `MFD_CLOEXEC|MFD_ALLOW_SEALING`, mode 0600 and exact journal length.
It copies every byte with complete `pread`/`pwrite` transfers of at most 65536
bytes, adds all four seals (15), checks them with `F_GET_SEALS`, checks the file
shape/owner/size and hashes the entire sealed clone against the same receipt.
All journal parsing and backward-reference reads use this sealed descriptor.
The clone remains held until the archive process exits.

The original journal descriptor remains the input to all the original
inventory, content hashing, archive copying and post-copy custody checks.
The new capture adds a complete hash of the immutable clone; it removes none
of the original hash passes. The master retains its own two archive hashes.
A concurrent writer cannot change a referenced chunk between its first parse
and a later reference read because the parser reads the sealed clone. A mixed
capture cannot pass the clone hash against the original driver receipt.

An AZ03 record is `HIAQAZ03`, the logical raw length, payload length 8, mode 3,
then the prior physical offset. The referenced bytes must be a complete earlier
original AZ01 or AZ02 record, with encoded extent at least 64 and at most
65536, and must end before or exactly at the current reference's physical
offset. The old record's raw length must equal the reference's raw length.
Reference-to-reference, future, cross-phase and non-boundary references are
not admitted.

The reader maintains its own 8192-entry, 64-byte-stride cache in the original
4 MiB workspace. It computes the shared word-at-a-time FNV selector only after
an original record has been independently decoded and structurally consumed.
A reference must match the cached fingerprint, original offset plus one and
encoded extent. References never insert or refresh cache entries. The writer
uses the additional private cache fields for SHA-256; the archive does not
use FNV as content integrity proof, because all its chunk reads are from the
receipt-verified immutable clone.

Workspace layout added by this change:

| Range / word | Purpose |
| --- | --- |
| 2008 | Held sealed clone FD |
| 2240, 2248 | Bounded capture cursor and transfer size |
| 2256 | Current reference raw length |
| 2272, 2280 | Validated prior offset and encoded extent |
| `0x330000..0x3b0000` | Shared 8192 x 64-byte boundary cache |
| `0x3b0000..0x3c0000` | At most 64 KiB capture transfer buffer |

The shared selector/cache author is owned by the driver change in
`tools/hia_cold_journal_backrefs.py`; this archive checkpoint depends on that
same source. No syscall adapter or common decoder is changed by this commit.

Qualification at this checkpoint: the original 19 archive controls pass for
both AZ01 and AZ02, including actual concurrent writes to the archive, source
file and original journal. A real native AZ03 writer plus this archive also
passed the unchanged base (3394 nodes) and original-chain (21424 nodes)
component runs. Every published byte matched the earlier actual observation,
and every archived file was independently read back by byte and hash. Those
component runs reused already qualified independent reference inputs for
performance measurement and are not the complete fresh cold replay.

The machine-readable source/product identities and these qualification pins
are in `HIA_COLD_ARCHIVE_BACKREF_NATIVE.json`. Independent malformed-reference,
selector-collision and live snapshot ABA controls are separate qualification
steps; neither these component receipts nor a format-only test replaces the
complete 60-phase admission.
