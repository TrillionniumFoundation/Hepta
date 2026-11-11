# Preserve four completed development copies before retiring them

This checkpoint precedes removal. It does not delete a production, reference,
compiler, Runtime or Agent owner. The exact main source is
`5831f52fada45e076f8f68f198a15c0585e6104f`, tree
`72084752441a61f879dbbcf363a8cade3ef2d6b1`.

All regular files, including ignored and untracked files, and directory modes
were inventoried for the inactive function, constructor, outer and v64 candidate
copies. Every file matching the exact main blob and mode is identified by that
immutable Git object. All other 194 files / 10,050,529 bytes are in the archive,
including candidate-only code and intermediate observations. All 199 archive
members, including four complete inventories and the plan, were independently
read back by bytes, SHA-256 and mode. No source symlinks were present.

Recovery starts in an empty directory and materializes each inventoried file
from its declared exact-main blob or its preserved archive member; then restore
its recorded mode and the recorded directory modes. Do not infer missing files
from a complete base checkout: the inventories describe the actual candidate
copies, including their intentionally absent files. Original Git HEAD, refs,
status and index hash are recorded. None had staged changes or Git objects absent
from the surviving main repository. Active main and Agent-state work use no
object alternates into these candidates. The working agents released these four
runtime/source dependencies before this plan was prepared.

Removal is permitted only after this checkpoint's immutable blobs, modes and
sizes are read back from the remote branch, then all candidate inventories and
main cleanliness are rechecked. A separate subsequent receipt records what was
actually removed. The original standalone development evidence directories and
all main/recovery archives remain.

The adjacent v64 publication files preserve the exact final source snapshot,
cold source map and canonical Git commit object. Fresh GitHub/ROG qualification
remains separate from publication and development evidence.
