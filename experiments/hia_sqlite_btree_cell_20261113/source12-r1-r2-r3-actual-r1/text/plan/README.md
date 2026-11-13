# SQLite B-tree selected-cell HIA draft

This implements a bounded read operation on one supplied database page. All page-header, varint, payload-distribution, rowid-bit and overflow-pointer decisions are authored in HIA. The Python adapter only copies owned buffers and checks the returned transport envelope.

It does not claim to validate an entire page or B-tree: other cells, pairwise overlap, full freeblock chains, cross-page key order and overflow-chain membership are not traversed. It performs no database I/O or modification and does not replace AgentStore. Full pager, SQL, transactions, locks, recovery and the complete storage contract remain open.

The command includes caller-supplied page size, reserved-byte count, page number, cell index and current database-page count. Page one additionally checks the fixed database header. Read/write header versions outside 1/2 and payload-length varints wider than five bytes are explicitly outside this initial admitted domain. Rowid varints retain all nine bytes and all 64-bit bit patterns. The payload-length bound is 2,147,483,647 bytes, so overflow descriptors can represent the existing 64 MiB artifact contract; this operation does not read that payload.

Every refusal preserves the complete output and both input spans. Successful output contains exactly sixteen little-endian u64 values. Size arithmetic is bounded before memory access. Integer division is implemented in HIA using a 32-step restoring division, without a host arithmetic callback.

Primary format source: https://www.sqlite.org/fileformat2.html#b_tree_pages . Original SQLite cell C functions will be retained separately at exact 3.46.0 and 3.53.2 commits and used only on fully bounded admitted cells, with no claim of a safe malformed-input C oracle.

Status: source draft only; no generation, VM, C or native execution has occurred.
