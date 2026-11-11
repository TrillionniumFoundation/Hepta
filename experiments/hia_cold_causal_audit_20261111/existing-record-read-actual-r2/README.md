# Original cold-record collector: partial output custody

The fixed readonly collector executed once on desktop and naturally completed with exit code 0. The authoritative original log is complete and durable: 442,920 stdout bytes, zero stderr bytes, no truncation. This checkpoint preserves the exact contiguous first 245,760 stdout bytes, original launch/terminal text, all 20 read receipts, and all five MCP read timeouts. The remaining 197,160 bytes have not yet been restored here. The JSON output is deliberately not treated as a complete independently parsed audit.

The product cold run is the pre-existing exact 608 formal r2 timeout/HOLD. This collector did not execute product code, import the project, write files, or rerun qualification. Its successful process exit does not change the old cold result. Timeout receipts concern readonly MCP retrieval, not the already completed collector. Their cause is unknown.

After every current read returned, the h lane was explicitly released to the ELF source-only task under root authorization. Later custody may resume the exact remaining byte offsets of the same durable job. No new key or product replay is permitted. Original SDK objects are serialized in .sdk.json files; h-start.original.json and h-terminal.original.json retain the tool's original JSON text, including unrounded numeric text.
