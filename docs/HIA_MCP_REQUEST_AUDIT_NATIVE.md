# Native durable request audit

The checked-in `mcp_request_audit_*.hepta` program implements the original Unix request audit prepare, begin with an optional retained-record read pin, and finish operations. It runs as one native daemon for the controller lifetime. Its syscall adapter only translates the HIA byte ABI into Linux syscalls; the HIA modules own request validation, actual descriptor custody, record decoding, retention decisions, durable publication and v12 recovery.

The original source used for the port is `runtime-v26-source/src/mcp/runtime/request_audit.rs` and its archive/store/stage modules at runtime commit `d022649c64b48fb2a43263faf90103a9a8957b94`.

## Lifetime and interface

`HIA_MCP_REQUEST_AUDIT_ABI.json` specifies the unchanged 512-byte prepare/begin header, 128-byte finish frame and 512-byte response. Frames are complete `SOCK_SEQPACKET` packets. The daemon rejects oversized packets, uses a blocking socket endpoint, and remains alive after successful prepare and all later responses. Controller death ends it through `PR_SET_PDEATHSIG` and a parent-PID race check.

The parent supplies a private, sealed-to-size 2 MiB memfd. Byte 0 serializes daemon transactions. Byte 1 serializes each caller's packet and matching response. Each live worker owns the POSIX write lock at byte `64 + slot`. The daemon checks the supplied worker PID against the kernel lock owner. The 32 slots match the parent worker limit; they do not impose an archive record limit. Closing any descriptor for the same memfd inode releases a process's POSIX locks, so a live worker must retain that descriptor custody.

The authenticated parent supplies the 64-character owner ID. The native daemon creates a fresh request ID using 32 bytes from `getrandom`, encoded as lowercase hex. No user argument supplies that identity. A valid begin publishes Unknown to the archive and syncs it before publishing and syncing the hot receipt. Only the complete successful begin response authorizes dispatch.

The daemon keeps actual ticket descriptors across dispatch. A worker cancellation releases the worker lease and leaves its durable Unknown record unchanged. The next packet reaps the dead worker's private ticket and actual hot-directory descriptor. A finish refers to the same slot, generation, PID and request ID. It preserves the original monotonic elapsed-time rules, writes the archive before the hot record, and refuses a changed terminal outcome. Parent reply handling preserves an already obtained operation result if finishing the audit fails.

## Archive and retention behavior

The original limits remain 512 hot records globally and 128 per owner. Eviction follows accepted timestamp and request ID order. An active request or retained-record read pin cannot be evicted. An eligible victim must have a matching archived copy. If no safe victim exists, a new request is admitted to the archive without a hot receipt. Corrupt existing archive counterparts are not repaired or overwritten by hot seeding.

Root ancestry, private directory and file modes, owner, no-follow traversal, inode identity, legacy anchor bytes and held descriptors remain checked. Historical timestamps retain the original unsigned 128-bit range. Record decoding refuses duplicate and unknown fields; optional elapsed time preserves the original absent/null behavior.

The v12 path retains the original 64 MiB legacy directory-size trigger and all 256 shards. Initialization persists the intent before directory creation and persists every bound prefix before extending it. Recovery accepts only the recorded prefix and at most the next empty unbound directory. Unexpected entries, missing or substituted identities and payloads in unfinished shards refuse recovery. A completed, root-bound metadata file may recover its one known temporary hard-link alias; an unknown alias is refused. The final anchor is published durably before the matching completed intent is removed.

All live tickets share the same actual validated archive directory set. A later begin can complete and validate v12 initialization for that shared set. An older flat ticket can then finish through it. Before that validation, an external layout change continues to refuse the older ticket's completion.

## Build and evidence

`tools/qualify_hia_mcp_request_audit_sources.py` compiles every HIA component through a separately selected native `hia-source-build`, then compiles and executes the HIA packer. The small existing native filter packer carries the full composition within its existing 8 MiB transport budget; the compiler observer's 1 MiB bound is unchanged. The tool checks exact component placement, source stability and malformed composition refusals. It reports component source custody, not a fresh whole-source cold admission.

The implementation checkpoint's native daemon is 1,388,969 bytes, SHA-256 `ffd240a825efe9d05ae3ba519099c9169f94ad0da0af3da1ceb59fb4b6b8ee87`. A separate native compiler CLI and native observer rebuild produce those exact same bytes. On that same executable, 24 actual filesystem v12 cases pass, covering prefix recovery, known and unknown metadata aliases, namespace refusals and both old-ticket epoch outcomes. Sixteen actual retention/custody cases pass, including 128/512 thresholds, read pins, archive-only admission, a real forked worker killed with SIGKILL, slot reuse, held-hot-directory completion, anchor replacement, immutable terminal records and stable descriptor counts across 32 staging refusals.

The reproducible source-tree runtime campaigns are `tools/qualify_hia_mcp_request_audit_v12.py` and `tools/qualify_hia_mcp_request_audit_retention.py`, using `tests/hia_request_audit_native_support.py` only as the external socket/filesystem observer. Each accepts the actual native executable and a fresh output directory. They preserve the original thresholds and exercise actual syscalls, files and worker death. They report native behavioral cases derived from the original implementation; they do not claim an independently executed Rust oracle for every malformed-error text.

This checkpoint implements the durable audit path used around tool and resource dispatch. It does not claim standalone history, usage, archive query/index operations or whole native service equivalence. Those surfaces require their own versioned native interface and original-source qualification. The parent service owns authentication, tool/resource completion mapping, transport cancellation and its final full-service gates.
