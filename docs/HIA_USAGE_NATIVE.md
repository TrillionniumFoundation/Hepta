# Native usage projection and complete stdio parameter diagnostics

This component extends the retained native MCP service with the read-only
`usage_stats` public tool and removes the one MiB diagnostic fallback from
`request_history`, `request_archive`, and the new usage parameter path. It adds
no native source paths or executable roles. It updates nine existing HIA
sources. Development Python authors and observers are not runtime policy.

## Public usage behavior and authority

The public catalog contains fourteen tools: the existing eleven Worker tools,
history, archive, and usage. Usage accepts the original empty, deny-unknown-fields
parameter object; omitted and null arguments retain the original defaults.
The native service binds the query to its authenticated held owner and root.
Callers cannot choose the owner, controller identity, generation, or root.

A distinct `HIAUSQ01` request and `HIAUSO01` response identify version one,
operation five. This is not an alias of the former no-query protocol.
The existing held-root envelope is retained, limit/cursor must be zero, all
reserved bytes are checked, and the absolute deadline uses the existing seconds
and nanoseconds fields. Audit composition remains `HIARAU03` with eighteen
roles; the usage implementation is composed into the existing archive-query
role. No adapter or process-state layout change is required.

The full retained archive scan, original validation, inode/watch fences and
store lock are reused. Counts include the owner's retained records beyond the
128-row public-history and 512-row hot-store bounds. States, sorted tool counts,
genuine live kernel tickets, and earliest/latest full-u128 accepted times are
projected. Foreign records are validated before owner filtering. Foreign u128
times do not poison the store merely by existing. An own u128 time that cannot
be represented in the public u64 JSON result preserves the original poisoned
store outcome.

The original 65,536-byte projection limit is retained, including the original
per-tool conservative name budget. Observed boundary controls cover 508/509
distinct 64-byte names and 963/964 distinct 3-byte names. A size refusal completes
the integrity scan and fence check; it does not itself poison the store.
Metadata calls retain the original absolute three-second deadline, including
time waiting on the lock. The public stalled-daemon control observes the
deadline and discards the stale generation before accepting a new query.

## Complete stdio diagnostics

The existing one MiB buffer is now the small-diagnostic path, not a new public
input limit. Larger original Rust Debug and JSON escaping is emitted in bounded
64 KiB chunks into the existing request-private response memfd. The scheduler
waits for child completion and cancellation resolution, seals the complete
file, and only then publishes 64 KiB chunks. Short reads/writes and EINTR preserve
the offset. Unfinished or cancelled private output is never published.

The original 16 MiB minus one byte stdio frame and 8 MiB canonical query limits
are unchanged. The 72 MiB plus 512 metadata response bound derives from those
input limits and worst-case escaping; ordinary response limits are unchanged.
State remains 384 MiB. Typed parameter errors occur before admission of a
metadata query, so large diagnostic generation does not extend the three-second
metadata-query deadline.

Real native controls compare complete original errors for ASCII, unknown keys,
DEL, Unicode, mixed escaping and chunk boundaries. The largest admitted case
has 8,388,556 canonical parameter bytes and returns 58,719,955 stdio bytes.
Actual process controls stop a request after it has written private output,
answer ping, observe all four Linux memfd seals after completion, and cancel
another partial request. Original raw Rust observations are retained.

## Evidence and limits

See `HIA_USAGE_NATIVE_QUALIFICATION.json` for exact source/product pins and
committed construction, raw observations and control reports. The four fixed
native bootstrap roots assemble, project, emit and pack all test executables.
The component does not borrow a prior full-cold qualification.

The original Rust reference is
`ae1c7ea593da45f7299c692a2acd44605c35be09`; its complete production modules and
observer project remain in the previously committed archive/history fixtures.
The usage fixture adds distinct-name boundary runs, schema observation, and
complete compressed original large diagnostic inputs/outputs.

HTTP delivery/cache still require a separate streaming implementation. The
HTTP-derived scheduler explicitly retains its existing 8,389,120-byte output
bound in this checkpoint. Native continuation controls compile both schedulers
and check that this limit is retained. They are not HTTP delivery qualification.

Pending-index batch timing and every concurrent archive mutation interleaving
have not been fully compared with the original Rust implementation. These
remain explicit Runtime closure work. The configured Worker in public component
fixtures is not an installed Worker. Full cold, release, installed rebuild,
HTTP parity and the whole Runtime remain separate integration gates.
