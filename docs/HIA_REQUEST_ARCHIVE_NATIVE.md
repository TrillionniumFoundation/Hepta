# Native retained request archive

This component adds the public native stdio `request_archive` tool. It is based
on Hepta `95f81abe2381dd51d798436fe53725e0059897f9`, preserving that commit's
`request_history` and independent div-word compiler profile. The original
behavioral reference is the complete archive implementation at Runtime
`ae1c7ea593da45f7299c692a2acd44605c35be09`.

## Runtime behavior

`tools/generate_hia_mcp_request_audit_archive_query.py` authors the new
`examples/hia_bootstrap/mcp_request_audit_archive_query.hepta` component. The
runtime executes native HIA code for owner checks, complete original-file
validation, full-u128 ordering, cursor admission, bounded selection, JSON
projection and observation fences. The existing mechanical adapter executes
the declared Linux syscalls.

The query scans retained v11 originals and all 256 v12 shards. It does not
truncate the archive to the hot history cache's 512 global or 128 owner rows.
It holds at most `limit + 1` selected records, with the original maximum page
size of 32 and 64 KiB complete tool-result wire bound. `total` counts all retained
records belonging to the held session owner, including rows before the cursor.
Cursor identity remains a lowercase 64-hex ID and must belong to that owner.
Every original is validated, including other owners' records. Malformed,
insecure, symlinked, hardlinked, misplaced or duplicate originals fail closed.

The trusted native service captures one absolute three-second monotonic
deadline before the metadata channel wait. Nonblocking channel and audit-store
lock acquisition, native query continuations, and the caller's final response
acceptance all retain that deadline. A timed-out caller does not replay an
operation. Subsequent explicit queries drain expired slot/generation replies.
The implementation keeps active native ticket observations distinct from
durable unknown state; reading metadata does not create an audit ticket.

Directory watches are installed before the complete scan and retained through
the final original-namespace/layout fence. Original content or namespace
changes invalidate the observation even when the bytes, names and mtime are
restored. Unrelated children of the state root do not invalidate the archive.
The ordinary held-file and held-directory checks remain in force independently
of watch events. A selected accepted timestamp above u64 reproduces the original
projection failure and poisons the global audit store, as the original Rust
panic does while holding its store guard.

## Explicit ABI and composition

The request is `HIARQY01`, version 1, operation 4. It retains the existing held
root, controller, worker, slot, generation, owner and cursor fields. Bytes 256
and 264 contain the deadline seconds and nanoseconds; bytes 272–511 are reserved
zero. A frame cannot supply a new budget beyond the trusted three-second bound.
The response is `HIARQO01`, version 1, with the existing 64-byte variable-response
header. Error 37 preserves the original public deadline text; other archive
failures expose the original redacted unavailable text. The composed daemon is
`HIARAU03` with 18 roles. Existing begin/finish frames and history protocol retain
their existing versions.

The SDK appends archive as tool 13; the native service maps it to dispatch 14,
leaving private resource dispatch 12 and history dispatch 13 intact. The Worker
catalog remains eleven tools. The release author's `specifications()` reads the
current audit role list and composition magic, so the new role participates in
the normal controller release graph. Shared native source authority, Worker
identity and `release_stage_controller.hiastd` must be regenerated together on
the eventual integrated HEAD; this component does not overwrite them from its
older base.

## Actual qualification

The four independently pinned native seed roots compile the existing div-word
profile and every daemon/controller role. No target successor compiler is used
as evidence for its own origin. The resulting audit executable is 1,722,341
bytes, SHA256
`f5d8596b6daaefd4961c245258e690704ab4d5200e9505fc057d80c7c392cb33`.

The committed qualification summary identifies the exact products, source
pins, construction transcripts and the following executed controls:

- 22 actual daemon controls: 800 retained rows / 600 owner rows, 256 shards,
  cursor/owner isolation, absolute lock-wait expiry, live kernel tickets,
  u128 overflow and store poison, protocol refusals and original-file policy.
- The unchanged history 16, retention 16 and v12 24 process controls.
- Four ptrace syscall-boundary controls on this observer's own daemon, after
  successful inotify installation: content/mtime restoration, namespace
  restoration, foreign-owner content restoration, and an unrelated root child.
  The observer stops and resumes execution; it never changes instructions or
  fabricates syscall results.
- 34 actual public native stdio archive queries compared byte-for-byte with the
  original Rust output, including complete typed parameter errors and redacted
  tool errors; plus three public controls for catalog/schema/null arguments,
  a real SIGSTOP/SIGCONT three-second deadline with stale-response drainage,
  and owner isolation after reconnect.
- Native malformed composition refusals for all 18 daemon roles and all public
  controller products.

The original reference compiled 18 complete production Rust modules, preserving
their bytes. A test-only observer is appended to the original audit module, and
the configuration shim only supplies an isolated state root. The project
archive contains the original modules, exact observer, Cargo manifest and
original Cargo.lock. All active dependency versions and checksums match that
lock. Eleven fixtures (46 archive/usage queries) were observed in two fresh
processes each, with equal results. Usage observations are retained for the
next component and are not claimed as native usage qualification here.

The first original run used macOS's soft descriptor limit 256; fixture creation
for 256 shards failed before a query with `Too many open files`. The remaining
seven fixtures used an explicit soft limit 1024. That failure and both contexts
are retained, and the original three-second query budget was unchanged.
Native attempt v1 stopped on a sparse-checkout seed source omission. Attempt v2
exposed an actual pointer-relocation error in the new lock-wait pause; v3 fixes
it using the existing zero-descriptor poll and passes the controls. Public v1
passed all 34 comparisons, then stopped on an omitted schema fixture; v2 uses
the exact committed schema blob and passes all additional controls.

## Scope still requiring integration

This is an independently constructed and qualified native stdio component.
It does not certify whole cold source admission, a release or installation,
HTTP behavior, an installed Worker, the original batch/cohort scheduling or
large-archive throughput under concurrent writers. Those require the integrated
source tuple and their original gates; no earlier source's cold receipt is
relabelled for this component.

The inherited history parameter diagnostic has a known reachable difference:
decoded wrong-type strings or unknown field names above 1 MiB return generic
`Invalid params` instead of the full original diagnostic. This remains a public
compatibility gap for both history and archive; existing larger input-frame
bounds do not make it unreachable. It is not counted as exact parity here.

## Reproduction

Use a fresh output directory for each command. The seed construction helpers
retain their historical filenames but load the current explicit audit role set.

```sh
python3 -m tools.qualify_hia_mcp_request_history_seed --source . \
  --bootstrap native/bootstrap/linux-x86_64/bin --output /path/audit
python3 -m tools.qualify_hia_mcp_request_archive \
  --audit /path/audit/hia-mcp-request-audit --output /path/archive-controls
python3 -m tools.qualify_hia_mcp_request_archive_fences \
  --audit /path/audit/hia-mcp-request-audit --output /path/archive-fences
python3 -m tools.build_hia_request_history_public_seed \
  --bootstrap native/bootstrap/linux-x86_64/bin \
  --audit /path/audit/hia-mcp-request-audit --output /path/controller
python3 -m tools.qualify_hia_mcp_request_archive_public \
  --bundle /path/controller/controller \
  --cases tests/fixtures/hia_request_archive_oracle/cases-v1.json \
  --oracle tests/fixtures/hia_request_archive_oracle/observations-v2.json \
  --output /path/archive-public
```
