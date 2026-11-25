# Native HIA HTTP concurrency and response checkpoint

This checkpoint covers the authenticated HTTP transport for the eleven HIA tools. It preserves the original default HTTP SDK protocol and the existing HIA provider behavior. It does not claim that the other filesystem, REA, or weight research tools have been migrated, or that the final native-only release and installation have passed.

## Request lifetime and cancellation

The HTTP parent owns a global execution-slot and generation allocator. A session's RequestId-to-token routing is separate from execution-slot lifetime. A duplicate ID replaces the current cancellation token and response route without cancelling an older execution. Whichever eligible handler completes first consumes the current token and sends through the current resource route. Cancellation closes and completes that resource before worker reap; the later completion is discarded. This preserves the original SDK's race semantics.

Before forking a session, the parent seals an explicit list of inherited HTTP descriptors. The child closes exactly that snapshot. It cannot accidentally consult a connection row that the parent has already cleared or reused. The controller's inherited ownership locks and role descriptors remain under their original ownership rules.

## Bridge transactions

The bridge now has a dedicated HIA transaction owner. An exact (host, idempotency key) lane serializes lookup, intent, launch and reconciliation for that identity. A separate process-owned POSIX mutex protects local registry/cache reads and writes. The global mutex is released before remote SSH and page-worker waits, and reacquired before subsequent local updates. A confirmed launched job drops its same-key lane before remote status observation, matching the original provider.

Lane files are retained while waiters may exist. Their exact host/key names, regular-file identity, owner, mode, link count and empty extent are validated. The parent's two long-lived controller flocks are never released by a child. The original valid_name domain includes @; host and record names now retain that character with the original 128-byte ASCII bound.

## HTTP presentation

HTTP uses dedicated session, dispatch, catalog and reply policies. The stdio policies retain their own contract. The HTTP policies preserve the original default rmcp/3.9.0 server presentation, capabilities and instructions. This is wire compatibility, not a dependency on a Rust process.

Modern negotiated responses use the original status mapping. A status-200 terminal response uses SSE with no session priming or event ID. Non-200 terminal responses use JSON. In particular, well-formed request metadata does not turn every Invalid params or internal business error into an HTTP 400.

The HIA tools retain their exact schema objects and appear in the original alphabetical list order. Discovery carries server information; ordinary list and tool results do not acquire the stdio-specific server-information metadata.

HTTP/1.0 SSE is close-delimited, without HTTP/1.1 chunk framing. HTTP/1.1 uses the original chunks. There is no invented 30-second header timeout. Common-stream primary/shadow behavior, the 32-shadow bound, inclusive replay and the exact 15-second colon-plus-two-newlines heartbeat remain covered by original-service observations.

## Verification

The JSON companion records exact binary/source pins and report digests. At the exact image pins recorded in each report:

- 61 inherited-role, owner-lease and cache-custody refusal cases passed.
- 7 predecessor/replay and namespace-drift cases passed.
- 19 modern default HTTP original/native cases matched, including status-200 business errors.
- 24 HTTP version, keep-alive and immediate/delayed half-close cases matched after normalizing Date/session headers and HTTP field order; raw bodies and EOF behavior matched.
- Five actual SSH groups matched: cancellation, duplicate-ID completion routing, cancellation of only the latest duplicate, consumed-token cancellation, and same-key versus independent-key progress using a legal @ host alias.
- Common and shadow SSE behavior, including heartbeat bytes, matched the frozen service.
- 87 HTTP responses covered two sessions, 64 overlapping requests, two actual native Worker requests observing the same terminal job, and parent-only SIGTERM with complete descendant reap.
- All 41 retained business calls covered all eleven HIA tools and 64 KiB pagination. Both the new native bridge and a fresh frozen Rust provider returned the original values. All 42 job-record hashes remained unchanged, and a mutated identity was rejected.

The older resource-failure case in that retained campaign remains explicitly a failure result from its old Worker. It is not used to claim current resource-success coverage. The current resource-success HTTP envelope is covered by the additional complete-envelope qualification below. Final native-only production integration remains a separate gate.

The frozen Rust private selected-Controller HTTP path lacks the admitted-wire extension installed by its stdio path. Positive default HTTP protocol/race oracles therefore use its valid default path. Native HTTP retains full actual role and controller admission; same-job HIA business values use the fresh frozen stdio provider.

## Preserved failures

The pre-v10 inherited-socket race and the first relocated-audit fixture rejection remain preserved. The latter copied an inode-bound audit anchor to a different namespace; the original reader correctly rejected it. The successful fixture copied only immutable job records and created a fresh valid audit namespace through the original owner.

## Complete HTTP business envelopes and DELETE reuse

The native HTTP image v13 executed all 41 retained calls in both legacy sessions and modern per-request mode. Its 82 complete result/error values matched 82 newly executed frozen-runtime stdio calls on the same durable jobs, including pagination; no result fields were filtered. The 42 actual job files remained unchanged.

A complete current Worker fixture separately supplied eight public calls and four resources in each mode. All 24 complete values matched fresh original calls: short text, Unicode, an 80 KB four-byte UTF-8 artifact whose first page is 65,536 bytes, and a missing artifact URI. Modern resultType, ttlMs, cacheScope, MIME type and cursor fields were compared as returned. Four further same-session resource observations also matched. No jobs were relaunched or replaced.

The final teardown probe found a real connection-lifetime difference. Session deletion traversed other connection records before restoring a stale copy of the DELETE connection. Saving its current admitted record before that traversal preserves HTTP version, consumed bytes and keep-alive state. V14 changes only that http_post payload; the other 41 packed roles are byte-identical to v13. Four fresh original/native pairs cover HTTP/1.0 and 1.1, explicit close and keep-alive, and reinitialization over the very same TCP socket. Headers, status 202 and empty bodies match. This small fix is not presented as a rerun of unrelated business roles.

All failed harness attempts remain available. The first business script incorrectly expected 200 after its 82 successful calls; the original DELETE contract returns 202. A too-short token and an HTTP/1.0 client that omitted Host were also corrected in new fixture directories. The separately observed v13 keep-alive difference was a product defect and is fixed in v14.
