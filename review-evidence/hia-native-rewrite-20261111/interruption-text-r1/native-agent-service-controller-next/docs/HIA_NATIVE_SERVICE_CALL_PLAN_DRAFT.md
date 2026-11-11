# Complete native service-call controller plan — unexecuted design

This is a design checkpoint, not a compiled or qualified implementation. It describes the complete existing selected-journal call boundary rather than a reduced tool subset. Ordinary Worker startup, tool business methods, namespace storage, and interpreter compatibility are tracked separately.

## Fixed reference sources

Read directly from the repository at commit abbreviation 0ef954:
- hepta/hia_agent_journal_native.py, especially call_with_native_journal and JournalSession._run/cached.
- hepta/hia_agent_service.py, especially _error and all eleven _hia_* methods.
- hepta/hia_agent_store.py, including transaction, wire and decode_data.

The controller must reproduce the selected HIA journal path. It must not copy the retained Python journal decision logic or treat hosted callbacks as native peers.

## Existing pieces to use

The frozen native Worker byte decoder produces the complete ordinary Graph, with finite binary64 and original full-byte UTF-8 precedence. Worker request admission binds the complete request, tool and three digests. The complete native tool-schema vocabulary/walker/wire owners cover all eleven published input/output schemas. Native service records create completed or rejected records and request deferred snapshot publication. The existing HIA journal determines request identities, key eligibility, lookup/reserve/cache/replay, atomic mode, and terminal write flags. Shared language metadata/inspection is a separate root-owned business service. Namespace transactions use the fixed 31-operation census, never arbitrary SQL.

The service-call controller composes these pieces but owns all remaining call order, exception unwinding, context admission order, publication order, business dispatch, and actual transaction/terminal-write sequencing.

## Full ordered call

1. Observe monotonic start and actual UUID entropy; retain an unadmitted request ID.
2. Install/admit the exact journal source/image and bind the complete actual tool catalog before the main try/finally interval. A ValueError/OSError here produces E_HIA_JOURNAL_NATIVE through _error and returns directly; no session.finish or cost write occurs.
3. Perform the original wire(arguments) followed by decode_data; project and encode the full {tool,arguments}; invoke journal prepare. Only after this actual call returns is request_id overwritten with the journal-issued value.
4. Honor the actual journal refusal or alias. Alias validates uri/max_bytes, calls actual resolve_uri, projects the new hia_read arguments, invokes the journal alias acknowledgment, then changes effective tool. The original request digest is retained.
5. On LOOKUP, enter an actual transaction, read the requests row, and give actual digest/state storage-class observations to HIA journal lookup. A reservation inserts running intent, then invokes the empty reserved acknowledgment before COMMIT. A cached result is decoded and optionally replay-verified, then returned after transaction exit.
6. Validate the full input schema. Check catalog identity except for hia_describe. Obtain and compare a fresh installed implementation identity. Only then resolve context. Publish context_id only after complete context success; then apply its budget except for hia_inspect and hia_rollback, with candidate-attempt mode only for hia_candidate.
7. Invoke journal effect. ATOMIC enters a transaction before the business call; other tools do not. Dispatch exactly one of the eleven original tool services.
8. Build the complete successful record and assign it before output validation. Validate the complete output schema. For atomic calls, run journal inline on the actual wire. If it requests JOURNAL, perform the UPDATE and empty committed_inline acknowledgment before COMMIT.
9. For a caught domain exception, unwind any active transaction before constructing the rejected record. If _error requests a pending slot-snapshot publication, perform it after rollback. If this publication or _error itself fails, mark the invocation native-failed and propagate without terminal writes.
10. If native-failed is false, call journal finish with the actual current response (or empty bytes if no response). Honor COST_WRITE before JOURNAL_WRITE, exactly in that order. No implicit retry follows a failed write or unknown acknowledgment.
11. Return the actual response, or the exact uncaught failure observation after cleanup. A protocol/owner mismatch cannot fall back to a hosted path.

## Required distinctions

- A cached early return does not assign response. Its finally still calls finish(None), but flags are NONE, so it writes neither a cost nor a new request terminal record. The misleading retained comment does not alter this.
- The reserved and committed_inline empty acknowledgments have no payload-refusal domain. Any failure, including a domain exception or asynchronous interruption, permanently retires the invocation and suppresses terminal writes.
- Ordinary non-ACK journal payload refusals may be caught domain errors. Native protocol refusal, bad custody, allocation/process failure, or non-domain exception retires the invocation.
- There is a separate outer asynchronous interval between successful SQL INSERT/UPDATE and entry into the ACK helper. Failure there has the same no-finalization behavior.
- A transaction's BEGIN happens before its try/yield. BEGIN failure does not run ROLLBACK. Body failure runs ROLLBACK; a rollback failure replaces the body exception. COMMIT occurs in the context manager's else block; its failure does not cause an added ROLLBACK. The native namespace peer must preserve this exact boundary rather than inventing a retry.
- response may already hold a successful record when output-schema validation fails. Successful _error replaces it; a failure inside _error marks native-failed and must not finalize the old record.
- finish and cost/journal writes execute in finally; their failures are not caught again by the main call's domain handler.
- Context and namespace Graph values are not borrowed storage-object authority. A Graph root ID cannot be substituted for an issued namespace handle.

## Native peer replies

Use explicit exact session/call/action-sequence correlation, an issued immutable result Graph or byte lease, a native error observation, and actual transaction/write acknowledgment. The controller must validate peer kind and lifetime before consuming a reply. A numeric nonce, header or digest is not authentication of an arbitrary replacement buffer.

All graph construction, schema selection, digest/input preparation, SQL operation selection/bind order, dictionary fields, error classification and business routing stay in HIA. The fixed executor performs only exact native calls, allocation/copy/read-only sealing, actual syscalls, actual clock/entropy collection and lease cleanup. It must never interpret a semantic plan or synthesize callback results.

Namespace get/put/json/profile/resolve_uri currently have no completed high-level native service ABI. Fixed relational operations can be represented as pending peers using the frozen census, but these pending requests are not native namespace completion. Proof/object build/evaluate, full artifact/slot behavior, migration and ordinary installed Worker entry remain explicit open owners until their actual native paths join.

## Validation plan

Before a whole-Worker claim: compare full trace/response/state against the same selected journal reference over success, unknown tool, changed request key, running intent, completed replay, verify replay failure, alias, schema/catalog/identity/context/budget order, all eleven dispatch targets, both atomic modes, every domain and non-domain continuation failure, BEGIN/COMMIT/ROLLBACK failures, failures before/after reservation and inline ACK, deferred snapshot publication success/failure, cached finally, and both ordered terminal writes.

Actual namespace and business operations must replace private fixture peers for the final joint tests. Unknown publication ACK must be a terminal lease failure, never an implicit replay. Install and fixed ELF tests must use the complete source/image bundle, empty Python paths, actual syscalls, and exact receipts. Original failed runs remain independent evidence.
