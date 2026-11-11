# Complete selected-journal service-call migration — new development

Reference: TrillionniumFoundation/Hepta commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5, hepta/hia_agent_journal_native.py and hia_agent_service.py. This document supersedes the inaccurate SQL-to-ACK exception wording in the earlier unexecuted plan. That earlier draft and every initial authoring failure remain unchanged.

## Current work and scope

The new journal bridge owns the entire existing JournalSession._run boundary in HIA: original allocation arithmetic, stage command preparation, actual reply validation, exact partial-state commit, original native diagnostic selection and full error text. It does not yet complete cached value materialization, selected installation admission, the surrounding call FSM, tool schemas, namespace effects, or the eleven business services. Generated authoring and actual image results must be reported separately. No ordinary selector or old owner is removed.

The first authoring attempt passed Python AST parsing but failed before generation/native execution because the existing CopyBuilder recognizes store, not setbyte. Its exact source and raw failure are retained. The next revisions use existing store plus a bounded HIA binary long division by ten; no primitive, language quota or compiler limit was added. The new short-workspace ACK check is a transport rejection, not a new JSON limit.

## Journal bridge command

The retained ABI is RWW; the second argument is borrowed read-only. Input s is the exact immutable raw bytes immediately followed by foreign-type observations. Input r is exactly 128 B (16 little-endian u64). Workspace is private, initially zero for its first 4096 B, and may GROW without a new semantic quota.

BEGIN: [HIASJB01, lease, commandSeq, stage, rawBytes, foreignBytes, dataProfile, digits, 0,0,0,0,0,0,0,0]. Stage is one of the eleven original stages 0..10. commandSeq starts at one and advances only for a fresh command. A GROW replays the exact same command and immutable input lease. Header comparison is correlation, not authentication of a replacement same-shape buffer.

ACK: [HIASJA01, lease, commandSeq, previousEventSeq, actualU32Return, actualRawBytes, outputBytes, scratchBytes, actualInputCustody, 0,0,0,0,0,0,0]. The fixed executor supplies the actual return from the exact source-bound journal image. actualInputCustody records only a mechanical full-input/canary comparison; it is not a semantic verdict. The HIA bridge checks its own output/scratch canaries before native status interpretation. A false custody result reproduces the old RuntimeError before all other status decisions.

CALL output and scratch are disjoint views of the bridge's private workspace. They have precisely the old buffer lengths, initial zeros, 512 B state copy, foreign-tag placement, 64 B canaries, stage and digit header. The raw journal input extent excludes the appended foreign bytes. The fixed executor does not compute sizes, read journal decisions, select a stage or replay the journal on GROW.

## Event

Every successful bridge entry returns 512; its 32Q event is at workspace offset 256. Fields: magic HIASJE01, action, lease, commandSeq, eventSeq, stage, growNeeded, rawBytes, rawOffset0, outputOffset, outputBytes, scratchOffset, scratchBytes, actualNativeReturn, savedStateOffset512, savedStateBytes512, writeFlags, statusEnum, responseOffset, responseBytes, costOffset, costBytes, arenaOffset, arenaBytes, errorClass, messageOffset2048, messageBytes, diagnosticReason, detailA, detailB, detailC, privateRefusalReason.

Actions: 0 completed original instruction; 1 GROW; 2 invoke the exact actual journal; 3 original exception observation; 4 private protocol refusal. BAD=0xfffffffd always retires the invocation lease. A workspace shorter than 4096 cannot be poisoned reliably; sequence overflow may retain an old event. The executor must act on BAD before reading an event. After a normal or exception event the session can receive its next fresh command; the enclosing call FSM decides when original native_failed semantics require retiring it.

Error classes: 1 ValueError, 4 OverflowError, 6 RuntimeError, 7 UnicodeDecodeError, 8 JSONDecodeError. Every emitted message is complete UTF-8. JSON syntax diagnostics retain source character indexing and full UTF-8 decode before line/column consistency. The old saved request_id ASCII conversion also precedes the identity comparison, including its error when a private prior state was malformed. The state is never committed on these errors.

Result views are private borrows until the next entry/GROW. The fixed complete call controller must consume or freeze an immutable result lease before then; this is not an assertion that arbitrary private Python Instruction objects have been replaced by borrowed memory. No digest or numeric header grants external buffer authority.

## Complete call order to implement

1. Actual monotonic start and UUID entropy occur before journal installation and before the main try/finally interval. Installation/catalog bind catches only ValueError/OSError and calls the complete _error record owner; it performs no finish/cost/request writes.
2. wire(arguments), decode_data, construct original {tool,arguments}, wire, native prepare. request_id changes only after prepare successfully returns. Alias validates keys, resolves URI, constructs arguments, acknowledges, then changes tool; it does not retroactively take LOOKUP.
3. LOOKUP begins a real transaction, materializes the complete six-column SQLite row, projects actual storage-class observations, and invokes the journal. RESERVE performs op8 then empty ACK before COMMIT. CACHE converts the complete value, performs optional replay verification, and returns after COMMIT.
4. Input schema precedes catalog match; that precedes fresh installation identity, context resolution and budget. context_id is assigned only after context succeeds. Describe bypasses catalog match; inspect/rollback bypass the budget; candidate alone sets the attempt flag.
5. The actual journal effect chooses atomicity. Business dispatch covers every original tool; the full successful record is assigned before output schema. Atomic calls then run inline, optional request UPDATE and empty ACK, followed by COMMIT.
6. A body error first unwinds its actual transaction. A ROLLBACK failure replaces the body error. BEGIN failures do not ROLLBACK; COMMIT failures do not add a ROLLBACK or retry. Classifying a body error before this unwind would change behavior.
7. Ordinary native_step sets native_failed only for non-domain errors. ACK native_step sets it for every exception. A domain exception from ACK may still produce a rejected response in the outer catch; native_failed suppresses its finally writes. An already-set flag never rolls back.
8. SQL-to-ACK gaps are governed by the actual enclosing try regions, not by a blanket new terminal rule. A domain error in that gap may be caught and finalized. A non-domain gap error is marked by the enclosing catch after transaction unwinding.
9. Caught domain errors construct the complete error record after ROLLBACK. Deferred snapshot publication occurs there. Failure of the error constructor or publisher sets native_failed and propagates, preventing an old already-assigned success response from being finalized.
10. If native_failed is false, finish receives the actual response or None. Cached early return leaves response=None: finish still runs but requests neither cost nor journal writes. COST writes precede final request UPDATE. Failures in finish or these finally writes are not caught again by the main handler.

## Storage and peer custody

Namespace op7 is SELECT * requests with one bind; op8 INSERT requests has key,digest,tool,state,response,started_ns; op9 UPDATE uses response,key; op10 costs has context_id,tool,request_id,wall_ns,status,details. The full row is materialized before projection. TEXT declarations do not cast BLOB/INTEGER/REAL/NULL. Time values are decimal TEXT at their original call points, not a new signed-64-bit domain.

Only an actual namespace row/commit result authorizes the next journal ACK and transaction publication. Clean commits and autocommit reads must retire result generations even if txseq does not advance. Graph IDs are not namespace capabilities. Until the high-level native namespace and business owners join, typed fixture peers prove only orchestration behavior and must not count as complete Worker effects.

Existing records are independently sealed: 228 cases, 1054 actual native entries, exact 8 MiB/+1 original wire behavior, and explicit private publication fixtures. The lost R15 tool-schema original archive has not been recovered; its new execution remains required. Whole Worker, installed dispatch, all business owners, and old-stack removal remain OPEN.
