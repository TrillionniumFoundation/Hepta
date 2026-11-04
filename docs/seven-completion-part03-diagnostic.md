# Original Part03 checked-chain completion diagnostic

This permanently nonaccepting diagnostic uses original #603, not candidate B or #648. Independent implementation review and a separate execution decision are required before any real Lean or hosted run. There is no automatic retry after failure or an inconclusive observation.

## Meaning of completion

Exactly one `#print axioms True.intro` follows original pre-inventory marker 008, immediately followed by new marker 011. All 1,655 original inventory subjects then run unchanged in their original order. Receipt of the exact sentinel or following marker in a valid prefix establishes that the prior checked environment chain resolved. Resolution may include error/fallback handling: it does not imply successful proof validation. Every error, nonzero exit, timeout, cap violation and cleanup failure remains a failure.

Receipt time is an upper bound, not an execution timestamp. No observed barrier is inconclusive because reporting/transport lag and censoring can hide execution. A positive barrier followed by later delay excludes unfinished prior tasks on that checked chain as the sole cause of the remaining interval. It does not isolate inventory cost, unrelated checking, message/snapshot finalization, compilation or shutdown. No observation attributes costs to the 156 proofs or establishes a performance improvement.

The semantic reference is official Lean v4.19.0 source commit `6caaee842e9495688c1567e78c0e68dbb96942aa`. Source semantics do not establish executable provenance. Activation must independently verify the locked binary and selected source/support graph.

## Exact source and isolation

Original unmarked Part03 is 612,376 bytes, SHA256 `076ba8582022029d053a80b279f13be2423334a9cb682a35b8889ff004370632`; original eleven-marker Part03 is 612,761 bytes, SHA256 `d920662dc97070e94fe95852af6ecbf15f5e4d35a25da4d6a2db977e1005f626`. Full actual bytes are required. The exact inverse removes only the two inserted commands at the independently checked boundary, restores original marker identities, and reruns complete original, seven-certificate and relocation source gates. Proofs, imports, declaration order, parent cuts, negative coordinates and original subjects are unchanged.

Marker prefix is HIA_SEVEN_COMP_v1_P03_. Ordered suffixes are 000 through 008, 011, 009 and 010. Marker 009 remains after subject 828 and marker 010 after subject 1,655. The 25-byte print and 35-byte marker add 60 bytes to the original marked source, producing 612,821 bytes. Existing prefix replacements preserve encoded length.

Runner protocol is seven-completion-part03-diagnostic-v1 and capture protocol is p03-completion-pty-hardened-v1. Old protocols cannot be replayed as this experiment. Identity binds original 247 paths plus exactly eight new files, 255 total, and unchanged 780 support paths. Runtime has no dependency on candidate-B files or semantics.

## Raw evidence and summary

Raw stdout/stderr are retained within unchanged caps. Exactly one result, `'True.intro' does not depend on any axioms`, is recognized after marker 008 and before 011. Only that result is excluded from inventory; no global True.intro ignore exists. Duplicated, moved, malformed, spoofed or stderr sentinel/marker claims fail. All original inventory multiplicity, order and allowed-axiom checks remain.

There are at most thirteen intermediate events: twelve markers and one sentinel. The two new records bind exact stdout offset, byte length, SHA256 and monotonic receipt time. Replay independently reparses raw bytes and matches events, source/protocol identity and bounded causal timestamps. Additional metadata must fit the 4 KiB ceiling inside existing reserve; added source and nominal output must each remain below 256 bytes. Static sizing must establish headroom before launch. The nominal 80-byte added output assumes the exact bare-row grammar; path-prefixed or info-decorated sentinel/marker lines are rejected, not accepted under an unaccounted prefix allowance.

The summary exposes positive completion only from validated safe prefixes and labels it checked_chain_resolved_not_proof_success. Unsafe capture, malformed framing, identity drift, cleanup uncertainty and unverifiable failure claims never manufacture a frontier. Raw preimages, not digest-only reports, are required for independent replay.

## Five slots, persistence and limits

Exactly four fresh same-run parents run, Baseline, SyntaxData, CertPart01 and CertPart02, then CompletionPart03. Parent inventories contain 56, 547, 271 and 54 subjects. Default threading is unchanged. Old modules or receipts cannot substitute. Every parent is authenticated before its descendant. The target never becomes an admitted parent and its module is never imported.

Capture preserves audited unreaped leader identity, waitid observation, one original-group termination before reaping, bounded reap and post-reap ESRCH probe. Detached descendants are outside the containment contract. PTY stdout, pipe stderr, strict UTF-8, fixed pending-EIO handling, actual-byte charging and source/identity checks remain mandatory. Uncertain spawn outcomes consume a slot and stop.

Publication uses exclusive pending RESULT, fsync/readback and atomic Linux RENAME_NOREPLACE. Existing files are never overwritten or removed to manufacture success. Partial writes remain charged. Pending/footer coexistence prevents trusted replay. Replay is read-only, launches no processes and rereads the complete actual final byte set. There are 23 retained sources and 53 nonterminal frozen files; RESULT adds one. No future-stage module, sixth slot, target receipt or extra raw stream is allowed.

Unchanged limits: 60 seconds/process, 2 seconds cleanup, 540-second launch cutoff, 600-second outer command and existing job bound. Raw caps are 507,392 bytes/stage and 819,891 total, with exactly one unretained overflow sentinel. Metadata reserve is 224,589 bytes, display 4,096, and combined metadata/raw/display 1,048,576. Sources remain bounded by 2 MiB each/8 MiB total; modules by 32 MiB each/128 MiB total. Preparation, validation, finalization and replay consume the existing run clock. No budget increase or retry follows failure.

## Tests and authority

Tests use Python fake children, never Lean. Genuine five-child integration retains the full actual source inverse and actual VerifiedEvidence replay. Faster branch controls are separately labeled and cannot replace it. Adversarial coverage includes killed-before/after completion, error text despite zero exit, missing original inventory, sentinel/marker spoofing and displacement, protocol crossing, forged event offsets/hashes/times, exact overflow accounting, spawn uncertainty, cleanup and persistence faults. Test groups retain a maximum 180-second outer bound. Deadline controls use a real Python child and collector termination with a test-only monotonic clock offset after output receipt. They do not physically wait 60 seconds. Separate self-SIGKILL controls exercise nonzero exits. Passing tests establish protocol behavior only, not real Lean timing or feasibility.

All results keep acceptance_eligible false, all connection/refinement flags false, twelve inherited obligations unproved and unchanged DENY authority; summaries say DENY_ALL. Nothing here grants activation permission.
