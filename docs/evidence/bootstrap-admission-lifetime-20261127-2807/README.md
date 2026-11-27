# Bootstrap admission metadata lifetime candidate

Status: **HOLD / full lifetime equivalence pending**. This commit is a recoverable
development checkpoint. It does not qualify the native stack or retire any owner.

## Actual diagnosis on db15

Durable job `1a21ee8be34-ffbe-56a2` completed naturally with exit 0.
The existing C post-write observer reproduced all 15,830 business calls
(760,288,413 bytes, SHA256
`83b60bf1953d9b54afb8243b9d3d2df3341ce3b5b131897f13ff58a748fa8e72`)
and the complete db15 late stream (1,748 bytes, SHA256
`809259b19d7a407e3481f279c6522c3419ef72cb956109f65194cd09338b7367`)
without changing either channel. The full original late comparison still has
eight differences. This is diagnostic non-interference, not reference equivalence.

All eight C stacks show the candidate's finalizers running in
`seal_record -> support.parse(raw) -> pairs`, while processing
`generator_protocol.root-destructor-at-exhaustion.outer1`. The original
previously ran these finalizers in `oracle.error` with an active outer exception.
Every late field remains intact.

The actual candidate child took 349.8468558610184 seconds; the complete
diagnostic including full prior admission and terminal byte comparison took
1047.0484633680026 seconds. Raw observation, stack and owned child receipt are
included here. Earlier failures remain in the parent commit.

## Minimal lifetime change

After complete original admission and the admission record are written, the
observer keeps the exact file-pin mapping and immutable captured raw documents
needed for final rereads, then releases the parsed authority and report metadata
before importing the candidate. No code later uses those removed temporaries.

The complete admission function, record seal and business loop have identical
ASTs. The seal's strict frozen-prefix validation remains unchanged. The same
mapping is fully reread at the end. There are no GC calls or threshold changes.

## Actual bounded controls and pending whole input observation

The 22 existing terminal/static/fixed-word/word controls passed with zero skips;
the original three test source files are unchanged. The exact command, complete
stderr and result are included. These controls do not prove the eight late
differences fixed.

New durable job `1a21efd09b2-ffbe-56c8` runs in a separate source snapshot with
all 103 physical source pins verified. It generates fresh four-lane originals
for this source and then executes the complete unselected domain, parent raw
and late byte comparison, and independent reader. These all remain inside the
original 1800-second outer budget with 3-second cleanup. At this checkpoint the
observation is still pending. The formal original Source8 owner has not been
rerun.

Source: `/home/qian-qi/hia-bootstrap-admission-lifetime-20261127-2807/src`.
Raw data: `/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-admission-lifetime-20261127-2807`.
The original db15 worktree and every earlier physical evidence path are untouched.
