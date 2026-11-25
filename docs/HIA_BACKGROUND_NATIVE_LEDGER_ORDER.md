# Native ledger outcome insertion order

The ledger now preserves the first occurrence order of execution outcomes,
matching the original BackgroundOptimizer._outcomes dictionary. This ordering
is part of the complete public snapshot. Existing HIABLG01 operations and
their reply/reserved-word behavior remain unchanged.

The qualified current ledger image is 131,856 bytes with SHA256
e1ad0e7ca7f1f8019a8c88a597f6084b9313d94a9d0021288891dcfaf39888e3.
The HIA policy flat is 120,514 bytes with SHA256
c549b900613c633d71ba897085d7bf3aa69766623dd203b9ad4acaeeda761393.
The HIA packer and readable mechanical bridge are unchanged. Both actual
policy compilations and both native pack/link runs are byte-identical.

## Atomic storage

The shared ledger context stores the number of first-seen outcomes at byte 168
and six possible outcome indexes at bytes 176 through 223. Indexes retain the
existing mapping: published, abstained, stale, rejected, cancelled, interrupted.

On a successful first settlement for an outcome, the ledger appends that index
while holding its existing native mutex, in the same transition that installs
the new counters, immutable receipt and outcome mask. Failed allocations do
not publish an order entry. Repeated settlement of an already-accounted Job
does not update counters or order. Additional settlements for an existing
outcome leave its position unchanged.

There is no new public outcome limit: these are the six existing execution
outcome categories. Receipt window, unbounded decimal counters, actual Job
markers, reference ownership and the original capacity limits are unchanged.

## Snapshot profile

HIABLG02 is a separate private request magic and accepts only operation 2.
It has the same 128-byte request, zero unused words, output extent of at least
8192 and context extent of at least 4096 as the existing ledger. Other
operations remain available only through their original HIABLG01 envelope.

A successful HIABLG02 snapshot returns the existing HIABLGR1 header and owned
counter/receipt rows. The added fields are order count at byte 64 and the
ordered indexes at bytes 72 through 112. Unused entries and byte 120 are zero.
The order, mask, counters and receipt references are captured under one ledger
mutex interval. The receiver owns and must release every returned row using
the original decimal or payload owner.

HIABLG01 still returns zeros at bytes 64 through 127. A failed HIABLG02
snapshot also leaves those added public fields zero. Existing private-frame
and transactional refusal behavior remains intact.

## Actual qualification

The same final image passed all seven original functional groups, all 37
original native allocation-failure controls and all 24 original packer and
mechanical-source controls.

New order qualification executed all 720 permutations of the six outcomes,
including every prefix and the initial empty dictionary, for 5,040 ordered
snapshots. It checked exact original insertion order, exact counters, duplicate
Job settlement and the unchanged legacy reply header. Sixteen further rounds
used eight actual concurrent settlement threads per round; every observation
preserved unique first occurrence order and all nonoverlapping real-time
precedence constraints. There were 5,056 ordered snapshots and 15,307 actual
ledger calls in this suite.

Twenty-six controls exercised the new envelope's operation and reserved-word
boundaries. The complete 37 actual decimal/payload allocation-failure controls
were also rerun through HIABLG02, verifying rollback, zero added fields on
failure and successful same-owner retry. Native allocator interception is
external QA only and uses the existing complete frozen injector source.

The first implementation incorrectly reread its private profile word after
clearing the public reply header. The first nonempty order test detected the
missing field. The final HIA captures that profile before clearing the header;
all suites above were rerun on the corrected image. The original failure and
image remain external evidence and are not counted as a qualified release.

The companion JSON embeds exact current source/build/report identities and
the additional external QA authors. This closes ledger storage and its
snapshot ordering; complete background construction, execution and production
activation are separate integration gates.
