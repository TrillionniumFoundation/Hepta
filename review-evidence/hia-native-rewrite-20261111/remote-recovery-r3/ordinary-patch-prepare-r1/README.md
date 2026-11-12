# Ordinary HIA patch preparation

Status: new authoring and unexecuted test inventory. This source delivery does
not qualify the complete patch command, installed runtime or whole project.

## Original function and ownership

The semantic reference is the complete _prepare_program_patch in
hepta/hia_program_tools.py at exact commit
0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5. Its Git blob is
c2be38ffe2871ca199783103d4dfa9867771df10, 22,198 bytes, SHA256
a1b42262d8a00fbce9057e40dd081210ad274ecad8fc0c126ffafe8c3568436a.

The parent must actually verify the original Core and independently admit the
original request with the same raw JSON, byte, node and depth rules. It then
holds those exact immutable values throughout every call and pure GROW retry.
A digest, caller-supplied record or private header never substitutes for those
admissions.

The HIA leaf computes the canonical base SHA256, validates the entire request
prefix, applies all four original edit kinds, and renders the complete
unadmitted candidate while preserving insertion order in request subtrees.
It produces all 22 complete original E_HIA_EDIT strings directly in HIA.
Python is not permitted to translate a reason into the business diagnostic.

The candidate must next enter the original object snapshot/byte/shape prefix,
the complete fresh Core verifier, and the interface policy check, in that
order. Only the actual parent may then construct the normal receipt. This
leaf intentionally has no candidate Core, function-count or 8 MiB admission
decision: valid preparation can produce a later-invalid candidate.

## Private ABI

The entry is R/W/W: immutable wire s, writable output o and workspace w.
s is exactly [original canonical Core, independently decoded request JSON].
The two original input byte limits imply a private envelope bound of
16,777,219 bytes. This is a transport bound; it adds no public language quota.
The original request object insertion order and Unicode values survive the
mechanical transport.

The output header is 16 little-endian u64 words:

| Word | Meaning |
|---:|---|
| 0 | ASCII magic HIAPPE01 |
| 1 | version 1 |
| 2 | action: 0 candidate, 1 GROW, 2 public edit error, 3 private BAD |
| 3 | zero for success/GROW, exact diagnostic ID 1..22 or private framing reason |
| 4 | required output capacity |
| 5 | required workspace capacity |
| 6 | payload offset, always 128 |
| 7 | exact payload byte length |
| 8 | patch schema number 1 or 2 |
| 9 | interface policy: 0 preserve, 1 migrate |
| 10 | requested edit count |
| 11 | successfully transformed edit count |
| 12..15 | zero |

Return 128 denotes a complete candidate or public edit diagnostic;
0xfffffffe requests GROW and 0xfffffffd is private BAD. A too-short header
buffer returns BAD without granting any public semantic interpretation.
Candidate bytes or the complete UTF-8 error occupy o[128:128+length].
Grow discards all transient work and recomputes from the same immutable input.
It never repeats Store, publication or another external effect.

The private decoder's node/depth workspace uses a measured transport bound.
This does not bypass the actual earlier original per-input admission.
Aligned scratch reserves 8,192 bytes: SHA state and digest, stable current
nodes, and 64 prior edit records are disjoint.

## Preserved error precedence

Request shape precedes policy, complete lowercase hexadecimal spelling
precedes stale digest, and 1..64 edits precedes edit traversal. Each known
action's exact fields precede function lookup. Existing add targets are
rejected before definition validation. Whole definitions must retain identity
before overlap is considered. For local edits, a prior whole replacement
rejects before block type/lookup. Exact integer index and bounds precede a
duplicate operation check; booleans are not integers and JSON -0 is zero.

The complete native candidate uses the canonical original dictionary order
with only the original four transformations. Replacement dictionaries retain
their request insertion order. Only the original base is canonicalized for
digest comparison; the final unadmitted candidate is not sorted.

## Actual verification to be run

The newly submitted driver builds one fresh image using the original pinned
B3 compiler 35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b
(669,556 bytes), at 10 CPU seconds, 20 wall seconds and 256 MiB. Source gates
remain 128 functions, 1,536 blocks, 8,192 operations, 256 blocks per function,
16 block parameters and 1 MiB source/image. Generation uses 90 CPU seconds,
180 wall seconds and 1 GiB; each of six native test groups independently uses
90 CPU seconds, 180 wall seconds and 1 GiB, with zero core-file allowance.

The intended inventory has 206 cases and 176 actual independent reference
preparation calls:

| Group | Cases | Purpose |
|---|---:|---|
| semantic | 113 | Core versions 1..8, all four edits, v1/v2 and both policies, insertion order, Unicode, -0, 64 edits, and later Core/interface checks |
| errors | 58 | all 22 original complete diagnostics and concrete first-error precedence pairs |
| private | 32 | 20 invalid private transports, four short ABI calls, two actual semantic baselines, six exact/one-short poisoned-capacity controls |
| functions-1024 | 1 | actual admitted 1,024 functions plus 64 additions; preparation returns all 1,088 before later Core rejection |
| large-bytes | 1 | individually admitted inputs whose prepared candidate exceeds 8 MiB while remaining within the snapshot node bound |
| large-nodes | 1 | individually admitted inputs whose prepared candidate exceeds the later snapshot node bound |

Counts above are a submitted plan, not completed test results. Fixture sizes
and reference admissions are asserted at execution; a fixture cannot silently
shrink to fit. Actual native entries include GROW and are counted on site,
never estimated or inherited from an older binary.

Every native entry has a durable ENTER/RETURN or failure ledger, a physically
read-only source, inaccessible guard pages, canaries, and complete before/after
buffers in a lossless SHA256-addressed store. The complete expected candidate
or original error is frozen before entry and compared byte for byte. All
host preparation, Core, interface, JSON and SHA business entry points are
forbidden during actual native execution. The independent original Python
functions run only outside that interval as test oracles.

The full original reference and all source/image pins are re-read. The source
syntax gate is independent and grants no HIA generation or runtime result.

## Known current dependency repair

The issued-object measure_transport reference originally used two Boolean
not expressions which the original authoring Builder does not implement.
An actual object-prefix generation attempt failed with UnaryOp(Not, done)
before any B3/native execution. The new dependency changes only those two
expressions to done == False; done is assigned only True/False. Original
resource gates and semantic checks are unchanged, and the original failed
source and job log remain reviewable.

## Remaining joins

Fresh object snapshot, complete candidate Core, interface policy, normal
receipt construction, static impact, ordinary CLI publication and cold
installed packaging remain separate required joins. Ordinary request admission
must use actual native validators, not the Python oracle used here. Private
arbitrary caller aliases, mutable object extensions and invalid foreign
transport receive no public-pipeline qualification from this leaf.
