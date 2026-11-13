# Resume retained original evidence, revision 2

This branch is an evidence custodian, not a product branch. Its only parent is
the failed custodian f59d24eb78055d217e329d7e447ff2c1e428c171. It never compiles,
imports or executes Hepta, runs tests, changes product or audit refs, posts
statuses, or changes original results.

The prior collector run43358604029 preserved the complete main51bc content
pool (89 chunks), then stopped while publishing a733 receipts. Its final
partial manifest is fedc691aeb5fb2004d76e5afdcc17374b92fae80. The prior failure
and all ACK boundaries are retained.

## Required first observation

This successor downloads only the prior collector artifact14007242551,
294955566 bytes, SHA256
05114049ee8b8311f82bc237731182a768e452aab894b89a401531713408adf1.
It validates the authority, full file hash and every ZIP member, then publishes
the exact original FAILURE.json and FINAL.json before checking the error.
The resume proceeds only if the actual error is precisely the original
900000-byte receipt guard at the a733 cold-authority stage. A different error
stops and is preserved. The expected error in inputs is a condition, not a
claim that it has already been observed.

## Narrow change

collect_originals.py and inputs/ORIGINALS.json remain byte-for-byte the
reviewed revision. resume_a733.py supplies two transport functions: a retained
ZIP member source and an explicitly indexed oversized JSON receipt encoder.
The original CRC, source binding, phase/reference/deadline/cleanup validation,
content pool and complete gzip/tar verification functions are unchanged.

Receipts retain every JSON field. Small and medium receipt encodings remain
the original format. Larger receipts use numbered 512 KiB chunks of the
zlib stream, with per-chunk, compressed-stream and original UTF-8 identities,
ordered offsets and complete Git readback. Original report bytes, including
their original formatting and modes, also remain in the unchanged original
ZIP members in the content pool.

The completed main pool is referenced, not rebuilt. The producer original
ZIP is not downloaded again. a733 bytes come only from the exact member
a733-original-core-original-artifact.zip in the retained prior collector
artifact. Previously existing immutable Git objects are read and matched;
they are not POSTed again. An ambiguous mutation stops instead of replaying.

## Scope

The two original source identities and results stay separate. main51bc has
original cold FAIL6/11 with a real qualification timeout and complete cleanup.
a733 has original cold11/11 and the admitted 5052-check fixed-core report,
while its later business step27 is still failure. This custodian success can
mean only evidence custody completed; it grants no new product qualification.

The derived pool does not reconstruct the original outer ZIP byte stream.
That exact stream remains in the prior collector artifact and in this
successor's always-retained artifact. All original logical members and
unchanged complete nested ZIP byte streams are recoverable from the pool
plus exact immutable Git source references. Computed raw archive Git hashes
are identities; the actual Git objects published are UTF-8 lossless wrappers.

The only token use is approved repository GETs and immutable /git/blobs POSTs.
No token or signed download URL is logged. Storage-host GETs carry no GitHub
Authorization header. Workflow artifacts retain originals and partial
receipts for 90 days on success or failure. No original product deadline is
changed; the 45-minute limit is solely evidence transfer and verification.
