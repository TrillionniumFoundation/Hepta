# Independent physical readback revision 2

This is a read-only audit of the original artifact 13911977275 from run
43140734709, attempt 1, source 9704596acc4470bd0042838586602e26bac7b3d1.
The complete 599,427,251-byte original ZIP is pinned to SHA-256
40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580.
It was recovered through the two bounded upload artifacts from the single
custody run 43171286581. No original product command is run by this audit.

The immutable revision-1 reader and its actual PHYSICAL_READBACK_HOLD remain
preserved. That run completely read all 19,100 outer members, all 787 copied
source files, all 1,025 previously unselected physical references, B0, and the
86 direct root invocation records. It stopped in the first phase because its
whole-dictionary comparison incorrectly treated an added object inspection
annotation as a changed original receipt. Its result is not relabelled.

A subsequent read-only observation of all 38 phase reports found two different
conditions. There are 688 observations whose complete original receipt fields
are unchanged and which add known producer annotation keys. There are also
46 actual earlier compilation records, 23 in each names phase, whose same
file label was reused by a later runtime call. The archive retains the final
runtime files. The earlier compilation data remains embedded in the original
phase report and its produced image remains present, but the original earlier
standalone receipt/request/input/output/stdio history cannot be claimed as
recovered. This is an actual historical custody gap, not an annotation issue.

Revision 2 keeps the original complete byte, CRC, mode, manifest and invocation
joins. For annotations it removes only the exact family-specific added keys,
then compares all remaining receipt fields exactly. It does not reexecute the
annotation or object inspection algorithms. For the 46 known gaps it requires
the precise differences already observed in the pinned all-phase report,
checks that the actual later call executes the surviving earlier produced
image, verifies that the earlier input/output hashes do differ from the
retained paths, and writes the complete earlier/later observations and actual
companion file records. No other mismatch is accepted as a known finding.

The audit must still read every file in all 38 stage archives, every original
manifest, all 12 full ELF boundary gzip originals, the unchanged full ZIP
afterwards, and every admitted metadata input and audit source before return.
Its successful audit status explicitly states that the 46 historical custody
gaps remain. It never declares complete historical invocation custody, changes
the original CI result, or claims a retained 5,400-second full suite ran.

Exact intended command, in the isolated cold directory:

```sh
python3 full_original_physical_audit_r2.py --archive full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip --selected-root container-readback-r1/inner-originals --semantic-report semantic-readback-r2/SEMANTIC-READBACK.json --difference-report phase-receipt-difference-r1.original.json --output full-physical-readback-r2 > full-physical-readback-r2.stdout.original.log 2> full-physical-readback-r2.stderr.original.log
```

Before execution, the reader is parsed without importing or running it and
published with this plan, the actual revision-1 failure, and the exact all-phase
difference observation. The output directory must be new. Existing originals
and prior reports are not overwritten.
