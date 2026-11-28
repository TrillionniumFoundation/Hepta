# Source8 builder terminal physical custody

A peer review identified a final callback window. Four actual private-copy
counterexamples reproduced the issue against commit 6f6cfc1f: the last
caller-supplied read changed an earlier builder, the executing helper, or
the selected outer reader, and verification still returned successfully.
The original inputs were restored and the complete records are retained.

Both the independent builder history and the outer current generation now
finish with direct physical byte and mode checks after every supplied read
callback has completed. The executing module snapshots are checked again.
The original 10 methods and fixed authorities remain unchanged. All 27
methods passed, including four actual late-callback mutations that now
refuse. No current product or Source8 performance result is implied.

The complete old counterexamples, construction precondition failure,
executed drivers, before/after source, raw test log and physical input
review are archived with independent full member byte and mode readback.
