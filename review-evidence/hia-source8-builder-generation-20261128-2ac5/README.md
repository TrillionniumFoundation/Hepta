# Source8 builder generation history

The original current-source controls rejected the new 31,169-byte Bootstrap
builder before any test method ran. The builder differs from the fixed
30,952-byte prior by four declared inputs, totaling 217 bytes.

This change adds one immutable complete-file inverse/forward relation.
Both builder versions were read from their original Git blobs. The new
reader captures all four new dependencies, its executing source, the fixed
relation and the original inverse engine from the selected physical root.
It passes an explicitly named prior view to the unchanged older relation.

The original 10 methods and their complete file are unchanged. All 10 plus
13 new source controls passed, with no skipped methods. Missing, altered,
late-replaced and mode-changed inputs, forged prior captures and a changed
reader between import and first prepare were actually refused.

The archive retains the original preparation failure, the two construction
precondition failures, exact executed drivers, original and current source,
Git provenance, complete successful test output and initial/terminal pins.
Every archive member was reread and checked against its original byte and
mode manifest. This establishes source history only; it does not turn the
separately preserved Source8 timeout or its ordered late differences into
a passed product gate.
