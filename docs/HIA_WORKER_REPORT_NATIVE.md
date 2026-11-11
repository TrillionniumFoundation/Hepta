# HIA worker control and report candidate

This is an explicit development candidate. It does not establish matching-source
cold qualification or a wholly native worker. The public opt-in selector is
`HEPTA_HIA_WORKER_REPORT_MANIFEST`, naming a bundle that binds both the worker
policy image and the generic HIA JSON wire image to their installed source bytes.
Changing the selector never silently falls back to the retained worker owner.

The HIA policy drives mode checks, administrator pins, service construction and
call/close sequencing, complete post-call manifest comparison, exception
correlation, UNKNOWN routing, callback order, Unicode message slicing, report
field access, virtual report construction and final output. The generic HIA wire
owner sees the entire report, including all parent dictionaries, in one graph.
The host never builds a report dictionary or encodes the response separately.

The Python boundary supplies exact builtin type, length, identity, child,
codepoint, integer magnitude and IEEE observations. It also performs explicitly
requested IO, attribute access, calls and opaque leaf comparison. CPython raw
dictionary iteration and known-hash lookup preserve stored key hashes during
manifest comparison; they do not decide manifest equality. Stateful foreign
callbacks remain foreign effects and their order is controlled by HIA.

Request admission retains its existing independent selection point after stdin.
`HEPTA_HIA_WORKER_REQUEST_MANIFEST` selects the existing native request owner.
When that selector is absent, `_reference_admission` is an explicitly retained
request validator. Installation IO and hashing, service methods, SQLite journal
durability and the external runtime process owner remain outside this candidate.
The native formatter selector is captured and admitted at the original final
wire entry point. Arbitrary untrusted observers or corrupted private
continuations are outside the native ABI trust boundary.

## Development checks and outstanding work

The first actual development policy image passed four independent comparisons
against the retained worker: success, an extra manifest field changing, a caught
service exception and an uncaught service exception. The comparison covered
output and stderr bytes, return or exception, and construction/call/close/after
order. These four checks are not a substitute for the dedicated suite, installed
resource tests, source-bound cold build or whole-project regression.

The structured manifest comparison currently uses the observed runtime recursion
limit to bound native frames. Ordinary installation manifests contain three
string hashes. Exact CPython recursion-resource behavior for pathological cyclic
or deeply nested extension manifests remains to be independently checked; this
checkpoint does not claim arbitrary Python graph refinement at that boundary.

The builder's `--development` mode records `DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD`.
Production qualification must use `--cold-report` for the current source closure.
No deployment, default selector activation or deletion of retained owners is part
of this feature checkpoint.
