# Real structured-editor engineering evidence

The final measured engineering source is original commit
`677a15928c1dd3b236c7bee8cf4b3e6041177f6c`. It passed 51 static tests and all nine
registered native transaction controls: five accepted transactions and four
expected rejections. There were seven actual public native observations and five
terminal hidden reference observations. There were zero model requests. These
engineering checks do not establish Agent coding success or productivity.

## Three separately preserved sources

| Original source | Static tests | Native controls | Role |
| --- | ---: | ---: | --- |
| e5b0766400970a3bacc38aea5f4dfbcb7f903f43 | 48 | 9/9 | Earlier engineering candidate |
| a22d6fe5910e8f9cc08713d7bf9e1194e8644484 | 50 | 9/9 | Earlier reviewed candidate |
| 677a15928c1dd3b236c7bee8cf4b3e6041177f6c | 51 | 9/9 | Final engineering source |

The older controls are retained under their actual source identities. Their
passing controls do not mean they covered subsequently discovered defects, and
are never relabeled as final-source results.

## Review findings and repairs

Independent review identified a concurrent stale-transaction overwrite, an
else-if parser-depth bypass, execution of a native artifact whose compiler
identity check had already failed, and a rejected transaction that could retain
a staged candidate after metadata hashing failed. The final source serializes the
whole transaction, applies the parser bound on that recursion, requires an
explicit compiled status before execution, and prepares all metadata before
staging while clearing staging on exceptions. Each has a focused negative
control. The independent final review is original commit
`4aa79516b5a54b01f4472a56f9757d2263080fd5`.

HIA node changes call the real production batch/patch implementation. Explicit
signature changes and certain insertion/deletion edits reconstruct only selected
fields in a function container before complete verification; no unselected
parameter, operation or operand is silently repaired. Rust uses an intentionally
finite ASCII expression/type parser with exact spans and whole-file
revalidation. Successful syntax editing is not type, ownership or native
admission. Rejected operations keep the original source revision; no candidate
is published into the repository.

## Records and limits

Each run folder retains the actual plan, query, response, transaction, compiler
record, relevant source and public/terminal hidden observations. The raw manifest
also binds every original native artifact and the full 158-file source snapshot
per run. Large binary files and duplicated source snapshots remain in the full
raw archive rather than the compact repository evidence.

The scope is this finite four-file study adapter. HIA's initial base must already
pass its verifier. This does not prove general Rust parsing, whole-language
soundness, compiler refinement, arbitrary failure cleanup, or Agent efficiency.
The later V8 model study uses a separate prospective source/protocol and fresh
qualification; these reference controls cannot qualify its model.
