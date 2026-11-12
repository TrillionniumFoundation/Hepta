# Wire protocol 04: second source qualification, actual originals

The six exact source methods passed once under the original 180-second owner and
3-second cleanup. The worker took 9.541171217 seconds, including 2.284256043 seconds
to generate the HIA source. The owner exited naturally with code 0 and recorded
all four expected lifecycle events and ECHILD; no descendant remained.

All 539 original source inputs and all 543 pinned inputs remained byte-identical.
The only new source file is the generated HIA assembly, 361,637 bytes, SHA-256
f4e353af23b251d645dee41596dd590820322af4bce5b2545375b74f8eed36a5.
Its 53 functions, 909 blocks, 7,208 operations and maximum 1,945 SSA values per
function satisfy the original fixed limits. There were no failures, errors,
skips, expected failures, unexpected successes or forbidden execution attempts.

The first source request remains a recorded HOLD: the unchanged verifier rejected
an unnamed intermediate crossing a short-circuit block. The second request uses
a named intermediate and an explicit conditional, preserving the arithmetic and
all verifier limits. It does not change the Builder or verifier. The request and
the first actual failure are retained in parent cb51003c4a0305f32cc5908ec3b09e4955ffd07e.

The archive contains all 20 actual originals plus root readback, invocation,
request and publication receipts. Every archive member was restored and compared
against its complete original byte string. ARCHIVE.json contains their original
physical identities and complete SHA-256 and Git blob hashes.

This result qualifies only the six source methods. The original native 89-method
group and its 256-case, 5-second assertion, the original native seven cache tests,
the additional native six tests, fresh Cold, installed behavior and the complete
rewrite are still unqualified for this candidate. No default was changed and no
legacy product source was deleted.
