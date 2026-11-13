# Original native composition failure and bounded corrections

The first native job for published commit
`3875e6bcd037d9d649e07ae5c4fcf7ce426f8210` ended in failure. Job
`130568441250` in [run 43034132760](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43034132760)
ran its final nominal composition group as 377 tests in 1766.489 seconds,
with seven failures and three errors. Subsequent durable-owner, retirement,
worker and release groups were not executed. The complete original decoded
job log is 283,389 UTF-8 bytes, SHA256
`fa8339d2d19be1d15548eaacfb3ee77c1877c2ab1a55e2391c909ca9ba5c7b35`.
The original Actions ZIP is 77,021,493 bytes, SHA256
`a8923008033eb9eec5ca3e28fd340a4f44ed63432e9b9bd3488897b20a0c3f3c`.

The published-source cold stage passed its eleven checks under the unchanged
180-second qualification and three-second cleanup limits. Its nested report
contains 5,049 passing checks, and B1/B2/B3 all have SHA256
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`.
Language coverage passed 1,242 checks. These are partial results for the exact
published commit, not qualification of the subsequent corrections.

## Failure causes

Five failures are the retained-reference AST dump compatibility defects
described in `HIA_REFERENCE_CUSTODY_COMPATIBILITY_20261111.md`. Their correction
preserves the original expected hashes and full AST fields.

Two native admission subtests expose a separate production compatibility defect
on Python 3.14.10. The native declaration owner correctly stopped at the
unhashable schema, but its adapter synthesized an older generic TypeError
message. CPython now distinguishes a failed dictionary-key lookup from failed
set-element membership. The original first and second foreign truth callbacks,
owner assignments and refusal position must remain observable.

HIA now emits distinct terminal results for the two original failure sites.
The fixed adapter invokes the corresponding built-in operation on the native
selected built-in container type, so the actual interpreter supplies its own
exception. No Python version string or replacement message controls admission.
The original initializer remains unchanged. The existing live-document and
assignment-order comparison retains all original modes and adds both mapping
variants; native result framing also rejects the next unsupported status.

Three call-primitive errors all occur while preparing the same reconstructed
reference fixture, before the selected native call owner runs. Its callee uses
`int.add.checked` twice but declared no `trap` effect, and its caller also omitted
the transitive effect. A replay of all eight original fixture factories on
Python 3.13.5 confirms that only `call_program` fails, with
`E_HIA_EFFECT: missing effects ['trap']`. The corrected fixture declares `trap`
on both functions. Its instructions, input values, expected result, verifier,
native call implementation and compiler limits are unchanged.

## Qualification scope

The original failed logs, original source bytes and reference-fixture replay
remain retained. Actual native verification of these corrections and fresh
combined-source cold/full qualification are subsequent gates. No source gate,
test, timeout, compiler limit, skip rejection or expected-failure rejection has
been removed. Whole-native delivery, default activation and old-owner removal
remain false.

The first actual-machine correction panel on commit
`60e4179b005826c86707ca1b61daf4c01678841f` ran 34 cases in 62.578564171
seconds on Python 3.13.5: 32 passed and two wheel cases failed before building
because their child interpreter could not import `pip`. That failed panel is
retained. The same two original cases then passed in 9.386569802 seconds after
the existing task-local dependencies were exposed to the child environment.
No product source, test body or deadline changed for that replay. There were
zero errors, skips, expected failures or unexpected successes in either panel;
all tracked source and bound compiler/image bytes remained unchanged.

The corrected admission image is SHA256
`43c447ac797c70627c811b551e74a47fdd7ec88c2f7081b801ba783df4e34df7`.
This panel reused the retained B3 compiler as explicitly labelled development
input. It is not a fresh cold build of the corrected source. The original
native admission suite includes the independent full-workspace VM comparison
and nested original 75-case nominal suite; neither is added to the outer count.
Python 3.14 execution and full combined-source qualification remain pending.
