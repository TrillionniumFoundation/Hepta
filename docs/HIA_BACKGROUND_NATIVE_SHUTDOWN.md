# Native BackgroundOptimizer shutdown development checkpoint

This checkpoint preserves newly authored source while the ROG executor is unreachable. It is not a native build or a runtime qualification. The original HIA source verifier accepts the policy, and the readable mechanical bridge matches its encoded packer template. No runtime or whole-background success is claimed.

The policy checks exact boolean flags, closes admission under the real queue condition, captures owned pending Jobs and independent actual Future references, then cancels outside the condition. It retains the first real callback exception and continues all selected cancellations. If requested, it uses the existing serialized worker join with its self-join avoidance. A join exception takes precedence over a previously caught callback exception, matching the original shutdown order. The successful cleanup path returns the original shared exception value, not a JSON reconstruction.

The private request is 128 bytes with magic HIABSHQ1. Operation zero accepts optional wait and cancel_pending value capabilities at offsets 16 and 40; an entirely zero triple denotes the omitted default True, while an actual None value remains an invalid flag. Operation one is reserved for the original retained cleanup frame. Output extent is 262144 bytes, and the private captured frame is 16384 bytes, magic HIABSHC1. Its fixed bindings are value at 8/16/24, queue at 32/40/48, Jobs at 56/64/72, public Future at 80/88/96 plus factory identity 104/112/120, worker at 128/136/144, and actual submission context at 152/160. The frame is exclusive to one call or its cleanup continuation. The reply is HIABSHR1: status 8, actual error kind 16, owned error capability 24/32/40, detail 48, and quarantine 56.

The additional captured cell entry/context/extent occupy 192/200/208 and must
come from the same actual public factory, whose lease is retained by the
enclosing owner. Queue capture uses HIABGQ04; Job drop/retry uses HIABJO03;
Future release uses HIABFP03/op26; value drop/retry uses HIABVQ02/29 and 31.
Consumed references are cleared even when retirement fails. Public retry alone
does not prove cleanup complete: shutdown reads the actual cell's profile-04
operation-21 retirement observation. A post-consumption value error with no
mapping record is quarantined without replay. Details are in
HIA_BACKGROUND_NATIVE_RETIREMENT_CONSUMERS.md.

Retained cleanup uses quarantine 1 and operation one with the original
exclusive frame. Unknown dependency outcomes use quarantine 2 and are not
accepted by that retry entry. Cleanup does not repeat cancellation, callbacks,
join, ledger settlement, or publication. Every context and the captured code
must remain strongly owned through the retained operation.

The source contains retained ownership handling, but its failure paths require actual component and full-worker tests before use. It does not replace the constructor, public lifecycle owner, or physical worker-exit qualification. The dependent Python files are development authors and oracles only; generated HIA and the mechanical adapter form the intended runtime component.
