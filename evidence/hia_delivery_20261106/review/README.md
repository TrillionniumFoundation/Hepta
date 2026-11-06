# Independent quota review and retained counterexamples

These are actual development counterexamples, not failures of the later fixed
candidate. `findings.json` and `engine-findings.json` bind their respective full
Python source snapshots by SHA256. The original probes and source bytes remain
unchanged. Absolute scratch paths in the original captures are historical
execution locations, not reusable deployment instructions. `SHA256.json` covers
the retained bytes.

The independent review reproduced:

1. A forked process using an inherited instance and flock descriptor. A child
   could commit between the parent's publication and readback, causing the
   parent receipt's sequence/hash to refer to the child's request.
2. A successful publication followed by a readback error reported as an ordinary
   error instead of an unknown completion acknowledgment.
3. A publication/cleanup interruption bypassing the unknown-outcome contract.
4. A str subclass overriding version comparison, allowing an invalid upgrade
   record to be published before recovery rejected it.
5. A deliberately injected, well-typed incorrect backend result being committed
   before VM replay rejected it, poisoning the journal. This was fault injection;
   no actual LLVM miscompilation was discovered.

The fixed source checks the originating PID before its thread lock, resolves
receipts by request identity, classifies post-publication and readback exceptions
as `CommitUnknown`, requires exact string version input, and compares live HIA
results to VM replay before publishing genesis, transitions or upgrades.
Malformed scalar backend results were already refused before publication.

`fix-verification.json` and `.log` retain the independent rerun of all six
corresponding focused regressions, with source and test hashes unchanged during
execution. The complete application qualification later reruns these within its
full registered inventory on the final candidate. These finite controls do not
claim physical power-loss testing or exactly-once external effects.
