# Cold owner: proc stat read race

The V5 cold run stopped in the original-cli phase at node 890. The child had exited with code zero and produced 930331 bytes. Its owner returned error phase 304 while scanning `/proc`, before the next target-output comparison. The original failure receipt does not record the syscall errno.

A controlled native replay reproduces the missing case. After the owner has obtained kernel `ECHILD`, the test stops it immediately after it opens the stat file of a test-owned sibling. The sibling exits normally and its actual parent reaps it. Reading the already-open stat file then returns Linux `ESRCH`. No executable instruction, register, or syscall result is replaced. Three original runs fail at phase 304, and three repaired runs pass their complete cleanup proofs.

Only this read error gets recovery: close the held descriptor successfully, then reopen the same numeric PID path once. A vanished path resumes the inventory scan. A live replacement goes through the original PID, parent, process-group, session, and start-time parsing. A second read race or any permission/other error fails closed. This path never supplies an empty-tree or ECHILD proof on its own. The original final inventory, identity records, child reap and ECHILD checks remain necessary.

The per-PID retry flag occupies the previously unused control word at workspace offset 360. It is reset only when advancing to the next numeric inventory entry. It does not reset either deadline or alter the 4 MiB workspace or inventory limits.

Qualification retains the original 20 process-owner gates, including actual 15-second timeout, session-detached descendants, grandchild adoption and final child cleanup. Thirty-four native-policy callback controls additionally cover non-ESRCH read errors, close and reopen failures, repeated races, malformed reopened identities, and a live replacement's complete identity record. These modeled error callbacks do not claim that host permission settings were changed. A separate all-native assembly/projector/independent-seed construction produces exactly the qualified owner bytes. The evidence hashes are in `HIA_COLD_OWNER_PROC_READ.json`.

This component checkpoint is not a full 60-phase cold replay pass. The failed V5 source and evidence remain intact; a new source-bound run is required.
