# Bounded relocated Part03 reporting diagnostic

This separately versioned diagnostic is not an acceptance attempt. It preserves the original complete eleven-source validation, five full input byte bindings, 66 positive targets and ten exact negations. The four parents are the unchanged relocated Baseline, SyntaxData, CertPart01 and CertPart02, captured with the hardened acceptance collector. The fifth and final invocation is the marked CertPart03 source using a separately specified PTY collector. There is no retry, sixth invocation, target admission or later module import. Execution and replay always return nonzero, including a completed diagnostic.

## Source boundary

The source derivative inserts exactly eleven fixed 35-byte String `#check` commands. Actual-byte removal and independent command-boundary reconstruction must recover all 612,376 unmarked bytes, followed by the unchanged full relocation inverse and original validators. The marked source is 612,761 bytes with SHA256 `d920662dc97070e94fe95852af6ecbf15f5e4d35a25da4d6a2db977e1005f626`. Marker offsets in the unmarked source are 65, 543, 125190, 125617, 310120, 432982, 473279, 533147, 533170, 572551 and 612376. Rehashing moved markers does not authorize another topology.

All eleven original and eleven unmarked relocated sources remain retained, plus the marked target, for 23 source files and 6,206,115 bytes. The target's unmarked retained path is `relocated/CertPart03.lean`; its marked execution path is `HiaSyntaxResearch/CertPart03.lean`. Unscheduled retained files do not acquire executable module identities.

## Evidence and trust

The new source protocol is `seven-relocated-part03-sources-v1`; the runner/record protocol is `seven-relocated-part03-diagnostic-v1`; the target capture protocol is `p03-pty-hardened-v1`. Old acceptance and diagnostic containers are not interchangeable with this protocol.

Identity includes every one of 247 source paths and 780 support paths. Its compact durable representation stores full paths and SHA256 hashes; actual safe reads still verify byte counts, stable sizes, inode/ancestor identity and all existing source/support limits. Hash-only persistence does not authorize omitted reads or omitted files.

Each successful parent requires full exact raw inventory and same-run source, start, finish and olean bindings. A prior olean or a receipt flag alone cannot authorize a child. Target stdout markers are checked independently against complete retained raw bytes and exact ordered inventory interleaving. The online observer is not the replay oracle. A safely terminated nonzero/timeout target may provide a verified reporting prefix, but never a partial proof admission. Incomplete capture, uncertain cleanup, malformed framing, overflow or failed finalization provides no validated marker frontier.

Target terminal records separate process and receipt clocks. The leader must be reaped, both streams must reach authenticated EOF, and the original process group must be confirmed empty. PTY EIO has bounded confirmation semantics, not an unconditional EOF assumption. Cleanup does not extend the process window. No record is rewritten after terminal persistence to manufacture success.

A complete frozen nonterminal set has 53 files: 23 sources, five globals, twenty parent artifacts and five target artifacts. RESULT adds the 54th file. Commitments are acyclic; RESULT does not hash itself, and a separate bounded summary commits to actual RESULT bytes. Pending/footer fragments are charged to budgets and cannot substitute for complete evidence. A malicious host is outside this integrity boundary; hashes are not host self-authentication.

## Unchanged limits

- At most five launch slots and five confirmed processes, with unknown spawn consuming a slot and stopping.
- 60 seconds per process, 2 seconds cleanup, 540-second new-launch cutoff, 600-second command and 15-minute job.
- 2 MiB per source and 8 MiB aggregate; 32 MiB per module and 128 MiB aggregate.
- 507,392 raw bytes per process and 819,891 aggregate.
- 224,589 hard metadata reserve within the 262,144 outer metadata limit, 4,096 display bytes and 1,048,576 total evidence/display bytes.
- Target start 2,368, marker 224, terminal 3,584, EVENTS 8,416, RESULT 7,968 and EVENTS+RESULT 16,384 bytes; every other inherited subcap remains enforced.

Synthetic serialization envelopes demonstrate finite shape feasibility only. Python fake-child controls establish implementation behavior, not Lean feasibility. Neither synthetic fixtures nor successful markers prove target completion, timing regression, a specific lemma bottleneck, full Core connection or production readiness. The PTY itself changes observation mode and cannot establish a controlled comparison with prior pipe runs.

Every outcome retains acceptance_eligible=false, every connection/refinement flag false, all twelve obligations unproved and DENY_ALL. No native, compiler, performance, initialization-elision, merge or deployment authorization follows.
