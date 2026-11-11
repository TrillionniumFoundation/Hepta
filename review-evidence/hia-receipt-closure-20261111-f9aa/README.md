# HIA receipt and source-admission closure

This change starts from Hepta `8dae9d0b74f8520d1522548e0a04c0c077b3f074`
(PR #890) and the separately retained Runtime candidate
`9a43021137b72316f5345ce660c7f3d00ea93c02` (PR #118).

## Reproduced defects and changes

1. The complete-program select observation admitted a correct low-u32 return
   and output despite a nonzero upper ABI status. A real isolated 24-byte x86
   fixture demonstrates that behavior. Producer and replay now require the
   complete typed ABI result and exact image/input/output identities. Replay
   additionally binds the original child stdout, augmented receipt, input and
   output files, and witness row.
2. The Agent identity helper builder omitted the current support profile and
   complete source map from cold admission. It also omitted a complete source
   recheck before publication. The builder now reuses the existing shared cold
   gate, checks the actual selected helper, and refuses dependency or direct
   input drift before publishing manifest/build receipts.
3. The new controls are included in the source contract and exact-source CI.
   The original cold and compiler-extension time budgets are unchanged.

## Development observations retained here

`development-artifacts.zip` contains original development logs and bytes.
`development-manifest.json` gives its exact digest and the digest/length of
every member. Archive members must be read as data, never executed or extracted
to archive-controlled paths.

- Combined focused suite: 21 tests, zero failures, errors or skips.
- The new identity-admission fixtures explicitly stub compilation. The archive
  retains the original builder's regression failure (`ValueError not raised`)
  as well as the corrected pass.
- The independent ABI fixture executed actual x86 bytes. Its original
  request, image, input, output, stdout, stderr and receipt remain available.
  Its low word is 7 and its output is the expected eight bytes, but its upper
  ABI status is 1. Both corrected admission and replay reject it.
- The existing PR #890 archive's 64 complete-program witnesses were separately
  read back under the stricter checks; all passed. Their original manifest was
  checked before readback. This is historical evidence review, with no new
  compiler, native-workload or SMT execution.
- Independent review exercised four real byte-ABI/replay controls and retained
  a Runtime Git-status bypass reproduction. The Runtime companion addresses
  its own qualification entry point separately.

The development worktree changed while these controls were being assembled.
These logs are not represented as qualification of a final frozen commit.
The exact candidate's GitHub workflows must execute their original cold,
language, native, compiler-extension and paired Runtime/MCP gates. Results and
original failures belong to their exact source revisions.

## Scope

No result here claims a fully native worker, whole-language compiler refinement,
fresh-agent learning, production deployment, exhaustive failure interleavings,
or a performance improvement. The worker JSON/journal/service policy and the
original Agent four-claim qualification retain their existing boundaries.
