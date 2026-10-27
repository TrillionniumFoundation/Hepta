# Independent zero-initialization-elision audit

This directory preserves the already-completed independent audit. No tests or
native compilation were rerun while archiving this evidence.

## Recorded execution

Both scripts originally ran as inline `python - <<'PY'` heredocs with working
directory `/workspace/scratch/06ad8295a712/hepta-unified`. The script bodies here
were copied from those exact recorded tool invocations; they were not originally
files on disk. Their output logs were copied from the recorded tool results.
`execution_record.json` identifies those results and the source binding printed
by the native run. `inputs_and_observations.json` lists the checked cases.

The native run completed with 39 classifier checks and 7 native/interpreter
input cases across the two scripts. The observer counted 5 attempts, comprising
3 malloc calls and 2 calloc calls; 4 non-null allocations were freed, with zero
live allocations or invalid frees. The malloc wrapper poisoned allocated bytes
with `0xA7`; the calloc wrapper cleared bytes. The size-13 malloc request returned
NULL deliberately. Zero length and a length of `2^63` made no allocation call.

## Source and path identity

The printed implementation SHA-256 is
`30c72316ea49f3fd5ac555e1b89e9d2520f47351d2a4ac333f85911cfe0c1c9b`.
The same hash was recomputed from the current source bytes at archival, without
running tests. Git HEAD at archival was
`9fe295e87352295de4b4eb396bda239ceef2a474`; the candidate backend changes were
uncommitted. `source_bindings.json` distinguishes execution-time evidence from
archival observations, and `backend_candidate.diff` and `backend_candidate.py`
preserve the reviewed backend bytes relative to that base.

The native script used Python TemporaryDirectory with prefix
`hia-zero-independent-`. Its actual randomized path was not printed or retained.
Within that directory the exact leaf names were `candidate.o`, `observer.c`, and
`observer`. The directory and native binaries were automatically deleted when
the script exited. This archive does not claim to contain the original object,
executable, complete compile receipt, or original random directory name.
`observer.c` is recovered exactly from the recorded driver string.
`native_program.hia` is the canonical input reconstructed from the recorded
pure-data fixture recipe; its digest matches the digest printed during the run.

## Review conclusion and limits

No blocking issue was found in this bounded audit. Positive scalar-type,
instruction and terminator allowlists scan all blocks. Calls, byte loads/stores,
unknown operations, and resource-valued function boundaries disable elision.
Allocation attempts, NULL handling and explicit drops remain observable; both
malloc and calloc have LLVM builtin-recognition suppression.

The future-operation classifier mutations test the private optimization
classifier's conservative default; they are not claims that malformed programs
pass the Core verifier. The 7 finite executions are not a compiler-refinement or
whole-language-soundness proof. Nothing here establishes equal physical OOM
probabilities or outcomes for malloc and calloc under real memory pressure.

No production source or test files were changed by this independent audit or
its archival step.
