# P2: bounded Clang output capture in C project migration

Previous behavior in hepta/c_project.py used subprocess.run(capture_output=True)
and only checked output length **after** allocating the entire stdout buffer.
A malformed, adversarial or unexpectedly huge preprocessing/Clang AST stream
could allocate much more than the declared 32 MB cap before being refused.

The new hepta/bounded_process.py is shared by the C project capture and the standalone scalar C migrator, and consumes stdout and stderr concurrently:
- stdout chunks have an actual total byte bound (32 million in c_project),
  and the child is killed as soon as the limit is exceeded;
- stderr is drained continuously but retains only the last 6000 bytes;
- the supplied stdin is bounded at 1 million UTF-8 bytes;
- 45-second timeout is enforced, with child kill/reap and bounded reader joins;
- nonzero Clang exit remains a hard E_C_BUILD_TOOL rejection with diagnostic tail;
- oversized output becomes E_C_BUILD_SIZE, never partial accepted output;
- invalid UTF-8 and stream I/O failures are hard rejects.

Both c_project.invoke() and c_migrate._run() now enforce their original error codes and timeouts with the shared bounded stream collector. Standalone scalar AST output beyond 32 MB maps to E_CLANG_SIZE, while C project capture maps to E_C_BUILD_SIZE.

This changes only the compiler subprocess capture boundary. The rest of
the C compilation-database capture, source/hash identities, flag allowlist,
declaration migration and native-validation rules remain unchanged. The output
cap now measures actual UTF-8 bytes rather than Python string characters,
which can reject some formerly accepted huge non-ASCII output conservatively.

## Executed local verification

Python 3.13.5: 16/16 focused tests passed (zero skips), including:
- real Clang preprocessing with stdin macro input;
- real standalone scalar C Clang AST JSON and data-model macro probe;
- 34 MB child output refused as E_C_BUILD_SIZE;
- normal stdout, a huge stderr with bounded tail;
- nonzero child exit and preservation of last diagnostic bytes;
- stdin capacity guard, timeout, invalid stdout encoding.

Four committed code/test file blobs exactly match the source bytes used for
these local tests. The complete PR #14 frontend and C migration project
validation were not executed in this local container. No full program
translation, target ABI, source equivalence, safety proof, or universal
performance claim is made.

The helper does not provide a process-wide CPU/RSS bound, sandbox, power-loss
recovery, or qualification of arbitrary compiler-spawned descendant processes.
General C/C++ migration and P0–P7 production blockers remain open.
