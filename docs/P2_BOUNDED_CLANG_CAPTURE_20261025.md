# P2: bounded Clang subprocess capture

The strict single-translation-unit C/C++ migrator (`hepta.c_migrate._run`)
and the captured C-project build frontend (`hepta.c_project.invoke`)
now share `hepta.clang_capture.run_bounded` rather than two independent
unbounded in-memory `subprocess.run(..., capture_output=True)` paths.

The capture process uses file-backed stdin, stdout and stderr, a 32 MB
stdout limit, a 1 MB stderr limit, 30-second single-TU and 45-second
project capture deadlines. Limits are periodically observed while the tool
executes, with final checks before any bytes are read into Python memory.
The POSIX child receives its own process session; process-group cleanup
covers timeout, byte-quota error, and a compiler parent that exits while
descendants remain. Windows supports the byte/deadline checks but the
POSIX process-group descendant guarantee is not claimed there.

No shell is used; existing source/compiler and publication identities
remain enforced by the importing compiler components. MigrationRejected
continues to reject unsupported inputs and maps byte quota failures to
`E_CLANG_SIZE` or `E_C_BUILD_SIZE`.

Observed standalone local probe: 9 positive/negative process tests
including real Clang 17 preprocessing, stdout/stderr over-budget rejection,
timed child rejection, malformed UTF-8, and POSIX orphan cleanup passed.
These are not full Hepta native compiler / rustc / ABI / migration
qualification; repository `tests.test_clang_capture` provides the
reproducible scoped test suite.

**Limitations:** the temporary-file spool can transiently exceed its byte
budget between polling samples, and malicious same-user filesystem changes,
child-created sessions, non-POSIX descendant trees, external filesystem
side effects and compiler binary attestation are not addressed. These
controls do not prove arbitrary source migration safe or equivalent.

Production P0-P7 and P01-P12 blockers remain open. No CI result is required
to keep work moving, but unrun qualification is not counted as passed.
