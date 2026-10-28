# Original C types on actual hosts

The merged `a61bb2baa3510dbe7d465232f1b4f08cdf9d68f1` host run
[`40651793646`](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40651793646)
passed the existing ABI route on all seven host/compiler jobs. Its newly added
complete `stb_divide` component passed on four Linux jobs and failed on macOS
and both Windows jobs during original-parameter-type admission. Those results
are distinct denominators. The failures must remain in retained evidence.

## Toolchain identity

On macOS, `/usr/bin/clang` is a developer-tool shim. The host preflight executes
`/usr/bin/xcrun --find clang`, retains the observation, and selects that actual
compiler. Its existing original-type reader must use `libclang.dylib` from the
same installation, with the actual compiler/reader version and bytes checked.
No global library search or alternative compiler is used to reinterpret the
serialized AST. The reference C compiler in the ABI/component matrix keeps its
own declared identity.

The preflight captures two small actual translation units. A fixed-size array
must retain its extent and original qualifiers; an entry-time variable array
with a side effect must retain its variable shape and be explicitly refused.
These are frontend checks, not native equivalence or ABI qualification. A
failed preflight retains its report and exits nonzero, without exporting a
compiler selection for later steps.

## Windows execution and process ownership

The serialized-AST worker waits explicitly for the selected Clang process on
Windows, passing an argument list to `Popen` without a shell. It inherits the
outer capture's file-backed standard handles and process job. The worker's
actual exit code is preserved. POSIX retains its existing `execv` path and
address-space/file-size limits.

The outer capture owns a Windows Job Object with `KILL_ON_JOB_CLOSE`. A small
trusted Python launcher waits on a private inherited pipe. The parent assigns
the launcher's retained process handle to the job before sending permission to
start the command. Assignment failure closes the gate; it does not fall back to
uncontained execution. Both launcher layers use ordinary child creation, with
no breakaway or new-session flags. Nested-job support is required when the
caller already belongs to a job.

Normal completion, nonzero completion, wall-time expiry and output-byte expiry
all terminate the job. Cleanup checks the job's active-process count and reaps
the launcher before disposing its handle. An unconfirmed cleanup retains its
owner and blocks subsequent capture admission until a retry confirms it has
drained. This is process lifetime control; it is not a filesystem, network or
privileged-code sandbox. Windows does not acquire the POSIX worker's `RLIMIT`
memory/file-size enforcement from this change.

AST emission failures include the actual return code, command, output-file
presence/type/size and bounded stdout/stderr tails. Original type receipts,
physical source bindings, compiler/library/worker identities and declared AST
budgets remain mandatory.

## Qualification boundaries

`tests.test_clang_capture` runs real child/grandchild processes on the host. The
descendant must first announce that it actually started; delayed output must
then be absent after normal return, nonzero return, timeout and output refusal.
The workflow retains its raw test stream. Linux observations do not qualify the
Windows Job Object path.

The host workflow separately retains the selected compiler/reader preflight and
the complete component's native differential evidence. Only successful actual
host executions at the published source head close the corresponding host
failure. Synthetic path/identity controls and a successful frontend preflight
cannot substitute for those component runs. No general callback lifetime,
direct-LLVM aggregate ABI, arbitrary C/C++ conversion, or cross-platform safety
proof is implied.

## Platform contracts

- [Apple: command-line developer tools and xcrun](https://developer.apple.com/library/archive/technotes/tn2339/_index.html)
- [Microsoft: Job Objects, inherited membership, nested jobs and termination](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Python 3.11: subprocess argument lists and inherited handle lists](https://docs.python.org/3.11/library/subprocess.html)
