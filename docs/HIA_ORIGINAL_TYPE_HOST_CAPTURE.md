# Original C types on actual hosts

The merged `a61bb2baa3510dbe7d465232f1b4f08cdf9d68f1` host run
[`40651793646`](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40651793646)
passed the existing ABI route on all seven host/compiler jobs. Its newly added
complete `stb_divide` component passed on four Linux jobs and failed on macOS
and both Windows jobs during original-parameter-type admission. Those results
are distinct denominators. The failures must remain in retained evidence.

The subsequent `0ecd748a8f30edd668a3059e879ea6117e2712d4` run's new
descendant tests exposed a second POSIX group-termination call in `finally`
after normal cleanup had already completed. On macOS that redundant call
raised `EPERM`. Capture now records completed cleanup and does not repeat a
signal after disposing that owner. Failure of the initial cleanup still
propagates; this change does not broadly ignore permission errors.

That run passed the new Windows process tests, then exposed the compile-command
parser's rejection of the actual `clang.exe` spelling. The parser explicitly
admits `.exe` spellings of its existing GNU-compatible driver allowlist. It
still records the original database command without executing it, and rejects
wrappers, `clang-cl`, MSVC driver syntax and response files. The separately
selected capture Clang retains its actual path and identity. A preflight
failure also surfaces the retained migration diagnostics rather than only
reporting that its expected type receipt is missing.

The `3dfe6b1d4b2468c33aeee2bedaf8f0bc0df277b8` run passed all seven hosts'
process tests. macOS then refused the original-type worker's address-space
limit, while both Windows workers reached the strict AST command/budget
comparison and refused it. These are later, independently retained failures.

## Toolchain identity

On macOS, `/usr/bin/clang` is a developer-tool shim. The host preflight executes
`/usr/bin/xcrun --find clang`, retains the observation, and selects that actual
compiler. Its existing original-type reader must use `libclang.dylib` from the
same installation, with the actual compiler/reader version and bytes checked.
No global library search or alternative compiler is used to reinterpret the
serialized AST. The reference C compiler in the ABI/component matrix keeps its
own declared identity.

The AST output's existing temporary directory is canonicalized before its
`-o` argument is constructed. Its receipt therefore records the same path used
by the file-identity reader. The original C source operand remains unchanged.
A real Linux symlink-temp reproducer rejected with only `argv` differing under
the former logic; after this normalization, fixed arrays admit and VLA entry
effects still refuse. Wrong argv, file identity and budgets remain refusals.
Windows short paths and macOS temporary aliases still require actual host
qualification; path equivalence is not used to loosen the receipt comparison.

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
mandatory address-space/file-size limits, with the platform policy below.

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

## Explicit platform process limits

Linux keeps an absolute 2 GiB address-space ceiling. Darwin observes the
worker's initial virtual address space using `MACH_TASK_BASIC_INFO` and limits
additional address space to 2 GiB above that baseline. XNU cannot lower
`RLIMIT_AS` below its already mapped VM size; a runtime/shared-map baseline is
not an AST heap or RSS allowance. The Darwin policy is a growth budget, not an
absolute 2 GiB address-space or resident-memory guarantee.

Both policies clamp to any tighter inherited soft/hard limit. Infinity and
noninteger requests are rejected. Actual `setrlimit` success and a finite,
no-larger readback are mandatory. Mach ABI/count/port/query failures and kernel
limit failures refuse admission; no failure is ignored and no extra mapping
padding is guessed. All POSIX phases keep the 32,000,000-byte `RLIMIT_FSIZE`.

The independent `--process-limits` probe emits
`hepta.c-original-type-process-limits.v1`. Its observation records platform,
memory policy, Darwin baseline when applicable, inherited limits, requested
and applied limits, actual readbacks, and an explicit false RSS claim. Failure
diagnostics retain the current limits or an explicit unavailable-readback
error. The host preflight retains this probe and binds its worker bytes to the
original-type reader. Original-type v2 receipts keep their existing fields and
strict limits/argv/file identity checks; a varying VM baseline is not inserted
into their stable tool-identity contract.

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
- [Apple XNU 11417.101.15: Mach task information ABI](https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/mach/task_info.h)
- [Apple XNU 11417.101.15: resource-limit validation](https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/bsd/kern/kern_resource.c)
