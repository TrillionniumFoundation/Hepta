# Empty-proc namespace sandbox qualification

The production candidate sandbox can run with a private empty `/proc` directory.
It does not need a procfs mount. This accommodates hosts that allow real user,
PID, IPC, mount, and network namespaces while prohibiting new procfs mounts.
The AI provider and comparison eligibility requirements are unchanged.

## Required release command

```sh
python tools/validate_sandbox.py \
  --rustc /absolute/pinned/toolchain/bin/rustc \
  --output /new/path/sandbox-qualification.json
```

The output must be a new file. Exit 0 requires every check to have actually run
and passed. The JSON uses `passed`, `failed`, and `not_run`; a missing namespace
facility produces `environment_blocked` and a nonzero exit. It never substitutes
trusted fixture mode for namespace isolation. The command needs Linux,
Bubblewrap, system Python 3, GCC, and the real pinned Rust 1.90.0 toolchain.
The host must permit the required namespace operations. A caller running under
an additional execution sandbox may need the execution environment's ordinary
approval mechanism to run this qualification; this command does not bypass it.

The command performs these real checks:

- Bubblewrap starts with `--unshare-all`, explicit required user/PID/IPC/network
  unshare options, `--new-session`, `--die-with-parent`, and `--cap-drop ALL`.
  The trusted parent compares namespace inode identities
  from Bubblewrap's child PID. User, PID, IPC, mount, and network namespaces must
  differ from the parent; UTS and cgroup identities are also recorded.
- Inside the capsule, `capget` reports zero effective, permitted, and inheritable
  capabilities, and `prctl(PR_GET_NO_NEW_PRIVS)` reports 1. These measurements do
  not require procfs. `/proc` must contain no entries.
- Real parent-side oracle and credential canaries exist before the test. The
  child cannot open them, a capsule symlink pointing to the oracle, the parent's
  private oracle module, `/proc/<parent>/root`, `/proc/1/root`, or
  `/proc/self/environ`. A credential environment canary is not inherited. A
  conventional credential path is checked too; the report distinguishes host
  paths that exist from those that do not.
- A real parent loopback listener receives no connection from the child. The
  network namespace identity must also differ; an error from the socket test
  alone cannot satisfy namespace qualification.
- `/usr` and the explicitly selected Rust toolchain are visible read-only. All
  boundary probes run with the same toolchain mount used by native compilation.
  Thus a visible `/workspace` or `/home` ancestor created for that mount does not
  substitute for checking specific unauthorized files beneath those ancestors.
- The capsule receives only a copy of the `hepta` compiler package, a fixed
  public Hepta program, and the trusted probe. The real pipeline validates the
  program, Rust emits a nonempty native executable, and that executable runs
  successfully. The probe also initializes and pins a real workspace snapshot
  and verifies its recorded native flags include the selected sysroot.

The report records compiler and sandbox executable identities, implementation
hashes, namespace inode observations, capability masks, negative-path results,
native process results, artifact hashes, and the workspace profile. It always
sets `ai_comparison_eligible` to false: this is trusted environment qualification,
not a provider run or a model performance measurement.

## Filesystem and toolchain behavior

Only the existing system allowlist (`/usr`, `/lib`, `/lib64`, `/bin`) is mounted.
Where the host uses merged-`/usr` symlinks, the sandbox preserves those aliases
rather than flattening them into separate bind directories. Both the immediate
normalized target and the fully resolved target must remain within that system
allowlist. An alias escaping it is rejected. This keeps GCC's executable-relative
library lookup correct without mounting host `/etc`.

The Rust ELF loader can need `/proc/self/exe` to resolve `$ORIGIN`. For an explicit
read-only toolchain mount containing `lib/rustlib`, the wrapper sets
`LD_LIBRARY_PATH` to that mount's `lib` directory. It does not inherit the caller's
loader path. No candidate directory is added to the loader search path.
Non-system Python installations still require their explicitly selected runtime
prefix to be mounted read-only by the trusted caller.

The common Rust backend supplies `--sysroot` only when the actual compiler's
prefix contains `lib/rustlib`. Nonstandard host wrappers retain compiler-managed
discovery; strict sandbox qualification rejects an unrecognized prefix. The
backend does not invent a sysroot or claim an unperformed validation. If native
host linking requires a default linker and `cc` is unavailable, it can select
the visible GCC executable. This fallback is restricted to actual link-producing
crate types, without an explicit target or explicit link arguments. Metadata
checks and cross-target/custom link configurations are not rewritten.

The backend report records the actual added sysroot/linker flags and the sysroot
discovery mode. Workspace snapshot identity already includes `native_flags`, so
the explicit sysroot becomes part of the immutable validation profile. A Rust
version string alone does not erase that difference.

## Scope

This qualifies the concrete namespace boundaries, capability state, and trusted
native compiler path on the current host. It is not a proof against all kernel,
Bubblewrap, compiler, or hardware vulnerabilities, and it does not authorize an
AI run when provider configuration or any other release requirement is absent.
Candidate and worker commands keep network isolation. The pre-existing explicit
network option for a separately authorized provider adapter is not used by this
qualification or changed by this implementation.
