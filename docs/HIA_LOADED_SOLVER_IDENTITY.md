# Loaded solver identity

The scalar and SIMD checkers identify the Z3 Python code that executed and the
native library that its actual function handle uses. The profile is
`hia.loaded-z3.python-source-and-library.linux.v1`. It supplements the existing
all-input obligations; it does not change their assumptions, deadlines or
required SAT/UNSAT answers. Z3 remains an identified trusted implementation,
not an independently proved solver.

## The closed attribution gap

Hashing files at the first proof was insufficient. A process could import Z3,
append an unconditional exception to its on-disk Python package, atomically
replace `libz3.so`, and then complete a proof using the old loaded code. The
receipt attributed that execution to the replacement source and library hashes.
Keeping the version string pinned did not distinguish these executions.

The new monitor admits a fresh standard-source import. It never registers
previously imported Z3 retrospectively. Import the HIA validation or verified
build entry before importing Z3; the normal HIA entrypoints do this themselves.
If the process already imported Z3 before the monitor was installed, start a
new process. Reloading Z3 or retrying a failed controlled import in the same
process also rejects. The ordinary source/object emission route still neither
imports Z3 nor performs proof-source compilation comparisons.

## Python binding admission

`hia_solver_identity` installs a finder for the `z3` package only. Each standard
`SourceFileLoader` is wrapped as follows:

1. Open and retain a descriptor for the bounded regular source file. Capture
   its bytes, hash, device, inode, size, nanosecond modification time and change
   time. Require stable metadata across the read and the pathname lookup.
2. Obtain the loader's code object, independently compile the captured source
   with the running interpreter's optimization level and no inherited compiler
   flags, and compare the complete recursive code shape. This includes nested
   code, constants, bytecode, flags, line and exception tables. A timestamp-valid
   stale `.pyc` cannot acquire the replacement source's identity.
3. Recheck the retained descriptor and pathname, then execute that exact
   compared code object. There is no second `exec_module` fetch that can read a
   different snapshot. Recheck the source again after execution.
4. On every solver identity request, require the same module objects,
   namespaces, loaders and file locations, and recheck the retained descriptors
   and current pathnames. The executed module inventory must equal every Python
   source file in the pinned flat package. The current Z3 4.15.4 distribution
   has ten such files, including `__init__.py`, `z3.py`, and `z3core.py`.

Missing or additional unexecuted source files, source drift, module replacement,
reloads and unsupported loading mechanisms reject. The monitor itself is
covered by HIA's executed-source binding and is included in both scalar and
SIMD checker source identities.

## Native library admission

The monitor observes `ctypes.dlopen` only while the controlled `z3core` module
is executing. CPython raises that event before calling the native loader; the
ordering is visible in
[`py_dl_open` in CPython 3.14.4](https://github.com/python/cpython/blob/v3.14.4/Modules/_ctypes/callproc.c).
The documented event and library-handle interface are described in
Python's [`ctypes` reference](https://docs.python.org/3.12/library/ctypes.html).

Before `dlopen`, the monitor retains and hashes the actual requested absolute
file, with the same stable device/inode/size/time checks. It rejects an already
mapped copy of that file or a pre-existing `libz3` image. This capture happens
during import, before callers can obtain the admitted Z3 module, rather than
at the first proof.

After `z3core` executes, the monitor obtains the actual C function pointer
retained by its `Z3_get_version` wrapper and the associated `ctypes.CDLL` handle.
The handle must identify exactly one observed pre-load file. Its function
address must lie within that file's private read/execute mapping, matched by
device and inode in `/proc/self/maps`; a second library with the same basename
cannot satisfy this check. The Linux kernel documents the mapping fields and
their file identities in its
[`/proc` reference](https://docs.kernel.org/filesystems/proc.html).

Every subsequent identity request rechecks the retained descriptor's bytes and
metadata, the current pathname, the actual function and library objects, and
the same executable mappings. Atomic pathname replacement therefore cannot
relabel an older mapping. A same-inode write, including a same-size write with
restored modification time, also rejects: the original hash, retained file and
change time remain part of the check. Mutations between capture and `dlopen`
reject before import completes; mutations after import but before the first
proof have no opportunity to establish a new baseline. Scalar and SIMD proof
completion repeat the identity check before publication.

## Receipt fields

The original `name`, `version`, `binding_sha256`, and `library_sha256` fields
retain their meanings. `binding_sha256` hashes the sorted source basenames,
each followed by a NUL, its raw source bytes and another NUL. The library hash
is the retained pre-load file's hash. An additional `load_binding` object
contains:

| Field | Required evidence |
| --- | --- |
| `profile` | `hia.loaded-z3.python-source-and-library.linux.v1` |
| `controlled_import` | `true` |
| `binding_code_matches_source` | `true` |
| `binding_files` | Complete source basename to SHA-256 map |
| `monitor_sha256` | Executed-source identity of `hia_solver_identity.py` |
| `preloaded_solver_authorized` | `false` |
| `library.device_major`, `library.device_minor`, `library.inode` | Actual mapped file identity |
| `library.source_size` | Retained library file size |
| `library.anchor_symbol` | `Z3_get_version` |
| `library.mapped_executable_segments` | Positive count of matched executable mappings |
| `library.file_identity_rechecked`, `library.loaded_mapping_bound` | Both `true` |

These fields describe freshly checked execution; a saved receipt does not grant
authority to a later process or substitute for checking its current bindings.
Inode and device values belong to the recorded host and file instance. They
are not portable content identifiers.

## Trust and regression boundary

This contract requires Linux, the pinned standard-source Z3 package, the
trusted running Python interpreter and import machinery, `ctypes`, the dynamic
loader, and truthful OS file/mapping observations. Audit hooks are observations
under that trust contract, not a Python security sandbox; Python explicitly
documents that limitation in
[`sys.addaudithook`](https://docs.python.org/3.12/library/sys.html#sys.addaudithook).
The monitor checks that its hook was installed. It does not promise resistance
to arbitrary in-process monkeypatching, hostile symbol interposition, privileged
memory modification, a compromised kernel or a malicious solver implementation.

`tests.test_hia_verified_solver_identity` runs each scenario in a fresh isolated
child and changes private package copies only. Its controls cover actual scalar
proof publication; full executed-source and actual mapping identity; preloaded
Python/native copies; source and library changes before the first proof; atomic
replacement and same-inode writes; capture-to-`dlopen` and `get_code` races;
stale timestamp bytecode for top-level and nested code; reloads, missing and
extra files; source drift during real queries; and library drift between proofs.
The existing missing-solver, solver-UNKNOWN, fresh independent consumer, ordinary
object emission and parallel SIMD-context controls remain separate gates.
