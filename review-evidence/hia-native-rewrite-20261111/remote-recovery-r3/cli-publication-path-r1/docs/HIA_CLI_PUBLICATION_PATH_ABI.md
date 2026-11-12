# Native CLI publication Path prefix — development revision 1

This is a new, unexecuted component. It has no inherited qualification from the
verified-publication kernel, the old CLI entry, or the fixed filesystem carrier.

## Ownership and current boundary

The HIA owner implements the prefix of the original `publish_program` after
successful program admission and before its `canonical_bytes` access:
POSIX `Path(destination).absolute()`, destination `exists() or is_symlink()`,
parent `mkdir(parents=True, exist_ok=True)`, parent `resolve(strict=False)`,
and the exact parent comparison. The test oracle stops the original function at
the `canonical_bytes` property, after those statements have actually executed.

The source is an already issued OS-argv string. It is UTF-8 surrogatepass, with
surrogateescape U+DC80..U+DCFF supported, and cannot contain NUL or other unpaired
surrogates. These impossible OS-argv values are private ABI refusals; this does
not claim equivalence to arbitrary Python `hia_main(argv=[...])` object calls.

Unclosed integration remains explicit: libc's getcwd fallback beyond PATH_MAX;
the old Python recursive realpath interpreter's dynamic recursion-limit error;
complete raw OSError and RuntimeError textual presentation; temporary directory
creation and recursive cleanup; writing/flushing/fsyncing the stage; invocation
of verified-publication; and actual parent HIACPR continuation. This component
cannot activate public publication while those dependencies are open.

The cwd peer contract is complete CPython `os.getcwd` behavior encoded back to
filesystem bytes. The initial actual corpus uses raw Linux SYS_getcwd only in
ordinary directories where it returns a complete absolute path. That corpus
does not prove the over-PATH_MAX fallback. A leading non-absolute
"(unreachable)" raw result is converted to ENOENT, as libc does.

## Native ABI

The wrapper is R/W/W with borrow.read of the second input. Internally both
command and reply are read-only. Workspace starts at 4,096 bytes; growth uses
actual requested extents and retains offsets. There is no node, call, directory
depth, path-length, or cumulative arena quota in the HIA owner.

Command: 64 bytes followed by the complete argv string:
`[HIAPPC01,1,lease,initialSequence,stringBytes,totalBytes,0,0]`.
Lease and sequence are nonzero. Initial reply is empty.

Reply: 64 bytes and the complete actual primitive payload:
`[HIAPPA01,lease,sequence,operation,status,result,errno,payloadBytes]`.
Status 0 is success and requires errno 0. Status 1 requires result and payload
zero and errno 1..4095. Exact operation, expected phase and complete extent are
checked before state advances.

The event is 128 bytes at workspace offset 256:
`[HIAPPE01,action,lease,sequence,operation,domain,error,errno,
viewAOffset,viewABytes,viewBOffsetOrCapacity,viewBBytesOrMode,
textOffset,textBytes,requiredWorkspace,phase]`.

Actions are 0 terminal, 1 GROW, 2 primitive request and 6 permanent private BAD.
GROW returns 0xfffffffe. BAD returns 0xfffffffd. A normal event returns 128.
Only a new primitive request increments sequence. GROW repeats the same
immutable command and reply; it never repeats a filesystem primitive.
The last accepted reply's complete header and extent remain pinned through
internal GROW. Its payload remains an immutable issued lease: a matching header
is not authentication of arbitrary substituted bytes.

For action 2, words 8/9 are the exact NUL-terminated workspace path window,
word 10 is the output capacity, and word 11 is the selected mkdir mode.
Cwd has an empty path view. No raw OS descriptor is returned to this owner.

| Operation | Primitive | Success payload |
|---|---|---|
| 7 | stat | exact Linux x86-64 stat, 144 bytes |
| 8 | lstat | exact Linux x86-64 stat, 144 bytes |
| 11 | mkdir | empty, result 0 |
| 13 | readlink | result-length bytes, no NUL, capacity 4096 |
| 14 | cwd | result-length bytes including final NUL |

The 4096 readlink capacity is the current Linux CPython MAXPATHLEN buffer,
not a new public JSON/path quota. The exact CPython 3.12.14
`os_readlink_impl` uses `char buffer[MAXPATHLEN+1]` and one readlink with
MAXPATHLEN. The immutable original posixmodule.c SHA256 is
a8f1410ad95326648a473672ee3bf8158a5f744b7c032c0142327fb252688ab4.

Terminal domain 0 exposes destination filesystem bytes in words 8/9, parent
filesystem bytes in words 10/11, and complete destination UTF-8 surrogatepass
text in words 12/13. These windows exclude terminating NULs.
Domain 1 is HIAEditRejected: code 1 means "destination must be a new file";
code 2 means "output parent must not traverse symlinks".
The final presentation layer prepends E_HIA_EDIT exactly.
Domain 2 preserves the original raw errno and offending filesystem path.
Domain 3/code 1 preserves the final resolve ELOOP and offending path, which
must become the original RuntimeError presentation at the parent boundary.
No complete error string is falsely claimed to be produced by this component.

## Ordering and storage

Path lexical parsing removes empty components and "." while preserving ".."
and exactly two leading slashes. Relative paths request cwd before any target
filesystem call. Existing destination refusal precedes parent creation.

Recursive mkdir first attempts the requested deepest directory. Only ENOENT
with parents enabled descends to its parent; after a successful ancestor, each
saved child is retried with parents disabled. Every other OSError invokes the
original is_dir check; its nonignored error can replace the saved mkdir error.
Ignored pathlib errors are exactly ENOENT, ENOTDIR, EBADF and ELOOP.

The resolver keeps explicit rest frames and a session-owned seen map. It calls
lstat before each symlink decision, supports both unresolved-cycle and resolved
cache entries, follows readlink contents in the original order, propagates
cycle suffixes, and performs the final non-strict stat before parent equality.
All strings and frames are copied into the arena; no pointer into reusable
reply storage is retained. The final destination text reverses filesystem
surrogateescape in HIA, with no host string re-encoding in the actual loop.

The source/command headers correlate private issued leases. They do not provide
authentication of arbitrary external graphs, files or state. Workspace memory
is a private session-owned mutable buffer.

## New planned verification

One fresh original-limit B3 compile; 26 physical filesystem/reference prefix
cases; 10 malformed actual-reply controls followed by a correct reply proving
permanent BAD; terminal reentry refusal on every public case; whole workspace,
source, reply and canary snapshots in lossless CAS. The original full
publish_program prefix executes with an admitted fixture and stops at the
canonical_bytes access. Every case compares complete numeric outcome/path and
all filesystem side effects. Native full OSError string production and native
temporary cleanup are deliberately not counted by this plan.
