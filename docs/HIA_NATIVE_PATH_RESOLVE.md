# Native POSIX path resolution

This component implements the selected Linux pathlib.Path.resolve(strict=False) behavior in HIA. It resolves the actual filesystem, including relative paths, symlinks, lexical dot and dot-dot components, ignored non-strict lookup errors, missing final components, and symlink loops. It does not validate an evaluator, receipt, or executable.

## Fixed six-word policy interface

The compiled entry uses (s, sN, o, oN, w, wN). Output requires 128 bytes; private work requires at least 200704 bytes. Set work[0]=0 to begin. A mechanical caller sets work[16] to the actual work base and writes each raw Linux syscall return to work[8]. Return 1 requests the syscall described by the 128-byte output; return 3 requests another policy step without a syscall; return 0 supplies the terminal record. Other returns are private ABI rejection.

A syscall request stores number at output 0, six arguments at 8 through 48, and two-bit argument selectors at 56: 0 scalar, 1 input offset, 2 output offset, 3 work offset. The effect layer translates only these pointers and executes the syscall. Business decisions remain in HIA.

The ordinary input has a 32-byte HIAPTH01 header: mode at 8, body length at 16, zero at 24, followed by the body. Mode 0 is filesystem bytes; mode 1 is a quoted JSON string that preserves the supplied Python-compatible Unicode value, including WTF-8 lone surrogates. The input is not reserialized through a different JSON value domain.

For a borrowed input view, write HIAPTB01 at work 512, mode at 520, start at 528, length at 536. This permits a validated string span from a larger immutable input without copying it. The private interrupt word is work 544. It is a caller-owned cancellation state, not an arbitrary pointer from the input.

## Terminal record and ownership

HIAPTR01 has status at 8, negative errno at 16, stage at 24, result FD at 32, result byte length at 40, and seals at 48. Statuses are 0 success, 1 invalid input, 2 embedded NUL, 3 Unicode encoding error, 4 OS error, 5 private resource or protocol failure, and 6 cancellation.

On success the result is the full resolved filesystem byte string in a memfd with all four seals (15). Ownership of this descriptor transfers to the caller. It is not NUL terminated. Every other internally owned descriptor has been closed. On failure result FD is UINT64_MAX. The caller must read the actual reported length and close the transferred descriptor.

For Unicode encoding errors, fields 56, 64, 72, and 80 contain the first bad code point, Python character start, exclusive end, and the ready flag 1. These preserve the exact original UnicodeEncodeError description when composed with the owner error renderer. Embedded NUL is reported separately; on the pinned CPython/Linux reference its eventual message is "lstat: embedded null character in path".

## Filesystem and storage behavior

The component uses private memfds for pending path records, the current path, a traversal stack, and seen symlink targets. It adds no fixed 40-symlink limit. The 64 KiB memory windows transfer records; they are not an aggregate path-length cap.

A relative path first obtains the actual current directory. If the ordinary getcwd buffer is too short, the component walks directory descriptors and matches device/inode pairs through real directory entries, reconstructing the path. A deleted or inaccessible current directory remains an actual error. This avoids substituting a proc-filesystem textual path for the original semantics.

Resolution errors are evaluated in the original order. In particular, cwd resolution precedes relative-path encoding failures, and a binary path can fail before a later receipt field is inspected. Full syscall result and cancellation processing closes live owned descriptors.

## Qualification and scope

The fixed source and flat pins, compiler identity, and three actual reports are recorded in HIA_NATIVE_PATH_RESOLVE.json. The current component passed 223 filesystem comparisons against CPython 3.14, 124 actual native borrowed-view and lifetime controls, and 207 Unicode diagnostic comparisons, including adjacent lone surrogates, supplementary scalars, surrogateescape bytes, long cwd, and partial cancellation. These reports cover this component only. They do not claim a complete rank caller, background optimizer, or final production installation.

The retained Python author is a development author. Production construction compiles examples/hia_bootstrap/native_path_resolve.hepta; runtime resolution requires no Python process.
