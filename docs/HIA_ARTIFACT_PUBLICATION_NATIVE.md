# Explicit native local artifact publication

The optional `hia-artifact` application implements three filesystem operations:

```
hia-artifact publish STAGE DESTINATION < EXPECTED-BYTES
hia-artifact verify STAGE DESTINATION < EXPECTED-BYTES
hia-artifact withdraw STAGE DESTINATION
```

`publish` uses a no-replace hard link. `verify` requires both names to identify
the same ordinary inode. Nonempty **exact bytes**, not a digest or receipt, are
the authority. HIA checks every read chunk, file descriptor and pathname
identity, type, size, mtime and ctime. Creation of a hard link may update ctime;
that exception is allowed only between pre-link and post-link staging checks.
A failed post-link check withdraws only a destination still naming the original
staging inode. A competitor's replacement must remain. `withdraw` returns a
boolean JSON receipt and never accepts inode ownership based on a prior receipt.

The executable has no libc, Python, external helper or dynamic interpreter.
Its fixed Linux x86-64 syscall adapter performs transport. Checked HIA handles
command admission, lexical absolute paths, identity/byte checks, receipt JSON
and streaming SHA-256. Expected input storage grows by mmap/mremap until OS
resources are exhausted; it does not impose the Agent store's 64-MiB limit or
the SHA per-call chunk size as a whole-artifact limit. File reads use bounded
scratch chunks. Linux argv strings and getcwd transport remain platform-sized;
getcwd failure is an I/O refusal, not a claim to support Python's long-cwd fallback.

Exit statuses: 0 success, 10 identity, 11 bytes, 12 concurrent identity change,
14 no-replace link failure, 15 I/O failure, 16 invalid input/policy state, 64 usage.
An existing destination (including a dangling symlink) is never overwritten.
FIFO and symlink staging are refused. O_NOFOLLOW | O_NONBLOCK descriptors prevent
blocking after a regular-file-to-FIFO substitution. Paths preserve `..` and the
POSIX special exactly-two-leading-slash spelling; normalization is lexical, not
symlink resolution or a filesystem access sandbox.

This provides **point-in-time local consistency**, like
`hepta/artifact_publication.py`, not immunity from later same-user writes.
There is no directory-fsync, SQLite intent/recovery, transactional Agent store,
atomic stdout receipt or automatic retry promise. A receipt-write failure can
leave a valid link. No default or installed Agent path is switched by building
this candidate. Host build, installation and executable-code custody remain.
The syscall template is authored with binutils; actual executable ELF layout,
call patching and HIA-image copying are performed by the HIA packer, not a host
payload compiler. Native-only build/delivery closure remains open.

Build with `python -m tools.build_hia_artifact_publication --compiler IMAGE
--cold-report CURRENT-COLD-REPORT --output NEW-DIRECTORY`. The builder rejects a
cold report from different source or changed images, before creating output.
Tests must retain independent Core-VM policy observations and real kernel
publication, races, fault injection and copied/empty-PATH execution evidence;
a byte-snapshot-only candidate does not qualify filesystem publication.
