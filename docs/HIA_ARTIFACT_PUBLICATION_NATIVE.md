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

## Explicit source-tree API selection (hosted custody)

`HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST=/absolute/build.json` selects this
application for the existing `publish_verified`, `verify_published` and
`withdraw_own_link` APIs. No selection means the unchanged reference path.
An invalid selection fails closed, not back to hosted filesystem verification.
Code admission checks the current source manifest and exact executable hash,
then executes a sealed memfd instead of re-opening a mutable executable path.
Only receipt JSON is decoded by the host; payload verification/hash/filesystem
publication execute in HIA. This route still requires Python and source-tree
build/custody tools; it is not a native-only installation or an untrusted-code
sandbox. Native no-replace refusal maps to `E_PUBLISH_LINK`, including an already
existing destination, rather than the reference's preliminary `EXISTS` category.
That diagnostic distinction and Agent journal/recovery/default-install closure
are not presented as replaced. Receipt I/O failure must not trigger replay.

## Explicit Agent artifact byte store (not journal replacement)

The same application additionally accepts:

```
hia-artifact store-hash ROOT - < BYTES
hia-artifact store-put ROOT - < BYTES
hia-artifact store-get ROOT LOWERCASE-SHA256
```

These three commands preserve the Agent's inclusive **64 MiB** quota and allow
empty artifacts; generic publication remains unbounded by that quota. `store-hash`
is pure HIA byte hashing, without filesystem effects. Put/get pin one owned,
non-group/world-writable ordinary directory descriptor. Only exact 64-character
lowercase hex content names are accepted. HIA generates UUID4 temporary names;
the syscall adapter opens them exclusively with nofollow and mode 0400, writes
all bytes and fsyncs the file before a no-replace link. Existing entries must
match every input byte. The directory is fsynced before a success receipt.
Owned temporary files are cleaned up, never a competitor's replacement inode.
Get captures and authenticates all bytes, size and identity before any stdout.
Symlinks/FIFOs, changed identities, corrupt bytes and over-quota files refuse.
Status 17 is the original Agent quota refusal.

`HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST=/absolute/build.json` selects this byte
layer in actual `AgentStore.put/get`. A sealed executable is admitted using the
current source contract; invalid selection never falls back. Payload hashing,
file byte verification and file publication are native. Metadata/ref hashing,
SQLite WAL authority, reference issuance, request intent, locks, recovery and
JSON values remain hosted. Issued refs are still checked before file access;
content digests do not grant namespace or kind authority. No default changes.

File fsync failure yields no content link or success. Directory fsync failure
can leave valid content, but no success or newly issued DB ref. Receipt or
DB failure can likewise leave content: this is not a file/SQLite transaction,
crash-recovery implementation or license to replay. Existing request-intent
unknown/conflict behavior remains mandatory. Neither filesystem capture nor
stdout grants immunity against a later writer or atomic stdout delivery.

A public `AgentStore.put` admits the complete current source and executable once
for its paired pure-hash and durable-write operations. Both execute the same
immutable admitted code, not two potentially different mutable build paths.
There is no cross-call code cache or metadata-only source trust: every next
public put/get again performs full source-byte and executable hash admission.
Selection changes between the pair refuse without file publication or DB
issuance. This bounded code view reduces redundant custody scans; it does not
change the original Agent context deadline or artifact quotas.

## Installed-package custody

Explicitly selected publisher/store code can now be admitted in the installed
wheel without importing checkout `tools`. Full checkout admission remains
unchanged. The wheel includes four additional build inputs; its existing SHA
source completes the exact five-input publisher custody set. Installed admission
checks all actual production modules and explicit resources against the owned
full build-source contract, then checks the selected manifest and executable.
Build-only source files remain declared by that exact contract, not falsely
reported as installed runtime modules. The contract itself must match the build
manifest's exact digest. There is no alternate-checkout fallback.

The Python custody bridge and SQLite request/ref authority remain dependencies.
The standalone HIA executable is still the only filesystem payload hash/read/
write implementation on the selected route. This does not select a live default,
qualify a native-only installed worker, or replace its journal.
