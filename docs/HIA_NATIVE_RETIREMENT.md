# Observable native retirement and bounded cleanup failures

The generation runtime now records native release and disk cleanup as separate
operations. A successful pointer publication stays published when an old
generation's disk cleanup fails. That failure is observable and continues to
consume the finite artifact capacity; it is not silently converted into a
successful cleanup.

## Ownership and release order

Only a retired generation with no active leases can enter retirement. Its
function references are cleared, its loader handle is released, and its owned
memfd is closed. Both native release operations are attempted independently, so
a loader error cannot skip closing the memfd. Normal-return records say the
operation completed; they do not prove the absence of other host-owned library
references or process-wide mappings.

Each native operation is attempted at most once. An exception can arrive after
an operation has taken effect, and a numeric file descriptor can already name a
different resource. Retrying that descriptor or loader handle would risk a
second release. An uncertain result therefore remains pending, recorded with
its exception type/errno, and is not retried automatically or by
`retry_cleanup()`.

The original artifact and runtime directory each have a separately owned open
identity fd. Keeping that fd open pins the original inode even if another actor
unlinks the file or removes the directory. A bare `(device, inode)` tuple is not
delete authority: the filesystem may immediately reuse both numbers for a new
object, without any concurrent race. Identity acquisition checks the real fd,
expected inode, pathname and object type. Acquisition failure leaves the path
unbound, and any fd already acquired during failed validation is closed at most
once without authorizing deletion.

Once native release succeeds, the runtime attempts to remove only its pinned
artifact inode. A missing artifact is recorded separately from a removed one;
a different inode, nonregular path or unbound identity is refused. It never
recursively erases unexpected directory entries. The runtime directory's inode
is pinned at creation and checked before attempting its removal. Initial
directory-identity acquisition failure is also caught and reported as unbound;
the directory is not deleted on an unestablished ownership assumption.

The identity fd is held until the path is successfully removed or observed
absent. It is then closed at most once. A close error remains explicitly
uncertain; the fd number is never retried. Once path release has been observed,
later pathname recreation cannot restore deletion authority, even if the new
path happens to reuse the old inode number. `retry_cleanup()` refuses that new
path. An uncertain native release still blocks deletion of an existing artifact;
if a caller has already removed that path, the identity pin can be released
independently while the native uncertainty remains recorded.

This is a private in-process directory protocol, not a filesystem transaction
against a hostile host that can mutate arbitrary Python state or race every
path operation. The host, OS, loader and compiler remain trusted components.

## Capacity, retry and snapshots

Both live generations and incomplete retirements count against
`max_live_generations`. Repeated failed cleanup cannot create an unbounded
internal pending queue while admitting more artifacts. The retained event
history is limited to 128 entries; counters and the bounded current pending set
remain available even after older history entries are evicted.

An uncertain artifact-identity close keeps its generation in that same pending
capacity. The runtime's one directory pin is separately reported as pending
after close if it is still held or its release is uncertain. Per runtime,
generation capacity bounds the owned artifact/memfd handles to at most twice
`max_live_generations`, plus the one directory identity fd. This count does not
include loader/host-owned descriptors or establish a process-wide resource cap.

`runtime.retry_cleanup()` retries only identity-checked owned-file/directory
cleanup after successful native release. It never closes a loader handle or fd
again, and it never deletes current-generation files to make room. It may close
a still-held identity fd for the first time after observing its path absent. If an
unexpected file is blocking directory removal, the caller must resolve that
file according to its ownership before retrying.

`runtime.snapshot()["cleanup"]` includes pending retirement records, recent
attempts, the last directory-removal result and a fresh directory observation.
`owned_native_release_complete` requires the runtime to be closed, every live
lease/generation to have finished, and no uncertain native release.
`owned_identity_release_complete` separately requires all owned identity fds to
have completed release. `pending_identity_releases` and `pending_resource_count`
include unresolved pins, including the runtime directory.
`observed_closed_and_directory_absent` additionally requires both release
conditions, no pending retirement and an absent path at that observation. It is explicitly not a
permanent filesystem absence guarantee. A later external recreation cannot be
inferred from, or retroactively explained by, an earlier successful removal.

If construction fails after obtaining a directory path, its original exception
is preserved and receives the bounded `hia_cleanup` diagnostic snapshot when
possible. There is no replacement successful runtime object or implicit
recovery from native corruption/asynchronous interruption.

## Actual negative controls

The native regression tests execute real sealed generations and cover delayed
lease release; file deletion errors during successful publication; capacity
exhaustion by pending cleanup; retry without second native release; a real fd
close followed by descriptor reuse and an injected error; a loader-release
error that still closes the memfd; replaced files and directories; unexpected
directory entries; cancelled prepared candidates; preparation and construction
failures; detached snapshots; and initial directory-identity failure.
They also cover actual unlink/recreate and rmdir/recreate with the original
inode held open, artifact/directory pin acquisition failures, validation failure
after fd acquisition, an identity close followed by actual descriptor reuse and
an injected error, capacity charged for uncertain artifact pins, and recreated
paths after both successful and uncertain identity close.

For injected loader errors, only the test fixture knows whether the real
operation was called. Its explicit fixture cleanup is not a production retry
policy. A runtime report intentionally continues to say unknown in those
cases. Successful standalone multiversion and background qualifiers now sample
after close and require the owned directory to be observed absent before the
outer temporary-directory helper can remove anything.

```sh
python -m unittest tests.test_hia_native_retirement -v
python tools/qualify_hia_multiversion.py --clang /path/to/clang --output /path/to/new/report.json
```

These observations do not reclassify the eight historical empty directories
from the separate `01310b2` experiment. Their original missing errno/post-close
observations remain missing, and their cause remains undetermined.
