# Full HIA Linux experiment preservation

The full experimental tree is preserved unchanged in `FULL_ROOT.tar.zst`.
`RESULT.json` identifies its exact compressed bytes and SHA-256, the independent
per-file inventory, and the independent streaming verification receipt. All
failed attempts remain alongside the final successful work. This is a source,
binary, and raw-evidence archive; it does not claim a self-contained host image.

The archive contains the original tree at
`tmp/hepta-hia-linux-full-20261106-bedaafad8a2f-r1/`. The three original/O3/Os HIA
program stores are retained separately, including their 3,029 compressed HIA
programs apiece, dependency sidecars, and index records. The replay build refers
to the original store. Build trees include generated source/data, objects,
images, configured modules, compiler ledgers, inventories, and complete logs.
The Linux source archive and extracted source, frozen compiler/guest/controller
source, native binaries, raw benchmark logs, native requests/responses,
calibration, preregistration, and evaluation are all retained.

## Verify without extracting or executing anything

1. Check the archive SHA-256 and size against `RESULT.json` using `sha256sum`
   and `stat`. Check `INVENTORY.jsonl.gz` the same way.
2. `STREAM_VERIFICATION.json` records the actual independent verification:
   each regular file was hashed from the decompressed archive and matched the
   source inventory. The exact member set, file type, permissions, numeric
   owner/group, size, nanosecond mtime, and symlink target also matched.
3. To repeat this verification, import the preserved `preserve_full_root.py`,
   read each JSON line from `INVENTORY.jsonl.gz`, build a mapping keyed by
   `member`, and call `verify_stream(archive_path, ["/usr/bin/zstd", "-d", "-c"],
   inventory, fresh_verification_directory)`. It never extracts or runs files.
   Use gzip in the decoder command if the actual archive suffix is `.tar.gz`.

## Restore into an isolated location

Create a new, empty restore directory with enough free space for the recorded
uncompressed bytes and filesystem overhead. Extract there, not over the live
original experiment:

```sh
zstd -dc FULL_ROOT.tar.zst | tar --extract --preserve-permissions --file=- --directory=/absolute/empty/restore
```

Numeric owners can be restored by an authorized administrator inside the
isolated environment. No archive member has a leading slash. Symlinks are
retained, and regular files that previously shared an inode are stored as
independent files; preservation creates no new source hardlinks. POSIX ACLs,
extended attributes, original inode numbers, and filesystem sparse allocation
are not claimed to be preserved by this content archive.

For rerunning the original commands, arrange the restored tree at its recorded
absolute path inside an isolated VM/container or mount namespace. The original
raw receipts are bound to those paths and remain untouched. Do not rewrite
receipts to pretend another path was used. A rerun must produce new output
directories and new receipts. Do not execute the benchmark PID1 ELF on the
host: the preserved collector boots it only inside QEMU after its guards.

## External restore dependencies

`DEPENDENCIES.json` lists the exact existing durable LLVM and Rust locations,
recorded compiler versions and hashes, the relevant package/version observations,
and original build receipts. LLVM runtime inputs already live under `/data`,
and the Rust toolchain lives under `/home`; they were not redundantly archived.
The installed QEMU/system build packages remain external. Their recorded recipe
and package versions are prerequisites for rebuilding; availability of identical
packages must be checked on a new host. The archive does not claim offline
self-containment.

`GIT_ALTERNATES.json` explicitly lists any archived Git object-store references.
The actual source files and source snapshots are preserved, but external Git
object databases are not silently copied. Restore or fetch the recorded public
Git objects if full Git history operations are required.

Keep all manifests, source of the preservation utility, command receipts,
inventory, and validation output beside the archive. A `.partial` file or a
`FAILURE.json` is not a verified successful archive; only the final atomic name
with `RESULT.json` status `PASS` is a successful preservation.
