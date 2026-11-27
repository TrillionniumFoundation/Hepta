# Cell current-native integration evidence

The ordinary integration retains merge 29849495411d6e74da89f920f4e91ff1d92a71d8,
with parents 077c0b2e82edd7da50d84c11b55756beb61ee043 and the original Cell
8ba46fc7a112fc220cdcbbd48dc5d24fda76a738. All original six files and their
historical evidence remain unchanged. New source adds a strict current-cold
builder and an HIA-native object packer, using the existing native ELF linker.

## Actual observations

Four separate ROG attempts are retained in all-attempts.tar.gz, with every
member's size, SHA-256 and mode independently verified after transport to Mac.
No failed attempt was overwritten or treated as a pass.

1. The first attempt reached native compilation/packing/linking but ran no
   methods because the sparse source lacked its real pyproject.toml marker.
2. The marker-complete attempt exposed tmpfs per-user EDQUOT and a genuine
   missing alias refusal in the initial 48-byte native entry.
3. The 201-byte complete ABI entry passed all 28 then-current controls.
   The original f33 comparison still used unittest.discover's independent
   module name and consequently retained its tmpfs failures.
4. Explicit preparation of that original module and final artifact
   publication checks passed the current 29 methods / 204 subtests, original
   f33 21 methods / 175 subtests, and 12 host custody/directory controls.
   Original and current physical source snapshots matched at both ends.
   The complete remote sequence naturally returned 0 in 4.579003874910995 s.

An independent reviewer identified a concrete publication gap. A separate
actual old-publisher run compiled, packed and linked through five native
calls, then changed the shared image after the pipeline's last check.
The old development publisher returned successfully with an image hash that
no longer described the file. Its exact result and altered file are retained.
The new native test repeats real pipelines and separately changes the
captured compiler, each of three flat images, the object and the shared
image. Every changed artifact is rejected at publication.

## Scope

The development compiler was the physically verified original 04 B3:
641344 bytes, SHA-256
acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9.
This evidence does not transfer its old cold qualification to the changed
union source. The current strict builder must run against the final union's
fresh complete native-cold report and three physical generations.

The old source domain really uses the unchanged f33 compiler tree and
original 21-method assertion set. The current subclass preserves all 20
behavioral methods directly and replaces only the old compiler identity
method with current native custody. Cell execution, model-learning benefit,
production activation and whole-stack qualification remain unclaimed.

The user's original /dev/shm quota failure and denied private unshare probe
are preserved. No global mount or quota was changed. Test preparation only
mapped the original module's exact one TemporaryDirectory call to an owned
0700 ext4 directory, with both names and the source relation recorded.
Every original child deadline remains unchanged.

The local Git object cache has explicit server-provided shallow boundaries;
complete local history is not claimed. Both original merge parents are
retained as their real commits. The final source is intended for ordinary
merge and the final matching union freeze, not an ours-only history merge.
