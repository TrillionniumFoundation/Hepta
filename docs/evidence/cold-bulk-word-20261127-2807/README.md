# Cold bulk word component qualification

The private cold driver previously performed eight independent byte stores for each put.
This change adds the explicit cold-bulk-word profile and uses a single native little-endian
64-bit store when the complete eight-byte range is valid. The invalid-range path retains the
original eight ordered byte stores, including partial writes before SIGILL. Existing word,
bulk, cold-bulk and cold-endian generated profiles remain byte identical.

## Source and execution identity

- Repository: TrillionniumFoundation/Hepta.
- Publication base: 6728cc419d88e56f8b802a0e258ce4848a4e28e9.
- Qualified source checkpoint: 9a7a84ad7d22f92d7680282459007a214089a4d2.
- Checkpoint tree: 28b83dc81567d9e42be588ac751bdd33d444e8d0.
- Execution host: ROG Linux x86-64, dedicated scope
  /home/qian-qi/hia-cold-bulk-word-20261127-2807.
- All retained qualification was rerun on ROG after loss of the transient cloud environment.
  No lost cloud logs or historical qualification receipts are reused.
- The two recovery failures are retained with their actual terminal causes: a full checkout
  timed out after 900 seconds, then sparse staging rejected two newly added paths. The
  subsequent guarded continuation successfully committed the sources, pushed the checkpoint,
  and completed every component and source-preparation command.

## Actual qualification

| Check | Result |
| --- | --- |
| Source/profile author tests | 8 passed |
| Native memory and admission cases | 646 passed |
| Original codec gates | 3250 passed |
| Malformed/overlap controls, complete 4 MiB workspace comparison | 2028 passed |
| Independent native preseed calls | 57 passed, 15 current sources |
| Frozen native source authority | 1285 sources |
| Original catalog and report checks | 60 phases, 479882 qualification nodes, 14 checks |
| Original wall and cleanup budgets | 180 seconds plus 3 seconds, unchanged |

The 646 native observations include complete u64 values, unaligned/end positions, partial-write
traps, atomic word-store traps, aliasing, both memmove directions, direction-flag checks,
interleaving, a real sparse mapping above 4 GiB, and unchanged admission refusals. B1 is
constructed from the original v1 seed. B2 and B3 are byte equal. The entire current private
driver emits identically through B1 and B2; the independent mechanical preseed packer also
matches the complete driver image.

Six alternating native trials of 200000 puts compare every complete result. The byte path
median was 3203063.5 ns and the word path median was 1326695.5 ns, a 2.414317 ratio.
This finite component measurement does not establish a whole-cold speedup or deadline result.

## Retained evidence

index.json records every compressed archive and every member by byte count and SHA256.
Archives contain the exact executed inputs, outputs, per-case observations, reports and
command logs. summary.json records the source pins, original seeds and report identities.
No Python source or evidence archive is added to the native source authority.

The source freeze is performed against the qualified source checkpoint before committing its
12 generated identity artifacts. Publication then repeats source preparation at the exact
new commit, requiring no changed source or development artifact, an identical native source
manifest and contract, and no tracked Git diff. Its durable publication receipt is under
finalize-v1/receipt.json in the dedicated scope and its report is freeze-clean-v1/report.json.
The PR description identifies that exact commit and report pin.

## Reproduction

From a checkout of this PR, use the unchanged fixed roots under
native/bootstrap/linux-x86_64/bin:

~~~sh
python3 -m unittest tests.test_hia_cold_bulk_word tests.test_hia_cold_codec_loops
python3 -m tools.qualify_hia_cold_bulk_word --bootstrap native/bootstrap/linux-x86_64/bin --output /absolute/new-native-output
python3 -m tools.qualify_hia_cold_codec_loops --bootstrap native/bootstrap/linux-x86_64/bin --output /absolute/new-codec-output --profile cold-bulk-word
~~~

For source preparation, create a root-receipt from the seven original bootstrap manifest
entries with exact name, path, byte count and SHA256. Run tools/hia_native_cold_preseed.py
with --source, a fresh --output, and that --root-receipt; then run
tools/hia_native_cold_prepare.py with the same source, its exact Git HEAD as --base,
the preseed directory, and a fresh output directory.

## Remaining gates

This evidence qualifies the explicit profile, driver store semantics, codec components and
source identity. It does not qualify a full cold run, whole native delivery, legacy removal,
or branch retirement. Those remain the integration owner's separately bound gates.
