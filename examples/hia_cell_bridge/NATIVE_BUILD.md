# Cell continuation through the current native HIA toolchain

The retained six-file continuation component and its original 21-method f33
qualification remain byte-for-byte unchanged. They are a separate historical
component oracle. A current build uses the explicit entry below:

```sh
python -m tools.build_hia_cell_bridge \
  --cold-report /absolute/qualified-cold.json \
  --generation-index /absolute/qualified-cold.generations.json \
  --output /absolute/new-cell-build
```

This entry requires the matching current native cold campaign and all three
physical compiler generations. It captures the complete tracked Python
implementation domain under hepta/ and tools/, the source checkout marker,
the four wrapper/object ABI documents, and the three HIA inputs. Exact Git
commit, tree, blob bytes and file modes are checked, including imported module
names, aliases and namespace paths. A different checkout or an uncaptured
implementation module is refused.

The real pipeline compiles continuation.hepta, image_packer.hepta, and the
existing bootstrap ELF shared linker with the admitted compiler. The HIA
packer produces a closed x86-64 ET_REL object. The existing HIA linker produces
the ET_DYN image exporting cell_bridge_step. Host Python transports captured
bytes and validates receipts; it does not emit the product machine code or
ELF object. The Python reference object and hia_cell_bridge_entry.S are
independent qualification oracles only.

The entry preserves the original six-argument borrowed-buffer ABI and 65,792
byte extent bound. Each range checks extent, nonempty null pointers, and
address overflow in original order. All three nonempty range pairs reject
overlap before the continuation core executes. Empty ranges retain the
original semantics. Every compiler, flat image, object and shared image is
read again against its captured bytes at final publication; the published
receipt is also reread.

## Qualification domains

The current native gate is explicit:

```sh
python -m tools.qualify_hia_cell_bridge_native \
  --cold-report /absolute/qualified-cold.json \
  --generation-index /absolute/qualified-cold.generations.json \
  --output /absolute/new-cell-controls
```

It runs 29 fixed methods. Twenty original behavioral method objects are used
unchanged. The original compiler identity method is replaced only in the
current subclass with current cold/Git custody assertions. Eight additional
methods exercise the real HIA packer, real HIA linker, independent assembly,
extent/null/address/alias ordering, the maximum packet, and six actual late
artifact corruptions. The original class and its original f33 identity
assertion remain unchanged and must run in the independent f33 source domain.

The mutually exclusive --development-compiler option is for development
observations only. It never admits a cold campaign or asserts whole-stack,
Cell execution, learning benefit, or production activation qualification.
The initial integration evidence used a physically verified prior B3 only
for this explicit development mode; a new union source must pass the strict
current-cold gate before release qualification.

The fixed original suite uses /dev/shm in its single class setup directory
call. On a host whose per-user tmpfs quota is exhausted, the test-only
tests/hia_cell_test_directory_preparation.py wrapper can explicitly map that
one exact call to a separately created owned physical 0700 directory. It
records both paths, binds the complete original test file, checks the actual
unittest module name, retains all method bodies and child time limits, and
rereads source and directory identity at the end. It does not change global
tempfile behavior or mounts. Both the qualified tests/ module name and the
original unittest.discover module name are handled explicitly. This
preparation is recorded in the evidence and is never a native-cold claim.

The four complete initial attempts, including environmental failures and
the actual initial alias and late-publication defects, are preserved under
docs/evidence/cell-current-native-20261127-2ac5. The final development run
completed the current 29 controls, original 21 controls and 12 host custody
and directory controls with stable physical inputs and no skipped methods.
