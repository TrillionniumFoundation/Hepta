# Preserved generated fixture sources

Eight unique UTF-8 source files recover eleven source members from a historical Hepta verified-optimization artifact. They are generated synthetic resource-lifecycle fixtures and a bounded native ABI timing driver. `FIXTURE_SOURCE_MANIFEST.json` preserves every original member mapping, byte size, SHA-256 and Git blob identity.

The other 160 source members considered in this artifact already match the exact published Hepta source tree or members of the existing public recovered evidence archive. Their existing immutable locations are listed in the manifest. This source-only recovery excludes the original private archive, all native executables and private bridge implementations, logs, runtime reports and saved API responses.

## Source content

- One shared `cases.h` defines 1,121 synthetic resource cases and maps to four identical original locations.
- The normal generated C program, destructor-order negative control and leak negative control are kept as distinct exact bytes. The destructor-order version swaps the field cleanup accesses; the leak version replaces `free` with a no-op.
- The generated Hepta and Rust programs and C++ reference wrapper are retained unchanged.
- `driver.c` loads the caller-specified shared library, looks up the `work` symbol, applies the original input/call bounds and reports timing/checksum fields. The private shared libraries are not included.

## Verify and restore source paths

The source objects are stored once per Git blob. From this directory, verify and restore their original relative paths into a new directory:

```sh
python3 - <<'PYVERIFY'
import hashlib, json
from pathlib import Path, PurePosixPath
m = json.loads(Path('FIXTURE_SOURCE_MANIFEST.json').read_text())
out = Path('restored-fixture-source')
out.mkdir(exist_ok=False)
for row in m['files']:
    data = Path(row['path']).read_bytes()
    assert len(data) == row['bytes']
    assert hashlib.sha256(data).hexdigest() == row['sha256']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob_sha1']
    for name in row['original_members']:
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        target = out.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as f:
            f.write(data)
print('Restored', m['new_source_member_mappings'], 'source paths from', len(m['files']), 'objects')
PYVERIFY
```

To rebuild the historical experiment, also obtain required companion sources from the immutable locations recorded under `already_custodied_source_members`, use the original toolchain/profile, and preserve the separation between normal cases and intentional negative controls. The source manifest is a custody and input map, not a replacement for original execution reports. This publication does not rerun those experiments or establish production qualification.
