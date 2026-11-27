# Original Future qualification inputs

These are immutable test inputs for the original 27 Future behavior campaigns.
They are development evidence, outside the native source authority and release
runtime. Keeping them here removes the dependency on the old ROG custody
directory and a network fetch during qualification.

`fixtures.tar.gz` contains the original 39 source and test-only native inputs,
plus their unchanged custody ledger. It is exactly 56,998 bytes, with SHA-256
`2fe655ee40a1a85a6f117bb110c7a7e3b646ca258bbfcd1a2ff700867dfdedd1`.

`hia_background_optimizer.py.txt` is the original independent oracle recovered
from commit `2bd473f6ff51c2afac7b7bb009402368af2afdee`, path
`hepta/hia_background_optimizer.py`, Git blob
`808135dc72c5a3d7b24954fde3383d3ba2337c42`. Its 29,432 bytes have SHA-256
`d5a3c81eb0d7907fe872565b6ca6605708f8a6f13fd5a8d55788a9a13a095f7b`.
This recovery does not assert that the missing old custody path was found.

From a clean checkout, create a new output directory with:

```sh
python -I -B tools/materialize_hia_future_original_fixtures.py --output /tmp/hia-future-original-fixtures
```

The reader checks all archive bytes, members, original source hashes, and the
independent Git blob before writing. It refuses an existing output directory.
It produces 41 exact files and executes none of them. Use that directory as
`--original-fixtures` for `tools.qualify_hia_future_value_integration`, together
with `--original-root-prefix /home/qian-qi/.local/state/hia-native-final-custody-20261125`.
The qualifier still requires its original Python 3.14 oracle, exact compiler
identity, current pending native build, complete campaign inputs, and original
deadlines. Materializing these files grants no behavior or release qualification.
