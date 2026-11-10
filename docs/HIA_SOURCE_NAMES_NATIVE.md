# Native qualified names and declaration parameters

`examples/hia_bootstrap/source_names.hiaasm` implements the current source
parser's qualified-name, type-parameter and function-parameter-list grammars.
The recognizer is HIA. Python retains value construction, image custody, arena
validation, token synchronization and the surrounding declaration grammar.

## Grammar and representation

The same image has three modes:

| Mode | Existing parser entry | Native result |
| --- | --- | --- |
| 1 | `_path` | Qualified ASCII name parts and exact consumed prefix |
| 2 | `_type_params` | Ordered type parameter names |
| 3 | `_function_type_params` | Ordered type names, Copy/Owned bounds and lifetimes |

Mode 3 retains implicit `Copy`, interspersed lifetime parameters, and the
original duplicate-parameter behavior. Syntactic acceptance does not substitute
for subsequent semantic checks. The recognizer preserves partial `>>` and `>=`
generic closing tokens, exact Unicode character/UTF-8 byte cursors and the
original diagnostic positions and messages.

The three-buffer ABI is `f0(readbuf, mutbuf, mutbuf) -> u32`. Input is bounded
to 8 MiB, workspace is 320 bytes, and the caller sets mode at byte offset 224.
The arena contains a 64-byte header and 64-byte rows, at most 1,048,576 rows.
Rows contain source ranges and roles; bounds use a second range. Native
validation/counting completes before any output is published. The bridge starts
with 4 KiB and retries with the exact native-requested size when needed.
Refused syntax and insufficient output leave output bytes unchanged.

The bridge checks header fields, row order and roles, source range bounds,
ASCII identifiers, reserved words and the exact character cursor before
constructing strings, tuples and dictionaries. It synchronizes already-native
tokens with the native prefix, including split closing operators. It does not
make the grammar decision or silently select the reference parser on failure.

## Selection and build

Build using a matching compiler with completed source-only cold evidence:

```sh
python -B -m tools.build_hia_source_names \
  --compiler /absolute/path/to/B3.bin \
  --cold-report /absolute/path/to/cold.json \
  --output /absolute/path/to/new-name-installation
```

The builder compiles the source with that native compiler and installs the
actual HIA lexer under `source-lexer/manifest.json`. The name manifest schema
is `hepta.hia.source-names-native.v1`. Set
`HEPTA_HIA_SOURCE_NAMES_MANIFEST=/absolute/path/to/manifest.json` to select it,
or use the unified frontend bundle described in
[`HIA_SOURCE_FRONTEND_NATIVE.md`](HIA_SOURCE_FRONTEND_NATIVE.md).
Every explicitly selected image and manifest must remain valid. Selection does
not change the production worker or release lock.

## Independent controls and remaining work

The component tests execute four manually specified complete arena examples in
the independent Core VM before B0 exists, build actual B1/B2 successors, and
compare every native arena byte. They exercise complete current grammar,
truncation and deterministic random inputs, exact cursor and diagnostics,
2,048-parameter inputs, concurrent calls, poisoned guards, malformed arenas
and broken manifests. Whole-parser corpus tests enumerate every actual
`.hepta` file in `examples` and `tests`; they disable the old lexer and all
three reference name/parameter methods for the selected execution.

These controls cover this finite profile. They do not establish whole-language
refinement or qualify subsequent changed source. Declaration/statement parsing,
semantic checking, modules, runtime, build/release orchestration, and the full
toolchain remain separate closure obligations. The Python authoring generator
and object/loading bridge remain explicitly included in the source inventory.
