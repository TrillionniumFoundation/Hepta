# Selected native source frontend bundle

This bundle selects the existing HIA lexical recognizer and numeric conversion,
type grammar, qualified-name/declaration-parameter grammar, effects/resources
clauses and expression grammar through one manifest. It is a bounded native
grammar bundle, not a completed replacement of the source parser or toolchain.
Declarations and statements still use Python, as do object materialization,
semantic checking, modules/packages and the production runtime and tool chain.

## Build and select

```sh
python -B -m tools.build_hia_source_frontend \
  --compiler /absolute/path/to/B3.bin \
  --cold-report /absolute/path/to/cold.json \
  --output /absolute/path/to/new-frontend-installation
export HEPTA_HIA_SOURCE_FRONTEND_MANIFEST=/absolute/path/to/new-frontend-installation/manifest.json
```

The build requires an actually completed matching source-only cold compiler.
A timed-out run with intermediate B3 bytes does not satisfy this condition.
The new destination is created exclusively. Names, clauses and expressions
are compiled with the supplied compiler; their lexer/type dependencies are
compiled and bound by the component builders. The root manifest is published
only after all components succeed and their identities agree. A failed build
cannot publish the final root manifest. The build receipt distinguishes a built
candidate from production activation or whole-stack qualification.

Every component also binds publication to the native invocation receipt:
compiler identity must equal the initially captured compiler bytes, input
identity must equal the captured HIA source, and output identity must equal the
actual image bytes. A compiler file temporarily replaced during compilation and
restored afterward cannot pass by relying on before/after path comparison.

The root schema is `hepta.hia.source-frontend-native.v1`. It binds the compiler
SHA-256 and the exact bytes of these seven manifests:

| Manifest path | Role |
| --- | --- |
| `names/manifest.json` | Qualified names and declaration parameters |
| `names/source-lexer/manifest.json` | Names scanner and native numeric support |
| `clauses/manifest.json` | Effects/resources clauses |
| `clauses/source-lexer/manifest.json` | Clause scanner and native numeric values |
| `expressions/manifest.json` | Complete current expression grammar |
| `expressions/source-types/manifest.json` | Expression/cast and declaration types |
| `expressions/source-types/source-lexer/manifest.json` | Expression/type lexer |

The loader rejects missing or additional root fields, duplicate JSON keys,
missing components, manifest drift, mixed compiler identities, unequal lexer
source/image identities and manifest or image paths that escape the bundle.
It captures and authenticates every component manifest and image once, checks
current source/schema/image identities, then maps those captured immutable
bytes. No manifest or image is reopened between admission and mapping. A
temporary manifest/image replacement followed by restoration therefore cannot
substitute another image. References between directories inside the bundle
remain valid. This custody process relies on trusted local native code and is
not an execution sandbox.

When the unified selector is present, simultaneous nonempty individual source
selectors are rejected. With individual grammar selection, every bundled lexer
and any explicitly selected lexer must have the same image identity. An invalid
explicit lexer is an error even when another component bundles a usable lexer;
it is never ignored. Broken selection does not fall back to reference grammar.

## Numeric and syntax behavior

The bundled lexer uses schema v3. Arbitrary integer magnitudes and decimal
binary64 conversion run in HIA. Binary64 conversion uses exact rational scaling
and nearest/ties-to-even rounding, including subnormals and overflow refusal;
the bridge constructs the result from bits without calling `float(text)`.
On a later lexical refusal, the native scanner retains the last completed float
range. At most one native prefix replay checks earlier numeric tokens before
reporting the later error. Thus `1e9999 @` retains the reference lexer's earlier
nonfinite-number diagnostic, while the failed native scan still publishes no
output bytes.

Each grammar component recognizes an exact source prefix and reports both
Unicode character and UTF-8 byte consumption. Expressions use an explicit
bounded Pratt stack and native type recognition. Generic-closing split events
preserve the distinction between `>>` as a shift and `>>`/`>=` as partial type
closes. Callers retain their original 96-level syntax nesting budget. See the
individual source lexer, types, names, clauses and expressions documents for
their complete ABI and finite bounds.

## Validation contract

`tests.test_hia_source_frontend_native` compiles real B1/B2 successors and all
five components. It compares sixteen combinations of individual grammar
selectors across twenty-one cases, then uses the unified bundle with all eight
reference name/type/clause/expression methods and the old lexer disabled.
The unified bundle also parses every actual `.hepta` file under `examples` and
`tests` with those reference methods disabled, against complete parser
observations recorded before B0. The cases cover cross-grammar delimiters, generic closes versus shifts,
remaining nesting depth, qualified names, function parameter bounds,
literal decoding and duplicate-diagnostic precedence. Adversarial controls
exercise conflicting selectors and invalid/mixed/corrupt/escaping manifests;
a failed cold receipt cannot publish a bundle. Separate custody-only tests use
tiny opaque image bytes without executing them to check external paths,
symlinks, valid internal cross-directory paths and temporary replacement of each
of the seven components between capture and mapping.

Component tests also execute independent VM arena oracles before B0, compare
native fixed-point builds and exercise actual repository sources. Their local
results do not replace fresh complete cold replay, full-repository regression,
remote exact-source checks, platform gates or clean-machine installation.
The production default and legacy implementations remain until all whole-stack
replacement and qualification obligations have passed.
