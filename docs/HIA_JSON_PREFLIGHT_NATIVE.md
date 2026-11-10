# HIA JSON preflight candidate — not whole-stack closure

`examples/hia_bootstrap/json_preflight.hiaasm` implements an iterative JSON
syntax/budget scanner in ordinary HIA Core. The native selfhost compiler consumes
that source and emits the actual executable scanner. Python AST authoring is a
development aid, not a JSON parser invoked by the generated scanner.

## Implemented profile

- Linux x86-64 LP64 flat three-buffer ABI, u32 statuses:0accept,1syntax/Unicode,
  2node/depth budget,3unsupported buffers/profile,4duplicate decoded key.
- UTF-8 wire up to8MiB, node budget1..1048576, depth0..128. Root values have
  depth0; keys are not nodes. Fractions, exponents and nonfinite values refuse.
- Strict UTF-8 scalar decoding and JSON escapes, including exact UTF-16 surrogate
  pairs. Unescaped controls, overlong UTF-8, invalid scalars and isolated
  surrogates refuse. Duplicate keys compare decoded scalars, not raw spelling.
- Iterative container frames; object scope uses the exact opening-byte identity.
  Sibling and nested objects may reuse keys. A bounded open-addressed key table
  retains full decoded comparisons on collisions, not trusted hashes.
- Per-call scratch is private: at most16MiB key slots plus4256bytes stack/state.
  Slots are bounded by both node budget and wire length. The compiler's own
  source/output/workspace capacities and cold deadlines are unchanged; this is
  an application-input ABI, not an expansion of compiler admission.
- No JSON value graph is materialized. No native claim about the subsequent
  JSON value decoder, Core checker, module linker or Agent store is made.

## Explicit candidate selection

Build with an already qualified native compiler and its retained cold report:

```sh
python -B tools/build_hia_json_preflight.py \
  --compiler /path/to/B3.image.bin \
  --cold-report /path/to/cold.json \
  --output /new/private/candidate-directory
```

The tool retains input hashes, actual native compiler request/output and a
manifest. It neither activates a service nor advances a release lock. An
operator-owned manifest is a **trusted executable-code selection**, not a
sandbox for user-supplied binaries or an all-input equivalence certificate.
Only a matching source/image identity loads; memory transitions RW to RX.

To exercise the existing API in a disposable candidate process:

```sh
HEPTA_HIA_JSON_PREFLIGHT_MANIFEST=/new/private/candidate-directory/manifest.json \
  python -B -m unittest -v tests.test_hia_json_preflight
```

All existing callers of `preflight_hia_json` then use the HIA candidate within
its explicit profile. Unsupported budgets, over-profile wire lengths and
unencodable Python strings retain the original API/reference behavior. A bad
selected artifact fails closed; native errors never trigger silent fallback.
With no manifest selected, the default path is unchanged Python. Production
activation, package installation, portability and removal of the reference are
still OPEN. Finite differential tests do not prove worst-case cost or all-input
refinement; this candidate is not advertised as a hardened public code sandbox.

## Independent regression authorities

The old Python scanner remains an independent reference. A scalar VM wrapper
creates real owners/loans and observes HIA results before any B0 construction.
Native tests build freshB0→B1→B2 (matching fixed-point bytes) and use B2 to compile
this scanner. They retain all original regression tests and additionally check
2000random JSON trees with randomized budgets,2000mutated wires, all256single
bytes and quoted single bytes, Unicode boundaries/escaped equivalents, dense
unique keys, nested scopes, exact1Mnode/128depth/8MiBwire boundaries, scratch
refusals, concurrent private state, source/image tampering and existing API
selection. Source CI checks exact authoring regeneration; native CI executes the
native test class. No skip or profile refusal is counted as accepted syntax.
