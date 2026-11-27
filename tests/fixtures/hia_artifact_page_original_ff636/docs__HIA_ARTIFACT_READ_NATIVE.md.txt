# Ordinary artifact-page ownership

`HEPTA_HIA_ARTIFACT_PAGE_MANIFEST` explicitly selects an HIAAPG02 bundle at the
ordinary `HIAAgentService._hia_read` entry. Its policy and bounded-wire images
are bound to the installed HIA source bytes. Selected admission errors do not
call the retained page owner. The complete original method remains separately
named `_reference_hia_read`; its AST is compared with the pinned original
fixture, with only that name changed.

The HIA continuation owns the original operation order: artifact lookup,
cursor presence and SQL lookup, exact artifact ID/SHA checks, offset and limit
handling, whole-artifact UTF-8 classification, page boundary trimming, base64,
three ordered wire invocations per budget attempt, the 230000-byte combined
wire limit, cursor canonical digest, insertion instruction and result graph.
It binds the SQL execute method before evaluating the original query arguments.
The insertion binding likewise precedes the final reference field reads.

The public product profile still admits artifacts up to 64 MiB and page limits
of 512 through 65536 bytes. Zero and smaller positive private limits, and every
signed SQLite integer offset, are included in differential controls. SQLite
NULL, REAL, TEXT and BLOB offsets execute the original arithmetic/slice
operation at the original point and preserve its interpreter exception. This
is not a claim that arbitrary replacement Store objects, oversized private
page limits or all Python extension objects have the same resource behavior.

The selected page uses an admitted HIA wire image. Each wire invocation first
observes the independent binary64 formatter selector, then the independent
wire selector, as the original `AgentStore.wire` does. An explicit wire
selection is re-admitted; without one, the page bundle's HIA wire is used.
The original content is not serialized or encoded by a Python page algorithm.
The virtual result nodes are authored by HIA and preserve the original
artifact object reference.

SQLite calls, transactions, locks and durability remain hosted. `AgentStore.get`,
its reference authority, stable file reads and metadata codecs retain their
independent selection boundaries. Interpreter object access, native executable
loading and foreign exception construction remain mechanical host effects.
There is no default selection change and no claim that the full AgentStore,
worker or service has been replaced. Arbitrary finalizer timing, interpreter
resource exhaustion and adversarial private-state mutation remain outside the
declared extension scope.

Each foreign effect permission is consumed before executing the effect. A
foreign exception, terminal result or exception after a native step closes the
session; stale SQL requests cannot be observed twice. The adapter preserves
the original exception and its chain instead of creating a replacement ACK.

## Builds and verification

`tools/build_hia_artifact_page.py --output NEW --compiler B3 --cold-report COLD`
requires the completed matching-source cold report before creating output.
It retains the two images, both manifests, the bundle and compilation receipts.
The explicit `--development` alternative is labelled development and cannot
establish a matching-source qualification.

`tests.test_hia_artifact_read_native` uses
`HEPTA_HIA_ARTIFACT_PAGE_COLD_REPORT` or the mutually exclusive
`HEPTA_HIA_ARTIFACT_PAGE_DEVELOPMENT_MANIFEST`. A new
`HEPTA_HIA_ARTIFACT_PAGE_FIXTURE_EVIDENCE` directory retains actual observations.
The suite includes a fresh execution of all 42 inherited page vectors, actual
SQLite binding/errors and close/reopen controls, one-shot protocol controls,
independent Core execution, source/image refusal, and a wheel child using
`-I -S -B`, empty PATH and no checkout import path.

`tools/qualify_hia_artifact_read_callers.py` selects the page for the original
five caller modules without changing their test IDs or budgets. It records
loaded/chosen/executed IDs, all five unittest anomaly categories, native entry
and return counts, actual tools exercised, forbidden-owner entries and source/
bundle identity stability. It requires a real native `hia_read` entry; it does
not pretend the other ten tools need the page owner. `--evidence-dir NEW` retains
the actual cold-built bundle under `NEW/page`. A development manifest requires
`--development` and is reported separately from cold qualification.

The earlier experimental 42-case run remains exactly five observed passes and
37 unknown cases after executor continuity loss. New runs have new identities
and do not relabel, resume or replace those observations. The original SQL
binding and corrupt-offset counterexamples are retained with the new source.
