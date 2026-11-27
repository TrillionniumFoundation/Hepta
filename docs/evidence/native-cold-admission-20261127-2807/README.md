# Native cold admission domain and identity repair

The component builder selected its admission rules from the submitted report schema. Since its current source reader already accepts the native source domain, a hosted-v1 report with eleven hosted checks could bind a native source map and pass the weaker path. The inverse report/domain pairing and unrecognized source roles were also admitted in the component controls.

The builder now validates the current source contract and uses its declared domain to choose admission. Native sources require the complete native-v2 report. The retained hosted domain keeps the existing v1 checks. Unknown domains fail through the existing source-domain reader.

The development native report reader also accepted all-zero SHA-256 identity strings. The HIA admission policy requires a nonzero lowercase 64-digit hexadecimal identity. The reader now follows that requirement for the independent seed, modified generations, and every phase journal and archive.

## Verification

The four added test methods initially exposed 129 failed assertions: two cross-domain cases, four unknown-domain cases, and 123 zero-identity positions across the seed, modified generations, and all sixty phases. Those original failure bytes are retained in `before.stderr.gz` with their decoded identity in `evidence.json`.

After the repair, the original six component methods plus four new methods, ten release-contract methods, and seven native-authority methods pass the repository strict unittest gate: 27 methods, zero failures, errors or skips. The gate was repeated after switching the isolated sparse checkout to the exact publication parent `8b088fc8b14c2d9dc5f2d1cf96910a1e84699d8f`; `after.stderr` is that complete terminal output. The three original modified-file blobs and native metadata are identical between the initial local base and this parent.

These are synthetic admission controls and source-contract tests. The actual sixty-phase cold, native compilation, installed execution, and full verified-kernel suite remain separate obligations. This change preserves the original 180+3-second cold limit, the sixty phases, all fourteen native checks, and the zero-skip requirement.
