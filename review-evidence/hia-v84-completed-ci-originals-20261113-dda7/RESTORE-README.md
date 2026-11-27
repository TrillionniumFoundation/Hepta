# Completed original evidence custody

Collector commit: f7fef2575fccdfe46915ceb2c7759fe078755f2d.
Actual collector run/job: 43354625082 / 131653590258, completed SUCCESS.
Final original manifest: caf91df852216fdcfe2cb35a4f58b44e1b51facf.

This is custody of five already completed original artifacts. It executed no
product compiler, test, or native program and changed no product/audit ref.
Original outcomes remain: a733 default PASS, a733 source PASS, a733 Evaluation
FAIL, a733 Artifact FAIL, and the separate 4925 diagnostic OBSERVATIONS_COMPLETE
with all three original methods FAIL. New main 51bc24b is a separate baseline.

All 99 UTF-8 chunk wrappers were fetched in full a second time and checked.
They reconstruct exactly five original inner ZIP byte streams totaling
50,039,157 bytes. All 129 collector objects were fully read back. Their original
14,539 outer and 1,354 inner ZIP members had been checked by the collector using
CRC, SHA256, Git object hash and original ZIP mode. The independent second
readback verifies wrappers, ordered raw chunks and entire inner ZIP identities.
The intermediate nontext MCP response and successful subsequent read-only
recovery are preserved in INDEPENDENT-READBACK.json.

The archive.blob fields are calculated Git object identities for raw ZIP bytes.
The raw ZIP binary blobs were not separately uploaded: the actual Git objects
are the UTF-8 wrappers. Original outer Actions ZIPs remain under the recorded
artifact IDs/digests/retention and any pre-outage local originals; this package
does not claim to reconstruct those outer ZIP byte streams.

## Offline restoration

After the parent mounts this recipe into an audit checkout:

    python3 restore_original_inners.py --root /absolute/audit-checkout --output /new/empty-output

The output directory must not exist. The helper validates the fixed complete
manifest, all referenced objects, ordered chunks, exact whole ZIP identity and
every inner ZIP member against INNER-MEMBERS.json. It never extracts or executes
project code. It does not access the network, create Git objects, or modify
existing archives. A failure leaves its new partial output for inspection.

The helper is AUTHORED_NOT_EXECUTED because the local executor is unavailable.
Its SHA is separately recorded; successful V8 reassembly is independently
documented and does not claim that this Python convenience helper ran.

## Scope still open

The underlying namespace/ledger budget failures remain unresolved. Current-cold
and whole-native are false. The prior 4925 four-profile and older 43332961445
Artifact/Source full raw persistence gaps are separate historical work; they are
not silently covered by this five-original collector. The new main original
Core artifact will use its own frozen custody input.
