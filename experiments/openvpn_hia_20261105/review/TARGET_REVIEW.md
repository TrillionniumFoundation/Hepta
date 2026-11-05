# Independent target-host acceptance review

## Concrete findings in the previous smoke runner

The preserved `tunnel_trial-v1.py.txt` allowed `dco_runtime_passed=true` after an
`ovpn` kind, a device-open log and positive iperf receiver bytes. It collected no
`ip -statistics` counters or official DCO peer-counter deltas. It queried a route
without the `from` source used by iperf `-B`, did not prove the requested source
belonged to the newly created interface, and did not reject a pre-existing
interface. Timeout exceptions could discard partial iperf stdout/stderr, and
OpenVPN cleanup status was absent. Its explicit false performance gate and the
historical preflight receipts remain preserved.

The revised v2 smoke runner requires an isolated network namespace, an interface
absent before OpenVPN launch, an exact device-open log, the expected negotiated
cipher, an assigned local VPN address, a source-specific route, and the same
ifindex/namespace before and after actual positive iperf payload delivery.
Both RX/TX bytes and packets must increase. A DCO trial additionally requires
fresh complete four-counter official netlink log groups for the same peer, no
peer replacement or counter reset in the measured interval, and positive deltas
in all four fields. Missing peer evidence cannot pass DCO. It records all direct
commands, stream-to-file partial output, real exit/timeout status and bounded
OpenVPN cleanup, and rejects changed binary/config identities.

This remains a diagnostic single-peer smoke check. `verb 6` is intentional for
counter evidence; it does not qualify no-trace timing, negative authentication,
replay, reconnect or rekey. The target matrix must supply those independent
scenarios. Config includes, certificates and dependencies are frozen by the
parent target-build/matrix receipt, not recursively discovered by this smoke
helper's top-level config hash.

The first local v2 preflight exposed a real `/proc/1/ns/net` PermissionError.
`target-probes-r1` preserves that traceback. The subsequent version records
unverifiable isolation as a blocker and saves a false-gate receipt; it never
bypasses the permission check. `target-probes-r2` records both blocked modes.

## Payload, replay and authentication gates

The new helpers and their contract are in `../target_host/PROBE_PROTOCOL.md`.
`payload_probe.py` records full finite sequence/body observations and never
silently deduplicates delivery. Its receiver must remain active throughout all
old-ciphertext injections. `encrypted_capture.py` records a real outgoing
OpenVPN UDP data frame, preserves its ciphertext for exact replay, repairs
outer checksums before submission, and can submit a one-bit corrupted copy.
Capture/submission alone is never a replay or authentication pass. The incoming
exact-hash witness added after this review closes the aggregate-veth-progress
ambiguity: the server must actually observe the injected ciphertext with valid
outer checksums, and the old receiver must remain alive beyond that observation.
Protocol checks must examine the newest session's lines, so old epoch evidence
cannot hide a reconnect that negotiated a different profile. Same-key actions
must also be bounded by actual no-reset/no-rekey observations, not timer guesses.

The target runner should require:

- Exclusive namespace/interface identities, source-specific routes and actual
  payload counts at both endpoints, with successful subsequent valid traffic.
- Explicit certificate-chain rejection for the negative client, no initialized
  client/VPN address, a live normal server, real attempted blocked sends and zero
  valid receive payloads. Give the untrusted client otherwise-valid clientAuth
  extensions so an unrelated purpose error does not masquerade as a trust test.
- A fresh token per logical stream. A continuous stream through forced reconnect
  preserves losses/errors; phase-specific fresh streams require full delivery.
- Before-injection proof that the captured old stream was delivered once; old
  receiver liveness across the injection and its post-action observation window.
- Actual completed TLS/key-update events in the same session before declaring
  a cross-rekey action. A soft-reset line, elapsed timer or a new-session initial
  key installation is insufficient.
- Distinct interpretation of same-key corruption and stale-key/peer rejection
  after rekey/reconnect. No payload delivery alone cannot identify a particular
  crypto failure reason. Netem and application-layer resend are not substitutes
  for an actual captured encrypted datagram.

The direct kernel-counter helper's UAPI field numbers match the frozen 2.7.8
header: VPN counters 16..19, link counters 20..23, IFINDEX 1, nested PEER 2 and
PEER_GET command 3. The helper now checks sender/sequence/family/cmd/version,
field widths, duplicate/missing attributes, truncated/interrupted dumps, and
records actual request/reply bytes. Preserve failures' wire journals too.
The target runtime must still execute and validate that API; parsing crafted
unit inputs does not establish kernel support or actual offload.

## Fair comparison limits

Linux OpenVPN 2.7.8 advertises no epoch data support when DCO is active, while
DCO-off peers can negotiate it. Fix an actually active official DCO peer for
C-off/HIA-off/C-DCO comparisons and retain negotiated profile evidence. Keep the
four DCO-off endpoint combinations as a separate epoch interoperability matrix.
Identical text configurations alone cannot close this fairness requirement.

The current target plan contains 54 cases and 216 five-second traffic workloads,
with 100 Mbit/s UDP offered load and local veth endpoints. This is a finite
hosted-VM experiment, not the full exploratory 60-second/multiple-rate/role-swap
grid in the manual document. All target results must identify that smaller
predeclared scope. At least 1,080 seconds are occupied by timed workloads before
connection, behavior, counters, cleanup and profiling overhead. A deadline
failure must remain visible rather than silently reducing the schedule.

The kernel microbenchmark review is separately recorded in `ABI_COST_REVIEW.md`
and `perf2-independent-sample-audit.json`. The read-only audit verified all 432
recorded batches and all declared six-arm orders without running another timing
experiment. It confirmed the retained long-read regressions. None of these
microbenchmarks replaces an actual full-process/kernel hotspot profile.

## Verification performed here

The local test suite uses actual loopback UDP processes to validate the payload
instrument, deterministic offline frame/checksum inputs to validate raw-packet
encoding, parser inputs to validate rejection of incomplete/mixed DCO evidence,
and a real timed-out child to prove stdout/stderr preservation. It launches no
fake OpenVPN, TUN stub or simulated DCO peer. Current-host capability/module/TUN
preflight and raw-capture restrictions remain failures; all tunnel/DCO acceptance
claims remain false until the real target host supplies its evidence.
