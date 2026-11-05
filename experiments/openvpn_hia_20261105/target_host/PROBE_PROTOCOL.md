# Target-host payload and encrypted-datagram evidence

These helpers are instrumentation for the target runner. They neither create a
VPN nor decide that a TUN/DCO gate passed. They are bounded, keep raw evidence,
and require fresh output directories. Their local validation is recorded under
`../review/target-probes-r1` and subsequent review directories. Local UDP tests
and offline frame/log-parser tests do not constitute a tunnel or DCO run.

## Payload protocol

`payload_probe.py` has two roles:

```bash
python3 payload_probe.py receiver --bind 10.77.0.1 --peer 10.77.0.2 \
  --port 23001 --count 100 --size 256 --run-id 12015e6d8ff641719f5743a7cd439e40 \
  --deadline 60 --out /absolute/fresh/receiver
python3 payload_probe.py sender --bind 10.77.0.2 --peer 10.77.0.1 \
  --port 23001 --count 100 --size 256 --run-id 12015e6d8ff641719f5743a7cd439e40 \
  --interval 0.01 --drain 2 --out /absolute/fresh/sender
```

The runner executes these commands in its already-created server/client network
namespaces. The above token is an example: generate a new 16-byte random token
for each logical stream. A receiver uses the same token as its sender. Reusing a
token with a restarted sender resetting its sequence to zero is a test error.
`ready.json` is atomically published only after binding the requested local IP.
The runner must wait for that receipt and confirm the process is still alive.

Every packet includes a magic/version, 128-bit run token, unsigned 64-bit sequence,
sender monotonic timestamp, declared packet count, declared payload size and a
deterministic body. Sizes/counts/tokens/sequence bounds/body bytes are checked.
Every valid datagram is echoed intact, including duplicates, so the instrument
never hides duplicate application delivery through deduplication. Receiver
`events.jsonl` is the authoritative application-delivery record; sender echoes
supply a second view and monotonic-clock RTTs. No receiver clock is used to claim
one-way delay. Each log flushes per event and is therefore unsuitable for a
throughput performance comparison.

The receiver remains active for its full declared deadline, even after all
expected packets arrived, to catch replayed late duplicates. It records unique,
duplicate, reordered, invalid, foreign-run and unexpected-peer packets, payload
bytes, missing sequence ranges, echo failures and every packet's timestamp/hash.
It accepts and echoes only packets matching the run contract. Its successful
receipt requires all expected unique sequences exactly once, no invalid packets
and no echo errors. Legitimate reordering is counted without failing delivery.
The sender requires all sends and all unique exact echoes; it also fails on
invalid or duplicate echoes. A sender's finite drain can end before a late
replay, which is why the longer-lived receiver remains authoritative.

An explicitly interrupted process writes partial evidence but cannot pass.
Sending to an absent path records every attempted send and its real socket
error. In a negative-authentication scenario, the expected observation is zero
valid receive payloads and a separately verified certificate rejection; the
receiver's ordinary all-packets-delivered `passed` flag is correctly false.

## Capturing and submitting an actual encrypted datagram

`encrypted_capture.py` runs only in a network namespace distinct from PID 1's,
on the dedicated veth with an assigned `192.0.2.1` or `192.0.2.2` source address.
It requires real AF_PACKET access. A missing permission or inaccessible namespace
identity is a failure, not a reason to substitute a socket/TUN simulation.

```bash
python3 encrypted_capture.py capture --interface ovpn-uc \
  --src 192.0.2.2 --dst 192.0.2.1 --dport 1194 \
  --min-data-bytes 284 --deadline 20 --out /absolute/fresh/capture
python3 encrypted_capture.py inject --interface ovpn-uc \
  --capture /absolute/fresh/capture/result.json --mode replay --count 1 \
  --out /absolute/fresh/same-key-replay
python3 encrypted_capture.py inject --interface ovpn-uc \
  --capture /absolute/fresh/capture/result.json --mode flip --count 1 \
  --out /absolute/fresh/same-key-flip
```

The capture filters outgoing, complete, unfragmented Ethernet/IPv4/UDP packets
for the declared endpoints/port and OpenVPN `P_DATA_V1`/`P_DATA_V2` opcodes 6/9.
An optional `--sport` restricts the observed client port. The minimum data length
must be at least 80 bytes to exclude small encrypted keepalives. With a 256-byte
probe, 284 excludes datagrams shorter than its inner IPv4/UDP payload. Keep other
application traffic out of the capture window. A length filter alone cannot
prove plaintext identity: correlate the controlled sender window, received
sequence receipts and the captured data length/time.

The capture saves the actual `frame.bin`, metadata, ciphertext SHA-256, endpoint,
key-id/opcode, namespace, ifindex and MAC identities. `replay` keeps the entire
UDP payload byte-for-byte identical. `flip` changes one bit of the last encrypted
datagram byte. Both recompute IPv4 and UDP checksums: Linux outgoing AF_PACKET
observations can contain incomplete checksum-offload fields, and blindly
reinjecting those could produce a checksum drop instead of a VPN rejection.
The helper checks the captured hash and original namespace/interface identity
before injection, and saves the exact submitted frame plus submission counts,
timestamps and hashes.

`status=injection_submitted` means the packet socket accepted the raw frame.
It does not prove that the peer received it, authenticated it, or rejected it.
Aggregate veth packet growth is insufficient when a continuous probe or VPN
keepalive can also increase those counters.

Before each injection, the runner now starts an exact incoming witness on the
server veth and waits for its atomic readiness receipt:

```bash
python3 encrypted_capture.py witness --interface ovpn-us \
  --src 192.0.2.2 --dst 192.0.2.1 --dport 1194 \
  --ciphertext-sha256 "$expected_ciphertext_sha256" --deadline 3 \
  --out /absolute/fresh/peer-ingress-witness
```

For replay, the expected digest is the original capture's `ciphertext_sha256`.
For a corrupted copy, compute the payload of `submitted_frame(frame, "flip")`
with this helper's pure functions and hash that exact payload before starting
the witness. The witness accepts only `PACKET_HOST` ingress for the declared
source/destination/port with that exact digest and valid, nonzero UDP and valid
IPv4 checksums. It saves the actual received frame and timestamp. An unmatched
background packet cannot satisfy the witness. A timeout or checksum failure
retains a failure receipt and cannot close peer-arrival evidence.

After submission require the witness's `status=captured`, `direction=incoming`,
`exact_ciphertext_match=true` and matching hash, plus continued old-receiver
liveness through a declared post-arrival observation interval. Its final
`finished_monotonic_ns` must be later than that interval. The witness proves
arrival of the exact valid outer frame at the peer veth; the actual VPN's
rejection and absence of duplicate/corrupt application delivery still require
independent payload/log observations and path evidence.

## Required phase evidence

1. Establish the real tunnel with the runner's exact interface/address/route and
   runtime DCO checks. Start the long-lived old-stream receiver and the capture
   before sending a finite old stream. Require successful original delivery.
2. With the old receiver still alive, submit exact replay and corrupted-copy
   actions. Preserve per-action pre/post counters and the peer logs. Require no
   duplicate or corrupt application delivery, then successful fresh valid data.
3. Wait for actual completed TLS/key-update events in the same live session;
   a soft-reset log alone is insufficient. Resubmit the same captured bytes,
   retaining the capture hash and the action's time. Confirm the old receiver
   is alive across the whole observation window and fresh traffic still works.
4. Force a documented reconnect and prove a new completed session. Submit the
   old frame again while the old receiver remains alive; also send a new-token
   stream that must deliver completely. Preserve any losses in a separately
   declared continuous stream through reconnect instead of deleting them.
5. Collect/finish the old receiver only after the final injection observation
   window. Its stopped/expired state cannot be used as evidence of no duplicates.

The after-rekey/reconnect corrupted-copy result may be an unknown key/peer or
replay rejection instead of an AEAD-tag rejection. Do not label every absence of
payload as a particular cryptographic error. A same-key corrupted datagram can
support an authentication-failure behavior claim when the actual receiving path
and its failure evidence are observed. A generic interface-drop counter alone
does not identify the rejection reason.

## DCO and shared wire profile

For OpenVPN 2.7.8, the Linux `dco_supports_epoch_data()` implementation returns
false. Fixing an official active-DCO peer while changing the tested endpoint
between C-off/HIA-off/C-DCO gives a shared non-epoch negotiated profile. Preserve
actual cipher/peer/protocol evidence in every run. The separate four off/off
endpoint combinations exercise the 2.7 epoch path. Do not infer an epoch profile
solely from matching config text.

Diagnostic `verb 6` logs identify an official `ovpn_handle_peer` peer ID followed
by four complete `dco_update_peer_stat` counters. The hardened `../tunnel_trial.py`
parser rejects partial groups, a peer replacement/reset, missing counters and
non-increasing before/after bytes. An active `ovpn` ifindex and growing RX/TX
bytes/packets are also required. Before/after queries used by no-trace performance
runs must come from the real kernel API, such as the separately reviewed
`dco_peer_stats.py`; cumulative OpenVPN status totals combine control and DCO
bytes and cannot substitute for kernel peer evidence.

The target's frozen `plan.json` defines the actual experiment budget and sample
grid. It must be reported as executed; this does not retroactively complete the
larger exploratory grid described in the manual acceptance document. All failures,
partial logs, failed samples and regressions remain in the public evidence.
