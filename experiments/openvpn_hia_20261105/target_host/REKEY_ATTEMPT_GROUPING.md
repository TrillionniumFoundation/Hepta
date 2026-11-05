# Preserve rekey attempt evidence across reset responses (offline only; HOLD)

This narrow follow-up stacks on Draft #726, exact
`614bef978774d95cfe65616976aa12b86152a817`. It does not replace that PR's ownership
of passive-rekey observation. Its raw `soft_resets` / `peer_soft_resets` counters,
same-epoch gate, completion checks and unrelated Netlink work remain unchanged.

## Two source-exact counterexamples

#726 makes every incoming reset packet a separate completion-attempt boundary.
That can discard an error or split the TLS/key evidence within one attempt:

| Log sequence | #726 completed count | Required count |
| --- | ---: | ---: |
| Local reset, TLS Error, inbound response, TLS, outgoing key, incoming key | 1 | 0 |
| Inbound reset, TLS, same-ID reset, outgoing key, same-ID reset, incoming key | 0 | 1 |

The raw local/peer reset counters stay **1/1** and **0/3**, respectively. Those
counters describe log records, whereas `completed_rekeys` describes the grouped
attempts with the existing required TLS/key evidence. These are synthetic parser
counterexamples, not claims that the target emitted these exact sequences.

The correction retains every explicit local reset boundary, associates its first
incoming response with that attempt, and keeps consecutive same-key-ID reset
packets in one attempt. A changed control key ID starts another attempt; session
boundaries clear tracking. Valid incoming UDPv4/UDPv6 READ/from packet records are
used for this grouping, never outgoing or malformed packet-name mentions. The
existing raw counters remain unchanged even for rejected malformed candidates.
No TLS/key/failure ordering requirement is weakened. In particular, an error
before an incoming response remains in the completion scan.

Deduplication is consecutive, not a global set, so IDs can wrap. It does not claim
to correlate arbitrary interleaved delayed old-ID packets. TLS/key association
retains the existing positional model, not cryptographic proof of the key ID.

## Existing real failure retained

[Failed run 42014583779](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42014583779)
used original #695 source `2f0646b9719ef0b175118b00da9c786e5707d5cf`.
[Artifact 13440824546](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42014583779/artifacts/13440824546)
has ZIP SHA-256 `3ae660728a3b537b23b315a23a0e3f11ec346cb6d3f8202169478f70422b37d6`.
Its `epoch-hia-c` client log SHA-256 is
`73043a3479d4ef9aa03291c4208a7fcd979cdd1c0e9ca5bee57799aa4e05be47`.

The regression retains a twelve-line verbatim projection of that client log:
reset/TLS/outgoing/incoming lines **1258/1282/1283/1284**,
**2302/2326/2327/2328**, **3349/3373/3374/3375**. Original observation was 0;
#726 and this follow-up both recognize 3. This is not a new protocol success.
The original timeout receipt remains failed; later unexecuted replay/reconnect
gates cannot be inferred from reparsed logs. All 130 original endpoint logs were
reparsed read-only; this follow-up preserves #726's completed counts on all of them.

Continuity still records 701 sent/received of 800 planned. The 99 missing planned
packets are not relabelled as 99 packets lost after sending. Existing Netlink,
profile/performance, continuity and production gates remain open. No original
receipt/log is changed and no real target workflow is dispatched or modified.

## Offline validation

From this directory:

```sh
python -B -m unittest -v test_rekey_attempt_grouping.py test_run_matrix_rekey.py test_matrix_evidence.py
```

- New 12-method suite against exact #726 source: RED, 4 failures.
- Follow-up: 29/29 pass (12 new, #726's unchanged 6, unchanged 11 controller tests).
- Independent review reproduces both counterexamples and checks grouped results,
  raw counters, fixture provenance and unchanged completion/failure/session checks.
- The existing exact-head offline workflow also runs the new grouping suite.

These finite checks qualify only the observer correction. No new target TUN/DCO,
throughput, release or production qualification is claimed. Keep Draft/HOLD.
