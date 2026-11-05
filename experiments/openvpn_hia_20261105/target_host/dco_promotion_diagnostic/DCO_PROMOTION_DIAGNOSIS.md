# DCO promotion delay in the failed #716 target

**Diagnostic only. Draft / HOLD / DENY_ALL. This does not repair or qualify the target.**

## Result

The common-profile failures are not failed TLS handshakes. The fixed C-DCO
server continues sending with the retiring data key until the following
renegotiation. The userspace C and HIA clients have already discarded that key
and reject one packet at each of rekeys 2 and 3. TLS and new-key installation
then complete milliseconds later. Both clients exhibit the same ordering.

The official OpenVPN source has a key-selection deadline that is absent from
the TLS scheduler's final wakeup calculation. That is a strongly supported
mechanism for the observed delay, not yet an instrumented full-event-loop
causality proof. The source-derived offline counterexample below demonstrates
the missing deadline under explicit mock state, not a successful target repair.

## Preserved original evidence

- [Failed run #42033735657](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42033735657),
  [artifact #13448779084](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42033735657/artifacts/13448779084).
- Hepta HEAD `1a9deb8ea58b9091e7b9179cae87d9f93eef4c35`, tree
  `02dd0a4b2752d3da2cea356cf8e6d0380ba58007`.
- Archive SHA-256:
  `0c4121ab9ff0467f67986a89aeb858345a2f0edbda7e0d26a323ab27234a43ba`.
- `dco-promotion-evidence.json` preserves four original failed case verdicts,
  original counters, eight full endpoint-log hashes, and 145 exact numbered
  excerpts. It does not rewrite or reclassify the receipts.

In `common-c-user`, all times on 2026-11-05 UTC:

1. Server line 385: at **19:54:23.036251**, kid1 is installed in DCO slot 1.
2. Client line 2256: at **19:54:33.032924**, the next soft reset starts.
3. Client lines 2259–2260: a kid0 data packet arrives at **.033341** and is
   rejected at **.033353**. Known usable key is kid1; kid2 is in `S_PRE_START`.
4. Server line 393: kid2 reset arrives at **.033418**.
5. Server lines 394–395: kid1 promotion and `dco_swap_keys` occur at
   **.033480 / .033485**, after the client's rejection.
6. Client lines 2280–2282: TLS and outgoing/incoming cipher installation
   complete at **.036160 / .036183 / .036191**.

At the third reset the same sequence repeats with rejected kid1 and new kid3.
`common-hia-user` reproduces this with rejected kid0 at **19:55:05.023206**,
then the fixed C-DCO server's swap at **.023344**. This is not specific to the
HIA packet-ID replacement.

The original observer reports client/server completed-rekey counts of **1/0**
for each userspace common arm and **1/1** for `common-c-dco`; all remain failed.
The latest #726/#727 observer corrects other passive-reset accounting but does
not fix this delayed encryption-key promotion. In this #716 archive,
`epoch-hia-c` has three TLS/key installations and no out-of-sync errors, while
its original receipt counts **1/3** and fails the rekey deadline.

Ten out-of-sync messages occur across five endpoint logs. Four are the common
clients' events above. The other six are in three epoch servers after deliberate
old-ciphertext injection; they must not be mistaken for this common-profile
promotion delay. Their original rejection evidence is unchanged.

## Source mechanism and boundaries

Official OpenVPN 2.7.8 is pinned to commit
`dc1f569087135894ac2703aeabd7a960ee9452d4`. Reads at both that commit and tag
`v2.7.8` returned identical Git blobs:

- `src/openvpn/ssl.c`: `a2eee6a72c59b658aaa0308ebc8f2983efac1ffe`.
- `src/openvpn/dco.c`: `88b18386fd3ec1b652c108448804a27a3306997a`.
- `src/openvpn/forward.c`: `c1330b4a8dd163e378ed816a5cd54ec08a5dd08b`.

Relevant exact source:

- [Authentication expiry](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L2446-L2476):
  `min(handshake_window, renegotiate_seconds / 2)`, hence 5 seconds for the
  observed 60-second handshake and 10-second renegotiation settings.
- [Key selection](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L4050-L4074):
  chooses a generated authenticated key according to that expiry.
- [TLS final wakeup calculation](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L3168-L3189):
  considers reliable-send, negotiation, and next renegotiation deadlines, but
  not the key-selection expiry. Key retirement is considered separately.
- [DCO promotion](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/dco.c#L133-L220):
  swaps only when invoked and the selected key is installed as secondary.
- [Caller](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/forward.c#L178-L236)
  explicitly notes this hidden time-based state transition and checks DCO
  status, but does not itself add its expiry as a wakeup.
- [Soft reset](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L1812-L1823)
  frees the preceding lame-duck key before moving the current primary, explaining
  why the userspace client no longer accepts kid0 at rekey2.

The full runtime has additional event sources and timers. A selective mock
cannot establish their entire behavior or determine whether another defect
contributes to the observed delay.

## Repeatable offline checks

From this directory, using the original downloaded artifact and the official
`src/openvpn/ssl.c` at the pinned commit:

```sh
python -B verify_dco_promotion_evidence.py /path/to/hepta-716-13448779084.zip
python -B reproduce_dco_promotion_schedule.py /path/to/openvpn/src/openvpn/ssl.c
python -B review_dco_promotion_states.py /path/to/openvpn/src/openvpn/ssl.c
```

The evidence check reads the ZIP as data only. It verifies the original
source/tree, receipt/log hashes, original verdicts/counters, exact excerpt line
numbers, and whole-archive endpoint out-of-sync counts.

The scheduler check first requires source SHA-256
`169e4d6ac5cacbb9beac51062e1f1a2d3f211cce3fd6e51badc3ab41d5ee9f03`. It extracts
three pure functions and the final scheduler fragment unchanged, supplies
explicit mock state, and compiles only that bounded harness with installed `cc`.
It does not compile or run the OpenVPN application, TLS, DCO, or archive binaries.

With old key mature, new key installed at t=100 and eligible at t=105, the
original fragment schedules t=110 while the selector changes at t=105. An
isolated candidate policy schedules t=105. **24 assertions** cover those bounds,
no secondary, no authenticated key, unusable new key, already-expired deadline,
earlier reliable/negotiation timers, and fallback selection where a later scan
key becomes eligible first. Passed with GCC 14.2.0 and
`-std=c11 -Wall -Wextra -Werror -O2`. A separately authored check enumerates
343 three-key mock states and compares the candidate wakeup with the earliest
actual selection change in those finite states; all passed.

The candidate policy exists only inside the mock harness. It is not an applied
upstream patch, and these assertions do not prove absence of full-event-loop
spinning, correct kernel transitions, or preserved authentication semantics.

## What remains open

Do not suppress the TLS-error rejection, count failed attempts as clean rekeys,
change the original verdict, or silently patch the frozen official 545-file
OpenVPN source baseline. A separately identified source variant would need a
reviewed event-loop change, full upstream tests, appropriate C/HIA comparison
design, and a fresh authorized target execution. None happened here.

No production source, existing workflow, benchmark plan, target build, or
acceptance gate changes in this diagnostic. A separate read-only CI workflow
runs only the source-derived mock check with the hash-pinned official source.
It does not fetch or execute the original target artifact; that archive check
was performed locally and independently. No target dispatch, merge, deployment,
or release qualification. Original target failure, replay/reconnect gaps, incomplete
performance inventory, and all HIA P0–P7 blockers remain open.
