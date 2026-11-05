# Independent review of official application evidence

Reviewer: packet-kernel agent, 2026-11-05. This review read the application
runner, link recipe, diagnostic wrapper, pinned source, final link receipt and
existing logs. It did not rerun network sessions or change codec/adapter code.

**Conclusion:** the recorded evidence supports six official application crypto
self-tests and all nine bounded `--dev null` UDP peer scenarios. One rekey-count
bug was found and corrected by the application owner. The corrected observations
were independently recomputed from the same unchanged logs. No remaining blocker
was found for that limited claim. Real TUN forwarding, DCO execution and fair
tunnel performance remain unqualified.

## Source and execution binding

- Independently invoked `source_freeze()` against the actual pinned archive and
  source. All 545 regular release files match; archive digest and closure-manifest
  digest match the final recorded evidence.
- Verified all 99 recorded official object hashes, the official C executable,
  uninstrumented HIA executable and diagnostic HIA executable against
  `baseline-application/integration-final2/link.json`.
- Verified the linked HIA and adapter objects match the qualified final3 objects
  (also byte-identical to final4), and verified the trace source hash.
- `baseline_link.mk` reuses the official object/link variables and applies the
  four public `packet_id_*` wraps. Diagnostic builds additionally wrap each
  actual `ovpn_hia_packet_id_*` export. The trace calls the real HIA export before
  incrementing its counter and returns the original packed status. It is not a
  C replacement for the kernel.
- The trace logs counters and ABI failures only. The uninstrumented binary is
  retained separately; trace binaries are not suitable for performance claims.

## Self-test and peer acceptance

All six self-tests (C and HIA for AES-256-GCM, AES-256-CBC and
CHACHA20-POLY1305) exited zero, logged the explicit success marker and recorded
exactly packet lengths 1 through 1768. Every saved self-test and peer log hash
matches its receipt. Each HIA self-test recorded 1768 regular reads and 1768
regular writes, with zero ABI failures. These self-tests do not exercise epoch
entrypoints; the actual peer sessions do.

There are three endpoint combinations: C/C, C/HIA and HIA/C. Each has one
positive session and two negative sessions, giving nine scenarios. A positive
session requires live peers before cleanup, clean process exits, both peers'
initialization, successful rekey evidence, client initialization after the
explicit SIGUSR1 and no certificate-verification errors. Each negative scenario
requires the expected client's verification failure, no initialization on either
peer, and both processes surviving the probe. Every negative log contains the
specific wrong-name or wrong-trust-anchor rejection. A generic TLS error is not
accepted as authentication-failure evidence.

The HIA client positive session reports read/write/read_epoch/write_epoch counts
28/32/12/12; the HIA server reports 32/28/12/15. All ABI failure counts are zero.
The strengthened positive trace gate requires all four counters to be positive.
Negative scenarios legitimately have zero HIA codec calls because certificate
validation rejects the session before the data path; they do not independently
prove execution of the HIA codec.

The positives include transient stale-key TLS error lines during forced
reconnection in the C/C and HIA/C controls. These lines remain in the evidence;
subsequent initialization completes. The conclusion is successful reconnection,
not a claim that the entire trace is free of protocol errors.

## Rekey-count correction

The original observer stopped a rekey-search interval at another soft reset or
a local hard SIGUSR1. A server need not receive that signal when its client
restarts. In `control-c-hia-server.log`, the soft reset at line 316 was followed
by a new session's initial packet at line 318, then TLS/key initialization. The
original observer incorrectly counted this reconnect as a fifth rekey. C/C had
the same pattern.

The application owner added initial-packet, initial-session-promotion and
initialization-complete boundaries. I independently parsed all 18 peer logs with
that observer and compared every returned observation against
`baseline-application/integration-run-final2/baseline-reviewed-v2.json`.
The three positive combinations now each have **four completed rekeys on both
peers**, and all nine pass decisions remain true. Original logs and the original
`baseline.json` remain unchanged. The corrected observer hash is
`a0e7053d52005b3fc88c652904c7ff51992c33ba6168bd2c9e49c328ae72d949`.

The acceptance sequence requires soft reset, then a TLS control channel and
outgoing/incoming epoch-key initialization in the same session interval. The
upstream source emits the control-channel line when moving the TLS key state to
S_ACTIVE; the key lines follow actual cipher-context initialization. A soft
reset alone is not successful rekey evidence. This validates TLS/key setup in
the recorded peer experiment, not arbitrary future rekey implementations.

## Keys and scope

The runner writes generated test private keys only under the caller-selected
`--out/ephemeral-pki`, with directory mode 0700 and key modes 0600. The actual
recorded outputs are outside the repository. The repository evidence contains
no ephemeral-PKI directory, `.key`/`.p12`/`.pfx` files, private-key/static-key PEM
markers, cipher/HMAC key dumps or TLS key-log markers. JSON contains paths to
the temporary keys, not their contents. The runner is not a redacting exporter:
selecting a repository path for `--out` would also place that temporary PKI
there, so an entire raw output directory must not be copied into publication.
The currently archived log/JSON evidence omits that directory.

All peer invocations explicitly use `--dev null`, `--disable-dco`, no executable
ifconfig or routes, and loopback UDP. The host has no TUN device, no effective
CAP_NET_ADMIN and no visible DCO module. The receipts correctly leave
`real_tun_tunnel_passed`, `dco_runtime_passed` and
`fair_tunnel_performance_qualified` false. These conclusions must not be promoted
to the corresponding user acceptance gates.
