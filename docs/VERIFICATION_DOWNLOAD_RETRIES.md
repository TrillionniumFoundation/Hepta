# Verification tool download retries

The QEMU bootstrap in CI run `40432186614`, job `121952281854`, failed when the
locked source returned HTTP 503. `tools/bootstrap_verification.py` now shares a
bounded network retry mechanism between the Lean and QEMU installers.

Each installation makes at most **four download attempts**, with **1, 2 and 4
seconds** between attempts. The existing 60-second `urlopen` timeout, locked
SHA-256 identities, selected Lean components and command-line options remain
unchanged. The explicit QEMU source repair below changes its download address
without changing the package or executable identity. JSON lines on stderr identify the component, attempt number,
maximum attempts, HTTP status when present, next delay and terminal exhaustion.
The existing successful JSON result stays on stdout.

Only failures originating in `urlopen` or response `read` qualify for retry:

- HTTP 408, 429, 500, 502, 503 and 504;
- structured `TimeoutError`, `ConnectionResetError` or `ConnectionAbortedError`,
  including an exception stored as a `URLError` reason;
- structured temporary DNS failure, `socket.gaierror` with `EAI_AGAIN`.

Certificate and other TLS errors, permanent DNS failure, other HTTP statuses,
unclassified text error messages, filesystem errors, extraction failures and
checksum mismatches terminate immediately. Retry exhaustion raises the original
network exception. Neither a mirror fallback nor a changed checksum is used.

Every retry starts a complete download in a new temporary directory. Lean's
archive digest and selected-component inventory are also recreated. Interrupted
response bytes and extracted files are discarded. Both installers retain their
existing checksum checks before publishing the staged tool directory with
`os.replace`; no failed attempt publishes a target.

## Focused verification

Run the tiny-payload regression tests without downloading or executing Lean,
QEMU or a compiler:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_bootstrap*.py' -v
```

The download tests simulate the HTTP transport and QEMU's `dpkg-deb` process,
while exercising actual response reads, temporary-directory cleanup, tar
extraction, SHA-256 checks and successful atomic publication. Cases cover 503
followed by a valid payload, the exact four-attempt bound, non-transient failures,
partial-response restart, and package/executable checksum rejection. The Lean
cases additionally use actual tiny zstd compression and decompression; they
require the installer's existing optional `zstandard` dependency and are skipped
when that dependency is absent. Full qualification CI already installs it.

These tests establish the bounded retry and publication behavior under the
simulated failures. They do not establish availability of the upstream download
service or completion of a subsequent hosted CI run.

## Explicit QEMU source repair

Both CI runs `40432186614` and `40433338725` failed at the same Ubuntu snapshot
URL. A subsequent single GET from the local host also returned HTTP 503. A
single GET from Ubuntu's official archive returned the complete 14,709,858-byte
package with the already locked SHA-256:

```text
5bb397f66063efa349f6fd5cb3b68cd96f29edd0994e4ba5115cf0859a716bf0
```

`formal/qemu-toolchain-lock.json` now names that verified archive URL. Its
package version, package digest and extracted executable digest remain
unchanged. This is an explicit lock-file source change; the installer still
uses one configured URL and does not search mirrors or substitute a different
package when verification fails. The prior snapshot URL, actual HTTP results,
fresh installation log and executable identity are retained in
`evidence/ci_prerequisites_20261026/qemu_source_repair/`.

The source probes establish availability from the observed host at that time.
They do not identify the snapshot service's root cause or establish that a
subsequent hosted CI run completed.
