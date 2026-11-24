# Native v26 controller installation

`hia-controller-install` assembles and qualifies the v26 MCP controller
from an already installed, pinned Store. Its policy and protocol probes are
HIA programs. The small syscall adapter translates their explicit syscall
plans and does not select products, interpret protocol responses, or choose
publication outcomes.

## Request and authority

Run the executable with no arguments and a fully sealed regular memfd on
standard input. The request is exactly 832 bytes, in little endian order.
All six capability descriptors must be distinct, open, and at least 3. The
caller must explicitly pass them through the subprocess runner.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HIACTI01` |
| 8 | Expected parent PID, or zero to accept the actual parent |
| 16 | Absolute CLOCK_MONOTONIC deadline in nanoseconds |
| 24 | Installed release directory FD |
| 32 | Controller package depot directory FD |
| 40 | Private, empty scratch directory FD |
| 48 | Sealed `hia-subprocess` executable FD |
| 56 | Sealed `hia-directory-package-build` executable FD |
| 64 | Sealed `hia-release` executable FD |
| 72 | Role count, exactly 19 |
| 80 | Six reserved 64-bit zero values |
| 128 | Three raw 32-byte tool SHA-256 values, in the FD order above |
| 224 | Nineteen raw 32-byte role SHA-256 values, in the order below |

The three directories must refer to different inodes. Depot and scratch must
be private directories owned by the caller's effective user. The release
members are captured through `openat2` without symlink traversal, checked
before and after capture, hashed, and sealed before they are executed.

The role order is bytewise filename order:

1. `HIA_AGENT_NATIVE_TOOL_CATALOG.json`
2. `hia-agent-job-terminal-receipt`
3. `hia-agent-mcp-catalog`
4. `hia-agent-mcp-input-schema`
5. `hia-agent-mcp-negotiation`
6. `hia-agent-mcp-proof-schema`
7. `hia-agent-mcp-reply`
8. `hia-agent-mcp-request`
9. `hia-agent-mcp-response-schema`
10. `hia-agent-mcp-terminal`
11. `hia-agent-mcp-uri`
12. `hia-job-cancel`
13. `hia-job-entry`
14. `hia-job-launch`
15. `hia-job-observation`
16. `hia-job-receipt`
17. `hia-job-submit`
18. `hia-job-supervisor`
19. `hia-worker-prepare`

Each original executable is bounded by 1 MiB; the catalog remains bounded by 64 MiB. The new entry and observation owners are bounded by 2 MiB, submit by 4 MiB, and cancel and launcher by 1 MiB. ELF roles require at least 64 bytes. These limits match the v26 runtime admission contract.

The output manifest schema is `hepta.hia.mcp.controller.v26`. The old 672-byte request and 14-role count are rejected. The Worker installation owner passes the sealed 96-byte controller receipt to configuration binder mode 3. That binder verifies the manifest and five native lifecycle images before adding the complete `native_jobs` selection to the chosen host.

## Qualification and publication

The HIA owner checks the protocol examples, terminal witnesses, owner
admission, cancellation and supervision decisions. It also executes real
writer probes, verifies persistent lock ownership and SCM_RIGHTS transfer,
and runs the native job supervisor with an actual sealed child. It checks
the resulting logs, terminal receipt, owner records, and terminal witness.

Ordinary child execution uses the pinned native subprocess owner. The
writer's special stdout authority ABI uses a separate HIA-selected syscall
plan because its stdout is a directory or lock capability. Both paths use
explicit descriptor inheritance and parent-death handling.

Only after these checks does the owner write the canonical controller
manifest, pack its 20 files, independently check the package digest, and
invoke the pinned directory installer with its FD authority interface.
Installation and subsequent verification must both succeed. It re-reads
the installed manifest before returning success.

Success produces exactly 96 bytes on stdout and no stderr:

```text
<8sQQ32s32sQ>
HIACTO01, 26, 20, package_sha256, manifest_sha256, 0
```

The package directory is named by its SHA-256 beneath the supplied depot.
The scratch directory is empty after success. A rejected attempt emits no
success receipt; any private scratch left by that attempt remains owned by
the outer installation transaction. The caller must not infer installation
success from a partial directory or a subprocess exit without the receipt.

## Source construction

The strict named source role is `hia-controller-install.hepta`, with
module `controller_install`. Its companions are
`controller_probe.hepta` and `sha256_stream.hepta`, in that canonical
object order. The packer is `controller_install_packer.hepta`. It accepts
`HIACTIK1`, three 64-bit image lengths, then the three images.

The installed Worker entry has a separate narrow pack product:
`hia-installed-worker-entry-pack.hepta` selects the existing
`installed_worker_entry_packer` module. The ordinary
`native_filter_packer` wraps that HIA packer as a byte filter. Construct
it through a single-source `HIASRC01` request after building the source
kit. The resulting executable takes no arguments and accepts the existing
`HIAWEP01` length-delimited code packet.

That filter preserves the original packer's byte and length checks. The
installation owner must still validate the exact captured policy,
configuration, three adapter call sites, and complete emitted extent.
Packing an image alone does not authorize its installation.

## Portable component qualification

The checked-in external qualification drivers accept explicit component and
reference paths, so their controls remain reproducible after temporary build
workspaces are removed. The supplied release must be independently qualified;
these component checks do not replace the complete Worker installation gate.

```sh
python3 -B tools/qualify_hia_controller_install.py --release RELEASE --runner RUNNER --component CONTROLLER_ELF --output NEW_EVIDENCE
python3 -B tools/qualify_hia_controller_install_refusals.py --release RELEASE --runner RUNNER --component CONTROLLER_ELF --output NEW_REFUSALS
python3 -B tools/qualify_hia_controller_install_sources.py --kit NATIVE_KIT --controller-reference CONTROLLER_ELF --worker-reference ORIGINAL_WORKER_ELF --output NEW_SOURCE_EVIDENCE
```

All accept `--source ROOT` when the source tree is separate from the script.
The source driver requires independent qualified controller and original public
Worker images for its exact-byte comparisons. It preserves the named-source
refusals, companion checks, order independence, raw pack refusals, and original
Worker round-trip checks. The installed controller driver retains the complete
v25 native probe sequence and checks that all five lifecycle owners reject an empty protocol. Their complete behavior campaigns remain separate release gates. The refusal driver retains all 13 original cases and adds legacy/count/extent request refusals plus the exact upper bound of every role.
