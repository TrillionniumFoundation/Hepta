# Native Worker state under systemd DynamicUser

## Production behavior and scope

The optional administrator-owned `native_worker` Jobctl profile admits one
pinned native Worker executable and maps one persistent private state directory
into each of its systemd jobs. Ordinary START and PTY requests retain their
previous domain. The Worker, Store, capsule, journal, MCP and Jobctl continue to
execute native HIA products. This change adds no Python production fallback,
new HIA instruction, caller-selected systemd property, writable shared group
state, fixed shared runtime UID or wider sandbox.

This source change has development component and actual systemd qualification.
Those reports distinguish their current control image from the unchanged global
supervisor. They do not substitute for the final integrated source cold build,
whole package, installed Worker binding, adoption or rollback gates.

## Authenticated profile

A root-owned administrator policy can include:

```json
{
  "native_worker": {
    "executable": "/var/lib/example-release/hia-agent-worker",
    "sha256": "<physical canonical ELF SHA256>",
    "principal_uid": 1000,
    "state_identity": "<64 lowercase hexadecimal configuration identity>"
  }
}
```

The native control selects this profile only for the exact executable. Its
actual process environment must contain a unique canonical `SUDO_UID` matching
the configured principal; a missing value is valid only for principal zero.
The JSON request's workload environment cannot supply that authority.

The native policy walks the executable's absolute path from a held root
directory descriptor. Every ancestor must be a real root-owned directory,
traversable and without group or other write permission. Empty, dot and parent
components, symlinks and unsafe ancestors refuse. The final ELF must be a
root-owned, singly linked regular file with no write permission, readable and
executable, bounded in size and matching the complete canonical ELF geometry
and configured physical digest. Pre-read and post-read descriptor observations
must preserve identity, size and timestamps.

The persistent domain is:

```text
SHA256(
    "HIAWS001"
    || little_endian_u64(workspace_byte_length) || canonical_workspace_bytes
    || little_endian_u64(principal_uid)
    || raw_32_bytes(state_identity)
)
```

The one accepted state argument is
`/var/lib/private/hepta-hia-worker-<domain>`. There must be exactly one
`--state-root` argument with this value. Changing the authenticated workspace,
principal or state identity changes the domain. The caller cannot name a host
state directory independently.

The selected systemd unit receives the existing per-job StateDirectory and the
derived Worker StateDirectory. Both retain mode 0700. A fixed explicit
`STATE_DIRECTORY=/var/lib/hepta-job-<job>` environment assignment preserves
the supervisor's original one-directory ABI; the Worker receives its separate
exact state path as an argument. All other original sandbox properties remain,
including DynamicUser, ProtectSystem, ProtectHome, PrivateTmp, PrivateDevices,
NoNewPrivileges and RestrictSUIDSGID.

On the qualified host the persistent backing inode is owned by UID 65534.
Each job's idmapped namespace sees that same inode owned by its own DynamicUser
UID. This preserves the original Worker and Store same-UID directory/file
requirements across jobs instead of making state group writable.

## Immutable code custody

The launcher retains its original same-UID release behavior. For a different
runtime UID, it additionally accepts a root-owned directory only when no write
bit is set. The complete capsule authority, role extents and physical role
digests remain mandatory.

The native Store loader retains its original private same-UID directory and
module cases. Its only new cross-UID cases are an exact root-owned 0555 code
directory and exact root-owned 0444 regular module file. Existing type, link
count, expected size, descriptor flags, complete module digest, repeated
descriptor/path metadata identity and sealed-image checks remain. The memfd
predicate is unchanged and still requires the calling UID, mode 0400, zero
links, exact size, read/write access and the expected seal set.

The loader keeps the same 29-function interface. Its native word filter moves
the existing three leaf patches by their observed function ordinals 19, 25 and
26; it preserves each replacement byte string. Those leaves are buffer-word
accessors, not the modified directory/file predicates. The other 24 unit
images, all four module images and the module manifest reproduce their
previous pins exactly.

## openat2 under the original sandbox

The real systemd sandbox returns ENOSYS for the Store's openat2 calls. The
transport first performs the original syscall and enters the compatibility
path only for exactly ENOSYS. EPERM, EACCES, EINVAL, ELOOP and other results
remain the original result. Qualification applies a second seccomp rule that
kills any attempted openat on those other errors, making accidental fallback
observable.

For the existing NO_MAGICLINKS/NO_SYMLINKS root-directory operation, the adapter
holds a directory descriptor while opening each subsequent component with
O_PATH and O_NOFOLLOW, checking its type and transferring custody before
closing the previous descriptor. It refuses parent components and bounds the
path and component lengths. It preserves each final operation's original
flags and mode.

The BENEATH compatibility domain is deliberately limited to one admitted
child component. Absolute, empty, dot, parent and multi-component child paths
refuse. The supported atomic operations are the original explicit O_NOFOLLOW
operation and exclusive O_CREAT|O_EXCL creation. The one original directory
shape without an explicit O_NOFOLLOW bit, flags 0x90000 and mode zero, first
captures the child with O_PATH|O_NOFOLLOW, rejects non-directory/symlink
objects, and reopens "." below that held descriptor with the original flags.
This preserves F_GETFL and follows the captured directory through a rename.
It does not emulate unrestricted multi-component BENEATH resolution.

The shared transport is mechanically embedded into both Store adapters.
Its native helper bytes are identical in both assembled adapters. The generator
rebinds complete packer literals, sizes and call geometry; existing owner call
holes and policy interfaces remain.

## Qualification

The durable operator evidence root used for this change is:

```text
/home/qian-qi/.local/state/hia-azi5-final-repair-20261124/system-jobctl-repair-v1
```

The reports retain all earlier natural failures and test-fixture corrections.

| Gate | Evidence directory | Scope |
| --- | --- | --- |
| 44 native profile cases | worker-managed-profile-admission-v1 | Complete control profile admission and rejection |
| 52 launcher cases | worker-root-release-custody-v1 | Four complete native policies at the release command boundary |
| 39 loader cases | store-loader-custody-v1 | Complete filtered f0 directory, module and unchanged memfd boundaries |
| 69 path cases | store-path-seccomp-races-v2 | Both emitted adapters, real seccomp errors, descriptor identities/flags and six controlled rename races |
| Native Store source build | store-path-native-build-v3 | 25 unit pins, four modules, manifest and full native packer placement |
| Full capsule/entry rebinding | worker-managed-rebound-v8 | All 168 physical roles reauthenticated by the real native authority |
| First actual isolated Worker | worker-managed-real-v6 | Real systemd, original sandbox, first Store creation, durable successful manifest response |
| Actual isolated MCP | worker-managed-isolated-mcp-v5 | Ten absent/null, identity, artifact, replay, Rust comparison and cancellation cases |
| Real failed publication and UNKNOWN | worker-managed-unknown-v1 and worker-managed-unknown-v2 | Real keyed request intent, publication fault, later UNKNOWN without re-execution |
| Concurrent Worker custody | worker-managed-concurrency-v6 | Different DynamicUser UIDs, same persistent inode, original root-lock collision and later replay |
| Original packer | worker-managed-original-packer-v1 | 76 original cases, all 20 current native owners |
| Original START/PTY | worker-managed-original-start-v1 | 41 original cases |
| Original diagnostics | worker-managed-original-diagnostics-v1 | 65 original exact stderr cases, including invalid UTF-8 and nine-MiB stderr |
| Original supervisor | worker-managed-original-supervisor-v1 | 54 original cases |
| Original supervisor faults | worker-managed-original-supervisor-faults-v1 | 52 original cases |
| Original real systemd | worker-managed-original-real-v1 | 13 original lifecycle cases |
| Original visibility refusal | worker-managed-original-visibility-v1 | Original Rust and current complete native image both refuse restricted group visibility |

The original 13-case driver runs unchanged with the current control image
privately bound to its fixed path. The system manager still starts the global
3a29 supervisor, whose supervisor component is unchanged. The separate
visibility gate executes the complete current image from a root-protected
qualification path. The scope record explicitly preserves this distinction.

The real MCP gate uses a private /etc and SSH fixture. Its command guard accepts
only `sudo -n /usr/local/libexec/hepta-runtime-jobctl`. The fixed path is
privately bound to the current development image; the global helper is
unchanged. Missing and null native_jobs both submit or replay genuine
isolated jobs. Frozen Rust observes the same jobs and byte-identical responses.
MCP cancellation remains error -32800 and preserves published durable jobs;
a separate live Jobctl cancellation produces its own confirmed terminal.

The publication-fault fixture places one symlink at a unique new content
address in its own state, after initialization. A real native keyed request
claims intent and fails publication. After removing that one injected fault,
subsequent jobs return E_HIA_REQUEST_UNKNOWN with observe_original and never
recreate the content. The first run's last replay overlapped an independent
external lock fixture and naturally failed; that failure remains. Two later
isolated replays preserve the same UNKNOWN response. No journal row is
fabricated, and no failed report is rewritten.

The Worker itself already takes an exclusive nonblocking lock on the state
root before entering Store. The concurrency gate therefore expects a second
overlapping Worker to refuse at that original lock. It does not require two
Store owners to enter simultaneously or change the original 9-second Store
LOCK_NB retry deadline. The first Worker must complete, and a later third job
must replay its original response.

## Product identities in this component qualification

| Product | SHA256 | Bytes |
| --- | --- | ---: |
| Native Jobctl | 980f14a6322b0632710c68241657bc3cb1c4087541a9f745974b002c760c34c1 | 3674042 |
| Full launcher | 4f9f242d77348761c847d57bdc6f2e59f31b08653e4311305b888c0e455ea6d6 | 657823 |
| Store | d31daafb70913a7b1f9af64fc320e527fabcfbcf08ee3241bc92a62d0d91a58c | 1027127 |
| Store initializer | a7b9cbc1a85948f98344e38e13ef21315b25443f1dea7fb82cba38b27399fbc4 | 161429 |
| Rebound development Worker entry | 14b5fa4269a1b2966b915cecb3669215b58dfdeb1a8343215a464760310a63e3 | 726372 |

The installed Worker entry and capsule depend on the complete integrated
installation. Their final package identities must be regenerated from that
installation and compared by its own cold/source/receipt gates; the development
entry identity above is not a substitute for them.

## Reproduction entry points

The checked-in component qualifiers are
`qualify_hia_system_jobctl_worker_profile.py`,
`qualify_hia_worker_release_custody.py`,
`qualify_hia_store_loader_custody.py` and
`qualify_hia_store_path_transport.py` under tools. Their command-line arguments
require explicit component images/build receipts and fresh output directories.

The exact actual-systemd drivers and inputs are retained beside the evidence:
`worker-managed-real-v6.py`, `worker-managed-concurrency-v6.py`,
`worker-managed-unknown-v1.py`, `worker-managed-unknown-v2.py` and
`isolated-mcp-driver-v5.py`. The MCP driver is parameterized by source, service,
runtime, config, controller manifest, catalog, Jobctl digest and output. A
development-only private control binding is explicitly separate from its final
installed phase. These fixtures require their own private mount namespace;
they do not replace the machine's administrator policy.
