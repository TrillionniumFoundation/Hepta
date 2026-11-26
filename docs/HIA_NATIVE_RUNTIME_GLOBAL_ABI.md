# Installed native resources and the Runtime root

This checkpoint closes the installed resource owner and its fixed binding into the sole native Runtime root. It also exercises the private GX3 Clang Runtime producer with those actual resources. The public ScalarMultiversionRuntime constructor, automatic Runtime-to-global borrow transfer, full BackgroundOptimizer binding, and whole release remain unfinished.

## Fixed installation authority

The resource policy admits only these catalog entries relative to its actual installed root image:

| Logical installation path | Bytes | SHA256 |
| --- | ---: | --- |
| components/hia-normalizer.bin | 5980873 | 84619bd15d8408f52c04519af11664cc4fa52cac352e7ad6680b6d50429123c6 |
| components/hia-proof.bin | 3486129 | 3fc158954dbecbde001d51065347a4e10e728f3c503816525da853babf2ffb3a |
| components/hia-builder.bin | 3819682 | 539ce9aab49b6f3e04517a511b08a6351421f86b978e03510ea3220e90f231e0 |
| source/examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat | 10100891 | 735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706 |

The native stable-file reader captures each file, hashes the bytes, writes a fresh sealed memfd, verifies seals and inode facts, rereads and rehashes that memfd, and applies tool mode0500 or data mode0400. The threshold has one actual read-only mapping. The source directory is held by a real directory FD. Public input cannot supply paths, hashes, descriptors, pointers, entries, or authority flags. Python author and qualification files are development provenance only.

The current native integer-to-string policy is4300 digits. A zero limit means disabled in the original contract; this checkpoint does not claim dynamic configuration of that setting.

## Resource entry

hia_native_runtime_resources uses the ordinary six-word ABI. Input is exactly128 bytes, output at least131072 bytes, work exactly8388608 bytes at one stable address. HIANGRQ1 operations are0 initialize,1 close,2 borrow,3 drop and4 retry. Only operation3 carries a cap at24/32/40. All other request fields are zero.

HIANGRR1 has status8, state16, returned capability24/32/40, pending80, known88, consumed96, retired104, detail112 and live count120. A successful borrow additionally transfers the three borrowed tool FDs at48/56/64, source FD72, threshold pointer128, length136, FD144, native nonce152 and digit policy160. Those descriptors and the mapping remain owned by the component; the consumer owns only its real borrow capability.

Live borrows prevent retirement. Borrow-node munmap failures preserve consumed-once facts in a native retry list. Threshold munmap must actually succeed before its FD can close. close_range failures retain exact owned descriptors; an ambiguous fallback close failure quarantines ownership. An ACK of retired is never inferred from a zero high-level status alone.

## Sole-root binding

hia_generation_runtime_global is a new fixed entry in the root DSO. Its work is the existing2048-byte root, output at least147456 bytes, and input exactly128 bytes. HIAGGIQ1 has the same0..4 operation numbers, with only drop3 carrying a capability. HIAGGIR1 returns the same facts as the resource reply.

Root words1088/1096 hold the actual native-owned resource mapping and extent. The initializer acquires one actual root active guard and captures all fixed code identities mechanically. It obtains a real resource borrow, duplicates each tool FD into the existing root bank at88/96/104, and only then marks that bank ready. The temporary initializer borrow is actually consumed. Real consumers subsequently obtain their own borrow capabilities.

The resource mapping's final1MiB is private native metadata; the first512 bytes at offset7340032 hold the global owner's persistent stage and custody facts. The resource policy does not use that region. The old root profiles and their layouts are unchanged.

Close refuses additional root active guards and actual resource borrows. It requires real resource-retired ACK, then actually closes the root bank descriptors and unmaps the resource context. Any failure retains the context and root guard until a trustworthy retry succeeds; unknown descriptor ownership remains quarantined.

## Registered Clang Runtime profile

The new private HIAMVHQ2 carrier family accepts creation with HIAMVEX5 and publication with HIAMVEX6. A native Runtime created by this profile is marked privately, and publication must use the matching actual clang Value capability. Existing HIAMVHQ1, HIAMVHA1 and HIAMVHB1 domains are retained.

The native registry, generation custody, loaded scalar calls, generation information and retirement all remain actual HIA execution. A Runtime Value strongly owns its clang Value as env, and Lease Values strongly own the Runtime. The test fixture supplies that real strong graph; this checkpoint does not substitute it for the missing public constructor.

The enclosing writer's original cancellation and admission deadline boundaries remain outside the Clang adapter. Clang keeps its original compiler discovery/version10-second and compilation60-second limits. The BC1 fields do not introduce extra cancellation polling, process killing or shorten those timeouts.

## Assembly and actual evidence

The root has45 logical roles. A378415-byte global capsule contains the three new policies and fixed bridges; it shares the root's existing stable-file and SHA bodies. Value115 is embedded exactly once. Text is13350287 bytes, below the original16MiB limit. All relevant policy and packer compilation budgets remain unchanged.

The qualification JSON records:
- actual native double compilation and independent object-byte comparison;
-14 resource lifecycle, mutation, concurrency and real kernel-failure groups;
-6 sole-root binding, sidecar coexistence and actual retirement-failure groups;
- actual installed resources through GX3 Clang creation, loaded scalar calls, twelve Info fields, publication, same-arena Future retention and final zero-FD retirement.

No host callback substitutes for a production role. Kernel fault tests reject actual syscalls and require real subsequent retry. Static malformed frames and copied/forked contexts preserve their no-write guards.

The new45-role image has not yet rerun the entire earlier14-group combined root suite, and the new public constructor has not run. Final source authority, release DAG, full public dispatch, BackgroundOptimizer kind6 binding and cleanup of historical repository versions remain explicitly false.
