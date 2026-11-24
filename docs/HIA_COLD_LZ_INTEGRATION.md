# Lossless journal integration in native cold driver and archive

This change explicitly selects the qualified HIAQAZ02 codec in the native cold
driver and installs only the independent legacy/LZ decoder and forward-copy
helper in the native archive. The archive does not receive an encoder
dictionary or read the original raw chunk. The old HIAQAZ01 mode 0/1 domain
remains accepted. HIAQAZ02 adds mode 2 without changing the plan, process,
receipt, FD, publication or archive protocols.

The existing driver still independently decodes every encoded chunk and
compares every byte, accumulates the physical SHA while writing and verifies
the actual file SHA after fsync. The archive still performs complete logical
node validation, file custody checks, repeated hashes and actual readback.
No existing hash, cap, deadline, validation or evidence is removed.

## Qualified products

Both products use independently constructed HIA policy, native packer and the
qualified inline cold SHA companion. The original independent bulk seed is
used where the existing profile requires resource 10; the target self-host
compiler is not involved.

| Product | Bytes | SHA-256 |
| --- | ---: | --- |
| Native plan driver | 404644 | b188c2564f7910225bcb95fe13f529935b7294747f616bc02b61768b21c264bf |
| Native stopped-phase archive | 251467 | 5c41a2d23aec8e5c9b4ac031785fec5baac498becc9a95fc4230801611ff2862 |

The unchanged inline SHA companion is d22c50dca15cf0b530b02e3c9aac4f73ccf2dbf371fd3597b28081cf3d9f4c34.
Any later companion change requires its own qualification and rebind evidence.

All original 18 driver gates pass, including actual external journal corruption
which is rejected with status 74. All original 19 archive gates pass against
the original HIAQAZ01 fixture. The complete same 19 predicates also pass with
an AZ02 fixture containing all three modes. That fixture preserves the exact
logical journal and plan; its first chunk intentionally uses a valid LZ literal
to exercise mode 2. The logical-header corruption test mutates the logical
header inside that literal, instead of accidentally testing its token. The
plan-pin, receipt, node-count, directory, symlink, hardlink, hidden-name, mode
and all three actual concurrent-write refusals are unchanged.

The external QA journal reader accepts both chunk profiles and retains the
complete original node-record parser. It is the exact function used by the
successful 18-gate driver run, with separate old/new 64-node readback evidence.

## Complete live signed-reference phase

A fixed 15,953-node signed-reference plan, SHA-256
990108a82a248317688b7bcc8a570b17d92f0497a22f2326a82ce7e3ff56b47c,
was executed with the qualified independent bulk frontend/projector and full
independent HIA VM. All 152 original live references and source/diagnostic
assertions are inside that plan. It completed before any target compiler was
provided. The stopped, actual resulting phase was then archived by the new
native archive with its actual receipt and plan.

| Measurement | Result |
| --- | ---: |
| Actual native driver wall time | 21.623362326 s |
| Child executions | 796 |
| Sum of actual child elapsed times at HIASBR01 + 112 | 15.345267089 s |
| Complete logical journal | 79,587,788 bytes |
| Physical AZ02 journal | 28,515,061 bytes |
| Actual native archive wall time | 8.886778066 s |
| Complete archive | 28,515,301 bytes |

The two wall times are sampled immediately after the native child returns,
before external Python evidence decoding. The complete logical journal,
every node failure word, physical SHA, archive receipt SHA and actual
post-write bytes were independently checked. Mode 2 occurs in 18,636 chunks.

These component and single-phase results do not claim that the combined
60-phase, two-worker cold replay has met its original 180 + 3 second contract.
The combined master is a separate required gate.
