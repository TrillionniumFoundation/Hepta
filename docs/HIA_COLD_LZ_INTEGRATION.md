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

## Qualified word-SHA rebinding

The same driver and archive policies now also have a qualified binding to
cold_sha256_stream from the independent word-store seed profile. The source
exporter uses the same qualified SHA companion with its unchanged original
policy. Each policy source was compared byte for byte with commit
47d63cac219f882a1855e40ea4ba7fd2f00e3350; the driver and archive policy
machine-code images also remain byte-identical. Only the selected SHA
companion changes the resulting product image.

| Product | Bytes | SHA-256 |
| --- | ---: | --- |
| Native plan driver | 420883 | 7e07587fa736f86319b020376e174d4be318596210311657909694e97ef2ea55 |
| Native stopped-phase archive | 267706 | 83280e8bb92a964038d0adeebe45bceae79c193e93ce9fbdb8fd0ea6b6cd0ac2 |
| Native source exporter | 212691 | 22b97602225a404c7bde5879f1eb343a3a197b6413214966322642c1ad256471 |

The selected SHA source is
d2edf6e888abc06ae9dae60ee36f84772d5f9b49b52a40d0dc510265acbf955f.
Its 64,588-byte machine-code image is
30f72e80f11d72b7a991304b4218a59232d7607dd6a399c7cc13bcb3ba8a0bd3,
constructed with the 151,857-byte independent word seed
9610956124383993a32f8e47fb697d1754d6b06778e0cb3339d12f6ec6166525.
The word profile is explicit; the original v1 and bulk seed identities remain
unchanged. Every native product was read back and its complete policy-plus-SHA
suffix compared with the actual independently constructed inputs.

Fresh validation of these exact products passed all 18 driver gates, the
19 original AZ01 archive gates, the same 19 AZ02 archive gates, and all 47
source-export gates. The exporter includes successful copying and independent
verification of an exact 64 MiB input, plus refusal at 64 MiB + 1. The archive
still detects all three actual concurrent file mutations. No time, byte,
path, permission, custody or receipt bound changes in this rebinding.

The earlier complete signed-reference phase above belongs to the previous
inline-SHA products. It is not relabelled as execution of these new images.
The original combined 60-phase cold deadline remains a separate requirement.
All fresh construction inputs, product pins, case identities and original
qualification-report hashes are recorded in the companion JSON under
word_sha_rebinding.
