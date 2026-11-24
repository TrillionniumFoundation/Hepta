# Native HIA release finalization

hia-release-finalize owns the final release transition in HIA. It consumes
sealed executable capabilities and an admitted member inventory. It builds the
package, constructs source attestation, installs and independently attests the
package, publishes without replacing an existing destination, verifies the
published inode and bytes, and fsyncs the destination directory before issuing
its success receipt.

## Request

The only input is a sealed regular descriptor at fd 0. The executable takes no
arguments. HIAFIN01 is a 128-byte little-endian header followed by the output
basename, 64 ASCII hexadecimal runner digest bytes, and the inventory frame.

| Header offset | Field |
| --- | --- |
| 0 | Eight bytes HIAFIN01 |
| 8 | Expected parent PID; zero binds the observed parent before prctl and rechecks it |
| 16 | Absolute monotonic deadline in nanoseconds |
| 24, 32 | Stage and private work directory descriptors |
| 40, 48 | Output parent and held output directory descriptors |
| 56 | Sealed hia-subprocess executable descriptor |
| 64, 72, 80, 88 | Sealed directory packer, source builder, release installer, artifact publisher descriptors |
| 96, 104 | Output basename length and inventory byte length |
| 112 | Runner digest byte length, exactly 64 |
| 120 | Reserved, zero |

The four tool digests are taken from their exact inventory names. HIA hashes
all five executable descriptors and requires all seals before using them.
The directory packer and installer use their native fd:N interface. Each
HIASUB01 invocation lists its required capabilities in HIAPFD01.

The inventory is HIAINV01, a little-endian member count, a zero package-size
placeholder, then length-delimited names and 64-byte ASCII digests. The
finalizer replaces the placeholder with the captured package size before
asking the source builder to construct HIAATT01.

The work directory is private and must have unused store.hiapack, verified,
and authority.hiapack names. The output directory must be empty, owned and
private, and must match its basename under the held output parent. The parent
and held directory identity are checked again after publication.

## Completion and refusal

Success is one JSON object with schema hepta.hia.release-finalize.v1, sha256,
bytes, files, published=true, and source_attested=true. The published package,
work package and authority link must all identify the same 0400 regular file.

Exit 65 refuses a request or operation. Before reporting a publication failure,
the owner invokes the native artifact withdrawal operation, independently
checks that its own inode is no longer published, and fsyncs the output
directory. It preserves unrelated destination inodes. Exit 74 identifies a
failed withdrawal or failed withdrawal durability check.

SIGPIPE is handled by HIA so a lost success-receipt reader becomes an EPIPE
refusal with withdrawal. A failure before publication does not claim a
successful release and retains its private work evidence.

The supplied generic native runner owns each child, its deadline, complete
stream captures, durable receipt and reaping. A caller that needs a deadline
around the entire finalization can also invoke this executable through the
same runner; parent PID zero supports that nested arrangement.

## Source and qualification

release_finalize.hepta is the policy. hia_release_finalize_syscalls.S is a
mechanical syscall, offset relocation and SHA transport adapter.
generate_hia_release_finalize.py authors only the ELF packer from those
adapter bytes. The ordinary native named-source builder compiles the policy,
SHA implementation and packer.

qualify_hia_release_finalize.py is an external fixture. It accepts explicit
native images, an installed release and a new evidence directory. It does
not participate in product execution. Its cases include a complete release,
nested native invocation, invalid pins/descriptors/parents/deadlines, existing
file protection, injected post-publication fsync failure and receipt loss.
Its observations are component evidence; they do not certify the whole
release constructor or activate a default service.
