# Fixed class-backed PosixPath factory

The factory takes the actual exact-str value produced by the caller's
previous resolve step and creates a real native class-backed PosixPath
instance. It does not resolve the string again, accept a caller type flag,
or publish a string as if it were a Path object. Its current source-only
qualification does not close the public Path method family.

## Fixed 6Q entry

`hia_native_posix_path_factory(s,sn,o,on,w,wn)` returns u32 status.
Private malformed buffers return `0xfffffffd`.

Input is exactly128 bytes, magic `HIANPX01`. Word8 is operation0 construct
or2 cleanup. The actual value cap is at16/24/32 for construction; cleanup
requires these three words zero. Bytes40..127 are zero.

Persistent work is at least4096 bytes. Its immutable prefix is:

| Offset | Meaning |
|---:|---|
| 0 | `HIANPXC1` |
| 8 | Fixed captured actual shared value entry |
| 16 / 24 | Actual value context address / bytes |
| 32 | Captured current PID |
| 40..127 | Zero |
| 128..4095 | Actual continuation, strong refs and cleanup custody |

The caller holds the actual value context and this work frame until all
cleanup is complete. A per-frame actual CAS guard rejects overlapping use.

Output is at least32768 bytes; the public reply is128 bytes with magic
`HIANPXR1`. Word8 is 0 success, 3 an actual value allocation failure, or4
dependency/lifecycle failure. On success16/24/32 contains one newly owned
class-backed value cap. Word88 is detail,96 cleanup_required Boolean,
104 quarantined Boolean,112 dependency status; other public words are zero.

## Construction and identity

The factory retains the input and checks its actual value kind is exact
str. It then obtains canonical catalog class18 through Q03 operation32,
creates a private list containing that actual string, creates a kind8
instance through operation35, and checks its actual operation36 type is
the same object as catalog18 using operation8 identity. No published
result precedes these checks or cleanup. The instance's MRO contains the
actual canonical PosixPath, Path, PurePosixPath, PurePath and object roots.

The retained raw-part list is a copy. The source string can be dropped
immediately after the call, and the new object still owns it. Strings,
including empty/NUL/surrogate strings, retain the lexical constructor
behavior; this leaf does not invent filesystem validation or an8MiB cap.

All temporary references use the exact correlated V02 drop protocol.
Only actual consumed flags clear a node. Unknown or contradictory replies
quarantine the frame. A known-unconsumed reply with mapping pending
retains both facts and quarantines; retrying mapping cleanup cannot prove
that the original cap was consumed. Operation2 resumes cleanup only,
never reconstruction. Output is published only after retained refs are
resolved. The public result remains pending while any cleanup is pending.

`HIANXP01` packs two actual HIA roles using the existing readable path
capsule: this factory policy plus the captured shared path-error role.
Its count/length/mode layout and 4MiB role /16MiB text limits match the
earlier two-role path packer, but its magic and export are separate. The
error role is not invoked by the fixed construction policy.

Native HIA construction and qualification remain pending while ROG is
unavailable. Current checks execute both real x86 effect capsules, actual
syscalls and value locks, with the exact HIA authors interpreted in the
development harness. That evidence is not labeled native HIA execution.
