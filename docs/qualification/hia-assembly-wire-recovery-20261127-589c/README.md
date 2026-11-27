# Assembly wire recovery and integer policy

This change recovers the missing assembly wire → native canonicalizer → full
Core admission path from `c13f81a9f479c749ab5f8054f3754705b2a5822d`, on
`06d21f6032d7b3a946b1d6581a13c5cfd5fa4375`. It preserves the later native
wheel ZIP directory, RECORD, inflater and CRC implementation, the binder and
proof identity errors, and the original CLI canonical image appearing exactly
once in the linked assembly executable. The native-v2 source contract and
authority are unchanged; the old historical hosted contract is not restored.

## Actual gap and repair

The historical 19-item package pin adds a canonicalizer but no current Python
integer-digit policy. In the initial real native component experiment,
96 cases at digit limits 0, 640 and 4300 produced seven differences: the
original packaged `json.loads` route rejected integers longer than the selected
640-digit limit with a `ValueError` containing the actual digit count, while
the unguarded native route reached a later Core type or attribute error.
The existing native syntax parser already refuses more than 4300 digits;
that original syntax behavior, including its behavior when the host limit is
zero, remains unchanged.

The new 20th pin binds the existing `core_json_bytes.hepta` image. Its HIA
policy checks the current digit limit and produces a canonical wire before
the original canonicalizer and full native Core verifier run. Accepted
inputs remain on this native wire path at the default nonzero limit. Older
19-item pins retain the original decoding path and cannot enter the
unguarded fast path.

A rejected Core JSON front policy returns to the original packaged JSON
decoder and verifier. This preserves the original exception type, message,
digit count and precedence, including integer conversion before a complete
Core tree exceeds its node budget. **This refusal compatibility route remains
hosted.** It is a migration component, not complete native replacement or
permission to retire the previous stack.

The package builder constructs the new image only in its strict cold branch,
using the admitted source, compiler and native cold observer. It checks the
actual compile receipt, output identity and input readback, adds the image to
the wheel and appends its digest to the pin. Runtime admission includes the
image in the captured resource inventory and repeats file checks even when
the native policy returns to the compatibility route.

## Retained observations

- All 26 original assembly and release source controls passed on the final
  five Python files, with source hashes unchanged before and after execution.
- The original 96-case / seven-difference result is retained without edits.
- The guarded experiment compared 114 cases exactly at limits 0, 640 and
  4300: **zero differences**. It includes signs, 639/640/641 and
  4299/4300/4301 boundaries, longer numbers, quoted and escaped digit strings,
  duplicate keys, nonfinite values, earlier and later syntax failures, Core
  errors, and the combined global node-budget and integer failure.
- Three accepted-input controls forbid the host payload parser and Core
  snapshot. All execute the real native front at their selected digit limit.
- The old 19-item pin refuses entry to the unguarded native Core route. A
  wrong front image pin and retargeting during accepted and refused calls are
  rejected. Both physical resources are restored after these controls.
- The final component run records unchanged source hashes and 284 actual
  binding readbacks. Five original compressed native process responses were
  independently decoded; all returned zero with no timeout or stderr, and
  their exact source and produced-image echoes match the retained pins.

The four original assembly/Core images were compiled from exact frozen source
`5622dafbcfa10ad0c6f99214994ee7dcf71523e0`. The added Core JSON front was
compiled from exact source `06d21f6032d7b3a946b1d6581a13c5cfd5fa4375`:
source SHA-256 `aeabd33a3f5c9ddc81d62ab5748136c43649e593c48dd16df9b690ba5c0d86a8`,
image 209,263 bytes, SHA-256
`b743137e9a874c95e2c6e3a48212c0f4264cd0f72489cba8b781214539661819`.
All five use the actual historical native B1
`acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`
and its separately identified 1,107-byte native observer. No current cold
qualification is inferred from that historical compiler or observer.

The first local compile attempt stopped before native execution because the
default Python 3.12 build lacked `fcntl.F_ADD_SEALS`. Its failure is retained
in the compile report. The actual native constructions used the existing
system Python 3.13.5, without changing the product or substituting a seed.

## Scope that remains pending

The component observer mocks package capture and Core owner selection while
executing all five real HIA images, the real image pin readers and their
physical readback checks. It does **not** claim a genuine installed wheel or
current cold release.

The 24 original native installed-release tests are retained, along with one
new installed integer-policy test. **All 25 remain pending on a matching
current cold installation.** No test skip is counted as a pass, and no new
cold, complete runtime, activation or retirement qualification is claimed.

`receipt.json` contains exact implementation, source, compiler, image and
evidence pins. `native-component/` retains the initial and final comparisons,
original native transport requests, receipts and compressed stdout/stderr.
`observers/` records the external component scripts as executed; their local
paths identify the original evidence and do not select production artifacts.
