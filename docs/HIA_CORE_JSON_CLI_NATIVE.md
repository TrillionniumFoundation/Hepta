# Standalone HIA JSON Core compiler filter

The native HIA ELF packer joins two qualified flat images: the JSON Core
representation frontend and the real semantic compiler. It writes ELF headers,
patches both relative calls and copies the images in HIA. The fixed syscall
adapter is emitted as literal instructions by that HIA program, like the
existing assembly compiler's executable entry. No host linker produces the
delivered executable.

The resulting Linux x86-64 executable reads JSON on stdin, runs the HIA
representation frontend, then runs the HIA semantic/resource checker and
code generator. Only a successfully compiled output is written to stdout.
There is no Python payload parser, compiler process, libc, PT_INTERP, dynamic
loader or runtime filesystem access. This is an explicitly built bounded
compiler filter, **not** the entire production CLI or a sandbox for machine
images. The trusted build driver remains Python and consumes a completed,
matching cold qualification; it is not rewritten by this change.

## Explicit build and invocation

```sh
python -B -m tools.build_hia_core_json_cli \
  --compiler /path/to/qualified/B3.image.bin \
  --cold-report /path/to/completed-cold-report.json \
  --output /new/private/json-compiler
/new/private/json-compiler/hia-core-json < program.core.json > program.image.bin
```

`--output-profile elf` at **build time** instead selects the existing
`selfhost_elf` relocatable-object profile. Its inputs must use that explicit
module label. A submitted JSON module cannot switch a flat executable into ELF
or executable output. Linking generated objects, foreign allocator ownership
and generic module resolution still require the existing external authorities.
No default service or release lock is changed.

The program accepts no command-line arguments. Exit0means compiled;
2means invalid JSON/representation/semantic input;3means wire/node/depth/
assembly/native-output capacity;4means mapping or descriptor I/O failure;
64means usage. Refusal writes no stdout. Kernel failures/signals can terminate
the process; this is not an unconditional liveness guarantee.

## Resource and trust boundaries

- JSON wire<=8MiB, nodes<=1048576, depth<=128; same frontend ceilings.
- Representation output<=1MiB; compiler input/output/workspace each<=1MiB.
- One private anonymous88MiB+8192-byte RW mapping accommodates the existing
  worst-case arena/key budgets and a one-byte oversize read guard. The first
  1MiB of reused arena is explicitly cleared before semantic compilation.
- Executable code is in a separate RX ELF load segment; GNU_STACK is RW.
  No RWX mapping, `mprotect`, filesystem open, linker or child compiler is needed.
- The packer frame is trusted image packaging, not admission of untrusted
  machine code. The build driver binds compiler/frontend/packer source and image
  hashes and retains actual compilation/packing receipts.

## Observations and open closure

Independent Core VM header/call/payload/canary observations precede B0. Fresh
B0/B1/B2 build the packer and frontend. Native tests compare every packaged
byte, compile and execute a byte program, obtain original and changed-source
compiler chains with separate fixed points, execute explicit ELF output, and
exercise malformed frames, semantic rejection, wire/node/depth/native-code
capacity, closed stdin, full stdout, mapping failure and usage. An actual strace
observation admits exactly execve/mmap/read/write/exit, with one initial execve
and no subsequent executable or filesystem dependencies. Strace is a test-only
prerequisite, not a dependency of the resulting executable.

The first development test incorrectly demanded that the modified compiler's
first generation already equal its fixed point; it remains a failed attempt.
The corrected test requires generations2and3to agree and remain distinct from
the original compiler. Development tests are not exact-source cold acceptance
or current remote CI; separate immutable receipts record those gates.

General language/composites/modules, runtime/task/I/O/library, full command
surface, build/install/release, Agent/store and optimizer/proof tooling remain
open. The old production authorities remain required. Whole-stack HIA-only
retirement is not yet eligible.
