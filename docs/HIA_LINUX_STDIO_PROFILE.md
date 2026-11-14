# Explicit Linux stdio profile

`hepta.hia.linux-stdio.v1` is an opt-in profile for two fixed physical effects.
It accepts explicit primitive v8 documents whose module is
`selfhost_linux_stdio`. It does not extend the default Core opcode or effect
tables, select a profile from an environment variable, or grant an arbitrary
system-call or file-descriptor interface.

| Instruction | Exact input types | Output | Effects | Physical operation |
| --- | --- | --- | --- | --- |
| `linux.stdin.read` | `mutbuf, usize, usize` | `i64` | `linux_io, write, trap` | One Linux `read` from fd 0 |
| `linux.stdout.write` | `readbuf` or `mutbuf`, then `usize, usize` | `i64` | `linux_io, read, trap` | One Linux `write` to fd 1 |

Attributes must be empty. The second and third operands are offset and count.
The range check proves `offset <= extent` before evaluating
`count <= extent - offset`; an invalid range traps before any external effect.
Read requires a live mutable loan. Write requires a live readable loan. The
existing checker still rejects suspended parents, consumed resources, exclusive
alias conflicts, inconsistent CFG joins, and unbalanced ordinary returns.
The `linux_io` effect propagates through ordinary calls just like the existing
effects. No fabricated helper call is substituted for either instruction.

The signed kernel result is retained without conversion: short transfer, EOF,
zero-length transfer, and negative errno remain distinct. A zero-length operation
still performs its single physical call. The instruction does not retry EINTR,
hide EPIPE, install a signal handler, or convert a foreign Python exception into
an errno. More elaborate retry/publication policy belongs in an HIA program.

## Public admission and reference execution

```python
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_linux_stdio import PROFILE

checked = assemble_program(source_bytes, profile=PROFILE)
checked_again = verify_program(checked, profile=PROFILE)
canonical_assembly = render_assembly(checked_again, profile=PROFILE)
observed = execute_program(
    checked_again, "f0", (source_bytes_for_f0, output_initial, workspace_initial),
    profile=PROFILE, linux_stdio_provider=physical_observation_provider,
)
```

The profile returns `VerifiedLinuxStdioProgram`, a detached immutable byte
container distinct from `VerifiedProgram`. Its constructor is not an authority:
all consuming entry points recheck its bytes. Default `verify_program`, default
assembly, default scalar VM, default LLVM/Code emission, and default machine
publication refuse this extended input. There is no fallback from a failed
profile build to ordinary Core or from an ordinary call target to a syscall.

The reference VM requires an explicit callable. It never implicitly binds the
real process's stdin or stdout. The callback receives a frozen
`LinuxStdioRequest` containing the fixed descriptor, offset, count, extent and an
immutable copy of the bytes for a write. It receives no pointer, mutable owner,
or capability to change VM storage. It returns an exact `(int, bytes)` tuple.
Negative results are limited to `[-4095, -1]`; positive results may not exceed
count. Read bytes must match the admitted nonnegative result exactly. Write and
negative results carry no returned bytes. Full response validation precedes any
read mutation. Provider exceptions retain their identity.

`LinuxStdioSignal` is an explicit reference observation with an exact built-in
integer signal number. It does not send an OS signal. Its report and provider
refusal reports preserve the actual VM buffers and effect attempt; they are
marked as reference outcomes, not kernel observations or ordinary Core traps.

The `f0` entry uses the existing three-buffer ABI and returns `u32`. Each public
reference input is an exact immutable byte string of at most 1 MiB. The adapter
creates distinct private roots, and only checked internal calls carry loans.
The existing step, heap, and call-depth limits remain. Native compilation retains
the original 128-function, 1536-block, 8192-instruction, 1 MiB
source/output/workspace and 20-second stage limits. Additional native signature,
name, call-graph, and stack constraints remain independently checked by the HIA
compiler; passing the reference checker does not certify native compilability.

## Explicit native construction

The repository construction endpoint is
`tools.build_hia_linux_stdio_program.build_linux_stdio_program`, also available
through its command-line module. It requires an explicit profile, compiler path,
exact lowercase compiler SHA-256, and a new output directory. It never executes
the produced program.

```sh
python -B tools/build_hia_linux_stdio_program.py program.hepta \
  --profile hepta.hia.linux-stdio.v1 \
  --compiler /absolute/path/to/linux-stdio-compiler.image.bin \
  --compiler-sha256 EXACT_SHA256 \
  --output new-build-directory
```

The public parser and typed checker admit the program first. The actual HIA
compiler generates its flat x86-64 image. That compiler also builds the pure HIA
ELF entry packer. The actual packer consumes the exact compiled program and
emits the complete ELF. Every original bounded child receipt is matched against
the outer captured compiler/source/input/output bytes. Final input readbacks,
full ELF structure checks and readback of the executable are mandatory.
No host assembler, host x86 code generator, `.S` template, or opaque startup
image is used by this endpoint.

The ELF has one RX file segment, one RW/NX zero-filled data segment, and an RW/NX
stack declaration. It has no interpreter. The minimal CPU startup establishes
alignment, performs the fixed nondumpable guard, calls the compiled HIA entry,
and exits with its returned word. The actual business read/write and loops are
in HIA. The input view initially has extent zero; output and workspace are each
1 MiB. SIGPIPE disposition is inherited, and the syscall-failure startup path
returns 126 before entering the program. The kernel's observable exit status is
the low eight bits of the returned word.

Construction currently records `EXPLICIT_PINNED_DEVELOPMENT_COMPILER`,
`compiler_provenance_qualified: false`, `matching_cold: false`, and `whole: false`.
A caller pin binds an input; it does not establish its bootstrap provenance.
The author tools, public reference checker/VM, build orchestration and test
supervision remain Python. The produced and tested ELF payload runs directly
under the kernel. These separate facts must not be merged into a whole-system
qualification claim.

## Canonical sources and remaining boundary

`tools/generate_hia_selfhost_linux_stdio.py` generates
`examples/hia_bootstrap/selfhost_linux_stdio.hepta`.
`tools/generate_hia_linux_stdio_entry.py` generates
`examples/hia_bootstrap/linux_stdio_entry_packer.hepta`.
Both support `--check`. The ordinary compiler and existing `.S` files remain
unchanged. The explicit compiler's grouping of adjacent constant ISA emissions
keeps it within the original limits; it is private to this profile.

This profile has no argv/environment observation, stderr operation, arbitrary
descriptor/syscall, pathname access, process creation, resident-image call
capability, or 64 MiB package buffer. In particular it does not replace
`hia_source_build_syscalls.S`, whose original 64 MiB/128-member input,
three separately admitted resident images, argv, allocation/protection,
SIGPIPE/EINTR and publication policy require additional explicit contracts.
No default CLI, worker, MCP configuration, production selector or resource
registration is changed by this development snapshot.
