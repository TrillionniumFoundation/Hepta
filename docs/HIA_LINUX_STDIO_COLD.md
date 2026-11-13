# Explicit Linux stdio: current-source cold construction

The public profile remains `hepta.hia.linux-stdio.v1`: one read on fd 0 and one
write on fd 1, with explicit typed borrows, checked offset/count bounds, signed
Linux results, and an explicit reference-VM effect provider. Default Core,
Code, assembly and VM entry points retain their original rejection behavior.
This document adds build and qualification custody; it adds no descriptors,
syscalls, environment or argument observation, implicit retry, default selector,
or production activation.

## Authorities and stages

`tools/build_hia_linux_stdio_program.py` retains its caller-pinned development
entry point. Its report cannot satisfy the new cold builder or qualifier.

The separate `tools/build_hia_linux_stdio_cold.py` admits the original complete
current-source cold report, its actual nested qualification and B1/B2/B3 files.
It checks the original 180-second qualification and 3-second cleanup receipts,
the full current source map, all original cold checks, and the actual equal B
images. An optional compiler pathname must contain the actual admitted B3
bytes. A digest in a serialized fixture never substitutes for this admission.

The toolchain then executes these five stages with the original child and
20-second, 1 MiB output and workspace limits:

1. Cold B3 compiles `selfhost_linux_stdio.hepta` to L1.
2. L1 compiles that same captured source to L2.
3. L2 compiles that same source to L3; all three images must be byte identical.
4. L3 compiles the ordinary `selfhost.hepta`; its complete result must equal B3.
5. L3 compiles the ordinary pure-HIA `linux_stdio_entry_packer.hepta`.

Each program build freshly admits that toolchain, uses L3 to compile the
explicit-profile program, and calls the actual HIA packer with the complete
`HIALNXE1` frame. Admission checks every original request, actual child stdout,
full receipt, complete 1 MiB output, captured input, produced image, and the
exact ELF headers, permissions and program region. ELF publication does not
execute the payload. Hosted Python still performs authoring, custody checks,
process supervision and file publication; this is not a claim that those
responsibilities have moved into HIA.

## Qualification entry point

```
python -B tools/qualify_hia_linux_stdio.py --cold-report COLD.json --evidence NEW_DIRECTORY
```

The qualifier accepts no development fixture or ambient compiler override. Its
preparation child has an owned 180+3-second limit and performs five toolchain
stages plus two stages for each of the five retained caller programs. A second
owned 180+3-second child runs the exact original 57 public/Core/assembly tests
and all 12 retained direct ELF/reference controls, in fixed order. Each direct
ELF call retains its original 20-second wall and 3-second cleanup limits.
Failures, errors, skipped tests, expected failures, unexpected successes,
missing IDs, changed source inputs or incomplete cleanup cannot qualify.

The twelve cases retain empty/short binary input, open and closed zero-length
transfers, full signed EBADF results, default SIGPIPE and inherited ignored
SIGPIPE/EPIPE, exactly 1 MiB, oversized input rejected before write, and bounds
rejection before a read. The permanent helper retains the complete original
control function bodies and comparisons; the original script is preserved as
an inert `.py.txt` source fixture. The full program, source, input/output and
process observations remain bound to the current cold fixture.

The final pass scope is `MATCHING_CURRENT_SOURCE_COLD`. It qualifies this
profile and these callers only. It leaves whole native delivery and default
activation false. A local development run or a Source pass cannot produce this
status without a real matching cold run.

## Installed resources and integration

The compiler and entry packer source assets are standalone build data in
`ENTRY_BUILD_FILES`. They are not members of `NATIVE_SOURCE_FILES` and do not
pretend to be loadable runtime image bridges. The original four ENTRY resources
remain, and the existing twelve-group setup and installation identity loops
include both new assets. `profile_resource_path()` accepts only these exact
two names. An installed package always reads its own `_data` tree; a missing
asset does not fall back to cwd, HOME or a source checkout.

Public profile parsing and reference execution are available from the wheel.
The strict compiler/qualifier are source-owned tools and require the complete
current source export and actual cold evidence. Installing two HIA source
assets does not by itself grant cold or native execution authority.

`hia_linux_stdio.py` is an explicit profile mechanism, not a default Core
semantic owner. Its reference-VM dependency on `hia_program_runtime.py` is an
explicit external provider edge; the physical source-custody generator follows
the real imports. There is no ambient manifest selector for this profile.

The original common compiler, opcode/effect tables, instruction/function
budgets and fixed fd 0/1 domain remain unchanged. This does not replace the
64 MiB/resident-image `.S` source-builder ports. Argv, environment and stderr
need separate explicit ABI work and are outside this profile.
