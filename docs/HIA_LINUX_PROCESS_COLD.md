# Explicit Linux process cold and portable qualification

This family uses the explicit `hepta.hia.linux-process.v1` profile. Ordinary
Core and the earlier Linux stdio profile continue to reject its startup and
stderr operations. The reference `LinuxStartupSnapshot` remains caller data;
it cannot grant native kernel, compiler, cold or default-selection authority.

## Admission and production

`tools/build_hia_linux_process_cold.py` accepts an actual matching-current-source
cold replay report. It reopens the original nested qualification, all three
actual B images and the complete current source map. The required source set
extends the complete existing Linux stdio cold domain with the process assets,
builders, retained controls, qualifier and this documentation.

Five bounded compiler calls produce P1, P2, P3, an ordinary B3 regression image
and the process entry packer. P1/P2/P3 must be byte-identical. Compiling the
ordinary selfhost source with P3 must reproduce the actual cold B3 bytes. Each
call retains its exact nine-field request, actual child stdout, full receipt,
full output, captured source and provider bytes. A program build separately
compiles one explicit checked process program and packs its actual image with
the captured entry packer. Its packed ELF has no interpreter, writable
executable mapping or executable stack. Publishing an ELF does not run it.

The caller-pinned development builder is retained as a separate entry point.
Its reports, image hashes and successful development observations do not supply
matching-current-source cold authority. The new cold builders reject missing,
failed, stale, extended or development-only admission before compilation.

## Permanent qualification

Run from the matching checkout:

```console
python -B tools/qualify_hia_linux_process.py --cold-report PATH --evidence NEW_DIRECTORY
```

The qualifier prepares the toolchain and eighteen original programs in an owned
process. It then runs these independent complete groups, preserving exact
ordered method IDs and start/stop events:

| Group | Methods | Observation |
|---|---:|---|
| Original public Source | 71 | Original stdio 18, Core program 21, assembly 18, process 14 |
| Direct process | 33 | Actual kernel executions and explicit reference VM results |
| Packer | 13 | Complete source/output/workspace bytes and all canaries |
| Startup refusal | 4 | Actual `prctl` and three `mprotect` refusal points |
| Entry boundaries | 4 | Buffer endpoints, raw string boundary and two kernel E2BIG refusals |
| Legacy output domain | 4 | Actual original B3 and P3 observations, eight compiler calls |
| Portable package | 1 | Actual sdist, wheel, install, explicit reference profile and missing resources |

The seven groups contain 130 methods. Cold preparation and every group retain
the original 180-second owner deadline and 3-second cleanup interval. Compiler
and direct child calls retain 20 seconds, 1 MiB compiler output/workspace,
10-second CPU, 256 MiB address-space and 8 MiB stack limits. Each original VM
case retains 10 million steps. The installed packaging commands retain their
existing 60-second limits inside the portable group's unchanged 180+3 owner.
There are no development, timeout, capacity, skip or expected-failure switches.

An ordinary observation failure does not skip later original groups. Actual
source or captured-input drift refuses further execution. The parent separately
reads complete child reports, exact request IDs, raw results, actual receipts,
all six anomaly sets, owned-process exit/deadline/cleanup and final fresh source
bindings. A partial discovery, skipped method, expected failure or missing
terminal cannot qualify.

The portable test builds and installs the actual package with all twelve
declared resource roles. It compares every installed resource byte, executes
the explicit reference profile with ordered raw argv/environment data and
stderr, checks ordinary/stdio rejection, removes each process asset in turn
and requires refusal without another checkout fallback, then restores and
rechecks. These installed VM observations are reference-only; they do not
stand in for native kernel or current-cold execution.

## Retained inputs and prior failures

`tests/fixtures/hia_linux_process_retained_controls.json` retains all original
authoring scripts, the original 71 IDs, every fixed case name and all eighteen
program inputs. Original raw custody is
`a66c166016fb9a7012bd45d257080c92ec9f5f27`; its source packet is
`0e11b2228ea61e9e0bacae7c841a8dccf95a9987`.

The first direct development group completed its 33 comparisons, then failed
when its additional packer comparison used different zero/A5 output preimages.
That original run stays FAIL. The retained thirteen-case packer successor uses
the same A5 preimage as the actual compile output and compares all bytes.

The first legacy-domain report's all-accepted assumption failed for explicit
empty exports: original B3 already refused those with code 68. The new process
compiler rejects that output domain with code 93 before function emission.
The permanent controls preserve this exact difference and the three originally
accepted legacy cases. They do not rewrite or upgrade the historical failure.

This qualification is specific to the explicit process family. It does not
activate a default backend, replace the whole CLI, eliminate hosted build/test
supervision, certify SQLite or close whole-native delivery.
