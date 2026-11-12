# Public CLI A service integration: new revision 1

This source joins the real CLI argv/capture/file/pretty owners with the already
completed A service (verify, inspect, normalize without an output path). It does
not install a dispatcher, grant a cold qualification, or complete the other CLI
actions. Publication remains an explicit unresolved path.

## Exact retained inputs

The reader verifies the entire nested archive and all member sizes, hashes and
modes, and independently decompresses content-addressed zlib/gzip objects:

* CLI artifact 13899330292, run 43115476503: inner archive 6,712,968 bytes,
  SHA256 abcd4411cf5fea4c26deb392471fed1dffc4581ce53fa38f062d4ba40ef4258f,
  1,453 members / 56,079,779 original bytes.
* A service artifact 13902950213, run 43122922476: inner archive 495,911,716
  bytes, SHA256 e754ac28c5a5117cb02bc0fdd5f82b541f5c6d9bae91247b3ca173cc6d54f43d,
  1,823 members / 1,441,424,405 original bytes.

Actions downloads unpack the outer ZIP; the new reader therefore claims complete
fixed inner-archive readback, not a fresh independent outer-ZIP hash check. Those
original ZIP identities remain recorded in their original upload logs. Selected
extracted files are made locally read-only and their original modes are recorded.

No completed 967 component cases, 193 CLI cases, or private-parent A75 cases are
rerun or inherited. Their native image bytes and fixture input bytes are reused
only after the complete archives and each source/image binding pass readback.

## New runtime composition

The exact passed 57,060-byte finite carrier is
ac4afce606abaca91b9b63c8ab8c7c3eb34ede0c, SHA256
f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de.
It retains the bounded CLI -> service -> program -> ordinary context graph.
The original A table's role 60 takes two read-only inputs; the table-2 role-60
policy stays separate.

The new HIA parent is compiled exactly once with the retained 669,556-byte B3
compiler SHA256 35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b.
The original 10 CPU-second / 20 wall-second / 256 MiB compiler limits remain.
The retained, source-bound HIA packer performs one actual entry to write the
complete ELF; all output bytes must equal an independent mechanical layout.
The native runtime has no Python callback or subprocess business dispatcher.

The parent owns:
1. Original capture and parser admission.
2. Original real filesystem read, with raw fd 0 permitted.
3. Read-only transfer of program, argv and parser views to the A context.
4. Complete typed result/lease/sequence validation.
5. Explicit child retirement while retaining the transferred result view.
6. Original CLI pretty output or original E_DRIVER diagnostic wrapper.

The initial source uses the already declared Linux UTF-8 startup profile and
digits=4300. Other startup digit policies, stdout surrogateescape boundaries,
installed activation, and actions outside A are separate open work.

## New actual test scope

The planned run uses the retained 25 program input bytes but exercises them
through a new real public CLI path: 25 inputs x verify/inspect/normalize = 75
complete argv/file/service/pretty comparisons. Three new join controls cover
actual fd 0, a Unicode filename, and a symlink in a parent directory. Every
stdout byte, stderr byte and exit status is compared to exact CPython 3.12.14
running the exact 0ef CLI in a separate oracle process.

Thus the new equality gate is 78 actual native processes and 78 oracle
processes. One additional native normalize --output call must remain a recorded
OPEN result (exit 126, empty streams, no destination created). Exit 126 alone
does not establish that a business request was reached and is never treated as
a publication or installed-entry success. Total planned native calls are 79,
one HIA packer entry and one new parent B3 compilation.

Each actual or oracle process receives the same argv/cwd/environment, empty
PATH and HOME, 90 CPU seconds / 1 GiB and a 30-second wall bound. Child
PDEATHSIG, parent-PID race handling, kill/wait cleanup and full raw process
outputs are retained. This is a new development integration; until the actual
run completes, none of these planned counts is a PASS observation.
