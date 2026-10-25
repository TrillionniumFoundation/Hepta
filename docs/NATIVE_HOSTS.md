# Actual host ABI qualification

`tools/validate_native_host.py` links an actual native C driver to a Hepta/Rust
`no_std` object on the executing host. The driver calls Hepta exports, which
call independently compiled C implementations. Values return through both
ABIs; separate Rust size/alignment/offset probes are compared with C layout.

The deterministic matrix has 36 generated record shapes, 12 scalar types,
12 nested pointer forms, three values per shape and a call with ten integer
plus ten floating arguments followed by a record. Both C `-O0` and `-O2` builds
execute. A separate, actually compiled wrong C echo must fail the same driver.
Padding bytes are not compared and foreign lifetime safety is not inferred.

```sh
python tools/validate_native_host.py --expected-system Linux \
  --expected-machine x86_64 --output artifacts/native-host.json
```

The JSON report retains the actual OS/architecture, C compiler/version/target,
pinned Rust identity, generated-source hashes, build/link commands, executable
hashes and process outcomes. Expected-host arguments refuse a host mismatch.
There is no emulator or object-only success fallback.

`.github/workflows/hepta-native-hosts.yml` requests separate native jobs on
Linux x86-64, Linux AArch64, Windows x86-64 and macOS AArch64. Jobs check out
the exact PR head, retain failures and do not cancel one another on failure.
The workflow is an execution request, not evidence that any remote job ran.
Only a successfully executed, retained report qualifies its actual host.

Hosted runners may be VMs. Their native execution does not establish physical
board startup or MMIO, DMA, IRQ, GPU device/driver qualification. Packed
records, bitfields, varargs and broader platform/compiler combinations remain
outside this finite matrix.
