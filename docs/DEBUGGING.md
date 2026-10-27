# Native debugging and source mappings

Build either supported backend with `--debug`:

```sh
python -m hepta build examples/debug/main.hepta --debug -o artifacts/debug-rust
python -m hepta build examples/debug/main.hepta --backend c --debug -o artifacts/debug-c
gdb artifacts/debug-c
```

This profile disables optimization while retaining checked arithmetic, bounds
and abort-on-panic behavior. Rust receives `debuginfo=2` and forced frame
pointers; C receives `-g3`, `-O0` and frame pointers. The default optimized
profile is unchanged. An explicit C unroll optimization cannot be combined
with `--debug`.

The build retains exact generated source in a content-addressed directory
beside the requested artifact, along with `source-map.json`. It refuses to
reuse a retained file whose contents differ. Debugging therefore does not
depend on a temporary compiler input which has already been deleted.

For C, every generated instruction retains its originating Hepta statement's
`#line` location. Resetting only once per multi-line expansion is insufficient:
the generated temporaries would otherwise acquire following Hepta line numbers
and a breakpoint could stop before those source locals were initialized. The
actual GDB qualification exercises this failure condition.

For Rust, DWARF names the retained generated Rust file. The manifest maps each
generated statement/declaration range back to the original Hepta path, byte
range and source line. To place a source breakpoint, find its statement entry
and break at `generated_source:generated_start_line`. This is an explicit map;
Rust's DWARF has not been rewritten to claim native Hepta file locations.

Local symbols currently use generated names such as `h_input`, `h_base` and
`h_result`. A return whose machine instruction is only the function epilogue
may have no independently breakable location, even at optimization level zero.
Use an executable statement with live values; the qualifier uses an assertion
after computing the values. No guarantee is made that every source line or
optimized variable has a distinct machine location.

```sh
python tools/validate_debugger.py --output artifacts/debugger.json
```

The qualifier launches actual GDB with user startup files, auto-loaded scripts
and debuginfod disabled. It stops at the requested mapped statement, reads
three live locals, checks the caller stack, performs `next`, continues to a
normal process exit and verifies program output. Both Rust and C backends must
pass. A missing debugger, ptrace restriction, pending source breakpoint or
missing local is a failed qualification, not a skipped or synthetic success.

Current coverage is this native Linux/GDB profile. Optimized debugging,
arbitrary debugger frontends, Windows/PDB, macOS/LLDB, richer type visualizers
and a complete Hepta debugger integration remain separate work.
