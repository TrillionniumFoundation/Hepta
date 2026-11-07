# Bounded Selfhost-Core v5 capacity evidence

Code tested: `4797783a03f003bb9620cc05d95ef2d95fae3085`, based on the exact
v4 source `894d2dfce54ff25271b8de2c18c902394484d5cc`. This is a new **v5
Selfhost-Core candidate**, not a production deployment or a replacement of
the independent v4 product qualification.

## Results

| Check | Observed result |
| --- | --- |
| Native qualification | 154/154 checks passed |
| Source-only cold replay | 10/10 outer checks; nested qualification 154/154 |
| Pinned v4 B3 → v5 U1/U2/U3 | 7/7 checks; same fixed point as fresh v5 B0 chain |
| Selfhost, support contract and machine-plan unit cases | 31 passed |
| Native tool unit cases in the configured `hia-venv` | 29/29 passed |

The initial combined unit command exited 1 because the primary Python did not
have `jsonschema`, so the native-tool module could not import. Its other 31
cases passed. The complete 29-case native-tool module was then rerun with the
existing configured environment and passed. Both original logs are retained;
the first unsuccessful command is not represented as an all-green invocation.

The new limit is 8,192 operations; compiler source has 3,044 operations and
1,102 blocks. Source, output and workspace remain limited to 1 MiB each.
CPU, address space, stack and deadline settings remain unchanged. An actual
8,192-operation program compiles to 214,030 flat bytes and returns 8,176, matching
the independent Core VM. Its ELF `.text` matches the flat image. 8,193 operations
are refused before output changes.

Separate 910,057-byte inputs have exactly 262,144 and 262,145 Core nodes. The
first passes native semantic/node admission and reaches the unchanged output
capacity check; its large instruction encoding needs 2,653,919 bytes and is
therefore correctly refused for the supplied 32-byte output. The second is
rejected at node admission. This demonstrates a precise structural boundary,
not execution of a program whose output exceeds the profile. The independent
general Core accepts and rejects the same respective source structures.

Native B1/B2/B3 and upgrade U1/U2/U3 share this SHA-256:

`76446640911c583bc70b7f5a0c59973383b01dacb007d6f1f5b5239e70b25ad6`

Modified M2/M3 share this distinct SHA-256:

`71f31e85003cb28ba081426106576322464ae2c15dcb97b7ab6c3ac344d59d55`

## Retained materials

`SUMMARY.json` identifies the tested source closure, results and archive digest.
The readable cold, native and upgrade reports accompany it. `raw-evidence.zip`
contains the source-only cold export, B0 receipt, original/modified/upgrade
images, every native input and output, raw child stdout/stderr, refusal receipts,
the initial trial, both test logs, and a per-file SHA-256 manifest. It contains
2,566 source files; no failed invocation output has been discarded.

Reproduce on Linux x86-64 with GNU `ld` and new output paths:

```sh
python -B tools/generate_hia_selfhost_contract.py --check
python -B tools/replay_hia_selfhost_cold.py --output /tmp/new-selfhost-v5-cold.json
python -B tools/replay_hia_selfhost_upgrade.py \
  --previous-evidence /path/to/original-v4/qualification.evidence \
  --output /tmp/new-selfhost-v4-to-v5.json
python -B -m unittest tests.test_hia_selfhost tests.test_hia_selfhost_contract tests.test_hia_selfhost_machine_plans
```

The upgrade reuses a digest-pinned historical v4 B3 and does not claim to freshly
rebuild it. The cold replay isolates source, process and caches on this host;
it is not a fresh virtual machine. The full language, owned resources, returned
loans, recursion, general external linking and general native backend remain
outside this profile. No compiler-correctness theorem or security sandbox is
claimed. A merged candidate must regenerate its support contract and perform
its own cold replay because the contract binds the entire Python seed package.
