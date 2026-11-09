# Two explicit public release entries: static review

This package records the five-path public-entry adaptation based on main `74063163ad19d096a4ff9a66a6f25728e6ce0d8f`. Static validation passed; execution of the two actual public installation jobs remains a separate qualification.

The selected default remains `tools/hia_release.py` with unchanged `releases/hia-current.json` (v9). A separately named entry, `tools/hia_release_v16_6ecd802.py`, is a byte-for-byte copy of B's original helper, using the unchanged original B lock at `releases/hia-v16-6ecd802.json`. The shared preflight already has identical source bytes in both versions.

| Object | Identity |
| --- | --- |
| Source B | `6ecd8023615a6e0b2dc269379fb059c656b38b6f` |
| Source tree | `4c51962e030e9ea39c6498224c99eb40fbdd2f35` |
| Original 47,762-byte lock SHA256 | `b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0` |
| Original 36,085-byte helper SHA256 | `2282167b6b0281e3a3660c2b75e5b81224b5a8f388eadc808140d36264afec11` |
| Unchanged shared preflight SHA256 | `ca2597a35f04bce129d6a96c4a56da0742cf3fd16d91edce06cad13d7d74e199` |

The existing v9 helper is not used to interpret the v16 lock: their source inventories differ, and the original executing-entry identity gate would reject that combination. The versioned helper keeps its original bytes and identity check; the explicit `--lock` and `--lock-sha256` arguments precede each subcommand.

The workflow has current/v16 rows, `fail-fast: false`, and the original 35-minute limit for each row. Current calls the true default with no lock override and retains the original artifact name. Both rows preserve every original public fetch/materialize/check, discoverability, eight locked task-input, native example and full installation-manifest equality gate. The preparatory check also verifies the selected original lock hash and executing helper/preflight bytes before fetch.

Validation includes YAML parsing, shell syntax checks for four workflow steps and documented commands, AST parsing of three embedded Python blocks, old-gate and task-input comparison, original B helper/lock equality, and `git apply --check`. It executes no project helper, compiler, solver, native image or runtime. The preparer's manifest, static results and complete patch are retained unchanged. The root reviewer independently rechecked every file's size, SHA256 and Git blob ID before publication.

Publishing this named entry does not change the default selection, activate a service, or rewrite source qualification flags. Source CI, metadata-head public installation and actual-main installation are distinct records; neither a static check nor an ancestor's successful run can replace the latter jobs.

