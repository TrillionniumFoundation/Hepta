# Repair the source workflow fixtures after compiler-owner integration

The two-file candidate is `0e79580fd4f9034dafc6a83f375fb00c3d1fd79d` (tree `f4846fcd1ade6a1b669aa56c3242cf8d2dccec59`), based on exact e8. It has not been executed. The original failed PR source log remains in `2d372b91d2691166cdc7464e8e0690f40e0a565d`; the full log's 137,723 bytes and Git/SHA256 identity were independently matched.

The shell fixture now supplies the actual contract and coverage commands before committing its temporary Git repository. It preserves the original clean/mutation/first-generator-failure controls and 0/1/7 return codes, real `git diff --exit-code`, and 20-second subprocess limit. Additional stdout assertions require the contract, coverage, contract, and check calls in order, and no such calls after the first generator's exit 7.

The store/page workflow check keeps the original 55 generators in their exact order, independently read from a3, and requires the four new state, instruction, ELF, and Core generators as the entire tail. All other assertions and methods remain unchanged. The two modules retain seven and six statically declared test methods respectively; these counts are lexical source observations, not an executed unittest discovery report.

Both changed files and the complete 4,023-leaf candidate tree were read back from Git. Applying the inverse exact replacements recovers every byte of both e8 files. The independent peer review is static only. Local Python was unavailable, and no remote product or qualification operation was launched. New execution evidence must be recorded separately; this repair does not relabel the original e8 failure.
