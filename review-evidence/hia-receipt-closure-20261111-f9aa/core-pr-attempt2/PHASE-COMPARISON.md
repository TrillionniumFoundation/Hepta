# Frozen Hepta phase wall observations

These are original observations from different jobs, not a controlled performance comparison. Every column uses Hepta 7c20; Runtime columns use Runtime 7924. A dash means no completed process receipt, not zero time. All values below are seconds, rounded to six decimal places; exact recorded nanoseconds/decimals remain in phase-comparison.json.

| Family | Compiler | Runtime push | Runtime PR | Core PR attempt 2 |
| --- | --- | ---: | ---: | ---: |
| capacity | original | 4.000805 | 6.286375 | 8.932248 |
| capacity | modified | 3.933170 | 6.290591 | 8.958635 |
| cfg | original | 1.615221 | 2.777514 | 4.112072 |
| cfg | modified | 1.610405 | 2.791649 | 4.181247 |
| elf | original | 1.733200 | 2.713094 | 3.744788 |
| elf | modified | 1.697867 | 2.705774 | 3.651509 |
| chain | original | 12.613040 | 14.992278 | 17.407962 |
| chain | modified | 12.555843 | 14.974210 | 17.489406 |
| owned | original | 5.588576 | 6.309280 | 7.218254 |
| owned | modified | 5.591658 | 6.321677 | 7.240302 |
| bulk | original | 1.210041 | 1.420566 | 1.609154 |
| bulk | modified | 1.209987 | 1.362633 | 1.621253 |
| loan | original | 0.900770 | 1.048596 | 1.258795 |
| loan | modified | 0.905118 | 1.053790 | 1.255144 |
| resource | original | 0.340797 | 0.406110 | 0.457909 |
| resource | modified | 0.329074 | 0.403244 | 0.455974 |
| tail | original | 0.329287 | 0.406556 | 0.475698 |
| tail | modified | 0.329357 | 0.399639 | 0.464833 |
| select | original | 0.735091 | 0.940407 | 1.120045 |
| select | modified | 0.735139 | 0.942000 | 1.127221 |
| effects | original | 1.538352 | 1.850493 | 2.198996 |
| effects | modified | 1.539328 | 1.837031 | 2.190309 |
| multi | original | 6.087071 | 6.870646 | 8.240507 |
| multi | modified | 6.074258 | 6.867814 | 8.267449 |
| keyword | original | 1.008520 | 1.213278 | 1.469704 |
| keyword | modified | 1.009591 | 1.213466 | 1.475173 |
| signed | original | 9.940991 | 13.091573 | 17.745310 |
| signed | modified | 9.941157 | 13.071264 | 17.126647 |
| scalar-casts | original | 8.604168 | 11.571712 | 14.834017 |
| scalar-casts | modified | 8.603533 | 11.526037 | 14.752398 |
| explicit-traps | original | 1.146061 | 1.313885 | 1.520264 |
| explicit-traps | modified | 1.147457 | 1.309221 | 1.520168 |
| cli | original | 6.760589 | 10.363851 | 13.574197 |
| cli | modified | 4.831740 | 7.386937 | 9.532371 |
| names | original | 15.437171 | 24.512049 | - |
| names | modified | 15.538448 | 24.574578 | - |
| exports | original | 1.796672 | 2.149454 | - |
| exports | modified | 1.724858 | 2.062012 | - |

The Core attempt contains 34 completed PASS reports, 3,758 true checks, no false checks and zero phase exceptions. Both names requests exist without a final report; neither exports request exists. Completed report hashes and the hashes of their 34 retained phase ZIPs were independently checked. The main raw ZIP retains every original member.

The Runtime archive readback was performed on already retained original ZIPs and is preserved in runtime-phase-comparison-observed.json. Their original archive SHA-256 values are 152676ded50e6fa9c6d0380f107ef88bd9f70135344b4a3f6b9afa1c3aba9721 (push) and d56dbb51331bbab23883c586aea29cdfa014d4676e429e1de82c27d29cac9645 (PR). No Runtime or Core qualification was rerun by this comparison.
