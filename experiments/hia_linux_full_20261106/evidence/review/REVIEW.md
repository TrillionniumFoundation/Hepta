# Independent numerical review

**PASS:** the exact evaluation and observation SHA256 values match; 160 boots / 800 measured samples reaggregate correctly.
All 32 published cycle/public-utility paired statistics reproduce exactly (256 exact numeric field checks).
This review imports no frozen driver and runs no benchmark. Input files remain unchanged.

## Eight-arm four-phase cycles

Guest time is the mean of five block sums of four per-boot medians. Net delivery includes QEMU and the allocated standalone controller cost; setup is separate.

| Arm | Guest cycle ms | Guest change vs stock, 95% interval | Net delivery s | Net change vs stock, 95% interval |
|---|---:|---|---:|---|
| stock | 62.897 | 0.000% [0.000%, 0.000%] | 5.249 | 0.000% [0.000%, 0.000%] |
| hia-static | 65.167 | 3.609% [-13.915%, 23.294%] | 5.283 | 0.650% [-0.914%, 2.951%] |
| best-fixed | 63.768 | 1.385% [-18.271%, 20.870%] | 5.281 | 0.621% [-2.846%, 4.911%] |
| greedy | 56.917 | -9.507% [-20.243%, -0.916%] | 5.354 | 2.004% [-0.695%, 4.756%] |
| ordinary-mpc | 57.431 | -8.691% [-18.849%, 0.483%] | 5.408 | 3.035% [0.501%, 5.440%] |
| independent-same-objective | 60.329 | -4.082% [-14.971%, 3.366%] | 6.125 | 16.688% [9.195%, 25.815%] |
| fixed-ndu | 63.734 | 1.331% [-14.050%, 19.040%] | 6.302 | 20.061% [11.383%, 27.610%] |
| dynamic-ndu | 61.809 | -1.730% [-18.796%, 19.552%] | 6.202 | 18.162% [9.164%, 29.571%] |

## Primary paired contrast: dynamic NDU versus independent Rust

The baseline for these intervals is the independent Rust same-objective arm, paired within five complete blocks. These are newly computed direct contrasts.

| Metric | Change, 95% interval |
|---|---|
| median_ns | 2.453% [-6.680%, 18.862%] |
| qemu_wall_ns | 1.944% [-0.543%, 5.763%] |
| net_delivery_wall_ns | 1.264% [-5.347%, 9.839%] |
| public_utility_q32 | 1.182% [-8.006%, 8.569%] |
| standalone_planning_wall_ns | -2.864% [-28.885%, 35.592%] |

## Action equivalence

Greedy, ordinary MPC, independent same-objective and dynamic NDU select the exact same image in every one of the 20 cells: 14 original, 4 Os, 2 O3.
Fixed NDU differs in one cell. Best-fixed uses Os for all 20. No arm abstains.
Consequently, differences in guest timing among the four action-identical policies do not demonstrate different kernel decisions; their separate boots remain subject to execution variability and controller/host state.

## Measured controller overhead

All long-tail observations are retained. Service and cold-process costs are distinct from durable logging, parsing and complete planner wall.

| Arm | Service mean ms | Cold-process mean ms | Logged-wrapper mean / median ms | Full planner mean / median ms |
|---|---:|---:|---|---|
| independent-same-objective | 8.850 | 13.546 | 190.023 / 47.851 | 216.617 / 75.881 |
| fixed-ndu | 12.595 | 17.657 | 184.021 / 52.665 | 214.438 / 80.751 |
| dynamic-ndu | 12.658 | 17.799 | 180.069 / 55.041 | 210.414 / 81.163 |

Direct native comparisons use the same five-block pairing:

| Cost | Dynamic change versus independent, 95% interval |
|---|---|
| service_ns | 43.028% [37.814%, 48.611%] |
| cold_process_io_wall_ns | 31.396% [26.159%, 36.754%] |
| wall_ns | -5.238% [-33.764%, 38.481%] |
| child_cpu_ns | 32.067% [26.784%, 37.358%] |
| parent_cpu_ns | 40.823% [30.923%, 51.053%] |

## Setup and interpretation

| Arm | Recorded setup seconds |
|---|---:|
| stock | 748.236 |
| hia-static | 1505.009 |
| best-fixed | 7096.095 |
| greedy | 7096.095 |
| ordinary-mpc | 7096.095 |
| independent-same-objective | 7128.682 |
| fixed-ndu | 7207.253 |
| dynamic-ndu | 7207.253 |

The shared search preparation includes a 7066.397 s observed build window: 3836.421 s active union plus 3229.976 s idle gaps. These are recorded preparation costs, not an isolated compiler-speed test.
Every arm has nonpositive observed direct net-delivery savings versus stock. The registered point-estimate break-even is therefore unreachable; fully charging shared feedback does not improve it.
The NDU service/cold-process increase does not justify treating the occasional smaller logged-wall mean as an algorithmic advantage.
Intervals are descriptive, with five block clusters and no correction for multiple comparisons. No observation was dropped or resampled in the campaign.

## Evidence limits

- Raw serial files and calibration source traces were admitted by the original collector; this review does not replay those remote files.
- All 800 retained measured sample durations are reaggregated here; public utility latency components use the published EVALUATION inputs.
- The five-block intervals are descriptive and unadjusted for multiple comparisons; later controllers share past feedback.
- Complete wrapper wall includes durable I/O; its long tails are retained, not treated as pure arithmetic time.

Input SHA256 values:

- EVALUATION: 27fb22c9cc12b6852efd2515730401c1094c1e90b174e756fde04a103d95b582
- HELDOUT_OBSERVATIONS: 542948cfcecc8d3328b9d47c2b1bc355d8ac046e5a319a2b0d579c9d2b262481

Reproduction: python3 review.py --evaluation EVALUATION.json --observations HELDOUT_OBSERVATIONS.json --output NEW_DIRECTORY
