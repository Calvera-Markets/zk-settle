# Compute-unit samples (test SBF, `mock-proof`)

Measured in LiteSVM / Mollusk tests.

| Instruction | Approx CU | Source |
| --- | ---: | --- |
| initialize | ~12k | mollusk `initialize_writes_genesis_root_and_keys` |
| plain Groth16 KAT | 78,561 | kat_groth16 Merkle inclusion |
| escape (0 siblings) | < 200k | litesvm `escape_withdraw_pays_leaf_owner` |
| escape (24 / 40 siblings) | < 200k | litesvm `escape_24_and_40_siblings` |

Settle (mock-proof) and claim are in the same suites. Wrap settle is `kat_sp1`
(~108k CU). Abort if wrap settle exceeds 400k CU.
