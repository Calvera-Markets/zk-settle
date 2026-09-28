# SP1 Groth16 wrap fixture

Optional. `kat_sp1` skips if `proof.bin` is missing. Do not generate this in CI or
as a unit test (`--groth16` wraps the whole SP1 recursion circuit).

| File | What |
| --- | --- |
| `proof.bin` | 356 bytes: `SHA256(gnark_vk)[0..4] ‖ exit(32) ‖ vk_root(32) ‖ proof_nonce(32) ‖ A‖B‖C (256)` |
| `public_values.bin` | 144-byte guest slice |
| `guest_vk_hash.bin` | 32-byte ELF `vk.bytes32_raw()` |
| `vk_account.bin` | groth16-solana VK account (`nr_pubinputs=5`) |
| `groth16_vk.bin` | raw gnark VK (prefix check only; not the on-chain account) |
| `meta.txt` | lengths, prefix, tree depth |

## Regen

Already-built host, explicit dump dir, allow-env. zkVM tree depth is 8 unless
you override `CLEARING_TREE_DEPTH`.

```sh
cd zkvm
SP1_ALLOW_GROTH16=1 RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2 \
  ./target/release/clearing-host --groth16 \
  --dump-dir ../solana/fixtures/sp1
```
