# Veilo privacy_pool — Security Review (Superteam Earn submission, v2)

- Target: `github.com/VeiloSolana/privacy-program` (Anchor/Solana `privacy_pool`)
- Mainnet Program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- Date: 2026-08-09 (v2 re-verification; v1 submitted 2026-08-09, revised same day after deeper source + on-chain re-check)
- Method: source review + read-only mainnet verification. **No live funds were moved; no on-chain writes.**

## Summary

Two confirmed findings and one retracted claim:

1. **H2 (Low, unconditional) — `ext_data.refund` is paid to the relayer, not the user.**
   Verified in `handle_public_amount` (lib.rs): on withdrawal, the SPL branch transfers
   `fee + refund` to the relayer ATA and `withdrawal − fee − refund` to the recipient;
   the native branch credits `fee + refund` to the relayer lamports. `ExtData.refund` is
   documented as "Refund to the user", and `ExtData::hash()` binds it into the proof, so a
   user who sets `refund > 0` silently loses that amount. `transact_swap` and the position
   open/close paths never read `refund` at all. No attacker required — user-signed silent
   loss / documentation mismatch. Suggested fix: pay `refund` to `recipient` (or the user's
   ATA) on withdrawal, or force `refund == 0` outside withdrawal.

2. **H3 (Medium, design contradiction) — deposits are custodied by whitelisted relayers.**
   `AUDIT.md` states relayers are "trusted for submission and liveness, not for custody".
   In practice `transact` deposit requires the user to pre-fund a relayer-owned account:
   SPL branch requires `user_token.owner == relayer` and transfers with relayer authority;
   native branch does `system_program::transfer(from: relayer, to: vault)`. A malicious or
   compromised whitelisted relayer (4 on the USDC pool) can keep a pre-funded deposit and
   the chain cannot distinguish it from a legitimate deposit. Suggested fix: user-signed
   deposit instruction (user → vault, authority = user), or explicit custody disclosure +
   relayer bonds/limits.

3. **Former H1 (retracted as a vulnerability, downgraded to informational).**
   The v1 report claimed `merge_positions` could inflate the shared per-mint position vault
   cap by burning untracked dust notes while setting `merged_amount` from arbitrary PDAs.
   Re-verification shows this is **not exploitable**:

   - `MergePositions` enforces `has_one = claimant` on **both** input PDAs and requires a
     co-signing `claimant: Signer` — victim PDAs cannot be merged by anyone else.
   - `merged_amount` must equal `pda_0.balance + pda_1.balance` — the new PDA balance
     cannot be inflated above the sum of the two consumed PDAs.
   - `close_position` / `close_position_to_sol` cap `swap_amount <= pos_pda.balance`
     (hardened in commit 8decb20), and with a sound circuit any close must burn
     position-tree notes whose value covers `swap_amount` (`sumIns = change + destAmount`
     in the swap circuit). The physical per-mint vault token balance is the hard cap.
   - `AUDIT.md` already discloses the circuit-soundness dependency ("a flawed circuit or an
     unsound trusted setup therefore breaks pool solvency"), so the conditional claim added
     no new attack surface beyond the team's own disclosure.
   - **On-chain (read-only, 2026-08-09):** the position pool currently holds **no** vault
     records for any checked major mint — USDC, SOL, USDT, PhUSD, WIF, JUP, POPCAT, BONK,
     JTO, PYTH, WEN, USDS all `getAccountInfo` = null for their `position_vault_v1` PDAs.
     The position tree (`B5tqSDVy7KEMuYyqXBniUZY7ZGaAbLb1bfJHVe3DbPMZ`) has `next_index = 35`
     leaves and `position_config` (`FjmEzWofqUPMyFyh9r4n2rw134c8rKfqqUK44mZqA6JE`) shows
     4 relayers, `num_trees = 1`, `min_swap_fee = 0`, `swap_fee_bps = 0`. I.e. no material
     funds are exposed on the position surface on mainnet, so even the conditional scenario
     cannot produce fund loss today.

   Kept as an informational note: the position pool's accounting (PDA balances vs.
   `total_balance` vs. physical vault) has no on-chain backstop that binds a PDA balance to
   the value of the notes it tracks — it rests on circuit soundness plus the vault balance
   cap. If the team ever activates fees (`swap_fee_bps > 0`), `pos_pda.balance =
   dest_amount` vs. `total_balance += dest_amount − fee` creates a small positive
   "air" that can block full closes (liveness), not theft.

## Exclusion analysis (key attack surfaces cleared, read-only verified)

- Double spend: nullifier markers via `init` + `is_spent`; dummy nullifiers burned; all
  transact/swap/phoenix/perps/prediction/position paths mark inputs spent. OK.
- Replay: proofs bind root, `ext_data_hash` (recipient/relayer/fee/refund/claimant), mint,
  nullifiers, commitments, deadline; nullifiers are one-time. OK.
- PDA seeds / non-canonical field elements: `require_canonical` on root/nullifier/commitment
  (AUDIT-001, verified in on-chain ELF). OK.
- Merkle bounds: `next_index < 2^height`, capacity checks, root must be in 256-entry
  history. Liveness-only caveat (stale proofs need refresh). OK.
- CPI safety: swap program whitelist (Jupiter + OpenBook + Phoenix/EMBER/Perps IDs),
  account/position checks, `dex_amount_in == swap_amount`, `vault_amount >= dest_amount`,
  `SwapLeftoverTokens`. OK.
- Fees/rounding: u128 checked math; fee caps at init/update; `fee + refund <=
  withdrawal_amount`; `min_valid_withdrawal` anti-bypass. OK.
- Auth: withdraw/exit require claimant co-sign; merge requires `has_one = claimant` on both
  input PDAs. OK.
- Vault reconciliation: USDC vault ATA == TVL (314,948,948 units) exactly; SOL vault holds
  ≈0.42 SOL surplus locked in the pool (informational, H5). OK.

## On-chain evidence (read-only, mainnet, 2026-08-09)

- ProgramData `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3`: last_deployed_slot
  432,860,998; upgrade_authority `cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR`; ELF
  sha256 `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb` (matches
  AUDIT.md).
- Main pools (USDC/SOL) live with TVL 314,948,948 / 4,924,854,492; trees at
  next_index 1228 / 4746.
- Position pool: config `FjmEzWofqUPMyFyh9r4n2rw134c8rKfqqUK44mZqA6JE` (4 relayers, 1
  tree, fees 0); tree `B5tqSDVy7KEMuYyqXBniUZY7ZGaAbLb1bfJHVe3DbPMZ` next_index 35;
  `position_vault_v1` records absent for USDC/SOL/USDT/PhUSD/WIF/JUP/POPCAT/BONK/JTO/PYTH/
  WEN/USDS → position surface carries no material TVL.

## What still cannot be verified without the circuit artifacts

1. Circuit source, r1cs/zkey, trusted-setup transcript (not in the repo; `zk/` is
   gitignored; not published on npm/GitHub code search as of 2026-08-09).
2. Reproducible build flow / ELF diff.
3. Relayer key management & bonding policy.

These limit any audit to source + on-chain state; they do not change the two confirmed
findings above, which are unconditional and code-level.

## Contact / payment

- Email: shopqwphvuhc@web-library.net
- Solana (USDC): 6HfLRFR6B2y1jgzVVF6inCzvd7kKSaW55nTiACJDyQJV
- EVM: 0x677e39F988135F5F10Db6a0Eb329CDC05D7c0946
