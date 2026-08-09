# Veilo Privacy Pool — Superteam Earn Submission Draft (EN)

- Bounty: veilo-bounty ($2,000 USDC, deadline 2026-08-20T22:59:59Z)
- Program: github.com/VeiloSolana/privacy-program — Anchor/Solana `privacy_pool`
- Mainnet Program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- Audit basis: read-only mainnet analysis + source review (lib.rs 5388 lines: swap/phoenix/perps/positions/predictions/merkle_tree/zk/groth16/vk_constants)
- Full technical report (Chinese): `/home/r/business/ops/veilo-audit.md` (submit alongside / attach)
- Compliance: read-only only; no live funds moved; no on-chain writes performed.

## Executive summary

No unconditional, logic-only exploit that directly drains funds was found in the
on-chain verifiable portion. Three findings are reported:

1. **H1 (High, circuit-conditional):** `merge_positions` decouples the PDA balance
   from the value of the notes burned by the proof → the shared per-mint vault
   withdrawal cap can be inflated.
2. **H2 (Low, unconditional):** `ext_data.refund` semantics are broken: withdrawals
   pay `fee + refund` to the relayer; swap/open paths ignore `refund` entirely.
3. **H3 (Medium, design/custody):** deposits must be pre-funded to whitelisted
   relayers, contradicting the stated threat model ("relayers do not custody user funds").

## H1 — merge_positions: PDA balance detached from proven note value

- **Invariant violated:** `PositionPDA.balance == value of the position notes it tracks`;
  the shared per-mint vault may only be drawn against the real value of burned notes.
- **Affected path:** `positions.rs` — `open_position` / `close_position` /
  `close_position_to_sol` / `merge_positions` → shared per-mint `position_vault_record`.
- **Facts:**
  - `merge_positions` only requires: both input PDAs active, same mint/tree,
    same claimant, `merged_amount == pda_0.balance + pda_1.balance`, and sets
    `new_pda.balance = merged_amount`.
  - The Groth16 proof (`verify_transaction_groth16`, public_amount=0) only binds
    root/nullifier/commitment as public inputs. **On-chain there is no check that
    the value of the two burned input notes equals the sum of the PDA balances.**
    The proof may burn any two notes (e.g. dust change notes produced by partial
    closes that are not tracked by any PDA).
  - `close_position` guards with `swap_amount <= pos_pda.balance`
    (commit 8decb20) plus the circuit-implicit `swapAmount <= sumIns`. The team's
    own commit message admits: "the only thing stopping one position from drawing
    on another's share of the vault was circuit soundness."
  - Attack sketch: open two positions of value 100 each (balances 100+100);
    partial-close a third position to mint two untracked dust notes of value 1;
    call `merge_positions` with the two balance-100 PDAs and a proof burning the
    two dust notes, `merged_amount = 200`; then `close_position` the new PDA with
    `swap_amount = 200`. If the circuit does not enforce `swapAmount <= sumIns`,
    the shared vault pays 200 while the notes are only worth 2 — other users'
    positions are diluted.
- **Severity:** High if the circuit fails to enforce `swapAmount <= sumIns`;
  even with a sound circuit, the position pool's solvency rests on a single
  circuit assumption with no on-chain backstop.
- **Verification status:** conditional — requires circuit artifacts (not in repo:
  no .circom/.r1cs/.zkey/.wasm). Local anchor test + `simulateTransaction`
  (read-only, unsigned) with a mismatched proof is the next step once artifacts
  are provided.
- **Suggested fix:** (a) expose the merged note value as a public input and have
  `merge_positions` verify `merged_amount == output note value`; (b) drop
  dependence on `pos_pda.balance` and use the proven note value as the only cap;
  (c) at minimum, cap close `swap_amount` by `min(pos_pda.balance, circuit-verifiable cap)`
  and initialize `new_pda.balance = 0` for recalibration at close.

## H2 — refund field is broken (unconditional)

- **Invariant violated:** `ExtData::hash()` claims to bind recipient/relayer/fee/
  refund/claimant with refund being the user's change; on-chain, both SPL and
  native withdrawal branches in `handle_public_amount` transfer `fee + refund` to
  the **relayer**; `transact_swap` and the open paths **ignore** refund entirely
  (`vault_amount = swapped − fee`).
- **PoC:** a user signs a withdrawal proof with `ext_data.refund > 0`; the chain
  pays `fee + refund` to the relayer account; the user receives no change. No
  attacker required — silent user loss / doc mismatch.
- **Severity:** Low (not a third-party exploitable drain; proofs are user-signed).
- **Suggested fix:** pay refund to recipient on withdrawal, force `refund == 0` on
  swap/open paths (or delete the field), and fix the docs/SDK.

## H3 — deposits are custodied by whitelisted relayers (design contradiction)

- **Invariant violated:** stated threat model "Relayers are trusted for submission
  and liveness, not for custody of private notes". In practice `transact` deposit:
  SPL branch requires `user_token.owner == relayer` and transfers with relayer as
  authority; native branch `system_program::transfer(from: relayer, to: vault)` —
  the user must first send tokens/SOL to a relayer-owned account.
- **PoC:** after a user pre-funds a relayer with 10 USDC for deposit, a malicious or
  compromised relayer submits a plain transfer (no `transact`) and keeps the funds;
  the chain cannot distinguish this from a legitimate deposit. 4 whitelisted
  relayers — any single one failing eats deposits.
- **Severity:** Medium (requires relayer compromise; threat-model vs implementation
  contradiction, not a pure program-logic bug).
- **Suggested fix:** add a user-signed deposit instruction (`user_token.owner == user`,
  authority = user, direct user→vault), or explicitly disclose the custody trust and
  add operational controls (relayer bond, per-relayer limits).

## Exclusion analysis (key attack surfaces cleared)

- Double spend: nullifier markers via `init` + `is_spent`; dummy nullifiers burned; all paths covered. ✅
- Replay: proof binds root/ext_data_hash/mint/nullifier/commitment/deadline; nullifiers one-time. ✅
- PDA seeds / non-canonical field elements: `require_canonical` on root/nullifier/commitment (AUDIT-001, verified in on-chain ELF). ✅
- Merkle bounds: `next_index < 2^height`, `remaining_capacity`, root in 256-entry history. ⚠️ liveness-only.
- CPI safety: whitelisted swap programs + account checks + amount bindings + `SwapLeftoverTokens`. ✅
- Fees/rounding: u128 checked math; fee caps enforced at init/update; `fee+refund <= withdrawal_amount`; `min_valid_withdrawal`. ✅
- Auth: withdraw/exit paths require claimant sign-off; trading-type instructions rely on trusted relayers (see H3). ✅
- Vault reconciliation: USDC vault ATA balance == TVL exactly (314,948,948); SOL vault surplus ≈0.42 SOL (benign, locked). ✅

## On-chain evidence (read-only, mainnet)

- ProgramData `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3`: last_deployed_slot 432,860,998;
  upgrade_authority `cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR`; ELF sha256
  `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb` (matches AUDIT.md).
- USDC pool: config `8isRtjjapkizW6QYBtwSEhZXuG4LVDoUVkNBsEhHDhQy` — vault balance == TVL
  (314,948,948 units); fee_bps=500; 4 whitelisted relayers; tree next_index=1228.
- SOL pool: config `BoEvEZQo9KWY7ajjbH3BQTrjgAdGfGCd8HYTcZhG8jpp` — vault 5,347,469,772 lamports
  vs TVL 4,924,854,492 (surplus 422,615,280 ≈ 0.42 SOL); tree next_index=4746.
- `global_config` `2gRVPz3nGAFxDaTzaGftgVDH3ufcKK1WYCR4H87cq8gk` and `position_config`
  `FjmEzWofqUPMyFyh9r4n2rw134c8rKfqqUK44mZqA6JE` exist, owner = program.

## Request to the Veilo team (unblocks H1 from conditional → deterministic)

1. Circuit source + r1cs/zkey + trusted-setup transcript.
2. Reproducible build flow + ELF comparison.
3. Relayer key management & bonding policy.

## Submission checklist

- [ ] Register Superteam Earn account (currently blocked by email whitelist; Privy user + tokens preserved)
- [ ] Attach `veilo-audit.md` (full technical report) + this summary
- [ ] Confirm "no live funds moved" statement
- [ ] Submit before 2026-08-20T22:59:59Z
