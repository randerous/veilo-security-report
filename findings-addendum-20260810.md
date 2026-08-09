# Veilo privacy_pool — Addendum 2026-08-10 (v3): Critical + Medium-High findings

> Independent source verification at HEAD `cb1022d` of github.com/VeiloSolana/privacy-program.
> Superteam Earn submission `67143715-44a4-4b7f-9ddf-25bbc0e7d412` (veilo-bounty) updated with the
> two findings below on 2026-08-10. Payment: USDC-Solana `6HfLRFR6B2y1jgzVVF6inCzvd7kKSaW55nTiACJDyQJV`
> / USDC-EVM `0x677e39F988135F5F10Db6a0Eb329CDC05D7c0946` | contact: shopqwphvuhc@web-library.net

---
## Finding 4 (Critical, code-confirmed) — uncapped executor lamport sweep routes settled native-SOL perp proceeds to the relayer

**Location:** `programs/privacy-pool/src/perps.rs` — `sweep_jperp_executor_lamports` (74-90), called from 5 instruction handlers without any cap: `jperp_open_position` (585), `jperp_set_tpsl` (742), `jperp_close_position` (920), `jperp_cancel_trigger` (1036), `jperp_reissue_notes` (1285). Source HEAD `cb1022d`.

**Root cause:** `sweep_jperp_executor_lamports` transfers the executor PDA's ENTIRE lamport balance to the relayer (`residual = executor.lamports()`; `system_instruction::transfer(executor, relayer, residual)`), no cap, no balance-split. The authors knew the hazard: `jperp_recover_native` (1346) computes `relayer_sweep = executor.lamports() - recover_amount`, caps the residual at `JPERP_RECOVER_RENT_CAP` (15M lamports, 63-68), and its comment (1334-1344) states verbatim: "a plain sweep would hand the funds to the relayer." The cap was added only to `jperp_recover_native` (commits `e3f1574`/`55d792f`, 2026-06-29) and never propagated to the 5 sibling call sites — incomplete fix, live at HEAD.

**Impact (unrecoverable user fund loss):** for native-SOL perp positions, Jupiter's keeper returns settled value (TP/SL/close, or a cancelled-open refund) to the executor PDA as native lamports, leaving the WSOL ATA empty (authors' comment, 1334-1344). The protocol runbook requires the relayer to run `jperp_cancel_trigger` (cancel the dead trigger) BEFORE `jperp_reissue_notes`; the cancel's uncapped sweep then takes ALL executor lamports — including the user's settled proceeds — and pays them to the relayer. The user's notes were burned at open; `jperp_recover_native` then reverts (`checked_sub` on an empty executor -> InsufficientFundsForWithdrawal). Total, unrecoverable loss of position value.

Two actors:
- Malicious/compromised whitelisted relayer: steals any settled native-SOL position. The claimant co-sign (`claimant: Signer`, lib.rs 2762) is auto-provided by the user's client, which signs every relayer-built transaction (the relayer builds every tx by design), so no user action is needed beyond normal flow.
- Honest relayer + in-flight settlement: the sweep grabs "any Jupiter refund" (author comment at 920) — a settlement landing in the executor between the keeper action and the mandatory cancel is routed to the relayer, and the user can never recover it.

**Fix:** apply the bounded sweep from `jperp_recover_native` to all 5 call sites (sweep only the `EXECUTOR_JUPITER_RENT_FUNDING`-sized residual; route anything above to the vault/claimant), or close the executor PDA into the vault on settlement and distribute via `jperp_recover_native`/reissue.

**Verification:** verified in source at HEAD `cb1022d` (refs above). The same sweep mechanism executes on mainnet: `jperp_cancel_trigger` on native-SOL positions (2026-06-29 txns `2fphUb22...`/`2tzYK2yf...`; executor lamports swept to relayer `5oV1czyCFdULn6njjBbkB9S779tMmhnWEk1qNgvoLtk`, ~0.0037 SOL rent each); native vault `G7pfSRPttztsKVNtJUNXWXE4DLLzcrqFgPfPuiKuDo1j` ~5.07 SOL (config `BoEvEZQo9KWY7ajjbH3BQTrjgAdGfGCd8HYTcZhG8jpp`, total_tvl 4.647 SOL). A public LiteSVM reproduction (`mohit-1710/veilo-privacy-pool-audit`) shows 2 SOL moved executor->relayer in a single `jperp_cancel_trigger`.

## Finding 5 (Medium-High, code-confirmed) — swap legs not bound to the ZK proof; whitelisted relayer can redirect pool swap surplus

**Location:** `swap.rs` 53-58 (author comment: "Current circuit/VK hash only mints, min_amount_out, deadline, and dest_amount; `swap_data_hash` is not proof-bound until the circuit and verifying key are upgraded"); `positions.rs` `execute_jup_legs` (1834-1874), leg-program whitelist (1821-1828) includes SPL Token / Token-2022.

**Root cause:** the Groth16 proof commits to `SwapParams` (mints, min_amount_out, deadline, dest_amount) but NOT to the actually-executed legs. `swap_data_hash` is only a runtime `sha256(legs)` self-check over relayer-supplied bytes. Legs execute via `invoke_signed` with the executor PDA (and cosigner where present) as signers, and the whitelist admits plain SPL token transfers — so a leg `token::transfer(executor ATA -> relayer ATA, amount = surplus)` is within the accepted program set.

**Impact:** a whitelisted relayer can substitute the staged legs between proof generation and submission, adding a transfer leg that captures the swap surplus (proceeds above `dest_amount`/`min_amount_out` minus fees) to itself. User principal is protected by the min-out and atomicity checks; pool income and swap efficiency gains are at risk, and the user cannot detect the substitution from the proof alone.

**Fix:** bind `swap_data_hash` into the circuit (new VK), or constrain legs on-chain (reject legs whose destination is not the canonical executor/cosigner ATA; drop SPL Token from the leg whitelist or restrict to exact Jupiter routes).