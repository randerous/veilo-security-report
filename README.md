# Veilo privacy_pool — Security Review (Superteam Earn Submission)

This repository contains a security review of the Veilo `privacy_pool` mainnet program
(Anchor/Solana, Program ID `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`),
submitted for the Superteam Earn bounty `veilo-bounty` ($2,000 USDC, deadline 2026-08-20).

**v2 (2026-08-09):** after the initial submission, the report was re-verified against the
source and on-chain state. The former H1 (merge_positions "inflation") was retracted as a
vulnerability — see the reports for the full re-verification (claimant check, balance caps,
and the position pool carrying no mainnet TVL). Two code-level findings remain:
H2 (Low, unconditional — refund paid to relayer) and H3 (Medium, design — deposits
custodied by relayers).

Files:
- `veilo-submission-en.md` — English executive summary + findings + exclusions + on-chain evidence
- `veilo-audit.md` — full Chinese technical report

Contact / payment:
- Email: shopqwphvuhc@web-library.net
- Solana (USDC): 6HfLRFR6B2y1jgzVVF6inCzvd7kKSaW55nTiACJDyQJV
- EVM: 0x677e39F988135F5F10Db6a0Eb329CDC05D7c0946

Still requested from the Veilo team (bounds any deep-dive):
1. Circuit source + r1cs/zkey + trusted-setup transcript
2. Reproducible build flow + ELF comparison
3. Relayer key management & bonding policy


## v3 update (2026-08-10)
Two additional code-confirmed findings were added: **Finding 4 (Critical)** — uncapped executor lamport sweep routes settled native-SOL perp proceeds to the relayer (`perps.rs` 74-90, five call sites); **Finding 5 (Medium-High)** — swap legs not bound to the ZK proof, whitelisted relayer can redirect pool surplus. See [findings-addendum-20260810.md](findings-addendum-20260810.md). Superteam submission updated.
