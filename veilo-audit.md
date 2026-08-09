# Veilo Privacy Pool 安全审计报告（Superteam Earn 赏金）

- 审计人: AI 工坊安全审计专员
- 日期: 2026-08-09
- 目标: github.com/VeiloSolana/privacy-program，Anchor/Solana 程序 `privacy_pool`
- 主网 Program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- 审计范围: `programs/privacy-pool/src/`（lib.rs 5388 行 + swap/phoenix/perps/positions/predictions/merkle_tree/zk/groth16/vk_constants），只读链上验证（未移动任何真实资金）
- 结论速览: **未发现可无条件、仅凭链上逻辑即可直接盗取资金的漏洞**；发现 1 个高价值但依赖电路健全性的资金安全缺口（H1）、1 个无条件但低危的 refund 语义缺陷（H2）、1 个与声明威胁模型矛盾的存款托管信任缺口（H3）。

---

## 1. 审计上下文（AUDIT.md / SECURITY.md 已声明内容核验）

| 项 | 声明 | 源码核验结果 |
|---|---|---|
| 非规范域元素作 PDA seed | 已修复（AUDIT-001） | ✅ `zk.rs` 中 `verify_transaction_groth16` / `verify_swap_transaction_groth16` 对 root/nullifier/commitment 均调用 `require_canonical`；错误码 `NonCanonicalFieldElement` 存在 |
| reissue 路径未烧输入 nullifier | 已修复（AUDIT-002） | ✅ `phoenix_reissue_notes`、`jperp_reissue_notes`、`jperp_recover_native`、`prediction_reissue` 全部：非零校验 + `is_spent` 检查 + `mark_nullifier_spent` |
| 原生预扣未绑定证明金额 | 已修复（AUDIT-003） | ✅ `fund_native_source` 配对校验 `transact_swap` 的 executor/swap_amount；`fund_native_jperp_open` 配对校验 `jperp_open_position` 的 deposit_amount；`handle_public_amount` 与各 open/reissue 的 `public_amount` 均绑定 `deposit_amount+fee` 全流出 |
| 用户 executor 操作缺 claimant 联签 | 已修复（AUDIT-005） | ✅ 退出/取现路径（phoenix queue_withdraw/reissue、jperp close/reissue/recover、prediction reissue、position close/merge）均已要求 claimant 签名或绑定。⚠️ 但一组交易型指令（phoenix place_order/cancel/transfer_collateral/ember_wrap、jperp set_tpsl/cancel_trigger 等）仍**不要求** claimant 联签，依赖白名单 relayer 可信 |
| circuits 不在仓库 | 属实（无 .circom/.r1cs/.zkey/.wasm） | ✅ 所有"票据价值 = swap_amount/dest_amount、sumIns+publicAmount=sumOuts"的守恒不变量**只能由电路保证**，链上仅能验证 hash/commitment 一致性 |
| `zk-verify` 特性可关验证 | 误报 | ✅ `Cargo.toml` 中 `zk-verify = []` 为空特性；`verify_transaction_groth16`/`verify_swap_transaction_groth16` 无条件执行 |
| VK 常量 | 存在 | ✅ `vk_constants.rs` 含 TRANSACTION_VK（8 输入）与 SWAP_VK（10 输入），Groth16 验证为 snarkjs 约定 e(−A,B)·e(vk_x,γ)·e(C,δ)·e(α,β)=1，经 Solana alt_bn128 precompile |

## 2. 链上只读验证（RPC: api.mainnet-beta.solana.com，经代理 172.24.224.1:7897）

- ProgramData `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3`:
  - last_deployed_slot = 432,860,998（与 AUDIT.md 一致）
  - upgrade_authority = `cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR`（与 AUDIT.md 一致）
  - ELF sha256 = `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb`（与 AUDIT.md 一致，ELF 长度 1,808,464 B）
- 活池子（主网确有资金）:
  - USDC 池: config `8isRtjjapkizW6QYBtwSEhZXuG4LVDoUVkNBsEhHDhQy`，TVL = 314,948,948（≈314.9 USDC），vault ATA 余额 = 314,948,948（✅ 完全一致）；fee_bps=500（5%，取上限）、min_swap_fee=5000、swap_fee_bps=15、4 个白名单 relayer、num_trees=1、树 next_index=1228
  - SOL 池: config `BoEvEZQo9KWY7ajjbH3BQTrjgAdGfGCd8HYTcZhG8jpp`，TVL = 4,924,854,492 lamports，vault lamports = 5,347,469,772（**超额 422,615,280 ≈ 0.42 SOL**，见 H5）；树 next_index=4746
  - global_config `2gRVPz3nGAFxDaTzaGftgVDH3ufcKK1WYCR4H87cq8gk`、position_config `FjmEzWofqUPMyFyh9r4n2rw134c8rKfqqUK44mZqA6JE` 均存在且 owner 为程序
- 说明: 未做可复现构建（AUDIT.md 自认 gap；本地无 solana/anchor 工具链），未做链上 simulateTransaction 探针（需构造含 Groth16 证明的指令，电路工件缺失），以上留待后续。

## 3. 漏洞假设（1-3 个可验证资金损失假设）

### H1（高 · 电路条件性）: merge_positions 的 PDA 余额与证明所烧票据价值完全脱钩 → 共享 per-mint vault 提取额上限可被夸大

- **违反的不变量**: "PositionPDA.balance == 该 PDA 跟踪的位置票据价值"；"per-mint 共享 vault 只能按被烧票据的真实价值被支取"。
- **受影响资金路径**: position pool（`positions.rs::open_position` / `close_position` / `close_position_to_sol` / `merge_positions`）→ 共享 per-mint position vault（`position_vault_record.total_balance`）。
- **代码事实**:
  - `merge_positions` 只要求两个输入 PDA `is_active`、mint/tree 相同、`claimant` 一致、`merged_amount == pda_0.balance + pda_1.balance`，并设置 `new_pda.balance = merged_amount`。证明（`verify_transaction_groth16`，public_amount=0）只把 root/nullifier/commitment 作为公共输入——**链上没有任何检查证明所烧两条输入票据的价值等于两个 PDA 的 balance 之和**。证明完全可以烧任意两条（例如 partial-close 产生的、无 PDA 跟踪的 dust change 票据）。
  - `close_position` / `close_position_to_sol` 的防护是 `swap_amount <= pos_pda.balance`（commit 8decb20 新增）+ 电路隐含的 `swapAmount <= sumIns`。团队自己的 commit message 承认："the only thing stopping one position from drawing on another's share of the vault was circuit soundness"。
  - 因此防御链为: `min(电路约束 swapAmount<=sumIns, pos_pda.balance)`。其中**pos_pda.balance 可被 merge 任意夸大**（例: 开两个 balance=100 的仓位，merge 时证明烧两条价值各 1 的 dust 票据，`new_pda.balance = 200`，而输出的位置票据 W0 只值 2）。
- **PoC 思路 / 交易模拟**: 需要电路工件（不在仓库）构造"烧 dust 票据、输出小值票据"的合法证明: 1) open 两个 100 值仓位（balance 100+100）；2) 对第三个仓位做 partial close 制造两条价值 1 的 position-tree change 票据（无 PDA）；3) merge_positions 传两个 balance=100 的 PDA + 烧两条 dust 票据的证明，merged_amount=200；4) close 新 PDA: 若电路**不**强制 `swapAmount <= sumIns`（即允许 negative change 或缺该约束），则 swap_amount 可设为 200，共享 vault 被抽走 200 而票据仅值 2 —— 其余用户仓位被稀释。模拟方法: 本地 anchor test + 用可用的 proving key 生成 mismatch 证明，对 `merge_positions`/`close_position` 做 `simulateTransaction`（只读、不签名）验证链上接受。**验证结论目前只能是"条件成立"**——电路健全则不可变现，电路有缺陷则直接抽干共享 vault。
- **严重等级**: 高（若电路未强制 swapAmount≤sumIns 则为直接资金损失；即使电路健全，该不变量缺口也使整个 position 池的偿付仅剩单点电路保障）。
- **建议修复**: (a) 电路侧把 merge 的输出票据价值（merged value）作为公共输入暴露给链上，`merge_positions` 校验 `merged_amount == 输出票据价值`；(b) 或让 PositionPDA 不再存 balance，close 时以证明内的票据价值为唯一上限（删除对 `pos_pda.balance` 的依赖）；(c) 至少把 close 的 `swap_amount` 上限改为 `min(pos_pda.balance, 电路可验证上限)` 并把 merge 的 `new_pda.balance` 初始化为 0 后再由 close 重新校准。

### H2（低 · 无条件）: 核心 withdraw 与 swap 路径的 `ext_data.refund` 语义缺失/被支付给 relayer

- **违反的不变量**: AUDIT.md 声称 `ExtData::hash()` 绑定 recipient/relayer/fee/refund/claimant 且 refund 属用户退款；实际链上 `handle_public_amount`（lib.rs）SPL 与 native 两条 withdrawal 分支都把 `fee + refund` 一起转给 **relayer**（`to_relayer = fee + refund`；native 分支 `relayer_ai += fee + refund`）；`transact_swap` / 各 open 路径的 refund 则被**完全忽略**（vault_amount = swapped − fee，refund 不产生任何支付）。
- **受影响资金路径**: `transact`（withdraw）、`transact_swap`、phoenix/jperp/prediction 的 open/reissue（refund 全部失效）。
- **PoC 思路**: 用户生成 ext_data.refund>0 的取现证明（SDK 或复制他人参数），链上 `fee+refund` 全部落入 relayer 账户，用户收不到退款。无需攻击者——用户自损，但语义与文档不符，且未来任何"refund 到账"假设都会静默出错。
- **严重等级**: 低（非第三方可利用的盗取面；证明由用户签名生成，relayer 无法篡改）。
- **建议修复**: 统一语义——要么在取现路径把 refund 转给 recipient、swap/open 路径强制 `refund==0`，要么删除该字段并修订文档；SDK 侧校验。

### H3（中 · 设计/托管信任）: SPL 与 native 存款必须经白名单 relayer 托管，与 AUDIT.md "Relayers 不托管用户资金" 的威胁模型矛盾

- **违反的不变量**: 声明 "Relayers are trusted for submission and liveness, not for custody of private notes"；实际 `transact` 存款: SPL 分支要求 `user_token.owner == relayer` 且以 relayer 为 authority 转账；native 分支 `system_program::transfer(from: relayer, to: vault)`——用户必须先把代币/SOL 预转进 relayer 拥有的账户。
- **受影响资金路径**: `transact`（deposit），USDC 与 SOL 池。
- **PoC 思路**: 用户为存款向 relayer 预转 10 USDC 后，恶意/被攻破的 relayer 可提交一笔"仅转移、不含 transact"的交易截留该笔资金（链上无从区分）。这是当前模型下最大的单点托管风险之一（4 个白名单 relayer 任一出事即吞存款）。
- **严重等级**: 中（需要 relayer 恶意/失陷；属威胁模型与实现的矛盾，非程序逻辑漏洞）。
- **建议修复**: 新增用户自签存款指令（`user_token.owner == user`、authority=user，直接 user→vault），或至少在文档中把存款路径的 relayer 托管信任显式披露并做风控（relayer 押金、限额）。

## 4. 排除论证（重点攻击面逐项排除）

- **重复花费/双花**: nullifier marker 用 `init`（PDA 已存在即失败）双保险 `is_spent`；deposit 的 dummy nullifier 非零且同样被 burn；`transact`/`transact_swap`/phoenix/jperp/prediction/position 全路径一致。✅
- **Replay**: 证明绑定 root、ext_data_hash（含 recipient/relayer/fee/refund/claimant）、mint、nullifier、commitment、deadline；nullifier 一次性。✅
- **PDA seed 碰撞/非规范域元素**: 所有 nullifier/commitment/root 均过 `require_canonical`（AUDIT-001 修复在链上 ELF 中，错误串 "Field element is not in canonical form" 已编译进 ELF）。✅
- **Merkle 树索引越界**: `append` 检查 `next_index < 2^height`；各 handler 检查 `remaining_capacity`；root 必须存在于 256 条 root history。⚠️ 仅有的限制是 liveness: root 历史只保留最近 256 次 append，久置的证明需重新生成（非资金损失）。
- **CPI 安全**: swap_program 白名单（CPMM/AMM/Jupiter）+ OpenBook program ID + Jupiter event authority + Phoenix/EMBER/Perps program ID 逐一 require；剩余账户数量与位置检查；`dex_amount_in == swap_amount`、`dex_min_out >= min_amount_out`、`vault_amount >= dest_amount`、swap 后 source 账户余额必须为 0（`SwapLeftoverTokens`）等。✅
- **金额/费用舍入**: u128 中间计算 + `checked_*`；fee_bps ≤ 500、swap_fee_bps ≤ 1000、fee_error_margin_bps ≤ 5000（初始化与 update 均校验）；`fee+refund <= withdrawal_amount`；`min_valid_withdrawal` 防止绕费。✅
- **授权缺失**: 取现/退出路径 claimant 联签完备；交易型指令（phoenix place_order 等）依赖 relayer 可信（见 H3 同源问题，属威胁模型）。
- **relayer 退款**: 见 H2（语义缺陷，非盗取）。
- **Vault 对账**: USDC vault ATA 余额 == TVL（314,948,948）完全一致；SOL vault 超额 0.42 SOL（H5，良性盈余）。

## 5. 观察项（非漏洞）

- H5（信息）: SOL vault lamports 比 TVL 多 ≈0.42 SOL——来源为 native 路径 close_account 时 WSOL ATA 的 rent 与未转走的 fee 全部落入 vault 但未计入 TVL（`jperp_reissue_notes` native 分支 close_account 到 vault、swap 原生目的路径 close 到 vault 等）。盈余锁死在池内，用户无法提取（取现上限=被烧票据价值），无资金损失，但对账时 TVL ≠ vault balance。
- H6（信息）: `swap_data_hash` 未绑定进 `swap_params_hash`（AUDIT.md 已披露）——relayer 可在满足 `min_amount_out`/`dest_amount` 的前提下自由换路由/给差价格，用户对路由无证明级承诺；外部池（Raydium/Jupiter/Perps）正确性超出本程序能力（AUDIT.md 已声明）。
- H7（信息）: root 历史 256 条 + 树容量 2^22，长期静置的 note 需刷新 root；执行器/ATA rent 由 relayer 垫付、退出时回收，存在小额 dust 沉淀。

## 6. 结论

- 对链上可验证部分: 未发现可直接导致资金损失的无条件漏洞。nullifier 一次性、Merkle root 校验、CPI 白名单与金额绑定、fee 上限、claimant 联签、TVL↔vault 对账（USDC 池精确一致）均已落地且主网状态与源码一致。
- 最大风险集中在**电路健全性**（circuits/proving key/trusted setup 不在仓库，无法核验）+ **H1 的 PDA 余额脱钩**（若电路未强制 swapAmount≤sumIns，position 池共享 vault 可被超提）+ **H3 的 relayer 托管**。三者均需电路工件或运营级缓解，建议在提交报告时向项目方索取: (1) circuit 源码与 r1cs/zkey 及 trusted-setup 笔录；(2) 可复现构建流程与 ELF 对比；(3) relayer 密钥管理与押金策略。
- 未执行: 可复现构建比对、带证明的交易 simulateTransaction 探针（缺电路工件）；这两项是"把 H1 从条件性升级为确定性结论"的必要步骤。

*本报告基于 2026-08-09 的主网只读状态；禁止移动真实资金，未发生任何链上写操作。*
