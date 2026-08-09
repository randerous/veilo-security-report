# Veilo Privacy Pool 安全审计报告 v2（Superteam Earn 赏金 · 修订版）

- 审计人: AI 工坊安全审计专员（randerous）
- 日期: 2026-08-09（v2 复核：提交后当天对 H1 做了源码+链上二次实锤）
- 目标: github.com/VeiloSolana/privacy-program，Anchor/Solana 程序 `privacy_pool`
- 主网 Program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- 方法: 源码精读 + 主网只读核验；**未移动任何真实资金，未发生链上写操作**

## 结论速览（v2 修订）

- **H2（低危 · 无条件，代码实锤）**: `ext_data.refund` 在取现时被支付给 relayer 而非用户。
  `handle_public_amount`（lib.rs）SPL 分支把 `fee + refund` 转给 relayer ATA、`withdrawal − fee − refund` 转给 recipient；native 分支同样把 `fee + refund` 计入 relayer lamports。而 `ExtData.refund` 文档注释是 "Refund to the user"，且被 `ExtData::hash()` 绑进证明——用户只要设 `refund > 0` 就静默损失该笔金额。`transact_swap` 与 position open/close 路径完全不读 refund。无需攻击者，用户自签即损（文档与实现不符）。建议: 取现时 refund 付给 recipient，或非取现路径强制 refund == 0。
- **H3（中危 · 设计矛盾，代码实锤）**: 存款实际由白名单 relayer 托管。`AUDIT.md` 声明 relayer "trusted for submission and liveness, not for custody"；但 `transact` 存款 SPL 分支要求 `user_token.owner == relayer` 并以 relayer 为 authority 转账，native 分支 `system_program::transfer(from: relayer, to: vault)`——用户必须先把资金预转给 relayer 拥有的账户。恶意/失陷的 relayer（USDC 池共 4 个）可吞掉预转存款，链上无法与合法存款区分。建议: 新增用户自签存款指令（user→vault、authority=user），或显式披露托管信任并加押金/限额风控。

## 原 H1 撤回为信息项（二次实锤结论）

v1 曾主张 `merge_positions` 可借"烧两张无主 dust note + 任意两个 PDA"夸大共享 per-mint position vault 的提取上限。**复核后该主张不成立**：

1. **PDA 归属**: `MergePositions` 对两个输入 PDA 均有 `has_one = claimant` 约束且要求 `claimant: Signer` 联签——受害者 PDA 无法被他人合并。
2. **无膨胀通道**: `merged_amount` 必须等于 `pda_0.balance + pda_1.balance`，新 PDA 余额不可能超过两输入之和。
3. **取现三重封顶**: `close_position` / `close_position_to_sol` 均要求 `swap_amount <= pos_pda.balance`（commit 8decb20 加固）；电路健全时任何 close 必须烧毁价值 ≥ swap_amount 的 position-tree note（swap 电路守恒 `sumIns = change + destAmount`）；物理 vault token 余额是最终硬上限。攻击者用自己 2 枚 dust note 合并自己的 100+100 PDA 再 close，只是把自己的 200 绕一圈取回——无跨用户稀释。
4. **团队已披露该依赖**: `AUDIT.md` 原文 "a flawed circuit or an unsound trusted setup therefore breaks pool solvency"——条件性声明与团队自述重叠，未新增攻击面。
5. **链上实证（只读）**: position 池当前对 12 个主流 mint（USDC/SOL/USDT/PhUSD/WIF/JUP/POPCAT/BONK/JTO/PYTH/WEN/USDS）均**不存在** `position_vault_v1` 记录；position 树 `B5tqSDVy7KEMuYyqXBniUZY7ZGaAbLb1bfJHVe3DbPMZ` 仅 35 片叶子；`position_config`（`FjmEzWofqUPMyFyh9r4n2rw134c8rKfqqUK44mZqA6JE`）4 relayer / num_trees=1 / 手续费均为 0。**该攻击面主网无实质资金**，即使条件成立也无损可失。

保留为信息项: position 池的账本（PDA balance vs total_balance vs 物理 vault）没有链上回退机制把 PDA 余额绑定到其所跟踪 note 的价值，依赖电路健全性 + vault 余额上限；若未来开启 `swap_fee_bps > 0`，`pos_pda.balance = dest_amount` 与 `total_balance += dest_amount − fee` 会产生小额"空气"导致全仓 close 受阻（活性问题，非盗取）。

## 排除论证（只读核验）

- 双花: nullifier marker `init` + `is_spent` 双保险，全路径一致。✅
- Replay: 证明绑定 root/ext_data_hash/mint/nullifier/commitment/deadline，nullifier 一次性。✅
- PDA seed / 非规范域元素: `require_canonical`（AUDIT-001，链上 ELF 已核）。✅
- Merkle 边界: `next_index < 2^height`、容量检查、root 在 256 条历史内；仅 liveness 影响。✅
- CPI 安全: swap 程序白名单 + 账户/位置检查 + `dex_amount_in == swap_amount` + `vault_amount >= dest_amount` + `SwapLeftoverTokens`。✅
- 金额/费用: u128 checked 运算；fee 上限、`fee + refund <= withdrawal_amount`、`min_valid_withdrawal`。✅
- 授权: 取现/退出 claimant 联签；merge 双输入 `has_one = claimant`。✅
- Vault 对账: USDC vault == TVL（314,948,948）精确一致；SOL vault 盈余 ≈0.42 SOL 锁死（信息项）。✅

## 链上证据（只读，主网，2026-08-09）

- ProgramData `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3`：last_deployed_slot 432,860,998；upgrade_authority `cu82g8m9evMKYFyedsrfr789bz5kgKpqyssNwKfjayR`；ELF sha256 `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb`（与 AUDIT.md 一致）。
- 主池 USDC/SOL 有真实 TVL（314,948,948 / 4,924,854,492；树 next_index 1228 / 4746）。
- position 池：config `FjmEz…`（4 relayer / 1 树 / 费用 0）；树 `B5tqSDVy…` next_index=35；12 个主流 mint 的 `position_vault_v1` 全部不存在 → position 面主网无实质 TVL。

## 仍缺的工件（决定审计上限）

1. circuit 源码与 r1cs/zkey 及 trusted-setup 笔录（仓库无；`zk/` 被 gitignore；npm/GitHub 代码搜索截至 2026-08-09 未公开）。
2. 可复现构建流程与 ELF 对比。
3. relayer 密钥管理与押金策略。

以上限制不影响 H2/H3 两个无条件、代码级结论。

## 联系方式 / 打款

- 邮箱: shopqwphvuhc@web-library.net
- Solana (USDC): 6HfLRFR6B2y1jgzVVF6inCzvd7kKSaW55nTiACJDyQJV
- EVM: 0x677e39F988135F5F10Db6a0Eb329CDC05D7c0946
