# Task 264 — AEAD 截断标签与解密失败的明文隔离

仓库：`0264-libgcrypt-2-79fbbdbb`（分支 `task/264`，基线 `f31c4bf` "random:csprng: Fix clearing KEYPOOL"）
日期：2026-11-22
范围：`cipher/cipher.c`、`cipher/cipher-{gcm,ccm,eax,ocb,poly1305,siv,gcm-siv}.c`、`doc/gcrypt.texi`、`tests/basic.c`、`tests/bench-slope.c`

---

## 1. 问题陈述（改动前的实测结果）

在改动前的代码上（本机独立构建 + 探针程序实测）确认了以下缺陷：

| # | 触发方式 | 改动前结果 |
|---|---|---|
| D1 | 任意 AEAD 模式 `checktag(h, NULL, 16)` | **进程段错误（SIGSEGV）**：模式实现直接 `buf_eq_const(NULL, ...)` |
| D2 | `checktag(h, tag, 0)`（EAX） | **返回成功**：零长度比较恒等，等于关闭认证 |
| D3 | 截断/超长标签长度 | 语义分裂：GCM/CCM/CMAC 返回 `GPG_ERR_INV_LENGTH`，而 EAX/Poly1305/OCB/SIV/GCM-SIV 返回 `GPG_ERR_CHECKSUM`，调用方无法区分“标签长度非法”和“认证失败” |
| D4 | 解密成功后再 `checktag` 失败 | 调用方输出缓冲区中仍保留完整明文（CCM/EAX/GCM/OCB/Poly1305），忽略返回值的调用方会直接使用未认证明文 |
| D5 | 解密调用自身失败（如 `outsize < inlen`、AESWRAP `CHECKSUM`、SIV `INV_STATE`） | `_gcry_cipher_decrypt` 无 failsafe，明文留在 `out`（`_gcry_cipher_encrypt` 早有此 failsafe，解密侧缺失） |
| D6 | `checktag(h, tag, <非法长度>)` 之后再 `checktag(h, tag, <正确长度>)` | 部分模式已在非法请求中推进/终结了内部状态，重试结果不稳定 |

## 2. 设计原则

1. **参数与长度校验前置**：任何会终结/推进认证状态的模式实现，都在最前面做 NULL 与长度校验，非法请求不改动上下文状态，因此可以安全重试（对应 D2/D3/D6）。
2. **长度错误 ≠ 认证失败**：长度不合法统一 `GPG_ERR_INV_LENGTH`；`NULL` 指针统一 `GPG_ERR_INV_ARG`；只有“长度合法但内容不匹配”才返回 `GPG_ERR_CHECKSUM`（对应 D3）。
3. **失败绝不外泄明文**：`_gcry_cipher_decrypt` 在返回错误时把可被写入的输出区间覆写为非明文图案（`0x42`，与加密侧 failsafe 一致），用 `wipememory2` 落盘防止被优化掉（对应 D5）。
4. **保持既有兼容面**：`gettag` 对“输出缓冲区大于标签”的既有宽容（GCM/Poly1305/EAX/GCM-SIV 写满标签长度）保持不变；GCM/EAX 的合法截断标签仍然接受；测试向量全部通过。
5. **不以跨调用指针记账换取隔离**：曾尝试在句柄中记住 `decrypt` 的输出区间、在 `checktag` 失败时回擦，但这要求句柄保存调用方缓冲区的原始指针。调用方完全可以在 `decrypt` 与 `checktag` 之间释放/复用该缓冲区，回擦会变成 use-after-free / 破坏无关内存。该方案在实现后被判定为**更危险**，已回退；D4 因此以“文档明确契约 + 单次调用内 failsafe”处理（见 §5）。

## 3. 关键边界（供评审直接复核）

### 3.1 统一入口校验（`cipher/cipher.c`）

| 边界 | 位置 | 行为 |
|---|---|---|
| `authenticate(h, NULL, n>0)` | `cipher.c:1466` | `GPG_ERR_INV_ARG`（零长度 AAD 仍是合法 no-op） |
| `gettag(h, NULL, n)` | `cipher.c:1492` | `GPG_ERR_INV_ARG` |
| `gettag(h, p, 0)` | `cipher.c:1494` | `GPG_ERR_INV_LENGTH` |
| `checktag(h, NULL, n)` | `cipher.c:1520` | `GPG_ERR_INV_ARG`（消除 D1 段错误） |
| `checktag(h, p, 0)` | `cipher.c:1522` | `GPG_ERR_INV_LENGTH`（消除 D2 认证绕过） |
| `decrypt(...)` 返回错误 | `cipher.c:1324` | 覆写 `out[0 .. min(inlen,outsize))` 为 `0x42`（D5） |

### 3.2 各模式标签长度规则

| 模式 | 合法 `taglen`（check/get） | 非法长度返回 | 关键代码 |
|---|---|---|---|
| GCM | 16 或截断 4/8/12/13/14/15（`gettag` 允许缓冲区 ≥16） | `INV_LENGTH` | `cipher-gcm.c:1233,1286` |
| EAX | 1..blocksize（截断为前缀比较；`gettag` 允许缓冲区更大） | `INV_LENGTH` | `cipher-eax.c:243,245` |
| CCM | 恰为初始化时声明的 `authlen`（4/6/8/10/12/14/16） | `INV_LENGTH` | `cipher-ccm.c:274` |
| OCB | 恰为 `GCRYCTL_SET_TAGLEN` 设定值（8/12/16） | `INV_LENGTH` | `cipher-ocb.c:755` |
| Poly1305 | 恰为 16 | `INV_LENGTH`（`gettag` 缓冲区过小仍是 `BUFFER_TOO_SHORT`） | `cipher-poly1305.c:260` |
| SIV | 恰为 16 | `INV_LENGTH` | `cipher-siv.c:356` |
| GCM-SIV | 恰为 16 | `INV_LENGTH` | `cipher-gcm-siv.c:605` |
| CMAC | 1..blocksize（既有行为，未改动） | `INV_LENGTH` | `cipher-cmac.c:221` |

### 3.3 状态切换 / 重入 / 异常输入

| 场景 | 期望 | 实测 |
|---|---|---|
| `checktag` 在 `decrypt` 之前 | 不做推进，返回 `CHECKSUM`（GCM 空上下文） | 一致 |
| 非法长度 `checktag` 之后再用正确长度 | 接受 | 一致（校验前置，状态未动） |
| 错误标签之后再用正确标签 | `CHECKSUM` → 成功 | 一致（`checktag` 不终结状态） |
| `gettag` 重复调用 | 幂等，均成功 | 一致 |
| `gettag` 之后再 `decrypt` | `INV_STATE` | 一致 |
| `reset` 后 `checktag` | 回到初始态，`CHECKSUM` | 一致 |
| `setiv` 重复调用（OCB/GCM） | 均成功并重置 | 一致 |
| 分块解密中途某块失败 | 仅失败块被 `0x42` 覆盖，之前成功块不动 | 一致 |
| 全量合法加密/解密 + `checktag` | 明文完整往返、无污染 | 一致 |

## 4. 测试与可复核方式

新增 `tests/basic.c::check_aead_tag_boundaries`（在 `check_cipher_modes` 中调用）覆盖 GCM/EAX/OCB/Poly1305/CCM：

- 对每种模式加密取标签，然后逐项断言：`NULL` 标签→`INV_ARG`；0 长度→`INV_LENGTH`；截断标签在允许模式下接受、否则 `INV_LENGTH`；非法请求后正确标签仍被接受；错误标签→`CHECKSUM`；短输出缓冲区解密→`BUFFER_TOO_SHORT` 且输出中不出现明文。
- FIPS 模式下跳过 ChaCha20/Poly1305 与 GCM（GCM 在 FIPS 下通过 `setiv` 直接给 IV 会拒绝加密，既有行为）。

`tests/bench-slope.c` 的 AEAD 基准改用 `GCRYCTL_GET_TAGLEN` 取真实标签长度（64 位块密码的 EAX 标签为 8 字节，原先硬编码 16 会在新语义下得到 `INV_LENGTH`）。

复核命令（本机实测，独立构建目录 `/tmp/264-build`）：

```sh
./autogen.sh
mkdir build && cd build
PATH=/srv/fb2/mei8085/tasks/258/local/prefix/bin:$PATH \
  ../configure --disable-doc --enable-maintainer-mode \
  --with-libgpg-error-prefix=/srv/fb2/mei8085/tasks/258/local/prefix
make -j12
make check                     # 41 个测试程序全部 PASS
tests/basic --cipher-modes     # 含新边界用例
tests/basic --fips             # FIPS 路径
```

## 5. 队列影响记录（最终核对）

本仓库为 C 库，无内部工作队列/消息队列抽象；“队列”在此按**调用序列与内部解密流水线的排队影响**记录：

| 影响面 | 结论 |
|---|---|
| 单句柄调用顺序 | 长度/NULL 校验前置，非法请求不改变排队中的状态；`checktag`→`decrypt`→`gettag` 的合法序列结果不变。 |
| 分块解密流水线 | 失败块被 `0x42` 覆盖，已成功入队的先前分块保持原样，不做跨调用回擦（避免持有调用方指针导致的悬垂写，见 §2 第 5 点）。 |
| 延迟认证的明文队列 | `decrypt` 已产出的明文在 `checktag` 成功前属于“未认证队列”。本库不跨调用保存这些缓冲区的指针，因此不做回擦；契约在 `doc/gcrypt.texi`（`gcry_cipher_checktag`、`gcry_cipher_decrypt`）中明确：`checktag` 返回 `CHECKSUM` 时调用方必须丢弃明文。 |
| 线程/重入 | 所有改动均为句柄局部状态，无全局队列；校验前置不会在错误路径上留下待处理状态。 |
| 性能 | 正常路径仅增加常数级判空/长度比较；failsafe 仅在错误路径执行。bench-slope 实测无回归。 |
| 兼容性 | 合法测试向量、`gettag` 大头缓冲、GCM/EAX 截断标签、CMAC 既有多长度行为均保持；仅把“原本会崩溃/静默成功/错误码含混”的异常路径改为可区分的稳定错误。 |

## 6. 已知取舍与验证缺口

- **D4 未做跨调用回擦**（见 §2 第 5 点）：跨 `decrypt`/`checktag` 的明文隔离依赖调用方遵守 `checktag` 返回值契约，已在文档中明确；这是为避免 use-after-free 的刻意取舍。
- 未新增独立的 `t-*` 测试文件，边界用例并入既有 `tests/basic.c`（沿用仓库测试布局）。
- 64 位块密码的 EAX 截断标签（`taglen ∈ 1..8`）行为经 `GET_TAGLEN` 修正的基准验证，但未单独新增向量级用例。
- 未在非 x86 平台实测（仅本机 x86_64 构建与 `make check`）。
