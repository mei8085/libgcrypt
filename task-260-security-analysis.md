# Task 260 — 安全内存池释放与异常回收取证分析报告

仓库：`0260-libgcrypt-5-fc29bd2b`（分支 `task/260`，HEAD `f31c4bf` "random:csprng: Fix clearing KEYPOOL"）
分析日期：2026-11-22
范围：`src/secmem.c`、`src/stdmem.c`、`src/global.c`、`src/misc.c`、`src/g10lib.h`、`random/random-csprng.c`、`tests/t-secmem.c`、`doc/gcrypt.texi`

---

## 1. 数据流、状态转换与异常传播

### 1.1 正常释放路径（数据流）

```
gcry_free / xfree
  └─ _gcry_free (src/global.c:1112)          保存/恢复 errno
      └─ _gcry_private_free (src/stdmem.c:120)
          ├─ _gcry_private_is_secure (src/secmem.c:817)   ← 无锁遍历池链表
          │     命中 → _gcry_secmem_free (src/secmem.c:757)
          │       └─ _gcry_secmem_free_internal (src/secmem.c:718)
          │            1. ptr_into_pool_p 定位所属池（secmem.c:152，uintptr_t 比较）
          │            2. ADDR_TO_BLOCK 取 memblock_t 头，读 mb->size
          │            3. MB_WIPE_OUT 四遍擦除 0xff/0xaa/0x55/0x00（secmem.c:735-741）
          │               → wipememory2 (g10lib.h:409)
          │               → _gcry_fast_wipememory2 (misc.c:563)
          │               → explicit_bzero / explicit_memset / volatile 函数指针 memset_ptr (misc.c:38)
          │            4. stats_update 记账，清 MB_FLAG_ACTIVE
          │            5. mb_merge 合并相邻空闲块（secmem.c:222）
          └─ 未命中（非本库安全内存）→ 回退 libc free()（stdmem.c:130-134）
```

### 1.2 状态转换

| 状态变量 | 转换 | 位置 |
|---|---|---|
| `pooldesc_t.okay` | 0→1：`init_pool`（mmap 或 malloc 成功）；1→0：`_gcry_secmem_term` | secmem.c:439/451, secmem.c:869 |
| `memblock_t.flags` 的 `MB_FLAG_ACTIVE` | 置位：`mb_get_new`；清除：free_internal | secmem.c:249, secmem.c:746 |
| `mainpool.next` 溢出池链表 | 只增不减（term 除外）；插入前 `memory_barrier()` 保证无锁读者安全 | secmem.c:681-683 |
| `not_locked` / `show_warning` | mlock 失败时置位；FIPS 下 `not_locked` 直接拒绝分配 | secmem.c:357-358, secmem.c:612-617 |
| `disable_secmem` | `_gcry_secmem_init(0)` 时置位，此后 `init_pool` 触发 `log_bug` | secmem.c:544, secmem.c:393 |

### 1.3 异常回收路径（异常传播）

四条路径汇聚到 `_gcry_secmem_term`（secmem.c:846）——整池四遍擦除 → `munmap`/`free` → 清描述符：

1. `_gcry_fatal_error`（misc.c:83-97）：term 后 `abort()`。
2. `my_gpgrt_post_fatal_handler`（misc.c:126-136）：gpgrt 日志 FATAL/BUG 级别回调，`done` 标志防重入。
3. 旧式 log handler 收到 FATAL/BUG（misc.c:170-176）：term 后 `abort()`。
4. `GCRYCTL_TERM_SECMEM` 控制命令（global.c:578-581）：应用主动清理，文档（gcrypt.texi:758）声明此后池不可再用、非线程安全、可从信号处理器调用。

分配失败的异常传播：`gpg_err_set_errno(ENOMEM)` 返回 NULL（secmem.c:271, 608, 616）；xmalloc 系在 `do_malloc` 失败且 outofcore handler 返回 0 时走 `log_fatal`（global.c:1210-1245）→ 即路径 1/2，**OOM 也会触发整池擦除后 abort**。

### 1.4 KEYPOOL 修复（HEAD 提交 f31c4bf，GnuPG-bug-id 8567）

- `keypool` 与 `rndpool` 均按 `POOLSIZE + BLOCKLEN` 分配（random-csprng.c:290-295），尾部 `BLOCKLEN`(=64) 字节被 `mix_pool` 用作哈希暂存 `hashbuf = pool + POOLSIZE`（random-csprng.c:544）。
- 修复前 `read_pool` 只 `memset(keypool, 0, POOLSIZE)`，尾部 64 字节残留由池状态派生的哈希中间值；修复后擦除整个 `POOLSIZE + BLOCKLEN`（random-csprng.c:1073）。
- 数据流：`rndpool` → 拷贝+`ADD_VALUE` → `keypool` → `mix_pool(keypool)` → 逐字节读出给用户 → 整池清零。边界输入 `length > POOLSIZE` 在 random-csprng.c:985 触发 `log_bug` → 异常回收路径 → abort。

### 1.5 边界输入如何影响最终安全结论

- **分配尺寸 0**：`stdmem.c:86-91` 拒绝（EINVAL）；但直接调 `_gcry_secmem_malloc(0)` 会四舍五入为 0 并返回一个 0 字节 ACTIVE 块——内部 API 无防护。
- **mlock 失败**（EPERM/EAGAIN/ENOMEM/ENOSYS 被静默吞掉，secmem.c:343-359）：安全结论从"锁定+擦除"降级为"仅擦除"，仅一次性警告；FIPS 模式下则直接拒绝分配（结论变为"失败安全"）。
- **溢出池触发条件**：仅 `xhint || auto_expand` 且非 FIPS（secmem.c:643）——同样的分配请求在 FIPS 下失败、在非 FIPS 下落入**未锁定**的 malloc 池，边界输入（请求大小、调用入口 xmalloc vs malloc）直接改变数据落点与隔离等级。
- **指针归属判定**：`ptr_into_pool_p` 用 `[pool_addr, pool_addr+size)` 半开区间；不属于任何池的指针静默回退 libc `free()`，**不做任何擦除**——调用方若误判内存属性，敏感数据将无擦除释放。

---

## 2. 隔离效果核实（最终核对）

| 隔离机制 | 核实结果 | 证据 |
|---|---|---|
| 主池与堆隔离 | ✅ mmap `MAP_PRIVATE\|MAP_ANONYMOUS` 独立映射，失败回退 malloc | secmem.c:413-414, 446 |
| 主池防换出 | ✅ `mlock`；失败仅置 `not_locked` 并警告，**不阻断使用** | secmem.c:327, 343-359 |
| 溢出池隔离 | ⚠️ plain `malloc`，**不 mlock、不 mmap**，可换出到磁盘；文档自认（gcrypt.texi "memory might be swapped out"） | secmem.c:663 |
| 释放时擦除 | ✅ 四遍 0xff/0xaa/0x55/0x00，经 `explicit_bzero`/`explicit_memset`/volatile 函数指针，抗死存储消除 | secmem.c:735-741, misc.c:552-578, g10lib.h:400-418 |
| 终止时擦除 | ✅ `_gcry_secmem_term` 整池四遍擦除后 `munmap`/`free` | secmem.c:856-867 |
| 无锁读取一致性 | ✅ 溢出池插入用 `memory_barrier()` 保证 `pool->next` 发布顺序 | secmem.c:676-683, 822-828 |
| KEYPOOL 残留 | ✅（本提交修复）read_pool 整缓冲清零；⚠️ 但见 §3 缺口 G2 | random-csprng.c:1073 |

**结论**：主池的"锁定+隔离+擦除"三重保护成立；溢出池与 mlock 失败场景下隔离结论降级为"仅擦除"，且擦除无法对抗已发生的换出。

---

## 3. 已由代码证实的事实 / 推断 / 验证缺口

### 3.1 已证实事实（直接读码确认）

- F1：安全内存释放必经四遍擦除，且擦除原语抗编译器优化（secmem.c:735-741, misc.c:38,552-578）。
- F2：fatal/bug/TERM_SECMEM 四条异常路径均汇聚 `_gcry_secmem_term` 做整池擦除（misc.c:95,134,174; global.c:580）。
- F3：KEYPOOL 修复前尾部 BLOCKLEN(64) 字节不清零，该区间确被 `mix_pool` 写入哈希中间值（random-csprng.c:544, 1073）。
- F4：溢出池不锁定，FIPS 下禁用溢出池（secmem.c:643, 663）。
- F5：`_gcry_private_is_secure` 无锁遍历，依赖"池只增不减 + 内存屏障"两个不变式（secmem.c:817-834）。
- F6：`_gcry_secmem_term` 不持 `secmem_lock`，文档明示非线程安全（secmem.c:846, gcrypt.texi:758）。

### 3.2 推断（代码暗示但未完全证实）

- I1：**TERM_SECMEM 后的悬挂释放造成类型混淆/二次释放**。term 后 `okay=0`，对旧安全指针再调 `gcry_free`：`_gcry_private_is_secure` 返回 0 → `stdmem.c:130-134` 直接 libc `free(p)`。主池已 `munmap` → `free()` 一个非堆指针，glibc 堆元数据损坏；溢出池已 `free()` → double-free。文档只说"池不可再使用"，API 不报错也不防护。兼容面：应用在 atexit 做 TERM_SECMEM，而 C++ 静态析构/其他库的 atexit 若在其后释放 MPI/密钥即触发；注册顺序相反时问题潜伏。
- I2：**memblock 元数据无完整性保护**。`memblock_t` 头部（size/flags）与用户数据相邻，无 canary/magic。用户块越界写可篡改下一块 `size`；free 时按被篡改的 `size`（`int` 截断，secmem.c:722）擦除并 `mb_merge`/`mb_get_prev` 遍历 → 受控擦除范围、分配器元数据攻击，甚至 `mb_get_prev` 死循环（secmem.c:207-214 无界 while）。
- I3：`_gcry_rngcsprng_update_seed_file` 混合 keypool 并写种子文件后**不清除 keypool**（random-csprng.c:895-938），残留依赖下一次 `read_pool` 末尾的清零或 `close_fds` 的 xfree 擦除——KEYPOOL 修复未覆盖此路径的窗口期。

### 3.3 验证缺口

- G1：I1/I2 未在本环境动态复现（未构建库；容器不可用）。
- G2：I3 的窗口期长度取决于应用调用序列，未做动态测量。
- G3：`tests/t-secmem.c` 只覆盖分配/溢出/term 基本流程，**无** term 后释放、元数据损坏、realloc 缩小尾部残留等用例；文件内 FIXME（t-secmem.c:205-207）自认测试不足。
- G4：四遍擦除在 LTO 构建下 `explicit_bzero` 是否仍跨 TU 生效，未在本环境验证（glibc 提供强符号，预期安全，但未实测）。

---

## 4. 最易被忽略的一条攻击面及有限本地复核

**选取 I1（TERM_SECMEM 后悬挂释放 → 非堆指针 free/double-free）**：它处于"兼容面"与"攻击面"交叉点——API 契约只写在文档里，代码不防御；清理顺序这种部署细节即可触发，且触发后是堆元数据损坏这一可利用原语。

**有限本地复核方式**（无需完整构建）：

1. 静态复核（已执行，零成本）：
   ```sh
   grep -n "okay = 0" src/secmem.c          # term 清标志
   sed -n '120,135p' src/stdmem.c           # is_secure=0 → 裸 free()
   sed -n '1069,1077p' src/global.c         # _gcry_is_secure 无 term 后防护
   ```
2. 动态复核（约 30 行 reproducer，可选）：`gcry_control(GCRYCTL_INIT_SECMEM, 16384)` → `p = gcry_malloc_secure(64)` → `gcry_control(GCRYCTL_TERM_SECMEM)` → `gcry_free(p)`，在 ASAN 或 `MALLOC_CHECK_=3` 下运行，预期观察到 invalid free / double free 报告；用 gdb 在 `_gcry_private_free` 断点确认走入 libc `free` 分支。
3. 回归复核：`make check TESTS=t-secmem`（需 autoreconf+configure 构建），并在 t-secmem.c 的 `GCRYCTL_TERM_SECMEM` 之后补一个 `gcry_free` 悬挂指针用例验证 G3。

---

## 5. 总结

释放与异常回收的主干路径（四遍擦除 + 整池清零 + abort）在代码层面闭环，KEYPOOL 修复补齐了哈希暂存区的残留缺口。安全结论对边界输入敏感的点集中在三处：mlock 失败的静默降级、溢出池的无锁定隔离、以及 term 之后 API 不防御的悬挂释放。建议优先复核 I1（部署即可触发、后果为堆损坏），其次为 memblock 元数据加 magic 校验（I2）并评估 update_seed_file 后 keypool 的擦除窗口（I3）。
