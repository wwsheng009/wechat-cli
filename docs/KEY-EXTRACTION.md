# Windows 数据库密钥提取（在线、无 Hook、不重启微信）

- 适用：Windows x64，微信 4.x
- 入口：`wechat-cli init`
- 代码：`wechat_cli/keys/scanner_windows.py`、`wechat_cli/keys/common.py`
- 状态：`4.1.15.56`、`4.2.0.13` 已实测通过
- 提交：`51c060c`（raw 内存扫描）、`5c0d949`（版本检测）

## 1. 结论

`wechat-cli` 在 Windows 上**不需要 Hook，也不需要重启微信**。微信已经登录、`Weixin.exe` 正在运行时，直接读取进程内存即可提取数据库 key。

它不会修改微信：

- 只使用 `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)`
- 只使用 `ReadProcessMemory`
- 不注入 DLL、不设置断点、不修改指令、不写微信进程内存

## 2. 版本检测

版本不是从数据目录猜的，而是从运行中的 `Weixin.exe` 读取：

1. `QueryFullProcessImageNameW` 获取进程可执行文件路径；
2. `GetFileVersionInfoW` / `VerQueryValueW` 读取文件版本；
3. 同时检查安装目录下的 `Weixin.dll`、`WeChat.dll`，取较高版本。

输出示例：

```text
[+] 微信版本: 4.2.0.13 (profile=lfh-0x40, 已验证)
[+] Weixin.exe: C:\Program Files\Tencent\Weixin\Weixin.exe
```

已验证的 raw 布局：

```python
VERIFIED_RAW_VERSIONS = {
    (4, 1, 15, 56): "lfh-0x40",
    (4, 2, 0, 13): "lfh-0x40",
}
```

版本与后端顺序：

| 微信版本 | `auto` 顺序 | 说明 |
|---|---|---|
| `>= 4.1.15` | **raw → hex** | 已验证版本直接走 raw，跳过 4 秒的 hex 扫描 |
| `< 4.1.15` | hex → raw | 低版本优先尝试旧 `x'<hex>'` 格式 |
| 读不到版本 | hex → raw | 打印告警，仍尝试 |

未在表中的新版本：

- 打印“未验证”告警；
- 仍然尝试 raw/hex；
- 只有通过 page-1 HMAC 校验才会输出 key，**不会因为布局变化写错 key**；
- 如果两种后端都没命中，错误信息会带上版本号，提示升级算法。

示例：

```text
[!] 微信版本: 4.3.0.1 未验证；当前算法仅验证过 4.1.15.56 / 4.2.0.13，
    仍会尝试，失败时需要升级算法
```

## 3. 算法：目录 + 内存

### 3.1 目录只提供 salt 和校验样本

`common.collect_db_files(db_dir)`：

- 递归遍历 `db_dir` 下的 `.db`；
- 跳过 `-wal`、`-shm`、`.db.factory` 迁移临时副本；
- 每个库读取第一页 4096 字节；
- `salt = page1[:16]`；
- 建立 `salt → 数据库文件列表` 的映射。

目录本身**不能推导出 key**，只提供 salt 和 page-1 HMAC 校验数据。

### 3.2 在 `Weixin.exe` 内存中找 raw key

新版微信（实测 4.1.15.56 / 4.2.0.13）把 key 存成裸 32 字节，而不是 `x'<hex>'`。

按 Windows LFH 堆块定位：

```text
8 字节块头 | 32 字节 key | 16 字节零 | 8 字节元数据 | 下一个块头
```

块头尾部特征（实测）：

```text
... 00 80
... 00 90
```

候选筛选条件：

- 32 字节 payload 不是全零；
- 可打印 ASCII 字节少于 24 个；
- 不同字节数至少 12；
- 后面 16 字节全零；
- 前后块头尾部都是 `00 80` 或 `00 90`。

### 3.3 两阶段扫描

1. **标记区域优先**
   - 只读 `MEM_PRIVATE` 且包含 WCDB 标记的私有内存区域：
     - `encrypt_key:32`
     - `encrypted:1`
   - 实测：5 个区域、14–17 MB、148–159 个候选、约 0.6–0.9 秒。

2. **全部私有内存回退**
   - 标记区域没有命中时，扫描所有 `MEM_PRIVATE` 可读区域；
   - 候选约 1,000+ 个，提取约 6 秒。

不会做全内存 32 字节滑窗：实测“32 字节 + 零填充”有 36 万个候选，单个候选 PBKDF2 约 130 ms，单线程需要十几小时，不可行。

### 3.4 校验

每个候选按 SQLCipher 4 规则校验：

```text
enc_key = PBKDF2-HMAC-SHA512(raw_key, salt, 256000, 32)
mac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)
HMAC-SHA512(page1[16:4032] + page_no=1) == page1[4032:4096]
```

对应代码：

```python
from .common import derive_enc_key, verify_raw_key
```

注意：`verify_enc_key(enc_key, page1)` 校验的是**已经过 256,000 轮的 enc_key**；裸 key 必须使用 `verify_raw_key(raw_key, page1)`。

候选校验使用线程池，默认 `min(16, CPU 数)`。

## 4. 实测性能

当前机器：微信 4.2.0.13，已登录，未重启。

```text
[+] 微信版本: 4.2.0.13 (profile=lfh-0x40, 已验证)
[*] raw 标记区域: 5 区域, 14MB, 148 个候选, 0.9s
[*] 校验 148 个 raw 候选 (probe=contact\contact.db, workers=16)
  [MATCH] PID=30284 ADDR=0x1ABA602FA30 key_sha256=a212a2ed2594fcbb
raw 校验完成: 1 个匹配, 5.6s
结果: 28/28 salts 找到密钥
```

- raw 模式总耗时约 **7 秒**
- `auto` 在已验证版本上直接 raw，约 **7 秒**
- 旧 hex 扫描约 4 秒（`4.1.15+` 通常 0 命中）
- 标记区域失败后回退全私有内存，约 **40 秒**

## 5. 使用方式

```bash
# 默认 auto：按版本选择
wechat-cli init --force

# 最快：只走裸 32 字节内存扫描
wechat-cli init --force --mode raw

# 只走旧版 x'<hex>' 格式
wechat-cli init --force --mode hex
```

指定数据目录：

```bash
wechat-cli init --force \
  --db-dir "D:/微信聊天/xwechat_files/wwsheng000_d1d1/db_storage"
```

`--mode` 仅 Windows 生效；macOS/Linux 使用各自的内存扫描实现。

## 6. 失败排查

| 现象 | 原因 / 处理 |
|---|---|
| `Weixin.exe 未运行` | 先启动并登录微信；不需要重启 |
| `OpenProcess` 失败 / `ACCESS_DENIED` | 以管理员权限运行终端；关闭拦截安全软件；确保微信不是以更高权限运行 |
| 版本显示 `未验证` | 算法尚未覆盖该版本；保留版本号，按第 7 节升级 |
| `hex 模式匹配 0 个` | `4.1.15+` 正常现象，key 是裸 32 字节；使用 `raw`/`auto` |
| `raw 候选校验未命中` | 版本布局变化、`db_dir` 不属于该账号，或 key 已轮换 |
| 结果 `27/28`、某个库 `MISSING` | 该库可能使用不同 key、已损坏，或不是活动库；检查是否 `.db.factory` 临时副本 |
| 多个账号 | 每个账号目录单独跑；`db_dir` 指向对应账号的 `db_storage` |

## 7. 新版本适配流程

1. 先跑：

   ```bash
   wechat-cli init --force --mode raw
   ```

2. 如果成功：
   - 说明 raw 布局仍然兼容；
   - 把版本元组加入 `VERIFIED_RAW_VERSIONS`；
   - 提交时记录实测版本和结果。

3. 如果失败：
   - 保留版本号、`hex 模式匹配 N 个`、`raw 候选校验未命中` 日志；
   - 检查 WCDB 标记是否仍为 `encrypt_key:32` / `encrypted:1`；
   - 检查 LFH 块大小是否仍为 `0x40`、块头尾部是否仍为 `00 80/00 90`；
   - 如果布局变化，更新 `_iter_raw_candidates()` 的块布局/特征；
   - 不要退回 Hook 作为默认方案，除非内存扫描确实无法覆盖。

## 8. 安全

- `all_keys.json` 包含明文 raw key，默认位于 `~/.wechat-cli/`；
- 不要把该文件提交到 git、发到聊天或工单；
- 日志中的 `enc_key` 已打码（`<redacted>`）；
- 建议给 `~/.wechat-cli/` 设置用户级 ACL；
- 提取过程只读微信内存和数据库 page 1，不写回微信数据目录。

## 9. 代码地图

| 文件 | 作用 |
|---|---|
| `wechat_cli/keys/scanner_windows.py` | 进程/版本检测、hex 后端、raw 后端、并行校验 |
| `wechat_cli/keys/common.py` | SQLCipher KDF/HMAC、目录 salt 采集、结果保存 |
| `wechat_cli/commands/init.py` | `init --mode auto|hex|raw` |
| `wechat_cli/keys/__init__.py` | 按平台分发 |

关键函数：

- `_detect_wechat_version()` / `_file_version()`
- `_backend_order()`
- `_iter_raw_candidates()`
- `_collect_raw_candidates()`
- `_validate_raw_candidates()`
- `derive_enc_key()` / `verify_raw_key()`
