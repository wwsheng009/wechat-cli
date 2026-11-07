"""Windows 密钥提取 — 扫描 Weixin.exe 进程内存。

两条后端：

- ``hex``：旧版微信在内存里保存 ``x'<64~192 hex>'``，直接正则匹配；
- ``raw``：新版微信（实测 4.1.15.56）保存裸 32 字节 key。按 Windows
  LFH 0x40 字节堆块定位：8 字节块头 + 32 字节 key + 16 字节零 +
  8 字节元数据 + 下一个块头。

``raw`` 先只扫包含 WCDB ``encrypt_key:32`` / ``encrypted:1`` 标记的区域，
通常只有几个区域、百余个候选；找不到再回退到所有私有内存区域。
校验使用 ``verify_raw_key``（PBKDF2 256,000 轮 + page-1 HMAC），
不会把裸 key 当成已经派生过的 enc_key。
"""

import concurrent.futures
import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import re
import subprocess
import time

from .common import (
    collect_db_files,
    cross_verify_keys,
    save_results,
    scan_memory_for_keys,
    verify_raw_key,
)

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

RAW_MARKERS = (b"encrypt_key:32", b"encrypted:1")
ZERO16 = b"\x00" * 16
ZERO32 = b"\x00" * 32

# 已验证的 raw 布局。微信升级后先在这里加版本；未列出的版本会告警并尝试，
# 扫描失败时错误信息会带上版本号，提示升级算法。
VERIFIED_RAW_VERSIONS = {
    (4, 1, 15, 56): "lfh-0x40",
    (4, 2, 0, 13): "lfh-0x40",
}
RAW_FLOOR = (4, 1, 15)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ("dwSignature", wt.DWORD),
        ("dwStrucVersion", wt.DWORD),
        ("dwFileVersionMS", wt.DWORD),
        ("dwFileVersionLS", wt.DWORD),
    ]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def _get_pids():
    """返回所有 Weixin.exe 进程的 (pid, mem_kb) 列表，按内存降序。"""
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True)
    pids = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            try:
                pid = int(p[1])
                mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            except ValueError:
                continue
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    pids.sort(key=lambda x: x[1], reverse=True)
    for pid, mem in pids:
        print(f"[+] Weixin.exe PID={pid} ({mem // 1024}MB)")
    return pids


def _get_process_path(pid):
    """QueryFullProcessImageNameW; needs QUERY_LIMITED_INFORMATION."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wt.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value or None
        return None
    finally:
        kernel32.CloseHandle(h)


def _file_version(path):
    """Read the fixed file version (major, minor, build, revision)."""
    if not path or not os.path.isfile(path):
        return None
    version = ctypes.windll.version
    handle = wt.DWORD(0)
    size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(handle))
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, buf):
        return None
    ptr = ctypes.c_void_p()
    length = wt.UINT(0)
    if not version.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
        return None
    if not ptr.value or length.value < ctypes.sizeof(VS_FIXEDFILEINFO):
        return None
    info = ctypes.cast(ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    ms, ls = info.dwFileVersionMS, info.dwFileVersionLS
    return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)


def _version_text(version):
    return ".".join(str(part) for part in version) if version else "unknown"


def _detect_wechat_version(pids):
    """Return (version_tuple, exe_path) for the running WeChat process."""
    seen = set()
    for pid, _mem_kb in pids:
        exe = _get_process_path(pid)
        if not exe or exe.lower() in seen:
            continue
        seen.add(exe.lower())
        candidates = [exe]
        install_dir = os.path.dirname(exe)
        for name in ("Weixin.dll", "WeChat.dll"):
            candidate = os.path.join(install_dir, name)
            if os.path.isfile(candidate):
                candidates.append(candidate)
        versions = [v for v in (_file_version(p) for p in candidates) if v]
        if versions:
            return max(versions), exe
    return None, None


def _backend_order(version, mode):
    """Choose backend order; explicit mode is honored verbatim."""
    if mode in ("hex", "raw"):
        return [mode]
    if version is None:
        print("[!] 未能读取微信版本，按 hex -> raw 顺序尝试")
        return ["hex", "raw"]
    if version >= RAW_FLOOR:
        return ["raw", "hex"]
    return ["hex", "raw"]


def _read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def _enum_regions(h, private_only=False):
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect in READABLE
            and 0 < mbi.RegionSize < 500 * 1024 * 1024
            and (not private_only or mbi.Type == MEM_PRIVATE)
        ):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def _header_ok(header):
    """LFH 块头尾部：byte6=0, byte7=0x80/0x90（实测 4.1.15.56）。"""
    return len(header) == 8 and header[6] == 0 and header[7] in (0x80, 0x90)


def _iter_raw_candidates(data):
    """Yield (offset, 32-byte raw key) from 0x40-byte LFH blocks."""
    for needle in (b"\x00\x80", b"\x00\x90"):
        pos = 0
        while True:
            p = data.find(needle, pos)
            if p < 0:
                break
            pos = p + 1

            off = p - 6 + 8  # header start + 8-byte header
            if off < 8 or off + 0x40 > len(data):
                continue

            buf = data[off:off + 32]
            if buf == ZERO32:
                continue
            if data[off + 32:off + 48] != ZERO16:
                continue
            if sum(1 for b in buf if 32 <= b < 127) >= 24:
                continue
            if len(set(buf)) < 12:
                continue
            if not _header_ok(data[off - 8:off]):
                continue
            # 0x40-byte block: next header starts at off + 0x38
            if not (data[off + 0x3E] == 0 and data[off + 0x3F] in (0x80, 0x90)):
                continue
            yield off, buf


def _scan_hex(db_files, salt_to_dbs, pids):
    """旧版内存 hex 扫描，返回 (key_map, hex_match_count)。"""
    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid_val, _mem_kb in pids:
        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid_val)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid_val}，跳过")
            continue
        try:
            regions = _enum_regions(h)
            total_bytes = sum(s for _, s in regions)
            total_mb = total_bytes / 1024 / 1024
            print(f"\n[*] hex 扫描 PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

            scanned_bytes = 0
            for reg_idx, (base, size) in enumerate(regions):
                data = _read_mem(h, base, size)
                scanned_bytes += size
                if not data:
                    continue

                all_hex_matches += scan_memory_for_keys(
                    data, hex_re, db_files, salt_to_dbs,
                    key_map, remaining_salts, base, pid_val, print,
                )

                if (reg_idx + 1) % 200 == 0:
                    elapsed = time.time() - t0
                    progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
                    print(
                        f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                        f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
                    )
        finally:
            kernel32.CloseHandle(h)

        if not remaining_salts:
            print("\n[+] 所有密钥已找到，跳过剩余进程")
            break

    print(f"\nhex 扫描完成: {time.time() - t0:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex模式")
    return key_map, all_hex_matches


def _collect_raw_candidates(pids, marked_only):
    """Collect unique raw 32-byte candidates as {hex: (pid, address)}."""
    found = {}
    regions_seen = 0
    bytes_seen = 0
    t0 = time.time()

    for pid_val, _mem_kb in pids:
        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid_val)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid_val}，跳过")
            continue
        try:
            for base, size in _enum_regions(h, private_only=True):
                data = _read_mem(h, base, size)
                if not data:
                    continue
                if marked_only and not any(marker in data for marker in RAW_MARKERS):
                    continue
                regions_seen += 1
                bytes_seen += len(data)
                for off, buf in _iter_raw_candidates(data):
                    found.setdefault(buf.hex(), (pid_val, base + off))
        finally:
            kernel32.CloseHandle(h)

    scope = "标记区域" if marked_only else "全部私有内存"
    print(
        f"\n[*] raw {scope}: {regions_seen} 区域, {bytes_seen / 1024 / 1024:.0f}MB, "
        f"{len(found)} 个候选, {time.time() - t0:.1f}s"
    )
    return found, regions_seen, bytes_seen


def _check_raw_candidate(payload):
    key_hex, page1 = payload
    try:
        return key_hex, verify_raw_key(bytes.fromhex(key_hex), page1)
    except Exception:
        return key_hex, False


def _validate_raw_candidates(found, db_files, workers=None):
    """Validate candidates in parallel; return {salt_hex: raw_key_hex}."""
    if not found or not db_files:
        return {}, 0

    probe = next(
        (item for item in db_files if item[0].replace("\\", "/").endswith("contact/contact.db")),
        db_files[0],
    )
    probe_page1 = probe[4]
    workers = workers or min(16, os.cpu_count() or 4)
    print(f"[*] 校验 {len(found)} 个 raw 候选 (probe={probe[0]}, workers={workers})")

    t0 = time.time()
    matched = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_raw_candidate, (key_hex, probe_page1)) for key_hex in found]
        for fut in concurrent.futures.as_completed(futures):
            key_hex, ok = fut.result()
            if ok:
                pid, addr = found[key_hex]
                matched.append(key_hex)
                print(
                    f"  [MATCH] PID={pid} ADDR=0x{addr:X} "
                    f"key_sha256={hashlib.sha256(key_hex.encode()).hexdigest()[:16]}"
                )

    print(f"raw 校验完成: {len(matched)} 个匹配, {time.time() - t0:.1f}s")

    key_map = {}
    for key_hex in matched:
        raw_key = bytes.fromhex(key_hex)
        for _rel, _path, _size, salt_hex, page1 in db_files:
            if verify_raw_key(raw_key, page1):
                key_map[salt_hex] = key_hex
    return key_map, len(matched)


def _scan_raw(db_files, pids, workers=None):
    """标记区域优先；没有结果再回退到全部私有内存。"""
    for marked_only in (True, False):
        found, _regions, _bytes = _collect_raw_candidates(pids, marked_only=marked_only)
        if not found:
            continue
        key_map, _matched = _validate_raw_candidates(found, db_files, workers=workers)
        if key_map:
            return key_map
    return {}


def extract_keys(db_dir, output_path, pid=None, mode="auto", workers=None):
    """提取 Windows 微信数据库密钥。

    Args:
        db_dir: 微信数据库目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定 PID（默认自动检测所有 Weixin.exe）
        mode: ``auto``（按版本选 raw/hex 顺序）、``hex``、``raw``
        workers: raw 校验线程数（默认 min(16, CPU 数)）

    Returns:
        dict: salt_hex -> raw_key_hex 映射
    """
    if mode not in ("auto", "hex", "raw"):
        raise ValueError(f"不支持的 mode: {mode}")

    print("=" * 60)
    print("  提取所有微信数据库密钥")
    print("=" * 60)

    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 下没有找到可读的 .db 文件")
    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    pids = _get_pids() if pid is None else [(pid, 0)]
    version, exe_path = _detect_wechat_version(pids)
    profile = VERIFIED_RAW_VERSIONS.get(version)
    if version:
        if profile:
            print(f"[+] 微信版本: {_version_text(version)} (profile={profile}, 已验证)")
        else:
            print(
                f"[!] 微信版本: {_version_text(version)} 未验证；"
                "当前算法仅验证过 4.1.15.56 / 4.2.0.13，仍会尝试，失败时需要升级算法"
            )
    else:
        print("[!] 未能读取微信版本；仍会尝试，失败时需要检查权限或升级算法")
    if exe_path:
        print(f"[+] Weixin.exe: {exe_path}")

    hex_matches = 0
    key_map = {}
    for backend in _backend_order(version, mode):
        if backend == "hex":
            key_map, hex_matches = _scan_hex(db_files, salt_to_dbs, pids)
            if key_map:
                cross_verify_keys(db_files, salt_to_dbs, key_map, print)
                return save_results(db_files, salt_to_dbs, key_map, output_path, print)
            print("\n[!] hex 后端没有匹配到 key")
        elif backend == "raw":
            key_map = _scan_raw(db_files, pids, workers=workers)
            if key_map:
                return save_results(db_files, salt_to_dbs, key_map, output_path, print)
            print("\n[!] raw 后端没有匹配到 key")

    version_note = _version_text(version) if version else "unknown"
    if profile:
        raise RuntimeError(
            f"微信版本 {version_note} 已验证，但仍未提取到密钥；"
            f"hex 模式匹配 {hex_matches} 个，raw 候选校验未命中。"
            "请确认微信已登录、db_dir 属于该账号，并以管理员权限运行。"
        )
    raise RuntimeError(
        f"未能从微信版本 {version_note} 的内存中提取到密钥；"
        f"hex 模式匹配 {hex_matches} 个，raw 候选校验未命中。"
        "该版本尚未验证：请保留版本号和失败日志，升级内存布局算法后再试。"
    )
