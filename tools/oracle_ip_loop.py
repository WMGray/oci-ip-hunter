"""Oracle Cloud 预留公网 IPv4 质量筛选与测试桩延迟测速闭环工具。

模块化架构设计：
1. 功能一 (Quality Filter): 纯静态信誉与纯净度快筛（Scamalytics, IPPure, 黑名单等），
   完全不触碰任何云主机，支持防封号平滑休眠（Sleep + Jitter）与自动猎取；
2. 功能二 (Latency Probe): 基于常驻测试桩私网 IP（10.0.0.250）进行借壳真实链路测速，
   使用原生 ICMP 穿透本地代理 TUN，测量直连 RTT 与丢包率，绝不损坏生产主 IP；
3. 联动流水线 (Pipeline): 质量达标 -> 自动挂桩测速 -> 双优选锁定或安全销毁。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import oci  # noqa: E402

# 确保能同时找到 src 与 tools 模块
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for d in (current_dir, parent_dir, os.path.join(parent_dir, "src")):
    if d not in sys.path:
        sys.path.insert(0, d)

from src.client import OCIClient  # noqa: E402
from tools.ip_quality import (  # noqa: E402
    CompleteIPReport,
    analyze_ip,
    calculate_composite_score,
    print_comparative_table,
    print_report_card,
)

# 终端色彩常量
C_CYAN = "\033[36m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_GRAY = "\033[90m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


class AntiBanGuard:
    """防封号安全控制器：实现动态平滑休眠、随机抖动、配额熔断与 API 退避。"""

    @staticmethod
    def safe_sleep(
        base_seconds: float = 18.0,
        jitter_range: float = 5.0,
        reason: str = "规避 API 高频调用风控",
    ) -> None:
        """带随机抖动的安全休眠，模拟非规律性访问，规避行为模式检测。"""
        # 计算抖动：base_seconds ± jitter
        delta = random.uniform(-jitter_range, jitter_range)
        duration = max(3.0, round(base_seconds + delta, 1))
        print(
            f"{C_GRAY}[防封保护] {reason}，休眠 {duration} 秒 (含随机抖动)...{C_RESET}",
            end="",
            flush=True,
        )
        t_end = time.time() + duration
        while time.time() < t_end:
            remain = round(t_end - time.time(), 1)
            if remain <= 0:
                break
            time.sleep(min(1.0, remain))
        print(f"\r{C_GRAY}[防封保护] 冷却完毕，继续下一步操作。{' ' * 20}{C_RESET}")

    @staticmethod
    def handle_rate_limit(error: Exception) -> None:
        """遭遇 429 TooManyRequests 或限流时触发深度熔断冷却。"""
        err_str = str(error).lower()
        if "429" in err_str or "toomanyrequests" in err_str or "throttl" in err_str:
            cool_down = 90
            print(
                f"\n{C_RED}[风控警报] 检测到 OCI 触发 429 速率限制！{C_RESET}\n"
                f"{C_YELLOW}触发安全熔断机制，强制休眠 {cool_down} 秒冷却...{C_RESET}"
            )
            time.sleep(cool_down)

    @staticmethod
    def check_reserved_quota(client: OCIClient) -> Tuple[int, int]:
        """检查当前租户闲置 Reserved IP 数量（Always Free 限制通常为 2 个闲置）。"""
        ips = client.network.list_reserved_ips()
        idle_count = sum(1 for r in ips if r.get("is_idle"))
        total_count = len(ips)
        return idle_count, total_count


def evaluate_quality(rep: CompleteIPReport) -> Tuple[str, bool]:
    """多维度质量准入评估，包装 calculate_composite_score 返回文本与是否合格。"""
    score, bd, is_qualified = calculate_composite_score(rep)
    scam = bd["scam_val"]
    ipp_s = f"{bd['ipp_val']}%" if bd["ipp_val"] >= 0 else "--"
    stream_c = bd["stream_cnt"]

    if is_qualified:
        desc = (
            f"★ 极品钻石 IP [综合系数: {score}分] "
            f"(欺诈:{scam}分, IPPure:{ipp_s}, 流媒体:{stream_c}解)"
        )
        return desc, True

    reasons = []
    if scam >= 5:
        reasons.append(f"欺诈分偏高({scam}>=5)")
    if bd["ipp_val"] > 35:
        reasons.append(f"IPPure偏高({bd['ipp_val']}%>35%)")
    if stream_c < 4:
        reasons.append(f"流媒体不足({stream_c}<4)")
    if not rep.mail_sec.spamhaus_clean:
        reasons.append("黑名单上榜")

    reason_str = "、".join(reasons) if reasons else "未完全达标"
    desc = f"▲ 未达标 IP [综合系数: {score}分] ({reason_str})"
    return desc, False


def generate_vip_display_name(
    client: OCIClient, base_prefix: str = "vip-pure"
) -> str:
    """根据现有预留 IP 名称，自动生成下一个可用的语义名称（如 vip-pure-01）。"""
    existing = client.network.list_reserved_ips()
    names = {r.get("name") or "" for r in existing}
    for idx in range(1, 100):
        candidate = f"{base_prefix}-{idx:02d}"
        if candidate not in names:
            return candidate
    return f"{base_prefix}-{int(time.time())}"


def rename_reserved_ip(client: OCIClient, public_ip_id: str, new_name: str) -> None:
    """更新 OCI 预留公网 IP 的 display_name。"""
    import oci

    details = oci.core.models.UpdatePublicIpDetails(display_name=new_name)
    client.network_client.update_public_ip(public_ip_id, details)


# ==============================================================================
# 功能一：纯静态质量筛选与自动猎取 (Quality Filter)
# ==============================================================================


def allocate_and_analyze_ip(
    client: OCIClient,
    fast: bool = False,
    timeout: float = 8.0,
) -> Tuple[Dict[str, Any], CompleteIPReport]:
    """向 OCI 申请一个预留 IP 并执行多维信誉质检。"""
    tag = datetime.now().strftime("%Y%m%d-%H%M%S")
    disp_name = f"auto-qual-{tag}"

    print(f"\n{C_CYAN}[1/2] 正在向 Oracle Cloud 请求分配预留公网 IPv4...{C_RESET}")
    try:
        alloc = client.network.create_reserved_ip(display_name=disp_name)
    except Exception as e:
        AntiBanGuard.handle_rate_limit(e)
        raise

    target_ip = alloc["ip"]
    ip_ocid = alloc["id"]
    print(
        f"{C_GREEN}✓ 成功分配新预留 IP: {C_BOLD}{target_ip}{C_RESET} "
        f"{C_GRAY}(OCID: ...{ip_ocid[-12:]}){C_RESET}"
    )

    mode_name = "极速 HTTP" if fast else "深度全景"
    print(f"{C_CYAN}[2/2] 启动信誉质量体检引擎（{mode_name}）...{C_RESET}")
    t0 = time.time()
    try:
        rep = analyze_ip(target_ip, skip_ippure=fast, timeout=timeout)
    except Exception as e:
        print(f"{C_RED}IP 质检中断: {e}，正在释放...{C_RESET}", file=sys.stderr)
        client.network.delete_public_ip(ip_ocid)
        raise

    cost_s = round(time.time() - t0, 1)
    print(f"{C_GREEN}✓ 体检完成，耗时 {cost_s} 秒。{C_RESET}\n")
    return alloc, rep


def run_batch_hunt(
    client: OCIClient,
    batch_size: int = 5,
    max_batches: int = 10,
    target_count: int = 5,
    fast: bool = False,
    max_scam: int = 5,
    max_ippure: float = 35.0,
    min_streaming: int = 4,
    cooldown: float = 4.0,
    timeout: float = 15.0,
    naming_prefix: str = "vip-pure",
) -> List[Dict[str, Any]]:
    """5x5 批量优选摇号：每批申请 batch_size 个 IP，筛选三大黄金指标，

    累计收集并保留至少 target_count (默认 5) 个极品黄金 IP，
    达标的自动按序重命名为 vip-pure-01~05 并保留，未达标的立即秒删。
    """
    batch_size = min(max(1, batch_size), 10)
    max_batches = min(max(1, max_batches), 20)
    target_count = max(1, target_count)
    tot_tested = 0
    mode_lbl = "极速" if fast else "深度全景"

    # 预载租户中已存在的黄金达标 IP，避免重复摇号
    existing_all = client.network.list_reserved_ips()
    existing_vips = [
        {"ip": r["ip"], "id": r["id"], "display_name": r["name"]}
        for r in existing_all
        if (r.get("name") or "").startswith(f"{naming_prefix}-")
    ]
    retained_list: List[Dict[str, Any]] = list(existing_vips)

    print(
        f"\n{C_CYAN}====== 启动 Oracle 优选猎取 "
        f"(目标保留 {target_count} 个) ======{C_RESET}"
    )
    if existing_vips:
        print(
            f"{C_GREEN}>>> 检测到租户中已存有 {len(existing_vips)} 个黄金 IP:{C_RESET}"
        )
        for ev in existing_vips:
            print(f"    • {ev['display_name']}: {ev['ip']}")
        needed = max(0, target_count - len(retained_list))
        print(
            f"    当前累计保留: [{len(retained_list)}/{target_count}]，"
            f"本次只需再猎取 {needed} 个！\n"
        )
        if len(retained_list) >= target_count:
            print(
                f"{C_GREEN}租户已满足目标保留数量 ({target_count} 个)，"
                f"无需继续摇号！{C_RESET}\n"
            )
            return retained_list
    print(
        f"每批申请: {batch_size} 个 | 轮次上限: {max_batches} 轮 | "
        f"目标保留: {C_BOLD}{target_count} 个{C_RESET} | 模式: {mode_lbl}"
    )
    print(
        f"硬核门槛: 欺诈分 < {max_scam} | IPPure <= {max_ippure}% | "
        f"流媒体 >= {min_streaming} | 黑名单 0 标记"
    )
    print(
        f"自动命名: 达标黄金 IP 自动按序重命名为 "
        f"{naming_prefix}-01~{target_count:02d}\n"
    )

    for b_idx in range(1, max_batches + 1):
        print(
            f"\n{C_CYAN}>>> [批次 {b_idx}/{max_batches}] "
            f"正在批量申请分配 {batch_size} 个预留 IPv4...{C_RESET}"
        )
        alloc_list: List[Dict[str, Any]] = []
        for i in range(1, batch_size + 1):
            tag = datetime.now().strftime("%H%M%S")
            disp_name = f"hunt-{tag}-{i}"
            try:
                alloc = client.network.create_reserved_ip(display_name=disp_name)
                alloc_list.append(alloc)
                print(
                    f"  [{i}/{batch_size}] 分配候选 IP: {C_BOLD}{alloc['ip']}{C_RESET}"
                )
            except Exception as e:
                print(f"  [{i}/{batch_size}] 分配失败: {e}", file=sys.stderr)
                AntiBanGuard.handle_rate_limit(e)

        if not alloc_list:
            print(f"{C_RED}当前批次未能成功分配任何 IP，休眠后重试...{C_RESET}")
            AntiBanGuard.safe_sleep(cooldown * 2, reason="批次分配失败冷却")
            continue

        tot_tested += len(alloc_list)
        print(f"\n{C_CYAN}[批次 {b_idx}/{max_batches}] 正在执行质检...{C_RESET}")

        batch_results: List[
            Tuple[Dict[str, Any], CompleteIPReport, float, Dict[str, Any], bool]
        ] = []
        for idx, alloc in enumerate(alloc_list, 1):
            target_ip = alloc["ip"]
            print(
                f"  正在体检 [{idx}/{len(alloc_list)}] {target_ip} ... ",
                end="",
                flush=True,
            )
            t0 = time.time()
            try:
                rep = analyze_ip(target_ip, skip_ippure=fast, timeout=timeout)
                score, bd, is_qual = calculate_composite_score(
                    rep,
                    max_scam=max_scam,
                    max_ippure=max_ippure,
                    min_streaming=min_streaming,
                )
                cost = round(time.time() - t0, 1)
                st_str = (
                    f"{C_GREEN}★ 达标{C_RESET}"
                    if is_qual
                    else f"{C_YELLOW}未达标{C_RESET}"
                )
                print(f"耗时 {cost}s -> 综合: {C_BOLD}{score}{C_RESET} ({st_str})")
                batch_results.append((alloc, rep, score, bd, is_qual))
            except Exception as e:
                print(f"体检异常: {e}")
                batch_results.append((alloc, None, 0.0, {}, False))

        # 打印本批次对比矩阵
        print(
            f"\n{C_BOLD}====== 批次 {b_idx}/{max_batches} 质检对比矩阵 ======{C_RESET}"
        )
        hdr = (
            f"{'序号':<4} {'公网 IP':<15} {'欺诈(<5)':<10} "
            f"{'IPPure(<=35%)':<14} {'流媒体(>=4)':<12} {'综合分':<8} {'状态'}"
        )
        print(hdr)
        print("-" * 75)
        for idx, (alloc, _rep, score, bd, is_qual) in enumerate(batch_results, 1):
            ip_str = alloc["ip"]
            scam_str = f"{bd.get('scam_val', '--')}"
            scam_flag = "✓" if bd.get("scam_val", 99) < max_scam else "✗"
            ipp_val = bd.get("ipp_val", -1)
            if ipp_val >= 0:
                ipp_str = f"{ipp_val}%"
                ipp_flag = "✓" if ipp_val <= max_ippure else "✗"
            else:
                ipp_str = "未测到"
                ipp_flag = "✗"
            st_cnt = bd.get("stream_cnt", 0)
            st_flag = "✓" if st_cnt >= min_streaming else "✗"
            qual_str = (
                f"{C_GREEN}★ 达标候选{C_RESET}" if is_qual else f"{C_GRAY}淘汰{C_RESET}"
            )

            print(
                f"[{idx}]  {ip_str:<15} "
                f"{scam_str + ' (' + scam_flag + ')':<10} "
                f"{ipp_str + ' (' + ipp_flag + ')':<14} "
                f"{str(st_cnt) + '/7 (' + st_flag + ')':<12} "
                f"{str(score) + '分':<8} "
                f"{qual_str}"
            )
        print("=" * 75)

        # 择优提取达标 IP
        qualified = [item for item in batch_results if item[4]]
        newly_kept_ids = set()

        if qualified:
            qualified.sort(key=lambda x: x[2], reverse=True)
            take_count = min(len(qualified), target_count - len(retained_list))
            to_keep = qualified[:take_count]

            print(
                f"\n{C_GREEN}{C_BOLD}🎉 本批次发现 {len(qualified)} 个合格黄金 IP！"
                f"择优保留前 {take_count} 个...{C_RESET}"
            )

            for item in to_keep:
                k_alloc, _k_rep, k_score, _k_bd, _ = item
                k_ip = k_alloc["ip"]
                k_id = k_alloc["id"]

                vip_name = generate_vip_display_name(client, naming_prefix)
                print(
                    f"  -> 锁定 IP: {C_BOLD}{k_ip}{C_RESET} "
                    f"(综合分: {k_score} 分) -> 重命名为: {C_BOLD}{vip_name}{C_RESET}"
                )
                try:
                    rename_reserved_ip(client, k_id, vip_name)
                except Exception as e:
                    print(f"     重命名提示: {e}")

                k_alloc["display_name"] = vip_name
                k_alloc["composite_score"] = k_score
                retained_list.append(k_alloc)
                newly_kept_ids.add(k_id)

        # 释放本批次其余未被保留的候选 IP
        unkept = [item for item in batch_results if item[0]["id"] not in newly_kept_ids]
        if unkept:
            print(f"正在释放本批次其余 {len(unkept)} 个未选中候选 IP 归还资源池...")
            for item in unkept:
                other_alloc = item[0]
                try:
                    client.network.delete_public_ip(other_alloc["id"])
                except Exception as e:
                    print(f"释放 {other_alloc['ip']} 失败: {e}", file=sys.stderr)
            print(f"{C_GREEN}✓ 未选中的候选 IP 已彻底释放。{C_RESET}")

        # 检查是否达成目标
        curr_count = len(retained_list)
        print(
            f"\n{C_CYAN}>>> 当前累计保留进度: "
            f"[{curr_count}/{target_count}] 个黄金 IP{C_RESET}"
        )

        if curr_count >= target_count:
            print(
                f"\n{C_GREEN}{C_BOLD}🏆 恭喜！已圆满收集达成 {target_count} 个"
                f"黄金纯净 IP 目标！{C_RESET}"
            )
            print(
                f"\n{C_BOLD}====== 最终保留的 {target_count} 个"
                f"黄金 IP 资产名录 ======{C_RESET}"
            )
            for idx, item in enumerate(retained_list, 1):
                print(
                    f"  [{idx}] IP: {C_BOLD}{item['ip']:<15}{C_RESET} "
                    f"名称: {item.get('display_name', '--'):<18} "
                    f"综合分: {item.get('composite_score', '--')} 分"
                )
            print("=" * 60 + "\n")
            return retained_list

        if b_idx < max_batches:
            AntiBanGuard.safe_sleep(cooldown, reason="批次轮询平滑间隔")

    print(
        f"\n{C_YELLOW}已完成全部 {max_batches} 轮摇号（共体检 {tot_tested} 个 IP），"
        f"当前共保留 {len(retained_list)}/{target_count} 个黄金 IP。{C_RESET}"
    )
    return retained_list


# ==============================================================================
# 功能二：测试桩私网 IP 借壳真实链路测速 (Latency Probe)
# ==============================================================================


def get_or_create_probe_private_ip(
    client: OCIClient,
    instance_query: str = "oci-main-arm",
    probe_ip: str = "10.0.0.250",
    probe_name: str = "latency-test-probe",
) -> Dict[str, Any]:
    """获取或在指定实例网卡上创建专用的测试桩私网 IP，不触碰实例主 IP。"""
    instances = client.compute.list_instances()
    matched = None
    for inst in instances:
        if (
            inst["id"] == instance_query
            or inst["name"].lower() == instance_query.lower()
        ):
            matched = inst
            break

    if not matched:
        raise ValueError(f"未找到名称或 OCID 匹配的计算实例: '{instance_query}'")

    # 获取主 VNIC
    vnics = matched.get("vnics", [])
    if not vnics:
        atts = client.compute_client.list_vnic_attachments(
            compartment_id=client.tenancy_id, instance_id=matched["id"]
        ).data
        if not atts:
            raise ValueError(f"实例 {matched['name']} 未挂载有效网卡。")
        vnic_id = atts[0].vnic_id
    else:
        vnic_id = vnics[0].get("vnic_id") or vnics[0].get("id")

    # 检查网卡上是否已经存在测试桩
    p_ips = client.network_client.list_private_ips(vnic_id=vnic_id).data
    for p in p_ips:
        has_probe = p.display_name and "probe" in p.display_name.lower()
        if p.display_name == probe_name or p.ip_address == probe_ip or has_probe:
            return {
                "id": p.id,
                "ip": p.ip_address,
                "vnic_id": vnic_id,
                "instance_name": matched["name"],
                "created_new": False,
            }

    # 不存在则常驻创建一个辅助私网 IP
    print(
        f"{C_CYAN}正在为实例 '{matched['name']}' 创建专用测试桩辅助私网 IP "
        f"({probe_ip})...{C_RESET}"
    )
    res = client.network.assign_private_ip(
        vnic_id=vnic_id, ip_address=probe_ip, display_name=probe_name
    )
    print(
        f"{C_GREEN}✓ 成功创建测试桩私网 IP: {res['ip']} "
        f"(ID: ...{res['id'][-12:]}){C_RESET}"
    )
    print(
        f"{C_YELLOW}[重要提醒] 请确保在 Ubuntu 实例内已执行过一次: "
        f"`sudo ip addr add {res['ip']}/24 dev enp0s6`{C_RESET}"
    )
    return {
        "id": res["id"],
        "ip": res["ip"],
        "vnic_id": vnic_id,
        "instance_name": matched["name"],
        "created_new": True,
    }


def get_default_physical_gateway() -> str:
    """自动获取 Windows 本地物理网卡的默认下一跳网关（穿透本地代理与虚拟网卡）。"""
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { "
                "$_.NextHop -notlike '127.*' -and $_.NextHop -ne '0.0.0.0' -and "
                "$_.RouteMetric -lt 5000 } | Sort-Object RouteMetric | "
                "Select-Object -First 1).NextHop",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        gw = proc.stdout.strip()
        if gw:
            return gw
    except Exception:
        pass
    return ""


def execute_unproxied_probe(
    ip: str, gateway: Optional[str] = None, count: int = 4
) -> Dict[str, Any]:
    """通过直连网关或底层 ICMP 执行无代理真实链路测速。"""
    gw = gateway or get_default_physical_gateway()
    ps_script = os.path.join(os.path.dirname(__file__), "windows_probe.ps1")

    # 1. 优先使用 windows_probe.ps1 绑定直接物理网关路由探测 (穿透任何代理与 TUN)
    if os.path.exists(ps_script):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ps_script,
            "-Action",
            "Probe",
            "-Ip",
            ip,
            "-Count",
            str(count),
        ]
        if gw:
            cmd.extend(["-Gateway", gw])
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20.0
            )
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout)
                except Exception:
                    data = {}

                if data.get("status") == "ok":
                    samples = [
                        float(s["rtt_ms"])
                        for s in data.get("ping_samples", [])
                        if s.get("rtt_ms") is not None
                    ]
                    sent = count
                    received = len(samples)
                    loss_pct = (
                        round(100.0 * (sent - received) / sent, 1)
                        if sent
                        else 100.0
                    )
                    return {
                        "success": bool(samples),
                        "ip": ip,
                        "gateway": gw,
                        "loss_pct": loss_pct,
                        "avg_ms": round(sum(samples) / len(samples), 1)
                        if samples
                        else None,
                        "min_ms": min(samples) if samples else None,
                        "max_ms": max(samples) if samples else None,
                        "jitter_ms": round(max(samples) - min(samples), 1)
                        if samples
                        else None,
                        "samples": samples,
                    }
                else:
                    err = data.get("error", "")
                    if "Administrator" in err or not data.get("is_admin", True):
                        print(
                            f"{C_YELLOW}(非管理员权限，转原生探测){C_RESET} ",
                            end="",
                            flush=True,
                        )
        except Exception:
            pass

    # 2. 回退机制：系统原生 ping.exe
    cmd_fallback = ["ping", "-n", str(count), "-w", "1500", ip]
    try:
        proc = subprocess.run(
            cmd_fallback,
            capture_output=True,
            text=True,
            encoding="gbk",
            errors="ignore",
            timeout=15.0,
        )
        out = proc.stdout
        times = [
            float(x)
            for x in re.findall(r"(?:time|时间)[<=](\d+)ms", out, re.IGNORECASE)
        ]
        loss_match = re.search(r"\((\d+)%\s*(?:loss|丢失)\)", out)
        loss_pct = float(loss_match.group(1)) if loss_match else 100.0
        if times:
            return {
                "success": True,
                "ip": ip,
                "gateway": "native",
                "loss_pct": loss_pct,
                "avg_ms": round(sum(times) / len(times), 1),
                "min_ms": min(times),
                "max_ms": max(times),
                "jitter_ms": round(max(times) - min(times), 1),
                "samples": times,
            }
        else:
            return {
                "success": False,
                "ip": ip,
                "gateway": "native",
                "loss_pct": loss_pct,
                "avg_ms": None,
                "min_ms": None,
                "max_ms": None,
                "jitter_ms": None,
                "samples": [],
            }
    except Exception as e:
        return {"error": str(e), "success": False, "loss_pct": 100.0}


def execute_icmp_probe(ip: str, count: int = 4) -> Dict[str, Any]:
    """保留旧版兼容接口，调用无代理直连探测。"""
    return execute_unproxied_probe(ip, count=count)


def run_latency_test_on_probe(
    client: OCIClient,
    public_ip: str,
    public_ip_id: str,
    instance_name: str = "oci-main-arm",
    rounds: int = 5,
    ping_count_per_round: int = 4,
    gateway: Optional[str] = None,
) -> Dict[str, Any]:
    """功能二：将待测预留 IP 借壳挂载到测试桩上，精准测量直连网络性能，测后安全解绑。

    逻辑顺序：
    1. 绑定：预留公网 IP -> 测试桩私网 IP (10.0.0.250)
    2. 执行无代理直连测速，重复 5 轮，取综合平均值
    3. 安全解绑复原
    """
    probe = get_or_create_probe_private_ip(client, instance_query=instance_name)
    probe_id = probe["id"]
    probe_ip = probe["ip"]

    print(
        f"\n{C_CYAN}[第 1 步: 借壳绑定] 正在将待测预留 IP {C_BOLD}{public_ip}{C_RESET} "
        f"挂载到测试桩私网 IP ({probe_ip})...{C_RESET}"
    )
    # 预防性检查：若测试桩上尚有遗留的旧公网 IP 绑定，先解绑恢复就绪状态
    try:
        details = oci.core.models.GetPublicIpByPrivateIpIdDetails(
            private_ip_id=probe_id
        )
        existing_pub = client.network_client.get_public_ip_by_private_ip_id(
            details
        ).data
        if existing_pub and existing_pub.id and existing_pub.id != public_ip_id:
            print(
                f"{C_YELLOW}测试桩私网 IP 当前绑定着旧公网 IP "
                f"({existing_pub.ip_address})，正在复原闲置...{C_RESET}"
            )
            client.network.unassign_public_ip(existing_pub.id)
            time.sleep(1.0)
    except Exception:
        pass

    t0 = time.time()
    try:
        client.network.assign_public_ip(
            public_ip_id=public_ip_id, private_ip_id=probe_id
        )
    except Exception as e:
        print(f"{C_RED}挂载测试桩失败: {e}{C_RESET}", file=sys.stderr)
        raise

    bind_cost = round(time.time() - t0, 2)
    print(f"{C_GREEN}✓ 1:1 NAT 动态映射生效（耗时 {bind_cost} 秒）。{C_RESET}")

    # 等待 2 秒确保底层 SDN 路由表全域同步
    time.sleep(2.0)

    print(
        f"\n{C_CYAN}[第 2 步: 无代理真实直连测速] 正在重复执行 {rounds} 轮探测取平均值 "
        f"(穿透本地代理，直连物理网关)...{C_RESET}"
    )

    rounds_data: List[Dict[str, Any]] = []
    try:
        for r_idx in range(1, rounds + 1):
            print(
                f"  • [轮次 {r_idx}/{rounds}] 正在直连探测 (Direct ICMP)... ",
                end="",
                flush=True,
            )
            res = execute_unproxied_probe(
                public_ip, gateway=gateway, count=ping_count_per_round
            )
            if res.get("success") and res.get("avg_ms") is not None:
                print(
                    f"平均 RTT: {C_BOLD}{res['avg_ms']} ms{C_RESET} "
                    f"(最小: {res['min_ms']}ms, 最大: {res['max_ms']}ms, "
                    f"丢包率: {res['loss_pct']}%)"
                )
            else:
                loss_val = res.get("loss_pct", 100.0)
                print(f"{C_YELLOW}探测超时或丢包 (丢包率: {loss_val}%){C_RESET}")
            rounds_data.append(res)
            if r_idx < rounds:
                time.sleep(0.5)
    finally:
        # 第 3 步：无论测速成功与否，立即解绑以确保测试桩干净
        print(
            f"\n{C_GRAY}[第 3 步: 安全复原] "
            f"正在从测试桩解绑预留 IP {public_ip}...{C_RESET}"
        )
        try:
            client.network.unassign_public_ip(public_ip_id)
            print(f"{C_GREEN}✓ 测试桩已恢复闲置就绪状态。{C_RESET}")
        except Exception as e:
            print(f"{C_YELLOW}解绑测试桩提示: {e}{C_RESET}")

    # 聚合 5 轮数据取平均值
    valid_rounds = [
        r for r in rounds_data if r.get("success") and r.get("avg_ms") is not None
    ]
    all_samples: List[float] = []
    round_avgs: List[float] = []
    for r in valid_rounds:
        all_samples.extend(r.get("samples", []))
        round_avgs.append(r["avg_ms"])

    total_loss_pct = round(
        sum(r.get("loss_pct", 100.0) for r in rounds_data) / rounds, 1
    )

    if not round_avgs:
        print(
            f"{C_RED}▲ {rounds} 轮探测全部失败，总丢包率 {total_loss_pct}%！\n"
            f"【故障排查要点】\n"
            f"1. 权限与路由（最常见）：若本地开启了 TUN 虚拟网卡代理，\n"
            f"   必须以【管理员身份运行】PowerShell 才能穿透代理直连物理网关；\n"
            f"2. 代理软件：可尝试暂时退出代理或关闭 TUN 模式再试；\n"
            f"3. 实例测试桩：确认 Ubuntu 实例内已挂载辅助私网 IP：\n"
            f"   `sudo ip addr add {probe_ip}/24 dev enp0s6`{C_RESET}"
        )
        return {
            "success": False,
            "ip": public_ip,
            "loss_pct": total_loss_pct,
            "avg_ms": None,
            "min_ms": None,
            "max_ms": None,
            "jitter_ms": None,
            "rounds": rounds,
            "verdict": "不可达/全部丢包",
        }

    overall_avg = round(sum(round_avgs) / len(round_avgs), 1)
    overall_min = min(all_samples)
    overall_max = max(all_samples)
    overall_jitter = round(overall_max - overall_min, 1)

    if overall_avg <= 180.0 and total_loss_pct <= 5.0:
        verdict = f"{C_GREEN}★ 极品超低延迟直连（骨干优化线路，极力推荐）{C_RESET}"
    elif overall_avg <= 235.0 and total_loss_pct <= 10.0:
        verdict = f"{C_CYAN}● 优质公网标准直连（低丢包/稳定主力推荐）{C_RESET}"
    elif overall_avg <= 245.0 and total_loss_pct <= 20.0:
        verdict = f"{C_YELLOW}◆ 普通可用直连链路（正常公网水平，偶有波动）{C_RESET}"
    else:
        verdict = f"{C_RED}▲ 延迟偏高或丢包严重（建议考虑更换）{C_RESET}"

    rtt_detail = f"(最小: {overall_min}ms, 最大: {overall_max}ms)"
    print(f"\n{C_BOLD}====== 真实链路 {rounds} 轮综合性能报告卡 ======{C_RESET}")
    print(f"目标公网 IP:      {public_ip}")
    print(
        f"有效测速轮数:     {len(valid_rounds)}/{rounds} 轮 "
        f"(共 {len(all_samples)} 个采样点)"
    )
    print(
        f"{rounds} 轮平均往返时延: "
        f"{C_BOLD}{C_GREEN}{overall_avg} ms{C_RESET} {rtt_detail}"
    )
    print(f"平均丢包率:       {total_loss_pct}%")
    print(f"网络抖动 (Jitter): {overall_jitter} ms")
    print(f"链路评估结论:     {verdict}")
    print(f"{'=' * 42}\n")

    return {
        "success": True,
        "ip": public_ip,
        "loss_pct": total_loss_pct,
        "avg_ms": overall_avg,
        "min_ms": overall_min,
        "max_ms": overall_max,
        "jitter_ms": overall_jitter,
        "rounds": rounds,
        "valid_rounds_count": len(valid_rounds),
        "verdict": verdict,
    }


def print_latency_comparative_table(results: List[Dict[str, Any]]) -> None:
    """打印挂桩测速综合排名对比表。"""
    print(f"\n{C_BOLD}====== 预留公网 IPv4 挂桩直连链路性能排行榜 ======{C_RESET}")
    print(
        f"{'排名':<4} {'公网 IP':<16} {'预留名称':<18} {'平均时延':<10} "
        f"{'抖动(Jitter)':<12} {'丢包率':<8} {'有效轮数':<10} {'评估结论'}"
    )
    print("-" * 92)

    # 排序：有延迟的按 avg_ms 升序，全丢包或超时的排在最后
    sorted_res = sorted(
        results,
        key=lambda x: (
            0 if x.get("success") and x.get("avg_ms") is not None else 1,
            x.get("avg_ms") or 99999.0,
            x.get("loss_pct", 100.0),
        ),
    )

    for rank, r in enumerate(sorted_res, 1):
        ip = r.get("ip", "未知")
        name = r.get("name", "未命名")
        avg_str = f"{r['avg_ms']} ms" if r.get("avg_ms") is not None else "超时"
        jitter_str = (
            f"{r['jitter_ms']} ms" if r.get("jitter_ms") is not None else "--"
        )
        loss_str = f"{r.get('loss_pct', 100.0)}%"
        valid_rounds = f"{r.get('valid_rounds_count', 0)}/{r.get('rounds', 5)}"

        color = C_GREEN if rank == 1 and r.get("success") else C_RESET
        if not r.get("success") or r.get("avg_ms") is None:
            color = C_RED

        raw_verdict = r.get("verdict", "")
        clean_verdict = re.sub(r"\033\[[0-9;]*m", "", raw_verdict)

        print(
            f"{color}{rank:<4} {ip:<16} {name:<18} {avg_str:<10} "
            f"{jitter_str:<12} {loss_str:<8} {valid_rounds:<10} "
            f"{clean_verdict}{C_RESET}"
        )
    print("-" * 92 + "\n")


# ==============================================================================
# 功能三：生产实例主网卡公网 IP 一键换绑 (Production Primary IP Binding)
# ==============================================================================


def bind_instance_primary_ip(
    client: OCIClient,
    target_ip_or_id: str,
    instance_query: str = "oci-main-arm",
) -> Dict[str, Any]:
    """将指定的预留公网 IP 绑定为目标云主机的主公网 IP（生产换绑闭环）。

    执行逻辑：
    1. 查找目标预留公网 IP 对象；
    2. 查找目标实例及其主 VNIC、Primary 私网 IP；
    3. 检查主私网 IP 当前关联的公网 IP：
       - 若为 EPHEMERAL 临时 IP，安全删除以腾位；
       - 若为旧 RESERVED 预留 IP，解绑使其恢复为闲置预留池；
    4. 将目标预留公网 IP 动态 1:1 NAT 映射至 Primary 私网 IP；
    5. 验证并返回最新状态。
    """
    print(f"\n{C_CYAN}====== 启动实例主公网 IP 生产换绑流程 ======{C_RESET}")
    reserved_ips = client.network.list_reserved_ips()
    target_reserved = None
    for r in reserved_ips:
        if r["ip"] == target_ip_or_id or r["id"] == target_ip_or_id:
            target_reserved = r
            break
    if not target_reserved:
        raise ValueError(f"未在预留 IP 池中找到目标 IP: '{target_ip_or_id}'")
    print(
        f"✓ 目标预留 IP: {C_BOLD}{target_reserved['ip']}{C_RESET} "
        f"({target_reserved['name']}) [ID: ...{target_reserved['id'][-12:]}]"
    )

    instances = client.compute.list_instances()
    matched_inst = None
    for inst in instances:
        if (
            inst["id"] == instance_query
            or inst["name"].lower() == instance_query.lower()
        ):
            matched_inst = inst
            break
    if not matched_inst:
        raise ValueError(f"未找到目标计算实例: '{instance_query}'")

    atts = client.compute_client.list_vnic_attachments(
        compartment_id=client.tenancy_id, instance_id=matched_inst["id"]
    ).data
    if not atts:
        raise ValueError(f"实例 {matched_inst['name']} 未挂载有效网卡。")
    vnic_id = atts[0].vnic_id

    p_ips = client.network_client.list_private_ips(vnic_id=vnic_id).data
    primary_p_ip = next((p for p in p_ips if p.is_primary), None)
    if not primary_p_ip:
        raise ValueError(f"实例 {matched_inst['name']} 主网卡未找到 Primary 私网 IP。")
    print(
        f"✓ 目标实例: {matched_inst['name']} | "
        f"主私网 IP: {primary_p_ip.ip_address} [ID: ...{primary_p_ip.id[-12:]}]"
    )

    det = oci.core.models.GetPublicIpByPrivateIpIdDetails(
        private_ip_id=primary_p_ip.id
    )
    current_pub = None
    try:
        current_pub = client.network_client.get_public_ip_by_private_ip_id(det).data
    except oci.exceptions.ServiceError as e:
        if e.status != 404:
            raise

    if current_pub and current_pub.id:
        if current_pub.ip_address == target_reserved["ip"]:
            print(
                f"{C_GREEN}✓ 该 IP ({current_pub.ip_address}) 已经是当前主公网 IP，"
                f"无需变更。{C_RESET}"
            )
            return {
                "success": True,
                "instance_name": matched_inst["name"],
                "private_ip": primary_p_ip.ip_address,
                "public_ip": current_pub.ip_address,
                "status": "UNCHANGED",
            }
        if current_pub.lifetime == "EPHEMERAL":
            print(
                f"{C_YELLOW}正在释放主私网 IP 当前关联的临时公网 IP "
                f"({current_pub.ip_address})...{C_RESET}"
            )
            client.network_client.delete_public_ip(current_pub.id)
            time.sleep(2.0)
        elif current_pub.lifetime == "RESERVED":
            print(
                f"{C_YELLOW}正在解绑原预留公网 IP "
                f"({current_pub.ip_address}) 使其恢复闲置池...{C_RESET}"
            )
            client.network.unassign_public_ip(current_pub.id)
            time.sleep(2.0)

    print(
        f"{C_CYAN}正在将预留 IP {target_reserved['ip']} "
        f"绑定至实例主私网 IP...{C_RESET}"
    )
    client.network.assign_public_ip(
        public_ip_id=target_reserved["id"], private_ip_id=primary_p_ip.id
    )
    time.sleep(2.0)

    vnic_after = client.network_client.get_vnic(vnic_id).data
    print(f"\n{C_GREEN}{C_BOLD}🏆 主公网 IP 换绑成功！{C_RESET}")
    print(f"实例名称:   {matched_inst['name']}")
    print(f"主私网 IP: {vnic_after.private_ip}")
    print(f"主公网 IP: {C_BOLD}{C_GREEN}{vnic_after.public_ip}{C_RESET}")
    print(f"预留名称:   {target_reserved['name']}\n")
    return {
        "success": True,
        "instance_name": matched_inst["name"],
        "private_ip": vnic_after.private_ip,
        "public_ip": vnic_after.public_ip,
        "status": "UPDATED",
    }


# ==============================================================================
# 联动流水线：质量筛选 + 延迟双门禁 (Pipeline)
# ==============================================================================


def run_pipeline(
    client: OCIClient,
    max_attempts: int = 5,
    fast: bool = True,
    cooldown: float = 18.0,
    instance_name: str = "oci-main-arm",
    max_acceptable_rtt: float = 220.0,
) -> Optional[Dict[str, Any]]:
    """联动流水线：摇出黄金纯净 IP -> 自动挂测试桩测速 -> 达到双优选方才锁定。"""
    max_attempts = min(max_attempts, 10)
    print(f"\n{C_CYAN}====== 启动 Oracle IP 质量与延迟联动双检流水线 ======{C_RESET}")
    print(
        f"最大尝试: {max_attempts} 轮 | 延迟阈值: <= {max_acceptable_rtt}ms | "
        f"防封休眠: {cooldown}s (含抖动)\n"
    )

    for attempt in range(1, max_attempts + 1):
        print(
            f"\n{C_CYAN}>>> [流水线第 {attempt}/{max_attempts} 轮] "
            f"门禁一: 质量快筛...{C_RESET}"
        )
        try:
            alloc, rep = allocate_and_analyze_ip(client, fast=fast)
        except Exception as e:
            print(f"{C_RED}申请或质检出错: {e}{C_RESET}")
            AntiBanGuard.safe_sleep(cooldown, reason="异常冷却保护")
            continue

        ip = alloc["ip"]
        ip_id = alloc["id"]
        eval_str, is_golden = evaluate_quality(rep)

        if not is_golden:
            print(
                f"{C_YELLOW}未达黄金纯净标准 ({eval_str})，跳过测速立即释放...{C_RESET}"
            )
            client.network.delete_public_ip(ip_id)
            if attempt < max_attempts:
                AntiBanGuard.safe_sleep(cooldown, reason="防封平滑休眠")
            continue

        print(
            f"{C_GREEN}✓ 门禁一通过（黄金 IP: {ip}）！"
            f"进入门禁二: 挂桩物理测速...{C_RESET}"
        )
        print_report_card(rep)

        try:
            probe_res = run_latency_test_on_probe(
                client=client,
                public_ip=ip,
                public_ip_id=ip_id,
                instance_name=instance_name,
            )
        except Exception as e:
            print(f"{C_RED}挂桩测速异常: {e}{C_RESET}")
            client.network.delete_public_ip(ip_id)
            continue

        avg_rtt = probe_res.get("avg_ms")
        loss = probe_res.get("loss_pct", 100)

        if avg_rtt is not None and avg_rtt <= max_acceptable_rtt and loss <= 10:
            print(
                f"\n{C_GREEN}{C_BOLD}🏆 完美！同时通过【黄金纯净度】与"
                f"【物理延迟 ({avg_rtt}ms)】双重门禁！{C_RESET}"
            )
            print(f"{C_GREEN}已将极品 IP ({ip}) 锁定保存在预留池中！{C_RESET}")
            return alloc

        print(
            f"{C_YELLOW}! 延迟未能达标 ({avg_rtt}ms > {max_acceptable_rtt}ms)，"
            f"释放该 IP...{C_RESET}"
        )
        client.network.delete_public_ip(ip_id)
        if attempt < max_attempts:
            AntiBanGuard.safe_sleep(cooldown, reason="防封平滑休眠")

    print(f"\n{C_YELLOW}已达到最大安全尝试次数，本轮未摇到双达标 IP。{C_RESET}")
    return None


# ==============================================================================
# CLI 入口
# ==============================================================================


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Oracle Cloud 预留公网 IPv4 质量筛选与测试桩延迟测速闭环工具"
    )
    parser.add_argument(
        "--mode",
        choices=["quality", "latency", "pipeline", "bind"],
        default="quality",
        help=(
            "模式: quality (纯质量筛选), latency (挂桩测速), "
            "pipeline (双检流水线), bind (生产主机主IP换绑)"
        ),
    )
    parser.add_argument(
        "--profile", default="DEFAULT", help="OCI 配置文件 Profile 名称 (默认 DEFAULT)"
    )
    parser.add_argument("--region", help="指定或覆盖 OCI 区域")

    # 功能一参数
    parser.add_argument(
        "--hunt", action="store_true", help="质量模式下开启 5x5 批量优选摇号"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5,
        help="批量摇号模式下每批申请的 IP 数量（默认 5 个）",
    )
    parser.add_argument(
        "--target-count",
        type=int,
        default=5,
        help="目标保留的黄金 IP 数量（默认至少保留 5 个）",
    )
    parser.add_argument(
        "--max-batches",
        type=int,
        default=10,
        help="批量摇号最大轮次数（默认 10 轮）",
    )
    parser.add_argument(
        "--max-scam",
        type=int,
        default=5,
        help="欺诈分严格门槛（必须 < MAX_SCAM，默认 5）",
    )
    parser.add_argument(
        "--max-ippure",
        type=float,
        default=35.0,
        help="IPPure 系数严格门槛（必须 <= MAX_IPPURE，默认 35.0%%）",
    )
    parser.add_argument(
        "--min-streaming",
        type=int,
        default=4,
        help="流媒体及 AI 解锁数量最低门槛（默认 4 项）",
    )
    parser.add_argument(
        "--naming-prefix",
        default="vip-pure",
        help="优选达标 IP 自动重命名格式（默认 vip-pure）",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=4.0,
        help="批次轮询休眠时长（默认 4.0 秒）",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="开启快速质检模式（跳过 Playwright 浏览器，秒级出结果）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="各信誉平台 API 探测超时时间（默认 15.0 秒）",
    )
    parser.add_argument(
        "--allocate",
        action="store_true",
        help="质量模式下申请并测试一个新分配的预留 IP（默认测试租户中现有的预留 IP）",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="单次质量模式下：黄金 IP 自动保留，非黄金 IP 自动释放",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="单次质量模式下：体检后自动释放该 IP（纯测试，不占配额）",
    )

    # 功能二参数
    parser.add_argument(
        "--ip",
        help="测试延迟模式下指定的预留公网 IP（若不指定则自动列出供选择）",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="测试延迟模式下：对所有已预留的公网 IP 逐个挂桩测速并生成排行榜",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=5,
        help="测试延迟模式下重复测速轮数（默认 5 轮取平均值）",
    )
    parser.add_argument(
        "--ping-count",
        type=int,
        default=4,
        help="测试延迟模式下每轮探测发送的 ICMP 数据包数（默认 4 个）",
    )
    parser.add_argument(
        "--gateway",
        help="自定义本地物理网卡网关（默认自动检测物理网关，穿透代理直连）",
    )
    parser.add_argument(
        "--instance",
        default="oci-main-arm",
        help="测试桩所依托的计算实例名称（默认: oci-main-arm）",
    )
    parser.add_argument(
        "--max-rtt",
        type=float,
        default=220.0,
        help="双检流水线允许的最大平均延迟阈值（毫秒，默认 220.0）",
    )

    args = parser.parse_args()

    try:
        client = OCIClient(profile=args.profile, region=args.region)
    except Exception as e:
        print(f"初始化 OCI 客户端失败，请检查认证配置: {e}", file=sys.stderr)
        return 1

    # 1. 联动流水线模式
    if args.mode == "pipeline":
        run_pipeline(
            client=client,
            max_attempts=args.max_attempts,
            fast=args.fast,
            cooldown=args.cooldown,
            instance_name=args.instance,
            max_acceptable_rtt=args.max_rtt,
        )
        return 0

    # 2. 挂测试桩测延迟模式
    if args.mode == "latency":
        reserved_list = client.network.list_reserved_ips()
        if not reserved_list:
            print("当前账号无预留公网 IP，请先通过 quality 模式申请。")
            return 1

        target_items = []
        is_batch = args.all

        if args.ip:
            matched = [r for r in reserved_list if r["ip"] == args.ip]
            if not matched:
                print(f"未在预留 IP 池中找到 IP: {args.ip}，请先确保其为预留 IP。")
                return 1
            target_items = matched
        elif is_batch:
            target_items = reserved_list
        else:
            print("\n当前可供测试延迟的预留公网 IP 列表:")
            for idx, r in enumerate(reserved_list, 1):
                idle_tag = "闲置" if r.get("is_idle") else "已绑定"
                print(
                    f"  [{idx}] {r['ip']:<15} (名称: {r['name']:<18}, 状态: {idle_tag})"
                )
            print("  [A] 全部逐一挂桩测速 (5 轮平均值并生成排行榜)")
            try:
                sel = input("请选择要挂载测试的 IP 序号 (或输入 A 全部测试): ").strip()
                if sel.upper() == "A":
                    target_items = reserved_list
                    is_batch = True
                elif sel.isdigit() and 1 <= int(sel) <= len(reserved_list):
                    target_items = [reserved_list[int(sel) - 1]]
                else:
                    print("选择无效。")
                    return 1
            except (KeyboardInterrupt, EOFError):
                return 0

        latency_results: List[Dict[str, Any]] = []
        for idx, item in enumerate(target_items, 1):
            if is_batch:
                print(
                    f"\n{C_CYAN}{C_BOLD}>>> [全部挂桩测速 {idx}/{len(target_items)}] "
                    f"目标 IP: {item['ip']} ({item['name']}){C_RESET}"
                )
            res = run_latency_test_on_probe(
                client=client,
                public_ip=item["ip"],
                public_ip_id=item["id"],
                instance_name=args.instance,
                rounds=args.rounds,
                ping_count_per_round=args.ping_count,
                gateway=args.gateway,
            )
            res["name"] = item["name"]
            latency_results.append(res)

        if len(latency_results) > 1:
            print_latency_comparative_table(latency_results)

        return 0

    # 3. 生产主机主公网 IP 换绑模式
    if args.mode == "bind":
        target_ip = args.ip
        reserved_list = client.network.list_reserved_ips()
        if not target_ip:
            if not reserved_list:
                print("当前账号无预留公网 IP。")
                return 1
            print("\n当前可供绑定为主机主公网 IP 的预留公网 IP 列表:")
            for idx, r in enumerate(reserved_list, 1):
                idle_tag = (
                    "闲置可用"
                    if r.get("is_idle")
                    else f"当前绑定: {r.get('instance_name') or '已占用'}"
                )
                print(
                    f"  [{idx}] {r['ip']:<15} (名称: {r['name']:<18}, 状态: {idle_tag})"
                )
            try:
                sel = input("请选择要设为主机主公网 IP 的序号: ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(reserved_list):
                    target_ip = reserved_list[int(sel) - 1]["ip"]
                else:
                    print("选择无效。")
                    return 1
            except (KeyboardInterrupt, EOFError):
                return 0

        bind_instance_primary_ip(
            client=client,
            target_ip_or_id=target_ip,
            instance_query=args.instance,
        )
        return 0

    # 3. 质量筛选模式 (默认)
    if args.hunt:
        run_batch_hunt(
            client=client,
            batch_size=args.batch_size,
            max_batches=args.max_batches,
            target_count=args.target_count,
            fast=args.fast,
            max_scam=args.max_scam,
            max_ippure=args.max_ippure,
            min_streaming=args.min_streaming,
            cooldown=args.cooldown,
            timeout=args.timeout,
            naming_prefix=args.naming_prefix,
        )
        return 0

    if args.allocate:
        # 单次申请新 IP 体检闭环
        try:
            alloc, rep = allocate_and_analyze_ip(
                client, fast=args.fast, timeout=args.timeout
            )
            print_report_card(rep)
            score, bd, is_qual = calculate_composite_score(
                rep,
                max_scam=args.max_scam,
                max_ippure=args.max_ippure,
                min_streaming=args.min_streaming,
            )
            eval_text, _ = evaluate_quality(rep)
            print(f"\n{C_CYAN}>>> 综合评级结论: {C_BOLD}{eval_text}{C_RESET}")

            action = "prompt"
            if args.release:
                action = "release"
            elif args.auto:
                action = "auto"

            if action == "auto":
                if is_qual:
                    vip_name = generate_vip_display_name(client, args.naming_prefix)
                    rename_reserved_ip(client, alloc["id"], vip_name)
                    print(
                        f"{C_GREEN}✓ 黄金纯净 IP (综合分: {score})，"
                        f"已重命名为 {vip_name} 并安全保留在 OCI 预留池中。{C_RESET}"
                    )
                else:
                    print(f"{C_YELLOW}! 未达三大黄金标准，正在自动释放...{C_RESET}")
                    client.network.delete_public_ip(alloc["id"])
                    print(f"{C_GREEN}✓ 预留 IP 已彻底释放。{C_RESET}")
            elif action == "release":
                print(f"正在释放测试预留 IP {alloc['ip']}...")
                client.network.delete_public_ip(alloc["id"])
                print(f"{C_GREEN}✓ 预留 IP 已彻底释放。{C_RESET}")
            else:
                try:
                    ch = (
                        input("操作: [K]eep 保留 / [R]elease 释放 (默认 K): ")
                        .strip()
                        .lower()
                    )
                except (KeyboardInterrupt, EOFError):
                    ch = "k"
                if ch in ("r", "release"):
                    client.network.delete_public_ip(alloc["id"])
                    print(f"{C_GREEN}✓ 预留 IP 已释放。{C_RESET}")
                else:
                    if is_qual:
                        vip_name = generate_vip_display_name(
                            client, args.naming_prefix
                        )
                        rename_reserved_ip(client, alloc["id"], vip_name)
                        print(
                            f"{C_GREEN}✓ 预留 IP 已重命名为 {vip_name} "
                            f"并保留。{C_RESET}"
                        )
                    else:
                        print(f"{C_GREEN}✓ 预留 IP 已保留在租户预留池中。{C_RESET}")
            return 0
        except Exception as e:
            print(f"执行异常: {e}", file=sys.stderr)
            return 1

    # 默认模式：自动读取当前租户中已存在的预留 IP 进行质量与信息体检，并进行综合打分
    reserved_list = client.network.list_reserved_ips()
    if args.ip:
        targets = [r for r in reserved_list if r["ip"] == args.ip]
        if not targets:
            targets = [{"ip": args.ip, "id": None, "name": "手动指定"}]
    else:
        targets = reserved_list

    if not targets:
        print(
            f"{C_YELLOW}当前账号无预留公网 IP。"
            f"若需申请新 IP 请添加 --allocate 参数。{C_RESET}"
        )
        return 1

    print(
        f"\n{C_CYAN}====== 正在读取并体检当前租户中的全部 "
        f"{len(targets)} 个预留 IP ======{C_RESET}"
    )
    print(
        f"评判标准: 欺诈分 < {args.max_scam} | IPPure <= {args.max_ippure}% | "
        f"流媒体 >= {args.min_streaming} | 黑名单 0 标记\n"
    )

    reports: List[CompleteIPReport] = []
    ip_meta: Dict[str, str] = {}
    for idx, item in enumerate(targets, 1):
        target_ip = item["ip"]
        target_name = item.get("name", "--")
        ip_meta[target_ip] = target_name
        print(
            f"[{idx}/{len(targets)}] 正在深度体检: {target_ip} "
            f"(当前名称: {target_name}) ... ",
            end="",
            flush=True,
        )
        t0 = time.time()
        try:
            rep = analyze_ip(target_ip, skip_ippure=args.fast, timeout=args.timeout)
            reports.append(rep)
            score, bd, is_qual = calculate_composite_score(
                rep,
                max_scam=args.max_scam,
                max_ippure=args.max_ippure,
                min_streaming=args.min_streaming,
            )
            cost = round(time.time() - t0, 1)
            st_str = (
                f"{C_GREEN}★ 达标{C_RESET}"
                if is_qual
                else f"{C_YELLOW}▲ 待复核{C_RESET}"
            )
            print(
                f"耗时 {cost}s -> 欺诈: {bd['scam_val']} | IPPure: {bd['ipp_val']}% | "
                f"流媒体: {bd['stream_cnt']}/7 -> 综合分: {score} ({st_str})"
            )
        except Exception as e:
            print(f"体检异常: {e}")

    print_comparative_table(reports, ip_meta=ip_meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
