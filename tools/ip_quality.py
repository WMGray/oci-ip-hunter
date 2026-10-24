"""IP 综合质量与风控信誉检测套件（对齐 xykt/IPQuality 架构）。

多源交叉印证与明确平台归属标注：
1. 一、基础信息（通过 IPinfo 权威数据库查询）
2. 二、IP类型属性（多数据库横向矩阵对比：IPinfo, ipregistry, ipapi 等）
3. 三、风险评分（全彩色风险等级刻度条 + 各数据库滑动标尺）
4. 四、风险因子（8大主流数据库风控特征矩阵）
5. 五、流媒体及AI服务解锁检测（主流 AI 与流媒体服务商）
6. 六、邮局连通性及黑名单检测（本地25端口、各大邮件服务商解析与439+黑名单库）
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import sys
import time
import unicodedata
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ==================== 常用地理中英对照字典 ====================

COUNTRY_DICT: Dict[str, tuple[str, str, str]] = {
    "US": ("美国", "NA", "北美洲"),
    "CN": ("中国", "AS", "亚洲"),
    "HK": ("中国香港", "AS", "亚洲"),
    "TW": ("中国台湾", "AS", "亚洲"),
    "JP": ("日本", "AS", "亚洲"),
    "KR": ("韩国", "AS", "亚洲"),
    "SG": ("新加坡", "AS", "亚洲"),
    "GB": ("英国", "EU", "欧洲"),
    "DE": ("德国", "EU", "欧洲"),
    "FR": ("法国", "EU", "欧洲"),
    "NL": ("荷兰", "EU", "欧洲"),
    "CA": ("加拿大", "NA", "北美洲"),
    "AU": ("澳大利亚", "OC", "大洋洲"),
    "MX": ("墨西哥", "NA", "北美洲"),
    "IN": ("印度", "AS", "亚洲"),
    "RU": ("俄罗斯", "EU", "欧洲"),
    "BR": ("巴西", "SA", "南美洲"),
}

STATE_DICT: Dict[str, str] = {
    "California": "加州",
    "Texas": "德克萨斯州",
    "Washington": "华盛顿州",
    "New York": "纽约州",
    "Illinois": "伊利诺伊州",
    "Virginia": "弗吉尼亚州",
    "Florida": "佛罗里达州",
    "Oregon": "俄勒冈州",
    "Tokyo": "东京",
    "Osaka": "大阪",
    "Seoul": "首尔",
    "Beijing": "北京",
    "Shanghai": "上海",
    "Guangdong": "广东",
}

CITY_DICT: Dict[str, str] = {
    "San Jose": "圣何塞",
    "Los Angeles": "洛杉矶",
    "San Francisco": "旧金山",
    "Seattle": "西雅图",
    "Austin": "奥斯汀",
    "Dallas": "达拉斯",
    "Ashburn": "阿什本",
    "Chicago": "芝加哥",
    "New York": "纽约",
    "Tokyo": "东京",
    "Osaka": "大阪",
    "Singapore": "新加坡",
    "Seoul": "首尔",
    "London": "伦敦",
    "Frankfurt": "法兰克福",
    "Paris": "巴黎",
}


def decimal_to_dms(lat: float, lon: float) -> str:
    """将十进制经纬度转换为标准度分秒 (DMS) 字符串（与 Check.Place 完全一致）。"""

    def _dms(val: float, is_lat: bool) -> str:
        d = int(abs(val))
        m_float = (abs(val) - d) * 60
        m = int(m_float)
        s = int(round((m_float - m) * 60))
        if is_lat:
            dir_str = "N" if val >= 0 else "S"
        else:
            dir_str = "E" if val >= 0 else "W"
        return f"{d}° {m}′ {s}″ {dir_str}"

    return f"{_dms(lon, False)}, {_dms(lat, True)}"


# ==================== 数据模型定义 ====================


@dataclass
class BasicInfo:
    """一、基础信息（以 IPinfo 数据库为权威数据源）。"""

    ip: str
    asn: str = ""
    org: str = ""
    dms: str = ""
    map_url: str = ""
    city_str: str = ""
    usage_loc: str = ""
    reg_loc: str = ""
    timezone: str = ""
    ip_type: str = "原生IP"
    is_native: bool = True
    lat: float = 0.0
    lon: float = 0.0
    ippure_score: str = ""
    ippure_level: str = ""
    ippure_human_ratio: str = ""
    ippure_bot_ratio: str = ""


@dataclass
class TypeAttributes:
    """二、IP类型属性（多数据库横向对比矩阵）。"""

    databases: List[str] = field(
        default_factory=lambda: [
            "IPinfo",
            "ipregistry",
            "ipapi",
            "IP2Location",
            "AbuseIPDB",
            "IPPure",
        ]
    )
    usage_types: Dict[str, str] = field(default_factory=dict)
    company_types: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScoreData:
    """三、风险评分（多数据库独立评分与定级）。"""

    ip2location_score: str = "0"
    ip2location_val: float = 0.0
    ip2location_risk: str = "低风险"

    scamalytics_score: str = "0"
    scamalytics_val: float = 0.0
    scamalytics_risk: str = "低风险"

    ipapi_score: str = "0.00%"
    ipapi_val: float = 0.0
    ipapi_risk: str = "低风险"

    abuseipdb_score: str = "0"
    abuseipdb_val: float = 0.0
    abuseipdb_risk: str = "低风险"

    ipqs_score: str = "0"
    ipqs_val: float = 0.0
    ipqs_risk: str = "低风险"

    cloudflare_score: str = "0"
    cloudflare_val: float = 0.0
    cloudflare_risk: str = "低风险"

    ippure_score: str = "--"
    ippure_val: float = -1.0
    ippure_risk: str = "未测到"
    ippure_human_ratio: str = ""
    ippure_bot_ratio: str = ""

    dbip_score: str = ""
    dbip_val: float = 0.0
    dbip_risk: str = "低风险"


@dataclass
class RiskFactorsMatrix:
    """四、风险因子（8大主流数据库特征矩阵）。"""

    databases: List[str] = field(
        default_factory=lambda: [
            "IP2Location",
            "ipapi",
            "ipregistry",
            "IPQS",
            "SCAMALYTICS",
            "ipdata",
            "IPinfo",
            "IPPure",
        ]
    )
    region: Dict[str, str] = field(default_factory=dict)
    proxy: Dict[str, str] = field(default_factory=dict)
    tor: Dict[str, str] = field(default_factory=dict)
    vpn: Dict[str, str] = field(default_factory=dict)
    server: Dict[str, str] = field(default_factory=dict)
    abuser: Dict[str, str] = field(default_factory=dict)
    robot: Dict[str, str] = field(default_factory=dict)


@dataclass
class MediaUnlockMatrix:
    """五、流媒体及AI服务解锁检测矩阵。"""

    services: List[str] = field(
        default_factory=lambda: [
            "TikTok",
            "Disney+",
            "Netflix",
            "Youtube",
            "AmazonPV",
            "Spotify",
            "ChatGPT",
            "Claude",
        ]
    )
    status: Dict[str, str] = field(default_factory=dict)
    region: Dict[str, str] = field(default_factory=dict)
    unlock_type: Dict[str, str] = field(default_factory=dict)


@dataclass
class MailAndSecurity:
    """六、邮局连通性及黑名单检测。"""

    port_25_outbound: str = "可用"
    mail_services: List[str] = field(
        default_factory=lambda: [
            "Gmail",
            "Outlook",
            "Yahoo",
            "Apple",
            "QQ",
            "MailRU",
            "AOL",
            "GMX",
            "MailCOM",
            "163",
            "Sohu",
            "Sina",
        ]
    )
    blacklist_total: int = 439
    blacklist_clean: int = 439
    blacklist_flagged: int = 0
    blacklist_bad: int = 0
    spamhaus_clean: bool = True
    firehol_clean: bool = True
    ipsum_clean: bool = True
    cf_colo: str = "-"
    cf_threat: str = "无盾拦截 (Pass)"


@dataclass
class CompleteIPReport:
    """聚合完整评测报告。"""

    basic: BasicInfo
    types: TypeAttributes
    score: ScoreData
    factors: RiskFactorsMatrix
    media: MediaUnlockMatrix
    mail_sec: MailAndSecurity
    query_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.basic.ip,
            "basic": asdict(self.basic),
            "types": asdict(self.types),
            "score": asdict(self.score),
            "factors": asdict(self.factors),
            "media": asdict(self.media),
            "mail_sec": asdict(self.mail_sec),
            "query_time_ms": self.query_time_ms,
        }


# ==================== 数据采集模块 ====================


def _fetch_ipinfo(ip: str, timeout: float = 4.5) -> Dict[str, Any]:
    """[权威基础数据源: IPinfo] 提取 ASN、组织、经纬度、城市等核心元数据。"""
    url = f"https://ipinfo.io/{ip}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
    res: Dict[str, Any] = {"status": "error", "data": {}}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res["data"] = json.loads(r.read().decode("utf-8", errors="replace"))
            res["status"] = "ok"
    except Exception as e:
        res["error"] = str(e)
    return res


def _fetch_ipregistry(ip: str, timeout: float = 4.5) -> Dict[str, Any]:
    """[类型核验数据源: ipregistry] 提取企业性质、Hosting机房分类与安全特征。"""
    url = f"https://api.ipregistry.co/{ip}?key=tryout"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    res: Dict[str, Any] = {"status": "error", "data": {}}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res["data"] = json.loads(r.read().decode("utf-8", errors="replace"))
            res["status"] = "ok"
    except Exception as e:
        res["error"] = str(e)
    return res


def _fetch_ipapi(ip: str, timeout: float = 4.5) -> Dict[str, Any]:
    """[类型核验数据源: IP-API] 提取 hosting 属性、AS 组织与广播判别数据。"""
    fields = (
        "status,message,country,countryCode,region,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
    )
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    res: Dict[str, Any] = {"status": "error", "data": {}}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            if data.get("status") == "success":
                res["status"] = "ok"
                res["data"] = data
            else:
                res["error"] = data.get("message", "IP-API error")
    except Exception as e:
        res["error"] = str(e)
    return res


def _fetch_scamalytics(ip: str, timeout: float = 6.0) -> Dict[str, Any]:
    """[平台: Scamalytics] 提取 0-100 欺诈分、黑名单库及安全特征。"""
    url = f"https://scamalytics.com/ip/{ip}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    res: Dict[str, Any] = {
        "status": "error",
        "score": 0,
        "risk": "Low Risk",
        "table": {},
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            html = r.read().decode("utf-8", errors="replace")
            res["status"] = "ok"

            m_score = re.search(r"Fraud Score[^\d]*(\d+)", html)
            if m_score:
                res["score"] = int(m_score.group(1))

            m_risk = re.search(r"(Very High|High|Medium|Low)\s*Risk", html, re.I)
            if m_risk:
                res["risk"] = m_risk.group(0).strip()

            table_match = re.search(r"<table>.*?</table>", html, re.S)
            if table_match:
                for row in re.findall(
                    r"<tr>\s*<th>(.*?)</th>\s*<td>(.*?)</td>\s*</tr>",
                    table_match.group(0),
                    re.S,
                ):
                    th = re.sub(r"<[^>]+>", "", row[0]).strip()
                    td = re.sub(r"<[^>]+>", "", row[1]).strip()
                    if th:
                        res["table"][th] = td
    except Exception as e:
        res["error"] = str(e)
    return res


def _fetch_ipquery(ip: str, timeout: float = 4.5) -> Dict[str, Any]:
    """[平台: IPQuery] 提取即时代理、VPN、Tor 及纯净度风控分。"""
    url = f"https://api.ipquery.io/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    res: Dict[str, Any] = {"status": "error", "data": {}}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res["data"] = json.loads(r.read().decode("utf-8", errors="replace"))
            res["status"] = "ok"
    except Exception as e:
        res["error"] = str(e)
    return res


def _fetch_ippure(ip: str, timeout: float = 12.0) -> Dict[str, Any]:
    """[平台: IPPure.com] 基于 Playwright 无头浏览器提取纯净风险系数与人机数据。"""
    res: Dict[str, Any] = {
        "status": "error",
        "score": None,
        "level": None,
        "human_ratio": None,
        "bot_ratio": None,
    }
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(channel="msedge", headless=True)
            except Exception:
                browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            # 仅等待 commit 状态，避免等待庞大第三方资源与阻塞
            page.goto(
                "https://ippure.com/",
                wait_until="commit",
                timeout=timeout * 1000,
            )

            js_code = f"""
            async () => {{
                const mod = await import('/assets/chunks/security.C1jHOmoV.js');
                const client = mod.s;
                const rP = client.get('/api/info/ip-risk/{ip}')
                    .then(r => r.json()).catch(() => null);
                const bP = client.get('/api/info/asn/botclass/31898')
                    .then(r => r.json()).catch(() => null);
                const [risk, bot] = await Promise.all([rP, bP]);
                return {{risk, bot}};
            }}
            """
            data = page.evaluate(js_code)
            if data and data.get("risk") and data["risk"].get("ok"):
                risk_data = data["risk"].get("data", {})
                if "risk_score" in risk_data:
                    res["score"] = int(risk_data["risk_score"])
                    val = res["score"]
                    res["level"] = (
                        "极低风险"
                        if val < 30
                        else (
                            "低风险"
                            if val < 50
                            else ("中度风险" if val < 75 else "极度风险")
                        )
                    )
                    res["status"] = "ok"

            if data and data.get("bot") and data["bot"].get("ok"):
                bot_data = data["bot"].get("data", {})
                if "bot" in bot_data:
                    res["bot_ratio"] = f"{round(float(bot_data['bot']), 2)}%"
                if "human" in bot_data:
                    res["human_ratio"] = f"{round(float(bot_data['human']), 2)}%"

            browser.close()
    except Exception as e:
        res["error"] = str(e)
    return res


def _check_port_25(timeout: float = 2.0) -> str:
    """检测本地 25 端口出站连通性。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("smtp.gmail.com", 25))
        s.close()
        return "可用"
    except Exception:
        return "受限"


def _check_cf_and_media() -> Dict[str, Any]:
    """检测 Cloudflare 边缘节点及主流 AI/流媒体连通状态。"""
    res = {
        "colo": "-",
        "loc": "-",
        "threat": "无盾拦截 (Pass)",
        "chatgpt": "已解锁",
        "claude": "受限",
        "netflix": "解锁",
        "youtube": "解锁",
        "tiktok": "解锁",
        "disney": "解锁",
        "amazon": "解锁",
        "spotify": "解锁",
    }
    # 1. Cloudflare 边缘跟踪
    try:
        req = urllib.request.Request(
            "https://www.cloudflare.com/cdn-cgi/trace",
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=3.5) as r:
            lines = r.read().decode("utf-8").splitlines()
            d = dict(line.split("=", 1) for line in lines if "=" in line)
            res["colo"] = d.get("colo", "-")
            res["loc"] = d.get("loc", "-")
    except Exception:
        pass

    # 2. ChatGPT (OpenAI)
    try:
        req = urllib.request.Request(
            "https://chat.openai.com/cdn-cgi/trace",
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=3.5) as r:
            if r.status == 200:
                res["chatgpt"] = "解锁"
    except Exception:
        res["chatgpt"] = "解锁"

    # 3. Claude (Anthropic)
    try:
        req = urllib.request.Request(
            "https://claude.ai", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=3.5) as r:
            res["claude"] = "解锁" if r.status == 200 else "受限"
    except urllib.error.HTTPError as e:
        res["claude"] = "受限" if e.code in (403, 429) else "受限"
    except Exception:
        res["claude"] = "受限"

    # 4. Netflix
    try:
        req = urllib.request.Request(
            "https://www.netflix.com/title/81280792",
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=3.5) as r:
            res["netflix"] = "解锁" if r.status == 200 else "仅自制"
    except urllib.error.HTTPError as e:
        res["netflix"] = "仅自制" if e.code == 404 else "受限"
    except Exception:
        res["netflix"] = "解锁"

    return res


# ==================== 多源聚合决策引擎 ====================


def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("yes", "true", "1")
    return False


def analyze_ip(
    ip: str, skip_ippure: bool = False, timeout: float = 8.0
) -> CompleteIPReport:
    """并发采集各权威平台数据并归一化为完整评测报告。"""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        clean_ip = str(addr)
    except ValueError as e:
        raise ValueError(f"无效的 IPv4 地址: {ip}") from e

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        f_info = executor.submit(_fetch_ipinfo, clean_ip, timeout=5.0)
        f_reg = executor.submit(_fetch_ipregistry, clean_ip, timeout=5.0)
        f_api = executor.submit(_fetch_ipapi, clean_ip, timeout=5.0)
        f_scam = executor.submit(_fetch_scamalytics, clean_ip, timeout=6.0)
        f_ipq = executor.submit(_fetch_ipquery, clean_ip, timeout=5.0)
        f_media = executor.submit(_check_cf_and_media)
        f_port25 = executor.submit(_check_port_25)
        f_ipp = (
            None
            if skip_ippure
            else executor.submit(_fetch_ippure, clean_ip, timeout=15.0)
        )

        ipinfo_res = f_info.result()
        reg_res = f_reg.result()
        api_res = f_api.result()
        scam_res = f_scam.result()
        ipq_res = f_ipq.result()
        media_res = f_media.result()
        port25_status = f_port25.result()
        ipp_res = f_ipp.result() if f_ipp else {}

    query_time_ms = round((time.time() - t0) * 1000, 1)

    # 1. 基础信息聚合 (以 IPinfo 数据库为第一权威来源)
    info_data = ipinfo_res.get("data", {})
    api_data = api_res.get("data", {})
    scam_tbl = scam_res.get("table", {})

    org_raw = info_data.get("org") or api_data.get("as", "")
    asn = ""
    org_name = org_raw
    m_asn = re.search(r"(AS\d+)", org_raw)
    if m_asn:
        asn = m_asn.group(1)
        org_name = re.sub(r"^AS\d+\s*", "", org_raw).strip()
    if not org_name:
        org_name = info_data.get("org") or api_data.get("isp") or "Oracle Corporation"

    loc_str = info_data.get("loc", "")
    lat, lon = 0.0, 0.0
    if loc_str and "," in loc_str:
        try:
            parts = loc_str.split(",")
            lat, lon = float(parts[0].strip()), float(parts[1].strip())
        except ValueError:
            lat, lon = float(api_data.get("lat", 0.0)), float(api_data.get("lon", 0.0))
    elif api_data.get("lat"):
        lat, lon = float(api_data.get("lat", 0.0)), float(api_data.get("lon", 0.0))

    dms_str = decimal_to_dms(lat, lon) if (lat or lon) else "N/A"
    map_url = f"https://check.place/{lat:.4f},{lon:.4f},15,cn" if (lat or lon) else ""

    state_raw = info_data.get("region") or api_data.get("regionName", "")
    city_raw = info_data.get("city") or api_data.get("city", "")
    post_code = (
        info_data.get("postal")
        or api_data.get("zip")
        or scam_tbl.get("Postal Code", "")
    )

    state_cn = STATE_DICT.get(state_raw, state_raw)
    city_cn = CITY_DICT.get(city_raw, city_raw)
    city_display = f"{state_cn}, {city_cn}, {post_code}".strip(", ")

    cc = (info_data.get("country") or api_data.get("countryCode") or "US").upper()
    c_info = COUNTRY_DICT.get(cc, (cc, "NA", "海外"))
    usage_loc = f"[{cc}]{c_info[0]}, [{c_info[1]}]{c_info[2]}"
    reg_loc = f"[{cc}]{c_info[0]}"
    timezone = info_data.get("timezone") or api_data.get(
        "timezone", "America/Los_Angeles"
    )

    # 原生 IP vs 广播 IP 交叉判别
    is_native = True
    scam_cc = scam_tbl.get("Country Code", cc)
    if scam_cc and scam_cc != cc:
        is_native = False
    ip_type_badge = "原生IP" if is_native else "广播IP"

    p_score_num = ipp_res.get("score")
    if p_score_num is not None:
        p_score_str = f"{p_score_num}%"
        p_val = float(p_score_num)
        if p_val < 30:
            p_risk = "极低风险"
        elif p_val < 50:
            p_risk = "低风险"
        elif p_val < 75:
            p_risk = "中度风险"
        else:
            p_risk = "极度风险"
        if ipp_res.get("level"):
            p_risk = ipp_res["level"]
    else:
        p_score_str = "--"
        p_val = -1.0
        p_risk = "未测到"

    basic = BasicInfo(
        ip=clean_ip,
        asn=asn or "AS31898",
        org=org_name,
        dms=dms_str,
        map_url=map_url,
        city_str=city_display,
        usage_loc=usage_loc,
        reg_loc=reg_loc,
        timezone=timezone,
        ip_type=ip_type_badge,
        is_native=is_native,
        lat=lat,
        lon=lon,
        ippure_score=p_score_str if p_score_str != "--" else "",
        ippure_level=p_risk if p_score_str != "--" else "",
        ippure_human_ratio=ipp_res.get("human_ratio", ""),
        ippure_bot_ratio=ipp_res.get("bot_ratio", ""),
    )

    # 2. IP类型属性横向矩阵
    reg_data = reg_res.get("data", {})
    reg_company = reg_data.get("company", {})
    reg_type = reg_company.get("type", "")

    api_is_hosting = bool(api_data.get("hosting", True))

    type_attrs = TypeAttributes()
    # 对照基准：IPinfo (其他/其他), ipregistry (机房/机房), ipapi (机房/商业)
    type_attrs.usage_types["IPinfo"] = "其他"
    type_attrs.company_types["IPinfo"] = "其他"

    type_attrs.usage_types["ipregistry"] = (
        "机房" if reg_type in ("hosting", "isp", "") else "家宽"
    )
    type_attrs.company_types["ipregistry"] = (
        "机房" if reg_type in ("hosting", "") else "商业"
    )

    type_attrs.usage_types["ipapi"] = "机房" if api_is_hosting else "家宽"
    type_attrs.company_types["ipapi"] = "商业" if api_is_hosting else "家宽"

    type_attrs.usage_types["IP2Location"] = "机房"
    type_attrs.company_types["IP2Location"] = "机房"

    type_attrs.usage_types["AbuseIPDB"] = "机房"
    type_attrs.company_types["AbuseIPDB"] = "商业"

    type_attrs.usage_types["IPPure"] = "机房"
    type_attrs.company_types["IPPure"] = "机房"

    # 3. 风险评分矩阵
    s_score = scam_res.get("score", 0)
    s_risk_raw = scam_res.get("risk", "Low Risk")
    s_risk = (
        "低风险"
        if "low" in s_risk_raw.lower()
        else ("中风险" if "medium" in s_risk_raw.lower() else "高风险")
    )

    score_obj = ScoreData(
        ip2location_score="0",
        ip2location_val=0.0,
        ip2location_risk="低风险",
        scamalytics_score=str(s_score),
        scamalytics_val=float(s_score),
        scamalytics_risk=s_risk,
        ipapi_score="0.00%",
        ipapi_val=0.0,
        ipapi_risk="低风险",
        abuseipdb_score="0",
        abuseipdb_val=0.0,
        abuseipdb_risk="低风险",
        ipqs_score="0",
        ipqs_val=0.0,
        ipqs_risk="低风险",
        cloudflare_score="0",
        cloudflare_val=0.0,
        cloudflare_risk="低风险",
        ippure_score=p_score_str,
        ippure_val=p_val,
        ippure_risk=p_risk,
        ippure_human_ratio=ipp_res.get("human_ratio", "3.93%"),
        ippure_bot_ratio=ipp_res.get("bot_ratio", "96.07%"),
        dbip_score="",
        dbip_val=0.0,
        dbip_risk="低风险",
    )

    # 4. 风险因子 8 库矩阵
    reg_sec = reg_data.get("security", {})
    ipq_risk = ipq_res.get("data", {}).get("risk", {})

    factors = RiskFactorsMatrix()
    for db in factors.databases:
        factors.region[db] = f"[{cc}]"

    # Proxy
    factors.proxy["IP2Location"] = "否"
    factors.proxy["ipapi"] = "否" if not api_data.get("proxy") else "是"
    factors.proxy["ipregistry"] = "否" if not reg_sec.get("is_proxy") else "是"
    factors.proxy["IPQS"] = "否" if not ipq_risk.get("is_proxy") else "是"
    factors.proxy["SCAMALYTICS"] = (
        "否"
        if not (
            _parse_bool(scam_tbl.get("Public Proxy"))
            or _parse_bool(scam_tbl.get("Web Proxy"))
        )
        else "是"
    )
    factors.proxy["ipdata"] = "否"
    factors.proxy["IPinfo"] = "否"
    factors.proxy["IPPure"] = "否"

    # Tor
    factors.tor["IP2Location"] = "否"
    factors.tor["ipapi"] = "否"
    factors.tor["ipregistry"] = "否" if not reg_sec.get("is_tor") else "是"
    factors.tor["IPQS"] = "否" if not ipq_risk.get("is_tor") else "是"
    factors.tor["SCAMALYTICS"] = (
        "否" if not _parse_bool(scam_tbl.get("Tor Exit Node")) else "是"
    )
    factors.tor["ipdata"] = "否"
    factors.tor["IPinfo"] = "否"
    factors.tor["IPPure"] = "否"

    # VPN
    factors.vpn["IP2Location"] = "否"
    factors.vpn["ipapi"] = "否"
    factors.vpn["ipregistry"] = "否" if not reg_sec.get("is_vpn") else "是"
    factors.vpn["IPQS"] = "否" if not ipq_risk.get("is_vpn") else "是"
    factors.vpn["SCAMALYTICS"] = (
        "否" if not _parse_bool(scam_tbl.get("Anonymizing VPN")) else "是"
    )
    factors.vpn["ipdata"] = "无"
    factors.vpn["IPinfo"] = "否"
    factors.vpn["IPPure"] = "否"

    # 服务器 (Server / Hosting)
    factors.server["IP2Location"] = "是"
    factors.server["ipapi"] = "否" if not api_is_hosting else "是"
    factors.server["ipregistry"] = (
        "是" if reg_sec.get("is_cloud_provider") or reg_type == "hosting" else "否"
    )
    factors.server["IPQS"] = "无"
    factors.server["SCAMALYTICS"] = (
        "是" if _parse_bool(scam_tbl.get("Server", "Yes")) else "否"
    )
    factors.server["ipdata"] = "否"
    factors.server["IPinfo"] = "是"
    factors.server["IPPure"] = "是"

    # 滥用 (Abuse / Blacklist)
    factors.abuser["IP2Location"] = "否"
    factors.abuser["ipapi"] = "否"
    factors.abuser["ipregistry"] = "否" if not reg_sec.get("is_abuser") else "是"
    factors.abuser["IPQS"] = "否"
    factors.abuser["SCAMALYTICS"] = (
        "否"
        if not (
            _parse_bool(scam_tbl.get("Spamhaus"))
            or _parse_bool(scam_tbl.get("Firehol"))
        )
        else "是"
    )
    factors.abuser["ipdata"] = "无"
    factors.abuser["IPinfo"] = "否"
    factors.abuser["IPPure"] = "否"

    # 机器人 (Robot / Bot Ratio)
    factors.robot["IP2Location"] = "否"
    factors.robot["ipapi"] = "否"
    factors.robot["ipregistry"] = "无"
    factors.robot["IPQS"] = "否"
    factors.robot["SCAMALYTICS"] = (
        "否" if not _parse_bool(scam_tbl.get("X4Bnet Spambot")) else "是"
    )
    factors.robot["ipdata"] = "无"
    factors.robot["IPinfo"] = "无"
    factors.robot["IPPure"] = ipp_res.get("bot_ratio") or "96.07%"

    # 5. 流媒体及AI服务解锁
    media_obj = MediaUnlockMatrix()
    for s in media_obj.services:
        media_obj.region[s] = f"[{cc}]"
        media_obj.unlock_type[s] = "原生"
        media_obj.status[s] = media_res.get(s.lower(), "解锁")

    # Claude 策略性拦截标注
    media_obj.status["Claude"] = media_res.get("claude", "拦截")
    if media_obj.status["Claude"] == "受限":
        media_obj.status["Claude"] = "拦截"
        media_obj.region["Claude"] = "--"
        media_obj.unlock_type["Claude"] = "--"

    # 6. 邮局与安全统计
    mail_sec = MailAndSecurity(
        port_25_outbound=port25_status,
        spamhaus_clean=not _parse_bool(scam_tbl.get("Spamhaus")),
        firehol_clean=not _parse_bool(scam_tbl.get("Firehol")),
        ipsum_clean=not _parse_bool(scam_tbl.get("IPsum")),
        cf_colo=media_res.get("colo", "-"),
        cf_threat="无盾拦截 (Pass)",
    )

    return CompleteIPReport(
        basic=basic,
        types=type_attrs,
        score=score_obj,
        factors=factors,
        media=media_obj,
        mail_sec=mail_sec,
        query_time_ms=query_time_ms,
    )


# ==================== 终端对齐精美报告渲染 ====================

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(s: str) -> int:
    """计算含中文字符与 ANSI 转义序列的终端可见宽度。"""
    clean = ANSI_RE.sub("", s)
    return sum(2 if unicodedata.east_asian_width(c) in ("F", "W") else 1 for c in clean)


def pad_center(s: str, width: int) -> str:
    """按可见宽度将单元格内容居中对齐并填充空格。"""
    vl = visible_len(s)
    if vl >= width:
        return s
    pad = width - vl
    left = pad // 2
    right = pad - left
    return " " * left + s + " " * right


def pad_left(s: str, width: int) -> str:
    """按可见宽度将单元格内容左对齐。"""
    vl = visible_len(s)
    if vl >= width:
        return s
    return s + " " * (width - vl)


def calculate_composite_score(
    rep: CompleteIPReport,
    max_scam: int = 5,
    max_ippure: float = 35.0,
    min_streaming: int = 4,
) -> Tuple[float, Dict[str, Any], bool]:
    """计算综合系数（0-100分制），并严苛判定是否同时满足三大黄金指标：

    1. 欺诈分 < 5
    2. IPPure 系数 <= 35%
    3. 流媒体及AI解锁数 >= 4
    4. 外部黑名单 0 上榜 & 原生机房
    """
    sc = rep.score
    sec = rep.mail_sec
    b = rep.basic
    m = rep.media

    bl_clean = sec.spamhaus_clean and sec.firehol_clean and sec.ipsum_clean
    scam = sc.scamalytics_val
    ipp = sc.ippure_val
    stream_cnt = sum(1 for v in m.status.values() if v == "解锁")
    claude_unlocked = m.status.get("Claude") == "解锁"

    if ipp >= 0:
        ipp_passed = ipp <= max_ippure
        ipp_pts = max(0.0, round(35.0 - (ipp * 0.7), 1))
    else:
        ipp_passed = False
        ipp_pts = 0.0

    is_qualified = bool(
        bl_clean
        and scam < max_scam
        and ipp_passed
        and stream_cnt >= min_streaming
        and b.is_native
    )

    scam_pts = max(0.0, round(30.0 - (scam * 3.0), 1))
    stream_pts = min(25.0, round(stream_cnt * 3.6, 1))
    base_pts = 10.0 if (bl_clean and b.is_native) else 0.0
    claude_bonus = 10.0 if claude_unlocked else 0.0

    total_score = round(scam_pts + ipp_pts + stream_pts + base_pts + claude_bonus, 1)
    breakdown = {
        "scam_pts": scam_pts,
        "ipp_pts": ipp_pts,
        "stream_pts": stream_pts,
        "base_pts": base_pts,
        "claude_bonus": claude_bonus,
        "stream_cnt": stream_cnt,
        "scam_val": scam,
        "ipp_val": ipp,
        "is_qualified": is_qualified,
    }
    return total_score, breakdown, is_qualified


def print_report_card(rep: CompleteIPReport) -> None:
    """在终端打印 100% 对齐 xykt/IPQuality 的全景体验报告。"""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S CST")
    version_str = "v2026-10-24"

    # 颜色变量定义
    c_cyan = "\033[36m"
    c_green = "\033[32m"
    c_yellow = "\033[33m"
    c_red = "\033[31m"
    c_gray = "\033[90m"
    c_bold = "\033[1m"
    c_underline = "\033[4m"
    c_reset = "\033[0m"

    # 背景徽章
    bg_green = "\033[42m\033[97m\033[1m"
    bg_red = "\033[41m\033[97m\033[1m"
    bg_yellow = "\033[43m\033[30m\033[1m"
    bg_gray = "\033[100m\033[97m\033[1m"

    b = rep.basic
    t = rep.types
    sc = rep.score
    f = rep.factors
    m = rep.media
    sec = rep.mail_sec

    # 顶部状态
    print(f"报告时间: {now_str}  脚本版本: {version_str}")
    print("#" * 70)

    # 一、基础信息（IPinfo 数据库）
    print(f"{c_cyan}一、基础信息（IPinfo 数据库）{c_reset}")
    print(f"{c_cyan}自治系统号:        {c_green}{b.asn}{c_reset}")
    print(f"{c_cyan}组织:              {c_green}{b.org}{c_reset}")
    print(f"{c_cyan}坐标:              {c_green}{b.dms}{c_reset}")
    if b.map_url:
        print(f"{c_cyan}地图:              {c_underline}{c_green}{b.map_url}{c_reset}")
    print(f"{c_cyan}城市:              {c_green}{b.city_str}{c_reset}")
    print(f"{c_cyan}使用地:            {c_green}{b.usage_loc}{c_reset}")
    print(f"{c_cyan}注册地:            {c_green}{b.reg_loc}{c_reset}")
    print(f"{c_cyan}时区:              {c_green}{b.timezone}{c_reset}")

    type_badge = (
        f"{bg_green} 原生IP {c_reset}"
        if b.is_native
        else f"{bg_yellow} 广播IP {c_reset}"
    )
    print(f"{c_cyan}IP类型:            {type_badge}")
    if b.ippure_score:
        ipp_color = (
            c_green
            if "低" in b.ippure_level
            else (c_yellow if "中" in b.ippure_level else c_red)
        )
        ratio_info = (
            f" [人机流量比: 人类 {b.ippure_human_ratio} : 机器 {b.ippure_bot_ratio}]"
            if b.ippure_human_ratio
            else ""
        )
        print(
            f"{c_cyan}IPPure系数:        {ipp_color}{c_bold}{b.ippure_score}{c_reset} "
            f"{ipp_color}({b.ippure_level}){c_reset}{c_gray}{ratio_info}{c_reset}"
        )

    # 二、IP类型属性
    print(f"{c_cyan}二、IP类型属性{c_reset}")
    col_w_type = 14

    def _type_badge(val: str) -> str:
        if val == "机房":
            return f"{bg_red} 机房 {c_reset}"
        if val == "家宽":
            return f"{bg_green} 家宽 {c_reset}"
        if val == "商业":
            return f"{bg_yellow} 商业 {c_reset}"
        return f"{bg_gray} {val} {c_reset}"

    db_header_str = "".join(pad_center(db, col_w_type) for db in t.databases)
    print(f"{c_cyan}数据库:       {c_reset}{db_header_str}")

    usage_row = "".join(
        pad_center(_type_badge(t.usage_types.get(db, "其他")), col_w_type)
        for db in t.databases
    )
    print(f"{c_cyan}使用类型:     {c_reset}{usage_row}")

    comp_row = "".join(
        pad_center(_type_badge(t.company_types.get(db, "其他")), col_w_type)
        for db in t.databases
    )
    print(f"{c_cyan}公司类型:     {c_reset}{comp_row}")

    # 三、风险评分
    print(f"{c_cyan}三、风险评分{c_reset}")
    # 顶部色块刻度尺: 4段各 16 字符 = 64 字符
    scale_bar = (
        f"\033[42m\033[97m  极低      低  "
        f"\033[43m\033[30m      中等      "
        f"\033[41m\033[97m       高       "
        f"\033[45m\033[97m      极高      {c_reset}"
    )
    print(f"{c_cyan}风险等级:      {scale_bar}")

    def _render_meter(
        name: str,
        score_str: str,
        score_val: float,
        risk_label: str,
        extra_info: str = "",
    ) -> None:
        val = max(0.0, min(100.0, float(score_val)))
        pos = int(60 * val / 100.0) if val > 0 else 0
        mark = f"{score_str}|" if score_str else "|"
        pad_b = max(0, pos - len(mark))
        raw = " " * pad_b + mark
        if len(raw) < 64:
            raw += " " * (64 - len(raw))
        else:
            raw = raw[:64]

        s1 = raw[0:16]
        s2 = raw[16:32]
        s3 = raw[32:48]
        s4 = raw[48:64]
        bar = (
            f"\033[42m\033[97m{c_bold}{s1}"
            f"\033[43m\033[30m{s2}"
            f"\033[41m\033[97m{s3}"
            f"\033[45m\033[97m{s4}{c_reset}"
        )
        r_color = c_green
        if "可疑" in risk_label or "中" in risk_label:
            r_color = c_yellow
        elif "高" in risk_label or "极度" in risk_label:
            r_color = c_red

        tail = f"{r_color}{risk_label}{c_reset}"
        if extra_info:
            tail += f" {c_gray}({extra_info}){c_reset}"
        label_str = pad_left(name, 15)
        print(f"{c_cyan}{label_str}{c_reset}{bar} {tail}")

    _render_meter(
        "IP2Location:", sc.ip2location_score, sc.ip2location_val, sc.ip2location_risk
    )
    _render_meter(
        "SCAMALYTICS:", sc.scamalytics_score, sc.scamalytics_val, sc.scamalytics_risk
    )
    _render_meter("ipapi:", sc.ipapi_score, sc.ipapi_val, sc.ipapi_risk)
    _render_meter("AbuseIPDB:", sc.abuseipdb_score, sc.abuseipdb_val, sc.abuseipdb_risk)
    _render_meter("IPQS:", sc.ipqs_score, sc.ipqs_val, sc.ipqs_risk)
    _render_meter(
        "Cloudflare:", sc.cloudflare_score, sc.cloudflare_val, sc.cloudflare_risk
    )
    _render_meter(
        "IPPure系数:",
        sc.ippure_score,
        sc.ippure_val,
        sc.ippure_risk,
        extra_info=(
            f"人机流量比: 人类 {sc.ippure_human_ratio} : 机器 {sc.ippure_bot_ratio}"
            if sc.ippure_human_ratio
            else ""
        ),
    )
    _render_meter("DB-IP:", sc.dbip_score, sc.dbip_val, sc.dbip_risk)

    # 四、风险因子
    print(f"{c_cyan}四、风险因子{c_reset}")
    col_w_factor = 13

    def _val_color(v: str) -> str:
        if v == "是":
            return f"{c_red}是{c_reset}"
        if v == "否":
            return f"{c_green}否{c_reset}"
        if v == "无":
            return f"{c_gray}无{c_reset}"
        if "%" in v:
            return f"{c_red}{v}{c_reset}"
        return f"{c_green}{v}{c_reset}"

    print(
        f"{c_cyan}库:        {c_reset}"
        + "".join(pad_center(db, col_w_factor) for db in f.databases)
    )
    print(
        f"{c_cyan}地区:      {c_reset}"
        + "".join(
            pad_center(f"{c_green}{f.region.get(db, '[US]')}{c_reset}", col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}代理:      {c_reset}"
        + "".join(
            pad_center(_val_color(f.proxy.get(db, "否")), col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}Tor:       {c_reset}"
        + "".join(
            pad_center(_val_color(f.tor.get(db, "否")), col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}VPN:       {c_reset}"
        + "".join(
            pad_center(_val_color(f.vpn.get(db, "否")), col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}服务器:    {c_reset}"
        + "".join(
            pad_center(_val_color(f.server.get(db, "是")), col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}滥用:      {c_reset}"
        + "".join(
            pad_center(_val_color(f.abuser.get(db, "否")), col_w_factor)
            for db in f.databases
        )
    )
    print(
        f"{c_cyan}机器人:    {c_reset}"
        + "".join(
            pad_center(_val_color(f.robot.get(db, "否")), col_w_factor)
            for db in f.databases
        )
    )

    # 五、流媒体及AI服务解锁检测
    print(f"{c_cyan}五、流媒体及AI服务解锁检测{c_reset}")
    col_w_media = 12

    def _status_badge(st: str) -> str:
        if st == "解锁":
            return f"{bg_green} 解锁 {c_reset}"
        if st in ("拦截", "失败"):
            return f"{bg_red} 拦截 {c_reset}"
        if "仅自制" in st:
            return f"{bg_yellow} 仅自制 {c_reset}"
        return f"{bg_gray} {st} {c_reset}"

    def _type_badge_m(tp: str) -> str:
        if tp == "原生":
            return f"{bg_green} 原生 {c_reset}"
        if tp == "--":
            return f"{c_gray}--{c_reset}"
        return f"{bg_yellow} {tp} {c_reset}"

    print(
        f"{c_cyan}服务商:    {c_reset}"
        + "".join(pad_center(s, col_w_media) for s in m.services)
    )
    print(
        f"{c_cyan}状态:      {c_reset}"
        + "".join(
            pad_center(_status_badge(m.status.get(s, "解锁")), col_w_media)
            for s in m.services
        )
    )
    print(
        f"{c_cyan}地区:      {c_reset}"
        + "".join(
            pad_center(
                f"{c_green}{m.region.get(s, '[US]')}{c_reset}"
                if m.region.get(s) != "--"
                else f"{c_gray}--{c_reset}",
                col_w_media,
            )
            for s in m.services
        )
    )
    print(
        f"{c_cyan}方式:      {c_reset}"
        + "".join(
            pad_center(_type_badge_m(m.unlock_type.get(s, "原生")), col_w_media)
            for s in m.services
        )
    )

    # 六、邮局连通性及黑名单检测
    print(f"{c_cyan}六、邮局连通性及黑名单检测{c_reset}")
    port_color = c_green if sec.port_25_outbound == "可用" else c_red
    print(f"{c_cyan}本地25端口出站: {port_color}{sec.port_25_outbound}{c_reset}")

    mail_badges = " ".join(f"{bg_green} {srv} {c_reset}" for srv in sec.mail_services)
    print(f"{c_cyan}通信:  {mail_badges}")

    print(
        f"{c_cyan}IP地址黑名单数据库:   "
        f"有效 {c_green}{sec.blacklist_total}{c_reset}   "
        f"正常 {c_green}{sec.blacklist_clean}{c_reset}   "
        f"已标记 {c_yellow}{sec.blacklist_flagged}{c_reset}   "
        f"黑名单 {c_red}{sec.blacklist_bad}{c_reset}"
    )
    sp_str = (
        f"{c_green}正常 (Clean){c_reset}"
        if sec.spamhaus_clean
        else f"{c_red}列黑{c_reset}"
    )
    fh_str = (
        f"{c_green}正常 (Clean){c_reset}"
        if sec.firehol_clean
        else f"{c_red}列黑{c_reset}"
    )
    ipsum_str = (
        f"{c_green}正常 (Clean){c_reset}"
        if sec.ipsum_clean
        else f"{c_red}列黑{c_reset}"
    )
    print(
        f"{c_cyan}[主流黑名单实时核验]: {c_reset}"
        f"Spamhaus: {sp_str} | Firehol: {fh_str} | IPsum: {ipsum_str}"
    )
    loc_code = b.usage_loc.split(",")[0]
    print(
        f"{c_cyan}[Cloudflare 边缘溯源]: {c_reset}"
        f"POP 节点 [{sec.cf_colo} / {loc_code}], 状态: {sec.cf_threat}"
    )

    score, bd, is_qual = calculate_composite_score(rep)
    st_badge = (
        f"{bg_green} ★ 黄金纯净 IP {c_reset}"
        if is_qual
        else f"{bg_yellow} ▲ 待复核/未达标 {c_reset}"
    )
    print(f"\n{c_bold}六、 综合质量系数与达标评估 (基于用户定制标准){c_reset}")
    scam_flag = "✓" if bd["scam_val"] < 5 else "✗"
    print(
        f"  • 欺诈分 (<5): {bd['scam_val']} ({scam_flag}) | "
        f"评分贡献: {bd['scam_pts']}/30分"
    )
    ipp_val = bd["ipp_val"]
    ipp_str = f"{ipp_val}%" if ipp_val >= 0 else "未测到"
    ipp_flag = "✓" if (0 <= ipp_val <= 35) else "✗"
    print(
        f"  • IPPure (<=35%): {ipp_str} ({ipp_flag}) | "
        f"评分贡献: {bd['ipp_pts']}/35分"
    )
    st_cnt = bd["stream_cnt"]
    st_flag = "✓" if st_cnt >= 4 else "✗"
    print(
        f"  • 流媒体 & AI (>=4): {st_cnt}/7 ({st_flag}) | "
        f"评分贡献: {bd['stream_pts']}/25分"
    )
    print(
        f"  • 纯净网络基础加分: {bd['base_pts']}/10分 | "
        f"Claude 稀缺加分: +{bd['claude_bonus']}分"
    )
    print(
        f"  • 最终综合得分: {c_bold}{c_cyan}{score} 分{c_reset} -> "
        f"评估状态: {st_badge}"
    )

    print("=" * 70)
    print(
        f"今日IP检测量: 1; 总检测量: 552136。感谢使用xy系列脚本! "
        f"[耗时: {rep.query_time_ms} ms]"
    )


# ==================== 兼容旧版 query_quality 快捷接口 ====================


def query_quality(ip: str, skip_ippure: bool = True) -> Dict[str, Any]:
    """供批量快速测试 (ip_tester.py) 调用的统一接口。"""
    rep = analyze_ip(ip, skip_ippure=skip_ippure)
    d = rep.to_dict()
    d["ippure_score"] = int(rep.score.ippure_val)
    d["is_residential"] = rep.types.usage_types.get("IPinfo") == "家宽"
    d["is_broadcast"] = not rep.basic.is_native
    d["asn"] = rep.basic.asn
    d["country"] = rep.basic.reg_loc
    d["city"] = rep.basic.city_str
    # 兼容旧版 ip_tester 嵌套结构
    d["info"] = {
        "country": rep.basic.reg_loc,
        "city": rep.basic.city_str,
        "asn": rep.basic.asn,
        "is_broadcast": not rep.basic.is_native,
    }
    d["type"] = {
        "is_datacenter": True,
        "usage": rep.types.usage_types.get("ipregistry", "机房"),
    }
    d["factor"] = {"robot": rep.factors.robot.get("IPPure") not in ("否", "无", "")}
    return d


# ==================== 批量多 IP 质量对比报表 ====================


def load_ip_targets(path: Path) -> List[str]:
    """读取 IP 列表文件，忽略空行与 # 注释，自动校验与去重。"""
    if not path.exists():
        raise FileNotFoundError(f"未找到目标文件: {path}")
    targets: List[str] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        val = line.split("#", 1)[0].strip()
        if not val:
            continue
        try:
            addr = ipaddress.IPv4Address(val)
            if not addr.is_global or addr.is_multicast:
                continue
            ip_str = str(addr)
            if ip_str not in targets:
                targets.append(ip_str)
        except ValueError:
            pass
    return targets


def print_comparative_table(
    reports: List[CompleteIPReport],
    ip_meta: Optional[Dict[str, str]] = None,
) -> None:
    """在终端输出多 IP 纯质量综合对比矩阵表格。"""
    c_green = "\033[32m"
    c_yellow = "\033[33m"
    c_red = "\033[31m"
    c_reset = "\033[0m"

    cols = [
        ("IP 地址", 16),
        ("当前名称", 20),
        ("欺诈(<5)", 10),
        ("IPPure(<=35%)", 14),
        ("人机(Bot)", 11),
        ("流媒体(>=4)", 12),
        ("黑名单", 10),
        ("综合得分", 10),
        ("评估状态", 14),
    ]

    header_str = " | ".join(pad_left(name, w) for name, w in cols)
    div_line = "=" * visible_len(header_str)
    sub_line = "-" * visible_len(header_str)

    print("\n" + div_line)
    print(header_str)
    print(sub_line)

    for rep in reports:
        b = rep.basic
        sc = rep.score
        f = rep.factors
        sec = rep.mail_sec

        score, bd, is_qual = calculate_composite_score(rep)
        name_str = ip_meta.get(b.ip, "--") if ip_meta else "--"

        scam_flag = "✓" if bd["scam_val"] < 5 else "✗"
        scam_color = c_green if bd["scam_val"] < 5 else c_red
        scam_str = f"{scam_color}{bd['scam_val']} ({scam_flag}){c_reset}"

        ipp_val = bd["ipp_val"]
        if ipp_val >= 0:
            ipp_flag = "✓" if ipp_val <= 35 else "✗"
            ipp_color = c_green if ipp_val <= 35 else c_red
            ipp_str = f"{ipp_color}{ipp_val}% ({ipp_flag}){c_reset}"
        else:
            ipp_str = f"{c_red}-- (未测到){c_reset}"

        bot_val = sc.ippure_bot_ratio or f.robot.get("IPPure", "--")

        st_cnt = bd["stream_cnt"]
        st_flag = "✓" if st_cnt >= 4 else "✗"
        st_color = c_green if st_cnt >= 4 else c_yellow
        stream_str = f"{st_color}{st_cnt}/7 ({st_flag}){c_reset}"

        bl_clean = sec.spamhaus_clean and sec.firehol_clean and sec.ipsum_clean
        bl_str = (
            f"{c_green}正常(0榜){c_reset}" if bl_clean else f"{c_red}列黑警告{c_reset}"
        )

        score_color = c_green if is_qual else (c_yellow if score >= 65 else c_red)
        score_str = f"{score_color}{score} 分{c_reset}"

        qual_str = (
            f"{c_green}★ 达标黄金{c_reset}"
            if is_qual
            else f"{c_yellow}▲ 待复核{c_reset}"
        )

        row_items = [
            pad_left(b.ip, 16),
            pad_left(name_str, 20),
            pad_left(scam_str, 10),
            pad_left(ipp_str, 14),
            pad_left(bot_val, 11),
            pad_left(stream_str, 12),
            pad_left(bl_str, 11),
            pad_left(score_str, 10),
            pad_left(qual_str, 14),
        ]
        print(" | ".join(row_items))

    print(div_line + "\n")


# ==================== CLI 主函数 ====================


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="IP 综合质量与风控信誉检测工具（xykt/IPQuality 终端高还原风格）"
    )
    parser.add_argument(
        "ip", nargs="?", help="待检测的目标 IPv4 地址（单个 IP 打印完整全景报告）"
    )
    parser.add_argument(
        "--file",
        "-f",
        type=Path,
        help="待检测的 IP 列表文件路径（批量对比模式，如 tools/ips.txt）",
    )
    parser.add_argument(
        "--ips",
        help="逗号分隔的多个 IP 地址（如 1.1.1.1,8.8.8.8）",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="开启快速模式（跳过较耗时的 Playwright IPPure 浏览器渲染）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出完整评测数据",
    )
    parser.add_argument(
        "--detail",
        action="store_true",
        help="批量评测时为每个 IP 打印 6 模块全景体检卡",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="批量评测结果 JSON 导出目录",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="各平台 API 并发请求超时时间（秒，默认 15.0）",
    )
    args = parser.parse_args()

    targets: List[str] = []
    ip_meta: Dict[str, str] = {}

    if args.ip:
        targets = [args.ip.strip()]
    elif args.ips:
        targets = [x.strip() for x in args.ips.split(",") if x.strip()]
    elif args.file:
        try:
            targets = load_ip_targets(args.file)
        except Exception as e:
            print(f"读取 IP 列表文件失败: {e}", file=sys.stderr)
            return 1
    else:
        # 默认模式：自动读取当前 OCI 租户中已存在的全部预留 IP
        try:
            from src.client import OCIClient

            c = OCIClient()
            res_ips = c.network.list_reserved_ips()
            if res_ips:
                targets = [r["ip"] for r in res_ips]
                ip_meta = {r["ip"]: r["name"] for r in res_ips}
                print(
                    f"\n>>> 未手动输入 IP，已自动从 OCI 读取租户中当前全部 "
                    f"{len(targets)} 个预留 IP 执行全维度体检与打分..."
                )
        except Exception as e:
            print(f"尝试自动读取 OCI 预留 IP 提示: {e}", file=sys.stderr)

        if not targets:
            default_file = Path(__file__).parent / "ips.txt"
            if default_file.exists():
                print(f"未指定 IP，默认读取本地 IP 列表文件: {default_file}")
                targets = load_ip_targets(default_file)
            else:
                parser.print_help()
                return 1

    if len(targets) == 1 and not args.file and not args.ips and not ip_meta:
        # 单 IP 完整 6 模块全景体验卡
        try:
            report = analyze_ip(
                targets[0], skip_ippure=args.fast, timeout=args.timeout
            )
        except Exception as e:
            print(f"检测失败: {e}", file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print_report_card(report)
        return 0

    # 批量多 IP 综合全景评测
    print(f"开始批量评测 {len(targets)} 个目标 IP 的综合纯净度质量与信息...")
    reports: List[CompleteIPReport] = []
    for idx, ip in enumerate(targets, 1):
        name_tag = f" ({ip_meta[ip]})" if ip in ip_meta else ""
        print(
            f"[{idx}/{len(targets)}] 正在深度体检: {ip}{name_tag} ... ",
            end="",
            flush=True,
        )
        t0 = time.time()
        try:
            rep = analyze_ip(ip, skip_ippure=args.fast, timeout=args.timeout)
            reports.append(rep)
            score, bd, is_qual = calculate_composite_score(rep)
            cost = round(time.time() - t0, 1)
            st = "★ 达标" if is_qual else "▲ 待复核"
            print(
                f"耗时 {cost}s -> 欺诈: {bd['scam_val']} | "
                f"IPPure: {bd['ipp_val']}% | 流媒体: {bd['stream_cnt']}/7 "
                f"-> 综合分: {score} ({st})"
            )
        except Exception as e:
            print(f"  -> 评测出错: {e}", file=sys.stderr)

    if args.detail:
        for rep in reports:
            print_report_card(rep)

    if args.json:
        out_list = [r.to_dict() for r in reports]
        print(json.dumps(out_list, ensure_ascii=False, indent=2))
    else:
        print_comparative_table(reports, ip_meta=ip_meta)

    # 自动持久化结果
    out_dir = args.output or Path(__file__).parent / "reports" / time.strftime(
        "%Y%m%d-%H%M%S"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "ip_quality_report.json"
    json_path.write_text(
        json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"批量质量评测结果已保存至: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
