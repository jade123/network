"""
员工IP流量监控 - Flask 本地服务
- 提供 REST API 给前端调用
- 后台定时采集网关数据
- 支持告警检测
- 支持 PBR (Policy Based Routing) 规则管理
"""

import json
import ipaddress
import os
import re
import sys
import threading
import time
import logging
from pathlib import Path
from urllib.parse import urlencode, urljoin

import requests
from flask import Flask, jsonify, make_response, request, send_from_directory
from flask_cors import CORS

from scraper import CloudValleyScraper, load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("server")

BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
CONFIG_PATH = Path(os.environ.get("NETMON_CONFIG_PATH", BASE_DIR / "config.json"))
DATA_DIR = Path(os.environ.get("NETMON_DATA_DIR", BASE_DIR / ".netmon_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "latest_data.json"
AUTO_LIMIT_FILE = DATA_DIR / "auto_limited_ips.json"
IP_GEO_CACHE_FILE = DATA_DIR / "ip_geo_cache.json"
EMPLOYEE_NAME_CACHE_FILE = DATA_DIR / "employee_names.json"
MAC_BINDINGS_FILE = DATA_DIR / "mac_bindings.json"

LOG_PATH = os.environ.get("NETMON_LOG_PATH")
if LOG_PATH:
    log_path = Path(LOG_PATH)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(file_handler)

DEEPSEEK_MODELS = [
    {"id": "deepseek-v4-flash", "name": "DeepSeek V4 Flash"},
    {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro"},
]

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="")
CORS(app)

# ─── 全局共享 scraper（避免重复登录）──

_shared_scraper = None
_shared_scraper_lock = threading.Lock()


def get_shared_scraper():
    """获取或创建共享的 scraper 实例（线程安全）"""
    global _shared_scraper
    with _shared_scraper_lock:
        if _shared_scraper is None:
            cfg = load_config()
            _shared_scraper = CloudValleyScraper(cfg)
        return _shared_scraper


def ensure_login(scraper=None):
    """确保 scraper 已登录，session 失效则自动重新登录"""
    if scraper is None:
        scraper = get_shared_scraper()
    try:
        test_url = scraper.base_url + "/cgi-bin/luci/admin/status/analyst"
        resp = scraper.session.get(test_url, timeout=scraper.timeout)
        if resp.status_code == 200 and "analyst" in resp.url:
            return True
    except Exception:
        pass
    log.info("Session 失效，重新登录...")
    return scraper.login()


# ─── 全局状态 ───

def normalize_mac(mac: str) -> str:
    """统一 MAC 格式，便于 H3C 数据和手动命名匹配。"""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2)).upper()


def mac_binding_payload() -> dict:
    items = []
    by_ip = {}
    by_mac = {}
    for key, item in state.mac_bindings.items():
        ip = str(item.get("ip", "")).strip()
        mac_source = item.get("mac") or (key if not str(key).startswith("ip:") else "")
        mac = normalize_mac(mac_source)
        if not mac and not ip:
            continue
        record = {
            "id": mac or f"ip:{ip}",
            "mac": mac,
            "ip": ip,
            "name": str(item.get("name", "")).strip(),
            "updated_at": item.get("updated_at", ""),
        }
        items.append(record)
        if record["ip"]:
            by_ip[record["ip"]] = record
        if record["mac"]:
            by_mac[record["mac"]] = record
    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return {
        "items": items,
        "by_mac": by_mac,
        "by_ip": by_ip,
    }


class AppState:
    def __init__(self):
        self.latest_data = {
            "source": [],
            "destination": [],
            "source_traffic": [],
            "source_traffic_24h": [],
            "scraped_at": None,
            "error": None,
        }
        self.scrape_history = []
        self.alerts = []
        self.rules = []
        self.whitelist = []
        self.auto_limited_ips = []
        self.auto_limit_events = []
        self.ip_geo_cache = {}
        self.employee_names = {}
        self.employee_names_updated_at = None
        self.mac_bindings = {}
        self.config = load_config()
        self.whitelist = self.config.get("monitor", {}).get("whitelist", ["192.168.20.1", "192.168.20.2"])
        self._load_rules()
        self._load_auto_limited()
        self._load_ip_geo_cache()
        self._load_employee_names()
        self._load_mac_bindings()
        # 注意：不加载旧数据，等首次采集完成

    def _load_rules(self):
        rules_path = DATA_DIR / "rules.json"
        if rules_path.exists():
            with open(rules_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)

    def _load_auto_limited(self):
        if AUTO_LIMIT_FILE.exists():
            try:
                with open(AUTO_LIMIT_FILE, "r", encoding="utf-8") as f:
                    self.auto_limited_ips = json.load(f)
            except Exception:
                self.auto_limited_ips = []

    def _load_ip_geo_cache(self):
        if IP_GEO_CACHE_FILE.exists():
            try:
                with open(IP_GEO_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.ip_geo_cache = json.load(f)
            except Exception:
                self.ip_geo_cache = {}

    def _load_employee_names(self):
        if EMPLOYEE_NAME_CACHE_FILE.exists():
            try:
                with open(EMPLOYEE_NAME_CACHE_FILE, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                self.employee_names = payload.get("names", {})
                self.employee_names_updated_at = payload.get("updated_at")
            except Exception:
                self.employee_names = {}
                self.employee_names_updated_at = None

    def _load_mac_bindings(self):
        if MAC_BINDINGS_FILE.exists():
            try:
                with open(MAC_BINDINGS_FILE, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                if isinstance(payload, list):
                    self.mac_bindings = {
                        normalize_mac(item.get("mac", "")): item
                        for item in payload
                        if normalize_mac(item.get("mac", ""))
                    }
                else:
                    self.mac_bindings = payload if isinstance(payload, dict) else {}
            except Exception:
                self.mac_bindings = {}

    def save_rules(self):
        with open(DATA_DIR / "rules.json", "w", encoding="utf-8") as f:
            json.dump(self.rules, f, ensure_ascii=False, indent=2)

    def save_auto_limited(self):
        with open(AUTO_LIMIT_FILE, "w", encoding="utf-8") as f:
            json.dump(self.auto_limited_ips, f, ensure_ascii=False, indent=2)

    def save_ip_geo_cache(self):
        with open(IP_GEO_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(self.ip_geo_cache, f, ensure_ascii=False, indent=2)

    def save_employee_names(self):
        with open(EMPLOYEE_NAME_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "names": self.employee_names,
                "updated_at": self.employee_names_updated_at,
            }, f, ensure_ascii=False, indent=2)

    def save_mac_bindings(self):
        with open(MAC_BINDINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.mac_bindings, f, ensure_ascii=False, indent=2)

    def save_data(self):
        """保存数据到文件（不保存 error 字段，避免旧错误污染）"""
        data_to_save = dict(self.latest_data)
        if data_to_save.get("error"):
            # 不持久化错误状态
            data_to_save["error"] = None
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, ensure_ascii=False, indent=2)


state = AppState()


# ─── 采集线程 ───

def scrape_loop():
    """后台定时采集"""
    cfg = load_config()
    interval = cfg.get("monitor", {}).get("scrape_interval_seconds", 300)
    log.info("采集线程启动，间隔 %d 秒", interval)

    scraper = get_shared_scraper()

    while True:
        try:
            if not ensure_login(scraper):
                log.error("采集登录失败，下次重试")
                state.latest_data["error"] = "登录失败"
                time.sleep(interval)
                continue

            data = scraper.scrape()

            if data.get("error"):
                log.error("采集失败: %s", data["error"])
                state.latest_data["error"] = data["error"]
            else:
                state.latest_data = data
                state.latest_data["error"] = None
                state.save_data()
                log.info("采集成功: 源地址 %d 条, 内网 %d 条, 内网24小时 %d 条, 目的地址 %d 条",
                         len(data.get("source", [])), len(data.get("source_traffic", [])),
                         len(data.get("source_traffic_24h", [])), len(data.get("destination", [])))
                check_alerts(data)
                check_auto_limit(data)
                # IP 归属地查询放到独立线程，避免阻塞采集循环
                t_geo = threading.Thread(target=batch_query_ip_geo, args=(data,), daemon=True)
                t_geo.start()
                summary = {
                    "time": data.get("scraped_at"),
                    "src_count": len(data.get("source", [])),
                    "dst_count": len(data.get("destination", [])),
                    "alerts": len(state.alerts),
                }
                state.scrape_history.append(summary)
                if len(state.scrape_history) > 20:
                    state.scrape_history = state.scrape_history[-20:]

        except Exception as e:
            log.error("采集异常: %s", e)
            state.latest_data["error"] = str(e)

        time.sleep(interval)


def check_alerts(data: dict):
    """检测流量异常并生成告警"""
    cfg = load_config()
    mon = cfg.get("monitor", {})
    th_down = mon.get("threshold_down_mb", 2000)
    th_up = mon.get("threshold_up_mb", 500)
    wl = state.whitelist

    new_alerts = []
    for row in data.get("source", []) + data.get("destination", []):
        ip = row.get("ip", "")
        if ip in wl:
            continue
        down = row.get("down", 0)
        up = row.get("up", 0)

        if down > th_down and up > th_up:
            new_alerts.append({
                "level": "danger",
                "ip": ip,
                "msg": f"严重超标: 下载 {down:.0f}MB / 上传 {up:.0f}MB",
                "down": down,
                "up": up,
                "time": data.get("scraped_at"),
            })
        elif down > th_down:
            new_alerts.append({
                "level": "danger",
                "ip": ip,
                "msg": f"下载超标: {down:.0f}MB (阈值 {th_down}MB)",
                "down": down,
                "up": up,
                "time": data.get("scraped_at"),
            })
        elif up > th_up:
            new_alerts.append({
                "level": "warning",
                "ip": ip,
                "msg": f"上传超标: {up:.0f}MB (阈值 {th_up}MB)",
                "down": down,
                "up": up,
                "time": data.get("scraped_at"),
            })

    state.alerts = new_alerts


def check_auto_limit(data: dict):
    """检测超标员工并自动触发 PBR 限制，流量恢复后自动解除"""
    cfg = load_config()
    mon = cfg.get("monitor", {})
    if not mon.get("auto_limit_enabled", False):
        return

    th_down = mon.get("auto_limit_threshold_down_mb", mon.get("threshold_down_mb", 2000))
    th_up = mon.get("auto_limit_threshold_up_mb", mon.get("threshold_up_mb", 500))
    release_ratio = mon.get("auto_limit_release_ratio", 0.5)
    iface = mon.get("auto_limit_interface", "wan")
    wl = state.whitelist

    scraper = get_shared_scraper()

    # 获取当前 PBR 规则
    try:
        if not ensure_login(scraper):
            log.error("自动限制: 网关登录失败")
            return
        pbr_rules = scraper.fetch_pbr_rules()
    except Exception as e:
        log.error("自动限制获取PBR规则失败: %s", e)
        return

    # 构建已有规则 IP 集合
    existing_ips = set()
    for r in pbr_rules:
        sip = r.get("src_ip", "")
        if sip:
            existing_ips.add(sip.replace("/32", ""))

    staff_rows = data.get("source_traffic", [])
    events = []

    for row in staff_rows:
        ip = row.get("ip", "")
        if not ip or ip in wl:
            continue

        down = row.get("down", 0)
        up = row.get("up", 0)

        over = down > th_down or up > th_up
        is_limited = ip in state.auto_limited_ips or ip in existing_ips

        if over and not is_limited:
            last_octet = ip.split(".")[-1]
            name = f"t0_{last_octet}_auto"
            src_ip = ip + "/32"

            result = scraper.add_pbr_rule(
                name=name, src_ip=src_ip, interface=iface, proto="all"
            )
            if result.get("success"):
                log.info("自动限制已触发: %s -> %s", ip, iface)
                if ip not in state.auto_limited_ips:
                    state.auto_limited_ips.append(ip)
                    state.save_auto_limited()
                events.append({
                    "ip": ip, "down": down, "up": up,
                    "action": "limit", "time": data.get("scraped_at"),
                })
            else:
                log.error("自动限制失败 %s: %s", ip, result.get("message"))

        elif not over and is_limited and ip in state.auto_limited_ips:
            release_down = th_down * release_ratio
            release_up = th_up * release_ratio
            if down < release_down and up < release_up:
                last_octet = ip.split(".")[-1]
                name = f"t0_{last_octet}_auto"
                result = scraper.delete_pbr_rule(name)
                if result.get("success"):
                    log.info("自动限制已解除: %s", ip)
                    state.auto_limited_ips.remove(ip)
                    state.save_auto_limited()
                    events.append({
                        "ip": ip, "down": down, "up": up,
                        "action": "release", "time": data.get("scraped_at"),
                    })

    state.auto_limit_events = events


def query_ip_geo(ip: str) -> dict:
    """通过 ip-api.com 查询单个 IP 的归属地信息"""
    # 跳过内网 IP
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {"country": "内网", "isp": "-", "as": "-"}
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return {"country": "本地", "isp": "-", "as": "-"}

    fields = "status,country,regionName,city,isp,org,as,reverse"
    url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields={fields}"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        d = resp.json()
        if d.get("status") == "success":
            return {
                "country": d.get("country", ""),
                "region": d.get("regionName", ""),
                "city": d.get("city", ""),
                "isp": d.get("isp", ""),
                "org": d.get("org", ""),
                "as": d.get("as", ""),
                "reverse": d.get("reverse", ""),
                "cached_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
    except Exception as e:
        log.warning("查询 IP %s 归属地失败: %s", ip, e)
    return {"country": "未知", "isp": "-", "as": "-"}


VIDEO_ACCESS_PATTERNS = [
    ("googlevideo.com", "YouTube 视频"),
    ("youtube.com", "YouTube 视频"),
    ("netflix", "Netflix 视频"),
    ("nflxvideo", "Netflix 视频"),
    ("bilivideo", "哔哩哔哩视频"),
    ("hdslb", "哔哩哔哩视频/CDN"),
    ("bilibili", "哔哩哔哩"),
    ("acgvideo", "哔哩哔哩视频"),
    ("douyin", "抖音视频"),
    ("bytecdn", "字节跳动视频/CDN"),
    ("bytedance", "字节跳动"),
    ("ixigua", "西瓜视频"),
    ("pstatp", "字节跳动资源"),
    ("iqiyi", "爱奇艺视频"),
    ("qiyi", "爱奇艺视频"),
    ("youku", "优酷视频"),
    ("ykimg", "优酷资源"),
    ("gtimg", "腾讯视频/资源"),
    ("v.qq.com", "腾讯视频"),
    ("kwaicdn", "快手视频/CDN"),
    ("kuaishou", "快手视频"),
    ("huya", "虎牙直播"),
    ("douyu", "斗鱼直播"),
]

CDN_ACCESS_PATTERNS = [
    ("akamai", "Akamai CDN"),
    ("cloudfront", "AWS CloudFront CDN"),
    ("fastly", "Fastly CDN"),
    ("cloudflare", "Cloudflare CDN"),
    ("alicdn", "阿里 CDN"),
    ("aliyun", "阿里云/CDN"),
    ("hwcdn", "华为云 CDN"),
    ("qq.com", "腾讯系服务/CDN"),
    ("qpic", "腾讯资源/CDN"),
    ("tencent", "腾讯云/CDN"),
    ("myqcloud", "腾讯云/CDN"),
    ("cdn", "CDN 节点"),
]


def extract_ipv4(value: str) -> str:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value or "")
    if not match:
        return ""
    ip = match.group(0)
    try:
        parsed = ipaddress.ip_address(ip)
        return ip if parsed.version == 4 else ""
    except ValueError:
        return ""


def is_private_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local
    except ValueError:
        return False


def ensure_detail_ip_geo(rows: list, limit: int = 5):
    """给 IP 明细里的公网目标补充轻量归属信息，避免每次弹窗大量外查。"""
    targets = []
    for row in rows[:limit]:
        ip = extract_ipv4(row.get("address", ""))
        if ip and not is_private_ip(ip) and ip not in targets:
            targets.append(ip)

    updated = False
    for ip in targets[:limit]:
        cached = state.ip_geo_cache.get(ip) or {}
        if cached.get("country") and (cached.get("org") or cached.get("isp") or cached.get("reverse")):
            continue
        state.ip_geo_cache[ip] = query_ip_geo(ip)
        updated = True

    if updated:
        state.save_ip_geo_cache()


def classify_ip_detail_row(row: dict) -> dict:
    ip = extract_ipv4(row.get("address", ""))
    if not ip:
        return {
            "access_name": "未识别",
            "access_type": "未知",
            "access_note": "地址中未解析到公网 IP",
            "is_video": False,
        }

    if is_private_ip(ip):
        return {
            "access_name": "内网地址",
            "access_type": "内网",
            "access_note": ip,
            "is_video": False,
        }

    geo = state.ip_geo_cache.get(ip) or {}
    reverse = geo.get("reverse") or ""
    org = geo.get("org") or ""
    isp = geo.get("isp") or ""
    asn = geo.get("as") or ""
    haystack = " ".join([row.get("address", ""), reverse, org, isp, asn]).lower()
    download_mb = float(row.get("download_mb") or 0)
    upload_mb = float(row.get("upload_mb") or 0)
    total_mb = float(row.get("total_mb") or 0)
    protocol = str(row.get("protocol") or "").upper()
    port = str(row.get("port") or "")

    for token, label in VIDEO_ACCESS_PATTERNS:
        if token in haystack:
            return {
                "access_name": label,
                "access_type": "视频/流媒体",
                "access_note": reverse or org or isp or ip,
                "is_video": True,
            }

    for token, label in CDN_ACCESS_PATTERNS:
        if token in haystack:
            possible_video = download_mb >= 30 and download_mb >= max(upload_mb * 5, 10)
            return {
                "access_name": label,
                "access_type": "疑似视频 CDN" if possible_video else "CDN/云服务",
                "access_note": reverse or org or isp or ip,
                "is_video": possible_video,
            }

    if protocol == "UDP" and total_mb >= 20 and port not in {"53", "123"}:
        return {
            "access_name": org or isp or "UDP 大流量连接",
            "access_type": "疑似视频/P2P",
            "access_note": f"{protocol} {port}，下载 {download_mb:.2f} MB",
            "is_video": True,
        }

    if download_mb >= 80 and download_mb >= max(upload_mb * 8, 20):
        return {
            "access_name": org or isp or "大流量下载",
            "access_type": "疑似视频/下载",
            "access_note": reverse or f"下载 {download_mb:.2f} MB，端口 {port}",
            "is_video": True,
        }

    return {
        "access_name": reverse or org or isp or "未识别网站",
        "access_type": "普通访问",
        "access_note": reverse or org or ip,
        "is_video": False,
    }


def skipped_ip_detail_insight() -> dict:
    return {
        "access_name": "未识别",
        "access_type": "未识别",
        "access_note": "仅识别前 5 条，避免加载过慢",
        "is_video": False,
    }


def enrich_ip_detail_rows(rows: list, inspect_limit: int = 5) -> list:
    ensure_detail_ip_geo(rows, limit=inspect_limit)
    enriched = []
    for idx, row in enumerate(rows):
        item = dict(row)
        if idx < inspect_limit:
            item.update(classify_ip_detail_row(item))
        else:
            item.update(skipped_ip_detail_insight())
        enriched.append(item)
    return enriched


def batch_query_ip_geo(data: dict):
    """对 source 和 destination 中的外部 IP 批量查询归属地，结果写入缓存"""
    vpn_ips = set()
    for row in data.get("source", []) + data.get("destination", []):
        ip = row.get("ip", "")
        route = row.get("route", "")
        if not ip or ip.startswith(("192.168.", "10.", "172.")):
            continue
        if route == "CN":
            # 国内线路直接标记，不调用 API
            if ip not in state.ip_geo_cache:
                state.ip_geo_cache[ip] = {"country": "中国", "isp": "China", "as": "-"}
        elif route == "VPN":
            vpn_ips.add(ip)

    if not vpn_ips:
        state.save_ip_geo_cache()
        return

    new_ips = [ip for ip in vpn_ips if ip not in state.ip_geo_cache]
    if not new_ips:
        state.save_ip_geo_cache()
        return

    log.info("开始批量查询 %d 个 VPN IP 的归属地...", len(new_ips))
    success = 0
    for ip in new_ips:
        geo = query_ip_geo(ip)
        state.ip_geo_cache[ip] = geo
        if geo.get("country") != "未知":
            success += 1
        # 轻微延时避免触发限流（ip-api 免费版 45 req/min）
        time.sleep(1.5)

    state.save_ip_geo_cache()
    log.info("IP 归属地查询完成: %d/%d 成功", success, len(new_ips))


def _decode_h3c_response(resp) -> str:
    """H3C GR8300 页面是 GB2312/GB18030 编码。"""
    return resp.content.decode("gb18030", errors="ignore")


def _h3c_login(cfg: dict):
    h3c = cfg.get("h3c_router", {})
    base_url = h3c.get("url", "http://192.168.20.1/").rstrip("/") + "/"
    username = h3c.get("username", "")
    password = h3c.get("password", "")
    timeout = h3c.get("timeout", 8)
    if not username or not password:
        return None

    session = requests.Session()
    # H3C 管理页必须直连，否则容易被系统代理/隧道路由劫持成 503。
    session.trust_env = False
    session.headers.update({
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Referer": urljoin(base_url, "userLogin.asp"),
    })

    try:
        session.get(urljoin(base_url, "userLogin.asp"), timeout=timeout)
        resp = session.post(
            urljoin(base_url, "userLogin.asp"),
            data={
                "account": username,
                "password": password,
                "vldcode": "",
                "save2Cookie": "",
            },
            timeout=timeout,
        )
        html = _decode_h3c_response(resp)
        match = re.search(r'var\s+sessionid\s*=\s*"([^"]+)"', html)
        session_id = match.group(1) if match else ""
        if not session_id or session_id == "ABCDEFGH":
            log.warning("H3C 登录未拿到有效 sessionid")
            return None

        session.cookies.set("JSESSIONID", session_id, path="/")
        return session
    except Exception as e:
        log.warning("H3C 登录失败: %s", e)
        return None


def _parse_h3c_arp_entries(html: str) -> dict:
    entries = {}
    for entry in re.findall(r'"((?:\d{1,3}\.){3}\d{1,3};[^"]+?)"', html):
        parts = entry.split(";")
        if len(parts) < 5:
            continue
        ip, mac, desc, bind_status = parts[:4]
        ip = ip.strip()
        mac = normalize_mac(mac.strip())
        if not ip or not mac:
            continue
        entries[ip] = {
            "name": desc.strip(),
            "mac": mac,
            "status": bind_status.strip(),
            "index": parts[4].strip() if len(parts) > 4 else "",
        }
    return entries


def _fetch_h3c_arp_entries_with_session(session, base_url: str, timeout: int) -> dict:
    # 先进入首页，保持与用户指定的来源页面一致，再读取绑定表
    session.get(urljoin(base_url, "home.asp"), timeout=timeout)
    resp = session.get(urljoin(base_url, "arp.asp?refresh=yes"), timeout=timeout)
    html = _decode_h3c_response(resp)
    return _parse_h3c_arp_entries(html)


def _h3c_arp_source_page(cfg: dict) -> str:
    h3c = cfg.get("h3c_router", {})
    base_url = h3c.get("url", "http://192.168.20.1/").rstrip("/") + "/"
    return urljoin(base_url, "home.asp")


def _h3c_arp_records(entries: dict) -> list:
    records = []
    for ip, info in (entries or {}).items():
        if not isinstance(info, dict):
            continue
        records.append({
            "ip": ip,
            "mac": normalize_mac(info.get("mac", "")),
            "name": str(info.get("name", "")).strip(),
            "status": str(info.get("status", "")).strip() or "未知",
            "index": str(info.get("index", "")).strip(),
        })
    return records


def _match_h3c_record(record: dict, field: str, keyword: str) -> bool:
    keyword = str(keyword or "").strip()
    if not keyword:
        return True
    field = (field or "ip").strip().lower()
    if field == "mac":
        return normalize_mac(record.get("mac", "")).find(normalize_mac(keyword)) >= 0
    if field == "name":
        return keyword.lower() in str(record.get("name", "")).lower()
    return keyword.lower() in str(record.get("ip", "")).lower()


def fetch_h3c_employee_names() -> dict:
    """从 H3C GR8300 首页进入 ARP 绑定表，读取 IP -> 描述（员工名）和 MAC。"""
    cfg = load_config()
    h3c = cfg.get("h3c_router", {})
    if not h3c.get("enabled", False):
        return {}

    base_url = h3c.get("url", "http://192.168.20.1/").rstrip("/") + "/"
    timeout = h3c.get("timeout", 8)
    session = _h3c_login(cfg)
    if session is None:
        return {}

    try:
        names = _fetch_h3c_arp_entries_with_session(session, base_url, timeout)
    except Exception as e:
        log.warning("读取 H3C ARP 绑定表失败: %s", e)
        return {}

    log.info("H3C ARP 绑定表设备信息: %d 条", len(names))
    return names


@app.route("/api/h3c/arp-bindings")
def get_h3c_arp_bindings():
    """查询 H3C ARP 绑定表，来源固定为 home.asp。"""
    cfg = load_config()
    h3c = cfg.get("h3c_router", {})
    if not h3c.get("enabled", False):
        return jsonify({"success": False, "message": "H3C 未启用", "items": []}), 400

    field = request.args.get("field", "ip").strip().lower()
    keyword = request.args.get("q", "").strip()
    force = request.args.get("refresh", "1").strip() not in ("0", "false", "False")

    try:
        before_count = len(state.employee_names)
        refresh_employee_names(force=force)
        if not state.employee_names and before_count == 0:
            return jsonify({
                "success": False,
                "message": "H3C ARP 绑定表读取失败或为空",
                "source_page": _h3c_arp_source_page(cfg),
                "items": [],
                "count": 0,
            }), 500
        items = _h3c_arp_records(state.employee_names)
        if keyword:
            items = [item for item in items if _match_h3c_record(item, field, keyword)]
        return jsonify({
            "success": True,
            "source_page": _h3c_arp_source_page(cfg),
            "updated_at": state.employee_names_updated_at,
            "count": len(items),
            "items": items,
        })
    except Exception as e:
        log.warning("查询 H3C ARP 绑定表失败: %s", e)
        return jsonify({
            "success": False,
            "message": f"查询失败: {e}",
            "source_page": _h3c_arp_source_page(cfg),
            "items": [],
            "count": 0,
        }), 500


def _post_h3c_arp_form(session, base_url: str, timeout: int, cmd: str, param: str):
    payload = urlencode({
        "LANIP": "",
        "LANMASK": "",
        "CMD": cmd,
        "GO": "arp.asp",
        "param": param,
    }, encoding="gb2312").encode("ascii")
    return session.post(
        urljoin(base_url, "goform/aspForm"),
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": urljoin(base_url, "arp.asp"),
        },
        timeout=timeout,
    )


def sync_h3c_arp_binding(ip: str, mac: str, name: str) -> dict:
    """把 IP/MAC/名称同步到 H3C ARP 绑定表描述字段。"""
    cfg = load_config()
    h3c = cfg.get("h3c_router", {})
    if not h3c.get("enabled", False):
        return {"success": False, "message": "H3C 未启用"}

    ip = (ip or "").strip()
    mac = normalize_mac(mac)
    name = (name or "").strip()
    if not ip or not mac:
        return {"success": False, "message": "缺少 IP 或 MAC，无法同步路由器"}
    if not name:
        return {"success": False, "message": "名称不能为空"}
    if len(name) > 15:
        return {"success": False, "message": "H3C 描述最多 15 个字符"}

    base_url = h3c.get("url", "http://192.168.20.1/").rstrip("/") + "/"
    timeout = h3c.get("timeout", 8)
    session = _h3c_login(cfg)
    if session is None:
        return {"success": False, "message": "H3C 登录失败"}

    try:
        current = _fetch_h3c_arp_entries_with_session(session, base_url, timeout)
    except Exception as e:
        return {"success": False, "message": f"H3C 读取 ARP 表失败: {e}"}
    entry = current.get(ip) or next((item for item in current.values() if normalize_mac(item.get("mac", "")) == mac), None)
    try:
        if entry and entry.get("status") == "静态绑定" and entry.get("index"):
            param = f"{ip};{mac};{name};{entry.get('index')};\n"
            cmd = "process_arp_edit"
        else:
            param = f"{ip};{mac};{name};"
            cmd = "process_arp_add"

        session.get(urljoin(base_url, "arp_tmp.asp"), timeout=timeout)
        resp = _post_h3c_arp_form(session, base_url, timeout, cmd, param)
        if "userLogin.asp" in resp.url:
            return {"success": False, "message": "H3C 提交被登录页拦截，请退出路由器管理页后重试"}
        if resp.status_code >= 400:
            return {"success": False, "message": f"H3C 提交失败: HTTP {resp.status_code}"}

        time.sleep(1)
        updated = _fetch_h3c_arp_entries_with_session(session, base_url, timeout)
        if updated:
            state.employee_names = updated
            state.employee_names_updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            state.save_employee_names()
        updated_entry = updated.get(ip)
        if updated_entry and normalize_mac(updated_entry.get("mac", "")) == mac and str(updated_entry.get("name", "")).strip() == name:
            action = "修改" if cmd == "process_arp_edit" else "新增绑定"
            return {"success": True, "message": f"H3C ARP 已{action}", "entry": updated_entry}
        if updated_entry and normalize_mac(updated_entry.get("mac", "")) == mac:
            actual_name = str(updated_entry.get("name", "")).strip() or "空"
            return {
                "success": False,
                "message": f"H3C 已提交，但描述未更新，当前回读为 {actual_name}",
                "entry": updated_entry,
            }
        return {"success": False, "message": "H3C 已提交，但回读未确认成功"}
    except Exception as e:
        log.warning("同步 H3C ARP 绑定失败: %s", e)
        return {"success": False, "message": f"H3C 同步失败: {e}"}


def refresh_employee_names(force: bool = False):
    cfg = load_config()
    h3c = cfg.get("h3c_router", {})
    if not h3c.get("enabled", False):
        return

    ttl = h3c.get("cache_seconds", 300)
    now = time.time()
    last_ts = 0
    if state.employee_names_updated_at:
        try:
            last_ts = time.mktime(time.strptime(state.employee_names_updated_at, "%Y-%m-%d %H:%M:%S"))
        except Exception:
            last_ts = 0
    if not force and state.employee_names and (now - last_ts) < ttl:
        return

    names = fetch_h3c_employee_names()
    if names:
        state.employee_names = names
        state.employee_names_updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        state.save_employee_names()


def _deepseek_config() -> dict:
    cfg = load_config()
    deepseek = cfg.get("deepseek", {})
    return {
        "api_key": os.getenv("DEEPSEEK_API_KEY") or deepseek.get("api_key", ""),
        "base_url": (os.getenv("DEEPSEEK_BASE_URL") or deepseek.get("base_url", "https://api.deepseek.com")).rstrip("/"),
        "model": os.getenv("DEEPSEEK_MODEL") or deepseek.get("model", "deepseek-v4-flash"),
        "timeout": deepseek.get("timeout", 30),
        "temperature": deepseek.get("temperature", 0.2),
        "max_tokens": deepseek.get("max_tokens", 1200),
        "models": DEEPSEEK_MODELS,
    }


def _top_rows(rows: list, limit: int = 12) -> list:
    return sorted(
        rows or [],
        key=lambda row: (row.get("down", 0) or 0) + (row.get("up", 0) or 0),
        reverse=True,
    )[:limit]


def _build_ai_context() -> dict:
    data = state.latest_data
    cfg = load_config()
    mon = cfg.get("monitor", {})
    return {
        "scraped_at": data.get("scraped_at"),
        "thresholds": {
            "alert_down_mb": mon.get("threshold_down_mb", 2000),
            "alert_up_mb": mon.get("threshold_up_mb", 500),
            "auto_limit_enabled": mon.get("auto_limit_enabled", False),
            "auto_limit_down_mb": mon.get("auto_limit_threshold_down_mb", mon.get("threshold_down_mb", 2000)),
            "auto_limit_up_mb": mon.get("auto_limit_threshold_up_mb", mon.get("threshold_up_mb", 500)),
            "auto_limit_interface": mon.get("auto_limit_interface", "wan"),
        },
        "whitelist": state.whitelist,
        "alerts": state.alerts[:20],
        "auto_limit_events": getattr(state, "auto_limit_events", [])[:20],
        "auto_limited_ips": state.auto_limited_ips,
        "pbr_rules": state.rules[:30],
        "top_staff": _top_rows(data.get("source_traffic", []), 15),
        "top_external_sources": _top_rows(data.get("source", []), 12),
        "top_destinations": _top_rows(data.get("destination", []), 12),
    }


def analyze_with_deepseek(extra_prompt: str = "", model_override: str = "") -> dict:
    ds = _deepseek_config()
    allowed_models = {item["id"] for item in DEEPSEEK_MODELS}
    if model_override:
        if model_override not in allowed_models:
            return {"success": False, "message": f"不支持的 DeepSeek 模型: {model_override}"}
        ds["model"] = model_override
    if not ds["api_key"]:
        return {
            "success": False,
            "message": "未配置 DeepSeek API Key。请设置环境变量 DEEPSEEK_API_KEY，或在 config.json 的 deepseek.api_key 中填写。",
        }

    context = _build_ai_context()
    system_prompt = (
        "你是企业网关流量监控助手。请用中文给出简洁、可执行的分析。"
        "重点判断异常员工 IP、是否需要限制通道、可能的风险、建议下一步操作。"
        "不要编造上下文中不存在的员工姓名或外部目的。"
    )
    user_prompt = {
        "task": "分析当前网络流量态势",
        "operator_note": extra_prompt.strip(),
        "context": context,
        "output_format": [
            "总体判断，一句话",
            "异常点，按优先级列出",
            "建议操作，说明是否建议 PBR 限制或解除",
            "需要人工确认的信息",
        ],
    }

    try:
        resp = requests.post(
            f"{ds['base_url']}/chat/completions",
            headers={
                "Authorization": f"Bearer {ds['api_key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": ds["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_prompt, ensure_ascii=False)},
                ],
                "temperature": ds["temperature"],
                "max_tokens": ds["max_tokens"],
            },
            timeout=ds["timeout"],
        )
        resp.raise_for_status()
        payload = resp.json()
        content = payload.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        if not content:
            return {"success": False, "message": "DeepSeek 返回为空"}
        return {
            "success": True,
            "model": ds["model"],
            "analysis": content,
            "scraped_at": context.get("scraped_at"),
        }
    except requests.HTTPError as e:
        detail = ""
        try:
            detail = resp.text[:500]
        except Exception:
            pass
        return {"success": False, "message": f"DeepSeek 请求失败: {e}. {detail}".strip()}
    except Exception as e:
        return {"success": False, "message": f"DeepSeek 调用异常: {e}"}


# ─── API 路由 ───

@app.route("/")
def index():
    resp = make_response(send_from_directory("static", "index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/data")
def get_data():
    """获取最新采集数据"""
    tab = request.args.get("tab", "src")
    data = state.latest_data
    employee_names = {}

    if tab == "dst":
        rows = data.get("destination", [])
    elif tab == "staff":
        refresh_employee_names()
        rows = data.get("source_traffic", [])
        employee_names = state.employee_names
    elif tab == "staff24":
        refresh_employee_names()
        rows = data.get("source_traffic_24h", [])
        employee_names = state.employee_names
    else:
        rows = data.get("source", [])

    cfg = load_config()
    mon = cfg.get("monitor", {})

    return jsonify({
        "rows": rows,
        "scraped_at": data.get("scraped_at"),
        "error": data.get("error"),
        "threshold_down": mon.get("threshold_down_mb", 2000),
        "threshold_up": mon.get("threshold_up_mb", 500),
        "whitelist": state.whitelist,
        "ip_geo": state.ip_geo_cache,
        "employee_names": employee_names,
        "employee_names_updated_at": state.employee_names_updated_at,
        "mac_bindings": mac_binding_payload(),
    })


@app.route("/api/ip-detail/<ip>")
def get_ip_detail(ip):
    """获取单个内网 IP 的 LuCI 连接明细。"""
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip or ""):
        return jsonify({"success": False, "error": "IP 地址格式不正确"}), 400

    octets = [int(part) for part in ip.split(".")]
    if any(part > 255 for part in octets):
        return jsonify({"success": False, "error": "IP 地址格式不正确"}), 400

    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "error": "网关登录失败，无法读取 IP 明细"}), 502

        period = request.args.get("period", "realtime")
        if period not in ("realtime", "24h"):
            period = "realtime"

        detail = scraper.fetch_ip_detail(ip, period=period)
        detail["rows"] = enrich_ip_detail_rows(detail.get("rows", []), inspect_limit=5)
        detail["count"] = len(detail["rows"])
        resp = jsonify({
            "success": True,
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            **detail,
        })
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    except Exception as e:
        log.error("获取 IP 明细失败 %s: %s", ip, e)
        return jsonify({"success": False, "error": f"获取 IP 明细失败: {e}"}), 502


def bandwidth_rate_stats(points: list, key: str) -> dict:
    values = [float(point.get(key, 0) or 0) for point in points]
    if not values:
        return {"current": 0, "avg": 0, "peak": 0}
    return {
        "current": round(values[-1], 2),
        "avg": round(sum(values) / len(values), 2),
        "peak": round(max(values), 2),
    }


@app.route("/api/wan-bandwidth")
def get_wan_bandwidth():
    """获取 tun0 等外网接口的实时带宽曲线数据。"""
    dev = request.args.get("dev", "tun0").strip() or "tun0"
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", dev):
        return jsonify({"success": False, "error": "网卡名称格式不正确"}), 400

    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "error": "网关登录失败，无法读取外网流量"}), 502

        payload = scraper.fetch_bandwidth_status(dev)
        points = payload.get("points", [])
        resp = jsonify({
            "success": True,
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            **payload,
            "stats": {
                "rx": bandwidth_rate_stats(points, "rx_bytes_per_sec"),
                "tx": bandwidth_rate_stats(points, "tx_bytes_per_sec"),
            },
        })
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    except Exception as e:
        log.error("获取外网流量失败 %s: %s", dev, e)
        return jsonify({"success": False, "error": f"获取外网流量失败: {e}"}), 502


@app.route("/api/stats")
def get_stats():
    """获取统计概览"""
    data = state.latest_data
    src = data.get("source", [])
    dst = data.get("destination", [])
    all_rows = src + dst

    total_down = sum(r.get("down", 0) for r in all_rows)
    total_up = sum(r.get("up", 0) for r in all_rows)

    sorted_down = sorted(all_rows, key=lambda r: r.get("down", 0), reverse=True)
    sorted_up = sorted(all_rows, key=lambda r: r.get("up", 0), reverse=True)

    return jsonify({
        "ip_count": len(src) + len(dst),
        "total_down_mb": round(total_down, 2),
        "total_up_mb": round(total_up, 2),
        "total_down_gb": round(total_down / 1024, 2),
        "total_up_gb": round(total_up / 1024, 2),
        "peak_down_ip": sorted_down[0]["ip"] if sorted_down else None,
        "peak_up_ip": sorted_up[0]["ip"] if sorted_up else None,
        "alert_count": len(state.alerts),
        "limit_suggest_count": len([a for a in state.alerts if a["level"] == "danger"]),
        "scraped_at": data.get("scraped_at"),
        "error": data.get("error"),
    })


@app.route("/api/alerts")
def get_alerts():
    """获取告警列表"""
    return jsonify({"alerts": state.alerts})


@app.route("/api/mac-bindings", methods=["GET"])
def get_mac_bindings():
    """获取手动维护的 MAC/IP 命名表"""
    return jsonify(mac_binding_payload())


def lookup_h3c_mac_by_ip(ip: str) -> str:
    info = state.employee_names.get(ip, {})
    if isinstance(info, dict):
        return normalize_mac(info.get("mac", ""))
    return ""


def employee_names_payload() -> dict:
    return {
        "employee_names": state.employee_names,
        "employee_names_updated_at": state.employee_names_updated_at,
    }


@app.route("/api/mac-bindings", methods=["POST"])
def save_mac_binding():
    """新增或更新一条 MAC/IP 自定义命名"""
    body = request.json or {}
    mac = normalize_mac(str(body.get("mac", "")).strip())
    ip = str(body.get("ip", "")).strip()
    name = str(body.get("name", "")).strip()

    if not name:
        return jsonify({"ok": False, "message": "自定义名称不能为空"}), 400
    if not mac and ip:
        mac = lookup_h3c_mac_by_ip(ip)
    if not mac and not ip:
        return jsonify({"ok": False, "message": "请至少填写 IP 或 MAC 地址"}), 400

    h3c_result = {"success": False, "message": "未同步 H3C"}
    if ip and mac:
        h3c_result = sync_h3c_arp_binding(ip, mac, name)

    binding_id = mac or f"ip:{ip}"
    state.mac_bindings[binding_id] = {
        "mac": mac,
        "ip": ip,
        "name": name,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    state.save_mac_bindings()
    return jsonify({
        "ok": True,
        "h3c_synced": bool(h3c_result.get("success")),
        "message": h3c_result.get("message", ""),
        "h3c_result": h3c_result,
        **employee_names_payload(),
        **mac_binding_payload(),
    })


@app.route("/api/mac-bindings/<path:binding_id>", methods=["DELETE", "POST"])
def delete_mac_binding(binding_id):
    """删除一条 MAC/IP 自定义命名"""
    key = normalize_mac(binding_id) or binding_id
    if key in state.mac_bindings:
        state.mac_bindings.pop(key, None)
    else:
        normalized = normalize_mac(binding_id)
        for stored_key, item in list(state.mac_bindings.items()):
            item_mac = normalize_mac(item.get("mac", ""))
            item_ip = str(item.get("ip", "")).strip()
            if (normalized and item_mac == normalized) or item_ip == binding_id:
                state.mac_bindings.pop(stored_key, None)
                break
    state.save_mac_bindings()
    return jsonify({"ok": True, **mac_binding_payload()})


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """获取限速规则"""
    return jsonify({"rules": state.rules, "whitelist": state.whitelist})


@app.route("/api/rules", methods=["POST"])
def save_rules():
    """保存限速规则"""
    body = request.json or {}
    if "rules" in body:
        state.rules = body["rules"]
    if "whitelist" in body:
        state.whitelist = body["whitelist"]
        cfg = load_config()
        cfg.setdefault("monitor", {})["whitelist"] = state.whitelist
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    state.save_rules()
    return jsonify({"ok": True})


@app.route("/api/scrape", methods=["POST"])
def trigger_scrape():
    """手动触发一次采集"""
    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"error": "登录失败"}), 500
        data = scraper.scrape()
        if not data.get("error"):
            state.latest_data = data
            state.save_data()
            check_alerts(data)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history")
def get_history():
    """获取采集历史"""
    return jsonify({"history": state.scrape_history})


@app.route("/api/config", methods=["GET"])
def get_config():
    """获取监控配置（隐藏密码）"""
    cfg = load_config()
    mon = cfg.get("monitor", {})
    ds = _deepseek_config()
    safe_cfg = {
        "gateway_url": cfg["gateway"]["url"],
        "analyst_path": cfg["gateway"]["analyst_path"],
        "scrape_interval": mon.get("scrape_interval_seconds", 300),
        "threshold_down": mon.get("threshold_down_mb", 2000),
        "threshold_up": mon.get("threshold_up_mb", 500),
        "auto_limit_enabled": mon.get("auto_limit_enabled", False),
        "auto_limit_threshold_down": mon.get("auto_limit_threshold_down_mb", mon.get("threshold_down_mb", 2000)),
        "auto_limit_threshold_up": mon.get("auto_limit_threshold_up_mb", mon.get("threshold_up_mb", 500)),
        "auto_limit_release_ratio": mon.get("auto_limit_release_ratio", 0.5),
        "auto_limit_interface": mon.get("auto_limit_interface", "wan"),
        "deepseek_model": ds["model"],
        "deepseek_models": ds["models"],
        "deepseek_configured": bool(ds["api_key"]),
    }
    return jsonify(safe_cfg)


@app.route("/api/config", methods=["POST"])
def update_config():
    """更新监控配置"""
    body = request.json or {}
    cfg = load_config()
    mon = cfg.setdefault("monitor", {})
    if "threshold_down_mb" in body:
        mon["threshold_down_mb"] = body["threshold_down_mb"]
    if "threshold_up_mb" in body:
        mon["threshold_up_mb"] = body["threshold_up_mb"]
    if "scrape_interval_seconds" in body:
        mon["scrape_interval_seconds"] = body["scrape_interval_seconds"]
    if "auto_limit_enabled" in body:
        mon["auto_limit_enabled"] = bool(body["auto_limit_enabled"])
    if "auto_limit_threshold_down_mb" in body:
        mon["auto_limit_threshold_down_mb"] = body["auto_limit_threshold_down_mb"]
    if "auto_limit_threshold_up_mb" in body:
        mon["auto_limit_threshold_up_mb"] = body["auto_limit_threshold_up_mb"]
    if "auto_limit_release_ratio" in body:
        mon["auto_limit_release_ratio"] = body["auto_limit_release_ratio"]
    if "auto_limit_interface" in body:
        mon["auto_limit_interface"] = body["auto_limit_interface"]
    if "deepseek_model" in body:
        model = str(body["deepseek_model"]).strip()
        allowed_models = {item["id"] for item in DEEPSEEK_MODELS}
        if model not in allowed_models:
            return jsonify({"ok": False, "error": f"不支持的 DeepSeek 模型: {model}"}), 400
        cfg.setdefault("deepseek", {})["model"] = model
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return jsonify({"ok": True})


@app.route("/api/auto_limit/events")
def get_auto_limit_events():
    """获取最近一次自动限制事件"""
    return jsonify({
        "events": getattr(state, "auto_limit_events", []),
        "auto_limited_ips": state.auto_limited_ips,
    })


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze_api():
    """使用 DeepSeek 分析当前流量态势"""
    body = request.json or {}
    result = analyze_with_deepseek(body.get("prompt", ""), body.get("model", ""))
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ─── PBR (Policy Based Routing) API ───

@app.route("/api/pbr/rules")
def get_pbr_rules():
    """从网关实时获取 PBR 规则列表"""
    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "message": "网关登录失败", "rules": []}), 500
        rules = scraper.fetch_pbr_rules()
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        log.error("获取 PBR 规则异常: %s", e)
        return jsonify({"success": False, "message": str(e), "rules": []}), 500


@app.route("/api/pbr/add", methods=["POST"])
def add_pbr_rule_api():
    """添加 PBR 规则 — 限制员工走指定通道"""
    body = request.json or {}
    name = body.get("name", "").strip()
    src_ip = body.get("src_ip", "").strip()
    interface = body.get("interface", "wan")
    proto = body.get("proto", "all")

    if not name:
        return jsonify({"success": False, "message": "规则名称不能为空"}), 400
    if not src_ip:
        return jsonify({"success": False, "message": "源地址不能为空"}), 400
    if interface not in ("wan", "vpn"):
        return jsonify({"success": False, "message": "接口必须是 wan 或 vpn"}), 400

    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "message": "网关登录失败"}), 500
        result = scraper.add_pbr_rule(
            name=name, src_ip=src_ip, interface=interface, proto=proto
        )
        return jsonify(result)
    except Exception as e:
        log.error("添加 PBR 规则异常: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/pbr/delete/<rule_name>", methods=["POST", "DELETE"])
def delete_pbr_rule_api(rule_name):
    """删除 PBR 规则 — 解除限制"""
    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "message": "网关登录失败"}), 500
        result = scraper.delete_pbr_rule(rule_name)
        return jsonify(result)
    except Exception as e:
        log.error("删除 PBR 规则异常: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/pbr/switch", methods=["POST"])
def switch_pbr_interface_api():
    """切换已有规则的接口 (wan <-> vpn)"""
    body = request.json or {}
    rule_name = body.get("rule_name", "").strip()
    new_interface = body.get("interface", "").strip()

    if not rule_name:
        return jsonify({"success": False, "message": "规则名称不能为空"}), 400
    if new_interface not in ("wan", "vpn"):
        return jsonify({"success": False, "message": "接口必须是 wan 或 vpn"}), 400

    try:
        scraper = get_shared_scraper()
        if not ensure_login(scraper):
            return jsonify({"success": False, "message": "网关登录失败"}), 500
        result = scraper.switch_pbr_interface(rule_name, new_interface)
        return jsonify(result)
    except Exception as e:
        log.error("切换 PBR 接口异常: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


# ─── 启动 ───

if __name__ == "__main__":
    # 预先登录
    scraper = get_shared_scraper()
    if scraper.login():
        log.info("预登录成功")
    else:
        log.error("预登录失败，将在采集线程中重试")

    # 立即执行一次采集（不等 300 秒）
    log.info("执行首次采集...")
    try:
        if ensure_login(scraper):
            data = scraper.scrape()
            if not data.get("error"):
                state.latest_data = data
                state.save_data()
                check_alerts(data)
                log.info("首次采集成功")
            else:
                log.error("首次采集失败: %s", data["error"])
                state.latest_data["error"] = data["error"]
        else:
            log.error("首次采集登录失败")
            state.latest_data["error"] = "登录失败"
    except Exception as e:
        log.error("首次采集异常: %s", e)
        state.latest_data["error"] = str(e)

    # 启动后台采集线程
    t = threading.Thread(target=scrape_loop, daemon=True)
    t.start()

    cfg = load_config()
    host = cfg.get("server", {}).get("host", "127.0.0.1")
    port = cfg.get("server", {}).get("port", 5100)

    log.info("服务启动: http://%s:%d", host, port)
    app.run(host=host, port=port, debug=False)
