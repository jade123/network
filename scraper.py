"""
CloudValley LuCI 网关流量采集脚本
- 登录 LuCI 管理面板
- 抓取流量分析页面 Highcharts 数据
- 解析并输出 JSON

数据来源：
  /cgi-bin/luci/admin/status/analyst    → 源地址（外部IP via CN/VPN）
  /cgi-bin/luci/admin/status/analyststm  → 源地址流量（内部192.168.x）
  /cgi-bin/luci/admin/status/analystdtm  → 目的地址（外部IP via CN/VPN）
"""

import json
import os
import re
import sys
import time
import logging
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("scraper")

BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
CONFIG_PATH = Path(os.environ.get("NETMON_CONFIG_PATH", BASE_DIR / "config.json"))


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def apply_no_proxy(config: dict) -> list:
    """把网关直连地址追加到 NO_PROXY，避免被系统/全局代理接管。"""
    gateway = config.get("gateway", {})
    hosts = list(gateway.get("no_proxy", []))

    gateway_host = urlparse(gateway.get("url", "")).hostname
    if gateway_host:
        hosts.append(gateway_host)

    current = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    merged = [item.strip() for item in current.split(",") if item.strip()]
    for host in hosts:
        if host and host not in merged:
            merged.append(host)

    value = ",".join(merged)
    os.environ["NO_PROXY"] = value
    os.environ["no_proxy"] = value
    return merged


class SourceAddressAdapter(HTTPAdapter):
    """让 requests 从指定本机地址发起连接，用于绕开错误的系统路由。"""

    def __init__(self, source_address: str, *args, **kwargs):
        self.source_address = source_address
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["source_address"] = (self.source_address, 0)
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["source_address"] = (self.source_address, 0)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class CloudValleyScraper:
    """CloudValley LuCI 网关流量采集器 — 基于 Highcharts 数据解析"""

    def __init__(self, config=None):
        self.cfg = config or load_config()
        apply_no_proxy(self.cfg)
        gw = self.cfg["gateway"]
        self.base_url = gw["url"].rstrip("/")
        self.username = gw["username"]
        self.password = gw["password"]
        self.timeout = gw.get("timeout", 15)
        self.session = requests.Session()
        source_address = gw.get("source_address")
        if source_address:
            adapter = SourceAddressAdapter(source_address)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            log.info("HTTP 请求绑定本机源地址: %s", source_address)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        })

    def login(self) -> bool:
        """登录 LuCI 面板"""
        # 注意：POST 登录必须用 /cgi-bin/luci（无尾部斜杠）
        login_url = self.base_url + "/cgi-bin/luci"
        log.info("登录 %s ...", login_url)

        try:
            # 1. GET 登录页（建立 session，获取初始 cookie）
            self.session.get(login_url, timeout=self.timeout)

            # 2. POST 登录
            data = {
                "luci_username": self.username,
                "luci_password": self.password,
            }
            resp = self.session.post(
                login_url, data=data, timeout=self.timeout, allow_redirects=True
            )
            resp.raise_for_status()

            # 3. 验证：检查 sysauth cookie 或能访问受保护页面
            if "sysauth" in self.session.cookies:
                log.info("登录成功 (sysauth=%s...)", self.session.cookies["sysauth"][:8])
                return True

            # 后备验证：尝试访问受保护页面
            test = self.session.get(
                self.base_url + "/cgi-bin/luci/admin/status/analyst",
                timeout=self.timeout,
                allow_redirects=True,
            )
            if test.status_code == 200 and "analyst" in test.url:
                log.info("登录成功（通过页面访问验证）")
                return True

            log.error("登录失败：未获取到 sysauth cookie，且页面访问验证未通过")
            return False

        except requests.RequestException as e:
            log.error("登录请求失败: %s", e)
            return False

    # ─── 页面抓取 ───

    def _fetch_page(self, path: str) -> str:
        """获取指定路径的页面 HTML"""
        url = self.base_url + path
        log.info("获取页面: %s", url)
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.text

    # ─── Highcharts 数据解析 ───

    def _parse_highcharts_data(self, html: str) -> list:
        """
        从 Highcharts 配置中提取流量数据
        格式: categories = ['IP via Route', ...], series = [{name:'Upload', data:[...]}, {name:'Download', data:[...]}]
        """
        soup = BeautifulSoup(html, "lxml")

        for script in soup.find_all("script"):
            if not script.string:
                continue
            text = script.string
            if "highcharts" not in text.lower() and "categories" not in text:
                continue

            # 提取 categories
            cat_match = re.search(r"categories:\s*\[(.*?)\]", text, re.DOTALL)
            if not cat_match:
                continue
            cat_str = cat_match.group(1)
            categories = [c.strip().strip("'\"") for c in cat_str.split(",") if c.strip()]

            # 提取 series 数据
            series_data = {}
            # 匹配 name + data 配对
            series_pattern = r"name:\s*['\"](.*?)['\"].*?data:\s*\[(.*?)\]"
            for match in re.finditer(series_pattern, text, re.DOTALL):
                name = match.group(1)
                data_str = match.group(2)
                values = [float(v.strip()) for v in data_str.split(",") if v.strip()]
                series_data[name] = values

            if not series_data or not categories:
                continue

            # 组装结果
            upload_data = series_data.get("Upload", [])
            download_data = series_data.get("Download", [])

            result = []
            for i, cat in enumerate(categories):
                # 解析 "IP via Route" 格式
                parts = cat.split(" via ")
                ip = parts[0].strip()
                route = parts[1].strip() if len(parts) > 1 else ""

                up = upload_data[i] if i < len(upload_data) else 0
                down = download_data[i] if i < len(download_data) else 0

                result.append({
                    "ip": ip,
                    "route": route,
                    "up": round(up, 2),
                    "down": round(down, 2),
                })

            return result

        return []

    def _parse_number(self, value: str) -> float:
        """解析页面表格里的数字，保留 KBytes 原单位。"""
        cleaned = re.sub(r"[^0-9.]", "", value or "")
        if not cleaned:
            return 0
        try:
            return round(float(cleaned), 2)
        except ValueError:
            return 0

    def _parse_ip_detail_table(self, html: str) -> list:
        """解析 /anascutm/<IP> 页面里的连接明细表。"""
        soup = BeautifulSoup(html, "lxml")
        result = []

        def parse_cells(cells: list):
            if len(cells) < 6:
                return None
            if "upload" in cells[3].lower() or "download" in cells[4].lower():
                return None

            address = cells[0]
            if not re.search(r"\d+\.\d+\.\d+\.\d+", address):
                return None

            upload_kb = self._parse_number(cells[3])
            download_kb = self._parse_number(cells[4])
            total_kb = self._parse_number(cells[5])

            return {
                "address": address,
                "protocol": cells[1],
                "port": cells[2],
                "upload_mb": round(upload_kb / 1024, 2),
                "download_mb": round(download_kb / 1024, 2),
                "total_mb": round(total_kb / 1024, 2),
            }

        for div_table in soup.find_all("div", class_=lambda x: x and "cbi-section-table" in x):
            for row in div_table.find_all("div", class_=lambda x: x and "cbi-section-table-descr" in x):
                cells = [
                    cell.get_text(" ", strip=True)
                    for cell in row.find_all("div", class_=lambda x: x and "cbi-section-table-cell" in x)
                ]
                parsed = parse_cells(cells)
                if parsed:
                    result.append(parsed)
            if result:
                return result

        for div_table in soup.find_all("div", class_=lambda x: x and "table" in x.split()):
            for row in div_table.find_all("div", class_=lambda x: x and "tr" in x.split()):
                cells = [
                    cell.get_text(" ", strip=True)
                    for cell in row.find_all("div", class_=lambda x: x and ("td" in x.split() or "th" in x.split()))
                ]
                parsed = parse_cells(cells)
                if parsed:
                    result.append(parsed)
            if result:
                return result

        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            if not rows:
                continue

            header_text = " ".join(cell.get_text(" ", strip=True).lower() for cell in rows[0].find_all(["th", "td"]))
            looks_like_detail = (
                ("upload" in header_text and "download" in header_text)
                or ("total traffic" in header_text)
                or ("地址" in header_text and "协议" in header_text and "端口" in header_text)
            )

            for row in rows[1:] if looks_like_detail else rows:
                cells = [cell.get_text(" ", strip=True) for cell in row.find_all(["td", "th"])]
                parsed = parse_cells(cells)
                if parsed:
                    result.append(parsed)

            if result:
                break

        return result

    def fetch_ip_detail(self, ip: str, period: str = "realtime") -> dict:
        """获取单个内网 IP 的连接流量明细。"""
        path_name = "anac" if period == "24h" else "anascutm"
        path = f"/cgi-bin/luci/admin/status/{path_name}/{ip}"
        html = self._fetch_page(path)
        rows = self._parse_ip_detail_table(html)
        return {
            "ip": ip,
            "period": period,
            "source_url": self.base_url + path,
            "rows": rows,
            "count": len(rows),
        }

    def fetch_bandwidth_status(self, dev: str = "tun0") -> dict:
        """获取 LuCI 实时带宽状态，并按字节差值计算每秒速率。"""
        safe_dev = re.sub(r"[^A-Za-z0-9_.:-]", "", dev or "tun0") or "tun0"
        path = f"/cgi-bin/luci/admin/status/realtime/bandwidth_status/{safe_dev}"
        text = self._fetch_page(path)
        samples = json.loads(text)
        if not isinstance(samples, list):
            samples = []

        points = []
        previous = None
        for item in samples:
            if not isinstance(item, (list, tuple)) or len(item) < 5:
                continue
            try:
                ts = float(item[0])
                rx_bytes = float(item[1])
                rx_packets = float(item[2])
                tx_bytes = float(item[3])
                tx_packets = float(item[4])
            except (TypeError, ValueError):
                continue

            if previous:
                prev_ts, prev_rx_bytes, prev_rx_packets, prev_tx_bytes, prev_tx_packets = previous
                delta_time = ts - prev_ts
                if delta_time > 0:
                    rx_delta = rx_bytes - prev_rx_bytes
                    tx_delta = tx_bytes - prev_tx_bytes
                    rx_packet_delta = rx_packets - prev_rx_packets
                    tx_packet_delta = tx_packets - prev_tx_packets
                    if rx_delta < 0:
                        rx_delta += 0xFFFFFFFF
                    if tx_delta < 0:
                        tx_delta += 0xFFFFFFFF
                    if rx_packet_delta < 0:
                        rx_packet_delta += 0xFFFFFFFF
                    if tx_packet_delta < 0:
                        tx_packet_delta += 0xFFFFFFFF

                    points.append({
                        "time": int(ts),
                        "rx_bytes_per_sec": round(rx_delta / delta_time, 2),
                        "tx_bytes_per_sec": round(tx_delta / delta_time, 2),
                        "rx_packets_per_sec": round(rx_packet_delta / delta_time, 2),
                        "tx_packets_per_sec": round(tx_packet_delta / delta_time, 2),
                    })

            previous = (ts, rx_bytes, rx_packets, tx_bytes, tx_packets)

        return {
            "dev": safe_dev,
            "source_url": self.base_url + path,
            "points": points[-180:],
            "count": len(points[-180:]),
        }

    # ─── 主采集流程 ───

    def scrape(self) -> dict:
        """执行完整的采集流程"""
        # 1. 登录
        if not self.login():
            return {"error": "登录失败", "source": [], "destination": [], "source_traffic": []}

        # 2. 采集三个页面的数据
        result = {
            "source": [],        # /analyst — 外部源地址 (via CN/VPN)
            "source_traffic": [], # /analyststm — 内部源地址 (192.168.x)
            "source_traffic_24h": [], # /analysts — 24小时内部源地址
            "destination": [],   # /analystdtm — 外部目的地址 (via CN/VPN)
            "scraped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": None,
        }

        pages = [
            ("/cgi-bin/luci/admin/status/analyst", "source"),
            ("/cgi-bin/luci/admin/status/analyststm", "source_traffic"),
            ("/cgi-bin/luci/admin/status/analysts", "source_traffic_24h"),
            ("/cgi-bin/luci/admin/status/analystdtm", "destination"),
        ]

        for path, key in pages:
            try:
                html = self._fetch_page(path)
                data = self._parse_highcharts_data(html)
                result[key] = data
                log.info("  %s: %d 条记录", key, len(data))
            except Exception as e:
                log.error("  %s 采集失败: %s", key, e)
                result[key] = []

        # 3. 检查是否有数据
        total = len(result["source"]) + len(result["source_traffic"]) + len(result["destination"])
        if total == 0:
            result["error"] = "所有页面均未采集到数据"
            # 保存调试 HTML
            debug_dir = Path(__file__).parent / "debug"
            debug_dir.mkdir(exist_ok=True)
            for path, key in pages:
                try:
                    html = self._fetch_page(path)
                    (debug_dir / f"{key}.html").write_text(html, encoding="utf-8")
                except Exception:
                    pass
            log.warning("无数据，已保存调试 HTML 到 %s", debug_dir)

        return result

    # ═══════════════════════════════════════════════════
    #  PBR (Policy Based Routing) 规则管理
    # ═══════════════════════════════════════════════════

    def fetch_pbr_rules(self) -> list:
        """获取当前所有 PBR 规则列表"""
        try:
            html = self._fetch_page("/cgi-bin/luci/admin/network/pbr")
            soup = BeautifulSoup(html, "lxml")

            rules = []
            # Rule Setting 表格 — 匹配 class 包含 'tr' 和 'cbi-section-table-descr' 的行
            rows = soup.find_all(
                "div",
                class_=lambda x: x and "tr" in x and "cbi-section-table-descr" in x,
            )
            for row in rows:
                cells = row.find_all(
                    "div",
                    class_=lambda x: x and "th" in x and "cbi-section-table-cell" in x,
                )
                if len(cells) < 7:
                    continue
                name = cells[0].get_text(strip=True)
                src_ip = cells[1].get_text(strip=True)
                src_port = cells[2].get_text(strip=True)
                dst_ip = cells[3].get_text(strip=True)
                dst_port = cells[4].get_text(strip=True)
                proto = cells[5].get_text(strip=True)
                iface = cells[6].get_text(strip=True)

                # 提取编辑/删除链接
                edit_link = ""
                delete_link = ""
                for btn in row.find_all("input", type="button"):
                    onclick = btn.get("onclick", "")
                    if "pbrif/" in onclick:
                        edit_link = re.search(r"location\.href='([^']+)'", onclick)
                        edit_link = edit_link.group(1) if edit_link else ""
                    elif "rule_delete/" in onclick:
                        delete_link = re.search(r"location\.href='([^']+)'", onclick)
                        delete_link = delete_link.group(1) if delete_link else ""

                rules.append({
                    "name": name,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto,
                    "interface": iface,
                    "edit_link": edit_link,
                    "delete_link": delete_link,
                })
            return rules
        except Exception as e:
            log.error("获取 PBR 规则失败: %s", e)
            return []

    def add_pbr_rule(self, name: str, src_ip: str, interface: str = "wan",
                     proto: str = "all", src_port: str = "",
                     dst_ip: str = "", dst_port: str = "") -> dict:
        """
        添加一条 PBR 规则
        :param name: 规则名称（合法字符: A-Z a-z 0-9 _）
        :param src_ip: 源地址，如 192.168.20.253/32
        :param interface: 接口，wan(国内) / vpn(VPN通道)
        :param proto: 协议 all/tcp/udp/any
        :return: {"success": bool, "message": str}
        """
        try:
            # 1. 获取添加页面的 token
            html = self._fetch_page("/cgi-bin/luci/admin/network/ruleadd")
            soup = BeautifulSoup(html, "lxml")
            token_input = soup.find("input", {"name": "token"})
            token = token_input["value"] if token_input else ""

            if not token:
                return {"success": False, "message": "无法获取 CSRF token"}

            # 2. POST 添加规则 — 使用 cbi.apply=1 触发"保存并应用"
            post_data = {
                "token": token,
                "cbi.apply": "1",
                "cbid.pbr.1._rulename": name,
                "cbid.pbr.1._proto": proto,
                "cbid.pbr.1._sip": src_ip,
                "cbid.pbr.1._sport": src_port,
                "cbid.pbr.1._dip": dst_ip,
                "cbid.pbr.1._port": dst_port,
                "cbid.pbr.1._interface": interface,
            }

            resp = self.session.post(
                self.base_url + "/cgi-bin/luci/admin/network/ruleadd",
                data=post_data,
                timeout=self.timeout,
                allow_redirects=True,
            )
            resp.raise_for_status()

            log.info("PBR 规则添加并应用成功: %s -> %s", name, interface)
            return {"success": True, "message": f"规则 {name} 已添加并应用"}

        except requests.RequestException as e:
            log.error("添加 PBR 规则失败: %s", e)
            return {"success": False, "message": f"请求失败: {e}"}
        except Exception as e:
            log.error("添加 PBR 规则异常: %s", e)
            return {"success": False, "message": f"异常: {e}"}

    def delete_pbr_rule(self, rule_name: str) -> dict:
        """删除指定名称的 PBR 规则"""
        try:
            delete_url = self.base_url + f"/cgi-bin/luci/admin/network/rule_delete/{rule_name}"
            resp = self.session.get(delete_url, timeout=self.timeout)
            resp.raise_for_status()

            # 保存并应用
            save_resp = self.session.get(
                self.base_url + "/cgi-bin/luci/admin/network/save_pbr/save",
                timeout=self.timeout,
            )
            save_resp.raise_for_status()

            log.info("PBR 规则删除成功: %s", rule_name)
            return {"success": True, "message": f"规则 {rule_name} 已删除"}

        except Exception as e:
            log.error("删除 PBR 规则失败: %s", e)
            return {"success": False, "message": f"删除失败: {e}"}

    def switch_pbr_interface(self, rule_name: str, new_interface: str) -> dict:
        """
        切换已有规则的接口（wan <-> vpn）
        先删除旧规则，再创建同名新规则
        """
        rules = self.fetch_pbr_rules()
        target = None
        for r in rules:
            if r["name"] == rule_name:
                target = r
                break

        if not target:
            return {"success": False, "message": f"规则 {rule_name} 不存在"}

        # 删除旧规则
        del_result = self.delete_pbr_rule(rule_name)
        if not del_result["success"]:
            return del_result

        # 添加新规则（同名，切换接口）
        return self.add_pbr_rule(
            name=rule_name,
            src_ip=target["src_ip"] or "",
            interface=new_interface,
            proto=target["proto"] or "all",
            src_port=target["src_port"] or "",
            dst_ip=target["dst_ip"] or "",
            dst_port=target["dst_port"] or "",
        )


# ─── 命令行测试 ───

if __name__ == "__main__":
    scraper = CloudValleyScraper()
    data = scraper.scrape()
    print(json.dumps(data, ensure_ascii=False, indent=2))
