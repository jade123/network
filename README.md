# 员工IP流量监控与限制工具

基于 CloudValley（睿谷）LuCI 网关的员工流量监控与自动限制管理系统。

## 功能

- **实时流量采集**：每5分钟自动抓取网关流量数据（可配置间隔）
- **三维度监控**：外部源地址 / 员工内网(192.168.x.x) / 外部目的地址
- **异常流量告警**：可自定义下载/上传阈值，超标自动标红提醒
- **自动限制通道（核心功能）**：员工流量超标后**自动触发 PBR 限制**，将其切到国内带宽通道；流量恢复正常后**自动解除限制**
- **PBR 规则管理**：查看、添加、删除、切换已有规则的通道（wan / vpn）
- **白名单管理**：白名单内 IP 不参与告警和自动限制
- **CSV 报表导出**：一键导出流量明细
- **前端实时刷新**：每30秒轮询最新数据

## 技术栈

- **采集层**: Python + requests + BeautifulSoup4（解析 Highcharts 数据）
- **后端**: Flask + Flask-CORS
- **前端**: 纯 HTML/CSS/JS（Canvas 自绘图表）

## 目录结构

```
network-monitor/
├── scraper.py          # LuCI 数据采集脚本 + PBR 规则操作
├── server.py           # Flask 后端服务（API + 定时采集 + 自动限制逻辑）
├── requirements.txt    # Python 依赖
├── config.json         # 配置文件（网关登录信息、阈值、自动限制开关）
├── config.example.json # 配置示例（复制为 config.json 使用）
├── 启动监控.bat        # Windows 一键启动
└── static/
    └── index.html      # 前端监控页面
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

依赖清单：
- `flask>=3.0`
- `flask-cors>=4.0`
- `requests>=2.31`
- `beautifulsoup4>=4.12`
- `lxml>=5.0`

### 2. 配置网关

复制示例配置：

```bash
cp config.example.json config.json
```

编辑 `config.json`，填入你的网关信息：

```json
{
  "gateway": {
    "url": "http://172.18.188.1/",
    "username": "root",
    "password": "your_password",
    "analyst_path": "/cgi-bin/luci/admin/status/analyst",
    "timeout": 15,
    "source_address": "",
    "no_proxy": ["192.168.20.1", "172.18.188.1"]
  },
  "monitor": {
    "scrape_interval_seconds": 300,
    "threshold_down_mb": 2000,
    "threshold_up_mb": 500,
    "whitelist": ["192.168.20.1", "192.168.20.2"],
    "auto_limit_enabled": false,
    "auto_limit_threshold_down_mb": 3000,
    "auto_limit_threshold_up_mb": 1000,
    "auto_limit_release_ratio": 0.5,
    "auto_limit_interface": "wan"
  },
  "deepseek": {
    "api_key": "",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-v4-flash",
    "timeout": 30,
    "temperature": 0.2,
    "max_tokens": 1200
  },
  "server": {
    "host": "127.0.0.1",
    "port": 5102
  }
}
```

### 3. 启动服务

**Windows**：双击 `启动监控.bat`

**命令行**：

```bash
python server.py
```

服务启动后会立即执行首次采集，随后进入后台定时采集循环。

### 4. 访问监控页面

浏览器打开：[http://127.0.0.1:5102](http://127.0.0.1:5102)

---

## 桌面 App 打包

项目已支持封装成 Windows / macOS 桌面应用。桌面版会自动启动本地 Flask 后端，并在 Electron 窗口中打开 `http://127.0.0.1:5102/`。

macOS 安装包为 Universal 通用包，同时兼容 Apple Silicon（M 系列芯片）和 Intel Mac。

### 配置与数据位置

桌面版首次运行会把 `config.example.json` 复制到系统用户数据目录，作为外置 `config.json` 使用；后续升级不会覆盖用户配置。运行数据和日志也保存在用户数据目录。

如果构建机器上存在项目根目录的 `config.json`，安装包会把它作为首次运行默认配置；如果不存在，则使用 `config.example.json`。首次运行后，用户目录里的外置配置优先级最高，升级不会覆盖。

后端支持以下环境变量，Electron 会自动传入：

| 变量 | 说明 |
|------|------|
| `NETMON_CONFIG_PATH` | 外置 `config.json` 路径 |
| `NETMON_DATA_DIR` | 运行数据目录 |
| `NETMON_LOG_PATH` | 日志文件路径 |

### 构建命令

先安装依赖：

```bash
npm install
pip install -r requirements.txt
```

构建后端可执行文件：

```bash
npm run build:backend
```

构建 macOS 安装包：

```bash
npm run build:mac
```

该命令会先构建 arm64 与 x86_64 两个后端，再用 `lipo` 合并为 universal 后端，并输出 universal DMG。

构建 Windows 安装包需要在 Windows 环境执行：

```bash
npm run build:win
```

输出目录为 `release/`。端口固定为 `5102`，如果启动时提示端口被占用，请先关闭旧的监控服务。

---

## 配置说明

### gateway 字段

| 字段 | 说明 |
|------|------|
| `url` | 网关管理地址，末尾带 `/` |
| `username` | LuCI 登录用户名 |
| `password` | LuCI 登录密码 |
| `analyst_path` | 流量分析页面路径，一般保持默认 |
| `timeout` | HTTP 请求超时秒数 |
| `source_address` | 可选。本机有 VPN/隧道导致网关 IP 走错路由时，填本机局域网 IP 强制直连 |
| `no_proxy` | 不走系统/全局代理的地址列表 |

### monitor 字段

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `scrape_interval_seconds` | 后端定时采集间隔（秒） | 300 |
| `threshold_down_mb` | **告警**下载阈值（MB） | 2000 |
| `threshold_up_mb` | **告警**上传阈值（MB） | 500 |
| `whitelist` | 白名单 IP 数组，不参与告警和自动限制 | `["192.168.20.1", "192.168.20.2"]` |
| `auto_limit_enabled` | 是否开启**自动限制** | false |
| `auto_limit_threshold_down_mb` | **自动限制**下载阈值（MB） | 3000 |
| `auto_limit_threshold_up_mb` | **自动限制**上传阈值（MB） | 1000 |
| `auto_limit_release_ratio` | 自动解除比例。流量低于 `阈值 × 比例` 时解除限制 | 0.5 |
| `auto_limit_interface` | 限制到的通道。`wan`=国内带宽，`vpn`=VPN海外通道 | wan |

> **注意**：告警阈值和自动限制阈值是两套独立的配置。建议把自动限制阈值设得比告警阈值高一些，避免一点波动就触发限制。

### deepseek 字段

也可以不写 `api_key`，改用环境变量：

```bash
export DEEPSEEK_API_KEY="你的 DeepSeek API Key"
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `api_key` | DeepSeek API Key。环境变量 `DEEPSEEK_API_KEY` 优先级更高 | 空 |
| `base_url` | DeepSeek API 地址 | https://api.deepseek.com |
| `model` | 使用的 DeepSeek 模型，也可用环境变量 `DEEPSEEK_MODEL` 覆盖；页面可在 `deepseek-v4-flash` / `deepseek-v4-pro` 间切换 | deepseek-v4-flash |
| `timeout` | 请求超时秒数 | 30 |
| `temperature` | 输出随机性，越低越稳定 | 0.2 |
| `max_tokens` | 单次分析最大输出长度 | 1200 |

---

## 自动限制功能详解

### 工作原理

1. 每次采集完成后，后端遍历「员工内网」Tab 的流量数据
2. 跳过白名单 IP
3. 检查 IP 是否**已经有限制规则**（避免重复添加）
4. 若下载 > `auto_limit_threshold_down_mb` 或 上传 > `auto_limit_threshold_up_mb`：
   - 自动在网关上添加一条 PBR 规则，命名格式：`t0_{IP末段}_auto`
   - 规则将该 IP 强制走 `wan` 国内带宽（无法访问 VPN 海外资源）
5. 若该 IP 已在自动限制列表中，且当前流量低于释放阈值：
   - 自动删除对应的 PBR 规则，恢复其 VPN 访问权限

### 前端操作

- 页面顶部导航栏有「自动限制」开关和阈值输入框
- 打开开关即生效，无需重启服务
- PBR 面板中带有「系统限制」绿色标签的规则就是系统自动添加的
- 系统自动限制/解除时，会在顶部告警栏给出提示

---

## PBR 通道限制管理

除了自动限制，你也可以手动管理：

- **添加限制**：指定员工 IP，选择 `wan`（只允许国内带宽）或 `vpn`（只允许 VPN 通道）
- **切换接口**：已有规则可以一键在 wan / vpn 之间切换
- **解除限制**：删除规则，恢复默认路由
- **快速限制**：在「员工内网」Tab 的流量表格中，点击「限制通道」按钮可一键限制该 IP

---

## 支持的网关

已在以下环境验证：
- 睿谷 CloudValley 网关（基于 OpenWrt/LuCI）

## 注意事项

- `config.json` 含登录凭据，**不要提交到公开仓库**（已加入 .gitignore）
- 采集脚本需在本地内网环境运行，需能访问网关管理地址
- 自动限制功能会直接修改网关 PBR 规则，建议先在测试环境验证后再开启
- 开发服务器仅用于本地调试，生产环境请使用 gunicorn/uwsgi 等 WSGI 服务器
