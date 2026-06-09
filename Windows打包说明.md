# Windows App 打包说明

当前项目的 Windows 安装包必须在 Windows 环境打包。原因是后端使用 PyInstaller，Windows 版后端 `netmon-backend.exe` 只能在 Windows 上生成。

## 1. 准备环境

在 Windows 电脑安装：

- Node.js 20 或更高版本
- Python 3.9 或更高版本

## 2. 确认配置

项目根目录需要有真实可用的 `config.json`。

如果没有，先从 `config.example.json` 复制一份，并填入网关和 H3C 路由器账号。

桌面 App 首次运行会把打包时的 `config.json` 复制到 Windows 用户数据目录。之后升级不会覆盖用户配置。

## 3. 一键打包

在 PowerShell 中进入项目目录，执行：

```powershell
.\scripts\build-windows-app.ps1
```

或者手动执行：

```powershell
npm install
python -m pip install -r requirements.txt
npm run build:win
```

## 4. 输出位置

打包完成后，到 `release\` 目录查看 Windows 安装包。

生成的安装包会包含：

- Electron 桌面窗口
- Windows 后端程序 `netmon-backend.exe`
- 首次运行默认配置

## 5. 注意事项

- 端口固定为 `5102`。
- 如果启动提示端口被占用，先关闭旧的监控服务或旧版 App。
- 如果页面没有数据，优先检查 Windows 用户数据目录里的 `config.json` 是否仍是示例密码。
