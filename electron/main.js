const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn, execFile } = require("child_process");
const fs = require("fs");
const net = require("net");
const path = require("path");

const APP_NAME = "Network Traffic Monitor";
const PORT = 5102;
const HOST = "127.0.0.1";
const APP_URL = `http://${HOST}:${PORT}/`;

let mainWindow = null;
let backendProcess = null;
let isQuitting = false;

function projectRoot() {
  return app.isPackaged ? process.resourcesPath : path.join(__dirname, "..");
}

function userPaths() {
  const base = app.getPath("userData");
  return {
    base,
    config: path.join(base, "config.json"),
    dataDir: path.join(base, "data"),
    logDir: path.join(base, "logs"),
    logPath: path.join(base, "logs", "monitor.log"),
  };
}

function ensureRuntimeFiles() {
  const paths = userPaths();
  fs.mkdirSync(paths.dataDir, { recursive: true });
  fs.mkdirSync(paths.logDir, { recursive: true });

  if (!fs.existsSync(paths.config)) {
    const packagedConfig = path.join(process.resourcesPath, "config", "config.json");
    const packagedExample = path.join(process.resourcesPath, "config", "config.example.json");
    const localConfig = path.join(projectRoot(), "config.json");
    const localExample = path.join(projectRoot(), "config.example.json");
    const template = app.isPackaged
      ? (fs.existsSync(packagedConfig) ? packagedConfig : packagedExample)
      : (fs.existsSync(localConfig) ? localConfig : localExample);
    fs.copyFileSync(template, paths.config);
  }

  return paths;
}

function backendExecutable() {
  if (!app.isPackaged) {
    const root = projectRoot();
    const venvPython = process.platform === "win32"
      ? path.join(root, ".venv", "Scripts", "python.exe")
      : path.join(root, ".venv", "bin", "python");
    const python = fs.existsSync(venvPython) ? venvPython : (process.platform === "win32" ? "python" : "python3");
    return {
      command: python,
      args: [path.join(root, "server.py")],
      cwd: root,
    };
  }

  const exeName = process.platform === "win32" ? "netmon-backend.exe" : "netmon-backend";
  const exePath = path.join(process.resourcesPath, "backend", exeName);
  if (process.platform !== "win32" && fs.existsSync(exePath)) {
    fs.chmodSync(exePath, 0o755);
  }
  return {
    command: exePath,
    args: [],
    cwd: path.dirname(exePath),
  };
}

function portIsOpen() {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(500);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(false));
    socket.connect(PORT, HOST);
  });
}

async function waitForBackend(timeoutMs = 45000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await portIsOpen()) return true;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function startupHtml(message = "正在启动本地监控服务...") {
  const safeMessage = escapeHtml(message).replace(/\n/g, "<br>");
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="utf-8">
      <style>
        body {
          height: 100vh;
          margin: 0;
          display: grid;
          place-items: center;
          color: #e7f5f7;
          background: #071014;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif;
        }
        main {
          width: min(520px, calc(100vw - 40px));
          padding: 28px;
          border: 1px solid #223b46;
          border-radius: 8px;
          background: #0d1a20;
          box-shadow: 0 20px 70px rgba(0,0,0,.28);
        }
        h1 { margin: 0 0 10px; font-size: 20px; }
        p { margin: 0; color: #89a2aa; line-height: 1.7; }
      </style>
    </head>
    <body><main><h1>${APP_NAME}</h1><p>${safeMessage}</p></main></body>
    </html>
  `)}`;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 720,
    title: APP_NAME,
    backgroundColor: "#071014",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadURL(startupHtml());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function startBackend(runtimePaths) {
  const backend = backendExecutable();
  if (app.isPackaged && !fs.existsSync(backend.command)) {
    throw new Error(`后端程序不存在：${backend.command}`);
  }

  backendProcess = spawn(backend.command, backend.args, {
    cwd: backend.cwd,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: "1",
      NETMON_CONFIG_PATH: runtimePaths.config,
      NETMON_DATA_DIR: runtimePaths.dataDir,
      NETMON_LOG_PATH: runtimePaths.logPath,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  backendProcess.stdout.on("data", (chunk) => console.log(`[backend] ${chunk.toString().trim()}`));
  backendProcess.stderr.on("data", (chunk) => console.error(`[backend] ${chunk.toString().trim()}`));
  backendProcess.on("exit", (code) => {
    if (!isQuitting && mainWindow) {
      mainWindow.loadURL(startupHtml(`后端服务已退出，退出码：${code ?? "-"}`));
    }
  });
}

function stopBackend() {
  if (!backendProcess || backendProcess.killed) return;
  const pid = backendProcess.pid;
  if (process.platform === "win32") {
    execFile("taskkill", ["/pid", String(pid), "/T", "/F"], () => {});
  } else {
    backendProcess.kill("SIGTERM");
  }
  backendProcess = null;
}

async function boot() {
  createWindow();
  const runtimePaths = ensureRuntimeFiles();
  if (await portIsOpen()) {
    const detail = `端口 ${PORT} 已被占用。请先关闭旧的监控服务，再重新打开 App。\n\n日志目录：${runtimePaths.logDir}`;
    mainWindow.loadURL(startupHtml(detail));
    dialog.showErrorBox("端口被占用", detail);
    return;
  }

  try {
    startBackend(runtimePaths);
    const ready = await waitForBackend();
    if (!ready) {
      const detail = `后端启动超时，请查看日志：${runtimePaths.logPath}`;
      mainWindow.loadURL(startupHtml(detail));
      dialog.showErrorBox("后端启动失败", detail);
      return;
    }
    await mainWindow.loadURL(APP_URL);
  } catch (error) {
    const detail = `${error.message}\n\n日志路径：${runtimePaths.logPath}`;
    mainWindow.loadURL(startupHtml(detail));
    dialog.showErrorBox("启动失败", detail);
  }
}

app.whenReady().then(boot);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  isQuitting = true;
  stopBackend();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
});
