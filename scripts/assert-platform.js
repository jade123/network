const expected = process.argv[2];
const labels = {
  win32: "Windows",
  darwin: "macOS",
  linux: "Linux",
};

if (!expected) {
  console.error("Usage: node scripts/assert-platform.js <win32|darwin|linux>");
  process.exit(2);
}

if (process.platform !== expected) {
  console.error(`当前系统是 ${labels[process.platform] || process.platform}，不能构建 ${labels[expected] || expected} 安装包。`);
  console.error("原因：PyInstaller 后端可执行文件必须在目标系统上构建。请在目标系统或对应 CI 环境执行打包命令。");
  process.exit(1);
}
