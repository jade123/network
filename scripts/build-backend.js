const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const venvPython = process.platform === "win32"
  ? path.join(root, ".venv", "Scripts", "python.exe")
  : path.join(root, ".venv", "bin", "python");
const python = process.env.PYTHON || (fs.existsSync(venvPython) ? venvPython : (process.platform === "win32" ? "python" : "python3"));
const dataSep = process.platform === "win32" ? ";" : ":";
const outputName = "netmon-backend";

const args = [
  "-m", "PyInstaller",
  "--noconfirm",
  "--clean",
  "--onefile",
  "--name", outputName,
  "--add-data", `static${dataSep}static`,
  "--add-data", `config.example.json${dataSep}.`,
  "--hidden-import", "lxml.etree",
  "--hidden-import", "lxml._elementpath",
  "--exclude-module", "markupsafe._speedups",
  "server.py",
];

console.log(`Building backend with ${python} ${args.join(" ")}`);
const result = spawnSync(python, args, {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    PYINSTALLER_CONFIG_DIR: path.join(root, ".pyinstaller-cache"),
  },
});

if (result.status !== 0) {
  process.exit(result.status || 1);
}

const executable = path.join(root, "dist", process.platform === "win32" ? `${outputName}.exe` : outputName);
if (!fs.existsSync(executable)) {
  console.error(`Backend executable was not created: ${executable}`);
  process.exit(1);
}

console.log(`Backend executable ready: ${executable}`);
