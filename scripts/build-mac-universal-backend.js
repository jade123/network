const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const venvPython = path.join(root, ".venv", "bin", "python");
const python = process.env.PYTHON || (fs.existsSync(venvPython) ? venvPython : "python3");
const outputName = "netmon-backend";
const archBuilds = [
  { arch: "arm64", dist: path.join(root, "dist", "mac-arm64") },
  { arch: "x86_64", dist: path.join(root, "dist", "mac-x64") },
];

function run(command, args, options = {}) {
  console.log(`Running: ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      PYINSTALLER_CONFIG_DIR: path.join(root, ".pyinstaller-cache"),
      ...(options.env || {}),
    },
  });
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

if (process.platform !== "darwin") {
  console.error("macOS universal backend can only be built on macOS.");
  process.exit(1);
}

for (const item of archBuilds) {
  const args = [
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--name", outputName,
    "--target-arch", item.arch,
    "--distpath", item.dist,
    "--workpath", path.join(root, "build", `${outputName}-${item.arch}`),
    "--specpath", path.join(root, "build", "specs"),
    "--add-data", `${path.join(root, "static")}:static`,
    "--add-data", `${path.join(root, "config.example.json")}:.`,
    "--hidden-import", "lxml.etree",
    "--hidden-import", "lxml._elementpath",
    "--exclude-module", "markupsafe._speedups",
    "server.py",
  ];
  run(python, args);

  const executable = path.join(item.dist, outputName);
  if (!fs.existsSync(executable)) {
    console.error(`Expected backend executable missing: ${executable}`);
    process.exit(1);
  }
}

const universalOutput = path.join(root, "dist", outputName);
run("lipo", [
  "-create",
  path.join(archBuilds[0].dist, outputName),
  path.join(archBuilds[1].dist, outputName),
  "-output",
  universalOutput,
], { env: {} });

run("lipo", ["-info", universalOutput]);
console.log(`Universal macOS backend ready: ${universalOutput}`);
