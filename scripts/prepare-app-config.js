const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const outDir = path.join(root, "build", "app-config");
const realConfig = path.join(root, "config.json");
const exampleConfig = path.join(root, "config.example.json");
const targetConfig = path.join(outDir, "config.json");

fs.mkdirSync(outDir, { recursive: true });

const source = fs.existsSync(realConfig) ? realConfig : exampleConfig;
fs.copyFileSync(source, targetConfig);
console.log(`Prepared app default config from ${path.basename(source)} -> ${targetConfig}`);
