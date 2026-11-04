import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("C:/Users/ankit/.vscode/extensions/danielsanmedium.dscodegpt-3.24.79/standalone/node_modules/patchright");
const b = await chromium.launch({ headless: true, channel: "chrome" });
const p = await b.newPage({ viewport: { width: 1024, height: 1024 } });
await p.goto("file:///C:/Users/ankit/gatekeeper/assets/icon.html");
await p.screenshot({ path: "C:/Users/ankit/gatekeeper/assets/gatekeeper-icon-light.png" });
await b.close();
