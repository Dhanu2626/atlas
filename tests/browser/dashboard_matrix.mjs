// Real-browser verification of the dashboard page, across engines (2026-09-22).
//
//   node tests/browser/dashboard_matrix.mjs <playwright-dir> <engine> <label>=<url> [<label>=<url> ...]
//
// Run by tests/test_dashboard_browsers.py, which serves the page over local HTTP
// and writes a failure page. For every page it loads the page FRESH in each
// viewport (browser default, 400x860, 1280x800) and colour scheme (light, dark)
// and checks, with real pointer clicks:
//
//   * one control per exported scenario, and clicking each shows THAT scenario:
//     its label, outcome, decision reason, local time and rail;
//   * the clicked control is the one marked current;
//   * no horizontal overflow at any width;
//   * no console error and no uncaught exception;
//   * no network request other than the page itself (it is one self-contained file);
//   * on a failure page: the warnings banner and a failed test run are shown,
//     and a missing snapshot section is left out rather than invented.
//
// Targets (2026-09-25 added the last four):
//   chromium, firefox, webkit   Playwright's own engine builds
//   chrome, msedge              the INSTALLED, branded Google Chrome and Microsoft
//                               Edge, driven through Playwright's channels
//   iphone-emulated             WebKit with Playwright's iPhone 13 profile: its
//                               viewport, user agent, touch and pixel ratio
//   android-emulated            Chromium with Playwright's Pixel 7 profile
// The two *-emulated targets tap instead of click and use the device's own
// viewport. They are EMULATION on this PC -- not Safari on iOS, not a phone --
// and the result says so ("emulated": true).
//
// Prints one JSON object; exits 1 if any check failed.

import { createRequire } from "node:module";
import path from "node:path";

const [playwrightDir, engineName, ...pageArgs] = process.argv.slice(2);
const require = createRequire(path.join(playwrightDir, "package.json"));
const playwright = require("playwright");

const VIEWPORTS = [null, { width: 400, height: 860 }, { width: 1280, height: 800 }];
const TARGETS = {
  chromium: { engine: "chromium" },
  firefox: { engine: "firefox" },
  webkit: { engine: "webkit" },
  chrome: { engine: "chromium", channel: "chrome" },
  msedge: { engine: "chromium", channel: "msedge" },
  "iphone-emulated": { engine: "webkit", device: "iPhone 13" },
  "android-emulated": { engine: "chromium", device: "Pixel 7" },
};
const SCHEMES = ["light", "dark"];

async function checkLoad(browser, label, url, viewport, colorScheme, device) {
  const context = await browser.newContext(device
    ? { ...device, colorScheme }
    : { colorScheme, ...(viewport ? { viewport } : {}) });
  const page = await context.newPage();
  const problems = [];
  const consoleErrors = [];
  const otherRequests = [];
  page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text()); });
  page.on("pageerror", (err) => consoleErrors.push(String(err)));
  page.on("request", (req) => {
    if (req.url().split("#")[0] !== url.split("#")[0]) otherRequests.push(req.url());
  });
  await page.goto(url, { waitUntil: "load" });
  const data = await page.evaluate(() => JSON.parse(
    document.getElementById("atlas-data").textContent.replace(/<\\\//g, "</")));
  const rows = (data.sweep || {}).rows || [];
  const buttons = page.locator("#scn button");
  const count = await buttons.count();
  if (count !== rows.length) problems.push(`controls ${count} != rows ${rows.length}`);
  let clicked = 0;
  for (let i = 0; i < count; i += 1) {
    if (device) await buttons.nth(i).tap(); else await buttons.nth(i).click();
    clicked += 1;
    const pane = await page.locator("#detail").innerText();
    const row = rows[i];
    for (const [what, needle] of [["label", row.label], ["outcome", row.final_status],
      ["reason", row.decision_reason], ["time", row.local_time], ["rail", row.rail]]) {
      if (needle && !pane.includes(needle)) problems.push(`scenario ${i}: ${what} "${needle}" missing`);
    }
    if ((await buttons.nth(i).getAttribute("aria-current")) !== "true") {
      problems.push(`scenario ${i}: not marked current after its click`);
    }
  }
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 1) problems.push(`horizontal overflow ${overflow}px`);
  const app = await page.locator("#app").innerText();
  const warnings = data.warnings || [];
  if (warnings.length && !app.includes(`This export reported ${warnings.length}`)) {
    problems.push("export warnings are not shown");
  }
  if (((data.measurements || {}).tests || {}).failed && !app.includes("did not pass")) {
    problems.push("a failed test run is not shown as failed");
  }
  if (!(data.snapshot || {}).devices && app.includes("Device registry")) {
    problems.push("a missing snapshot section was rendered as if present");
  }
  if (consoleErrors.length) problems.push(`console errors: ${consoleErrors.slice(0, 3).join(" | ")}`);
  if (otherRequests.length) problems.push(`unexpected requests: ${otherRequests.slice(0, 3).join(", ")}`);
  await context.close();
  const shown = device ? `${device.viewport.width}x${device.viewport.height}`
    : (viewport ? `${viewport.width}x${viewport.height}` : "default");
  return { page: label, viewport: shown,
           scheme: colorScheme, controls: count, clicked, overflow, ok: problems.length === 0, problems };
}

const target = TARGETS[engineName];
if (!target) throw new Error(`unknown target ${engineName}`);
const device = target.device ? playwright.devices[target.device] : null;
const viewports = device ? [null] : VIEWPORTS;
const result = { engine: engineName, version: null, loads: [], launched: false,
                 emulated: Boolean(device), device: target.device || null,
                 channel: target.channel || null, viewports: viewports.length };
let browser;
try {
  browser = await playwright[target.engine].launch(target.channel ? { channel: target.channel } : {});
  result.launched = true;
  result.version = browser.version();
  for (const arg of pageArgs) {
    const at = arg.indexOf("=");
    const label = arg.slice(0, at);
    const url = arg.slice(at + 1);
    for (const viewport of viewports) {
      for (const scheme of SCHEMES) {
        result.loads.push(await checkLoad(browser, label, url, viewport, scheme, device));
      }
    }
  }
} catch (err) {
  result.error = String(err).split("\n")[0];
} finally {
  if (browser) await browser.close();
}
console.log(JSON.stringify(result));
process.exit(result.launched && result.loads.every((l) => l.ok) ? 0 : 1);
