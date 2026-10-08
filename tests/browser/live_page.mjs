// Drives the real "Run it live" page (docs/live/index.html) in a real browser engine:
// clicks Start, waits for ATLAS to come up inside the page (Pyodide from jsDelivr), sends
// each parity scenario through the page's own form, then a replay, and prints the results.
// Scenarios with a location use the browser's real geolocation API: the context grants the
// permission and reports a fixed test position (never anyone's real one), and the page asks
// for it exactly as it does for a visitor.
//
//   node tests/browser/live_page.mjs <playwright-dir> <docs-dir> <scenarios-json> [engine] [device]
//
// <scenarios-json> is a list of [label, payee, rupees, hhmm, where] or
// {"scenarios": [...], "spots": {where: [lat, lon, accuracy_m]}}.
//
// docs/ is served through a route on a made-up origin, so nothing listens on any port.
// Network: only cdn.jsdelivr.net, for Pyodide -- exactly what a visitor's browser fetches.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";

const [playwrightDir, docsDir, scenariosJson, engine = "chromium", device = ""] = process.argv.slice(2);
const require = createRequire(path.join(playwrightDir, "package.json"));
const playwright = require("playwright");
const parsed = JSON.parse(scenariosJson);
const scenarios = Array.isArray(parsed) ? parsed : parsed.scenarios;
const spots = Array.isArray(parsed) ? {} : parsed.spots || {};

const browser = await playwright[engine].launch();
const context = await browser.newContext({ ...(device ? playwright.devices[device] : {}),
  permissions: ["geolocation"], geolocation: { latitude: 0, longitude: 0, accuracy: 100 } });
const page = await context.newPage();
const types = { ".html": "text/html", ".py": "text/plain", ".zip": "application/zip", ".json": "application/json" };
await page.route("https://atlas.live/**", (route) => {
  const rel = new URL(route.request().url()).pathname.slice(1) || "index.html";
  try {
    route.fulfill({ body: readFileSync(path.join(docsDir, rel)), contentType: types[path.extname(rel)] || "application/octet-stream" });
  } catch { route.fulfill({ status: 404, body: "not found" }); }
});
const origins = new Set();
let bytes = 0;
page.on("request", (r) => origins.add(new URL(r.url()).origin));
page.on("response", async (r) => { try { bytes += (await r.body()).length; } catch {} });
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));

const t0 = Date.now();
await page.goto("https://atlas.live/live/index.html");
const before = [...origins];                                   // before the click: nothing but the page
await page.click("#go");
await page.waitForFunction(() => window.__atlasReady || window.__atlasError, null, { timeout: 600000 });
const error = await page.evaluate(() => window.__atlasError || null);
const ready = await page.evaluate(() => window.__atlasReady || null);
const startup_s = (Date.now() - t0) / 1000;
const results = [];
if (!error) {
  let locationOn = false;
  for (const [label, payee, rupees, hhmm, where] of scenarios) {
    if (where) {
      const [latitude, longitude, accuracy] = spots[where];
      await context.setGeolocation({ latitude, longitude, accuracy });
      if (!locationOn) { await page.evaluate(() => window.__atlasUseLocation()); locationOn = true; }
    }
    await page.evaluate(([p, a, t]) => window.__atlasPay(p, a, t), [payee, rupees, hhmm]);
    results.push({ label, ...(await page.evaluate(() => window.__atlasLast)) });
  }
  await page.evaluate(() => window.__atlasReplay());
  results.push({ label: "replay", ...(await page.evaluate(() => window.__atlasLast)) });
}
const shownLed = error ? null : await page.evaluate(() =>
  ["GREEN", "AMBER", "RED"].filter((c) => document.getElementById("led-" + c).dataset.on === "true"));
console.log(JSON.stringify({ engine, device, error, ready, startup_s, downloaded_mb: +(bytes / 1048576).toFixed(1),
  origins_before_click: before, origins: [...origins], page_errors: pageErrors, shown_led: shownLed, results }));
await browser.close();
