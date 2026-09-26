// Automated tests for the dashboard page's own JavaScript (docs/index.html).
//
//   node tests/js/dashboard_page_tests.mjs
//   .venv/Scripts/python -m pytest tests/test_dashboard_page_js.py   (same thing, via pytest)
//
// The page is deliberately one self-contained file with no build step and no
// dependencies, so these tests have none either: the behaviour script is
// extracted from the page and run against a small DOM stub below. That keeps
// the thing under test the shipped file itself -- not a copy that can drift.
//
// What is NOT here, because the page does not do it: network calls, form
// submission, authentication, or any device interaction. The page renders one
// frozen export and nothing else, which test_the_page_never_talks_to_anything
// pins. The server-side flows those would belong to are covered by the Python
// suite (tests/test_step_up.py, tests/test_phase3_device_trust.py).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PAGE = path.join(HERE, "..", "..", "docs", "index.html");
const html = readFileSync(PAGE, "utf8");

// ---------------------------------------------------------------- DOM stub
function makeElement(id) {
  return {
    id,
    _html: "",
    textContent: "",
    attributes: {},
    listeners: {},
    get innerHTML() { return this._html; },
    set innerHTML(value) { this._html = String(value); },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return this.attributes[name]; },
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
    click() { (this.listeners.click || []).forEach((fn) => fn({ type: "click" })); },
  };
}

function makeDocument(islandText) {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  get("atlas-data").textContent = islandText;
  return {
    elements,
    getElementById: (id) => get(id),
    querySelectorAll(selector) {
      if (selector !== "#scn button") throw new Error(`unexpected selector ${selector}`);
      const app = get("app").innerHTML;
      // Memoised against the current markup: a second call has to return the
      // same objects the page bound its click handlers to, or a test would
      // click stand-ins and see nothing happen.
      if (this._buttonsFor === app) return this._buttons;
      const buttons = [];
      const re = /<button[^>]*data-i="(\d+)"[^>]*>([\s\S]*?)<\/button>/g;
      let match;
      while ((match = re.exec(app)) !== null) {
        const button = makeElement(`scn-${match[1]}`);
        button.markup = match[0];
        buttons.push(button);
      }
      this._buttonsFor = app;
      this._buttons = buttons;
      return buttons;
    },
  };
}

/** Runs the page's own behaviour script against a fresh stub document. */
function render(data) {
  const open = html.indexOf("<script>");
  const source = html.slice(open + "<script>".length, html.indexOf("</script>", open));
  const islandText = data === undefined ? "{}" : (typeof data === "string" ? data : JSON.stringify(data));
  const document = makeDocument(islandText);
  // eslint-disable-next-line no-new-func
  new Function("document", "window", source)(document, { document });
  return document;
}

// ------------------------------------------------------------------ fixtures
// Built on the real export the repository ships, so these tests exercise the
// shape the exporter actually produces rather than a hand-written guess.
const SHIPPED = JSON.parse(readFileSync(path.join(HERE, "..", "..", "docs", "dashboard-data.json"), "utf8"));

// A full export (--run-tests) measures ML and replays every envelope; a quick one
// does not, and a fresh clone's first export has no databases at all. The page
// must render all of those, so the fixtures fill in whatever the shipped export
// is missing rather than assuming a rich one. Filled-in values are fixtures, not
// measurements, and the shipped export gets its own rendering test below.
function complete(data) {
  const filled = JSON.parse(JSON.stringify(data));
  // A fresh clone has no databases, so its export carries no snapshot at all.
  // The page's snapshot sections still have to be tested, so stand one in.
  if (!filled.snapshot || filled.snapshot.available !== true) {
    filled.snapshot = {
      available: true,
      transactions: { total: 138, by_state: { CONFIRMED: 84, DENIED: 53, AWAITING_STEP_UP: 1 },
        first_seen: "2026-08-25T22:31:46+00:00", last_seen: "2026-09-11T16:52:11+00:00",
        distinct_subjects: 1, amount_min: 100, amount_max: 150000 },
      step_up: { challenges: 6, by_outcome: { ALLOW: 5, UNRESOLVED: 1 }, unconsumed: 1,
        unconsumed_expired: 1,
        awaiting: { live: 0, expired: 1, no_challenge: 0, consumed_not_advanced: 0 },
        events: { CHALLENGE_ISSUED: 6, PROOF_VERIFIED: 5, INVALID_PROOF: 1 },
        authenticators_enrolled: 1 },
      devices: { total: 14, by_status: { ACTIVE: 1, REVOKED: 13 },
        by_provisioning_mode: { demo: 14 }, with_secure_element: 0,
        firmware_versions: ["0.3.0", "0.4.0", "0.5.0"] },
      bank: { consumed_assertions: 84 },
    };
  }
  filled.measurements = filled.measurements || {};
  if (!(filled.measurements.ml || {}).at_medium_and_above) {
    filled.measurements.ml = {
      method: "measured by this export", personas: 5, training_history_per_persona: 200,
      at_medium_and_above: { flagged_as: "MEDIUM or HIGH", planted: 30, ordinary: 200,
        true_positives: 28, false_negatives: 2, false_positives: 0, true_negatives: 200,
        precision: 1.0, recall: 0.9333, f1: 0.9655, false_positive_rate: 0.0 },
      at_medium_and_above_excluding_the_legitimate_large_purchase: { precision: 0.8214 },
      latency: { score_ms_median: 78.74, score_ms_p95: 123.76, fit_ms_median: 1813.5 },
    };
  }
  for (const row of filled.sweep.rows) {
    if (!row.replay) {
      row.replay = { final_status: "FAIL_CLOSED", decision_reason: "COUNTER_REGRESSION", refused: true };
    }
    if (typeof row.elapsed_ms !== "number") row.elapsed_ms = 2750.5;
  }
  return filled;
}

const REAL = complete(SHIPPED);
const DATA = (over = {}) => JSON.parse(JSON.stringify({ ...REAL, ...over }));
const STEP_UP_INDEX = REAL.sweep.rows.findIndex((r) => r.final_status === "STEP_UP");

// -------------------------------------------------------------------- runner
let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed += 1; console.log(`ok   ${name}`); }
  catch (err) { failures.push(name); console.log(`FAIL ${name}\n       ${err.message}`); }
}
function assert(cond, message) { if (!cond) throw new Error(message); }
function includes(haystack, needle, message) {
  assert(haystack.includes(needle), `${message}\n       expected to find: ${needle}`);
}
function excludes(haystack, needle, message) {
  assert(!haystack.includes(needle), `${message}\n       should not contain: ${needle}`);
}

// --------------------------------------------------------------------- tests
test("every exported scenario becomes a control, in order", () => {
  const doc = render(DATA());
  const buttons = doc.querySelectorAll("#scn button");
  assert(buttons.length === REAL.sweep.rows.length,
    `expected ${REAL.sweep.rows.length} controls, got ${buttons.length}`);
  includes(buttons[0].markup, 'data-i="0"', "first control is not the first scenario");
  buttons.forEach((b, i) => includes(b.markup, REAL.sweep.rows[i].local_time,
    `control ${i} does not carry its scenario's local time`));
});

test("the first scenario is selected on load, with its decision shown", () => {
  const doc = render(DATA());
  const detail = doc.getElementById("detail").innerHTML;
  const first = REAL.sweep.rows[0];
  includes(detail, first.label, "the opening detail pane does not name the scenario");
  includes(detail, first.final_status.replace(/_/g, " "), "the decision is missing");
  includes(detail, first.ml.risk_band, "the risk band is missing");
  includes(detail, first.decision_reason, "the decision reason is missing");
});

test("clicking a control swaps the detail pane to that scenario", () => {
  const doc = render(DATA());
  const buttons = doc.querySelectorAll("#scn button");
  const row = REAL.sweep.rows[STEP_UP_INDEX];
  buttons[STEP_UP_INDEX].click();
  const detail = doc.getElementById("detail").innerHTML;
  includes(detail, "STEP UP", "clicking a scenario did not show its decision");
  includes(detail, row.policy.deciding_rule, "the deciding rule is missing after a click");
  assert(buttons[STEP_UP_INDEX].getAttribute("aria-current") === "true",
    "the clicked control is not current");
  assert(buttons[0].getAttribute("aria-current") === "false",
    "two controls are current at once");
});

test("a decision that was never signed is never shown as signed", () => {
  const doc = render(DATA());
  const row = REAL.sweep.rows[STEP_UP_INDEX];
  assert(row.crypto.assertion_signed === false, "fixture drift: this row should be unsigned");
  doc.querySelectorAll("#scn button")[STEP_UP_INDEX].click();
  const detail = doc.getElementById("detail").innerHTML;
  includes(detail, "not signed", "an unsigned decision is not marked as such");
  excludes(detail, "Ed25519 signature", "signature details appeared for an unsigned decision");
  const signed = REAL.sweep.rows.find((r) => r.crypto.assertion_signed);
  if (signed && signed.crypto.key_id) {
    excludes(detail, signed.crypto.key_id, "another row's key id leaked into this one");
  }
});

test("the step-up snapshot explains why a payment is still waiting", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  includes(app, "denied at next service start",
    "an expired challenge is presented as though someone were still deciding");
  includes(app, "Authenticators enrolled", "the step-up panel is missing");
});

test("export warnings are shown, not swallowed", () => {
  const app = render(DATA({ warnings: ["no step-up database on this machine; step-up figures omitted"] }))
    .getElementById("app").innerHTML;
  includes(app, "1 warning", "the warning count is not announced");
  includes(app, "no step-up database", "the warning text is not shown");
});

test("a failed test run is reported as failed", () => {
  const app = render(DATA({ measurements: { ...DATA().measurements,
    tests: { total: 340, failed: true, failed_count: 11, error_count: 0, method: "executed by this export" } } }))
    .getElementById("app").innerHTML;
  includes(app, "run did not pass", "a failing test run is not flagged");
  includes(app, "11 failed", "the failure count is missing");
});

test("a missing snapshot section is left out rather than invented", () => {
  const data = DATA();
  delete data.snapshot.devices;
  const app = render(data).getElementById("app").innerHTML;
  excludes(app, "Device registry", "a device section was rendered without device figures");
  includes(app, "Step-up authentication", "unrelated sections disappeared too");
});

test("an export with no rows says so instead of showing an empty table", () => {
  const app = render(DATA({ sweep: { available: false, rows: [], scenarios_attempted: 7 } }))
    .getElementById("app").innerHTML;
  includes(app, "did not run", "a sweep that produced nothing is not reported");
});

test("a page with no data explains how to generate it", () => {
  const app = render().getElementById("app").innerHTML;
  includes(app, "no exported data", "an empty island renders nothing at all");
  includes(app, "export_dashboard_data.py", "the empty state does not say how to fix it");
});

test("a malformed data island fails safe instead of throwing", () => {
  const app = render("{not valid json,,,").getElementById("app").innerHTML;
  includes(app, "no exported data", "broken JSON did not degrade to the empty state");
});

test("hostile text in an export cannot inject markup", () => {
  const nasty = '<img src=x onerror="alert(1)">';
  const app = render(DATA({ warnings: [nasty] })).getElementById("app").innerHTML;
  excludes(app, "<img src=x", "a warning was rendered as live markup");
  includes(app, "&lt;img", "the warning was not escaped");
});

test("a hostile scenario label is escaped too", () => {
  const data = DATA();
  data.sweep.rows[0].label = '</button><script>alert(1)</script>';
  const app = render(data).getElementById("app").innerHTML;
  excludes(app, "<script>alert(1)", "a scenario label was rendered as live markup");
});

test("the page never talks to anything", () => {
  const open = html.indexOf("<script>");
  const source = html.slice(open + "<script>".length, html.indexOf("</script>", open));
  for (const api of ["fetch(", "XMLHttpRequest", "WebSocket", "navigator.sendBeacon", "import("]) {
    excludes(source, api, `the page uses ${api}; it must render the frozen export only`);
  }
  for (const tag of ["<form", "<iframe", "src=\"http"]) {
    excludes(html, tag, `the page contains ${tag}; it must not submit or load anything`);
  }
});

test("figures that were not measured by the export are labelled as recorded", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  includes(app, "Source:", "a recorded figure carries no source line");
  includes(app, "recorded, not re-measured by this export",
    "a recorded figure is presented as though this export measured it");
  // and a figure that names no source gets no source line invented for it
  const count = (s) => (s.match(/Source:/g) || []).length;
  const data = DATA();
  delete data.measurements.step_up_device_checks.source;
  assert(count(render(data).getElementById("app").innerHTML) === count(app) - 1,
    "removing a figure's source did not remove exactly its own source line");
});

test("the mutation panel totals every recorded break set, not just the first", () => {
  // Added 2026-09-23: the panel used to read one hardcoded set, so a second set of
  // deliberate breaks would have been recorded in the export and shown nowhere.
  const data = DATA();
  data.measurements.mutation_checks = {
    one: { introduced: 10, caught: 10, source: "the first recorded set" },
    two: { introduced: 15, caught: 14, source: "the second recorded set" },
  };
  const app = render(data).getElementById("app").innerHTML;
  includes(app, ">25<", "the breaks introduced are not totalled across sets");
  includes(app, ">24<", "the breaks caught are not totalled across sets");
  includes(app, "the first recorded set", "the first set's source is missing");
  includes(app, "the second recorded set", "the second set's source is missing");
});

test("each scenario shows whether its envelope survived a replay", () => {
  const doc = render(DATA());
  const detail = doc.getElementById("detail").innerHTML;
  const row = REAL.sweep.rows[0];
  assert(row.replay.refused === true, "the fixture should describe a refused replay");
  includes(detail, "Replay defence", "the replay panel is missing");
  includes(detail, "refused", "a refused replay is not shown as refused");
  includes(detail, row.replay.decision_reason, "the defence that answered is not named");
});

test("a replay that was accepted would be shown as accepted, not hidden", () => {
  const data = DATA();
  data.sweep.rows[0].replay = { final_status: "ALLOW", decision_reason: null, refused: false };
  const detail = render(data).getElementById("detail").innerHTML;
  includes(detail, "accepted again", "a second approval of the same envelope was not surfaced");
});

test("an export that never tested replay says so", () => {
  const data = DATA();
  delete data.sweep.rows[0].replay;
  const detail = render(data).getElementById("detail").innerHTML;
  includes(detail, "not tested", "a missing replay result reads as though it passed");
});

test("measured ML figures are shown with the synthetic caveat attached", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  assert(REAL.measurements.ml.at_medium_and_above, "the fixture should carry measured ML figures");
  includes(app, "Precision", "the measured precision is missing");
  includes(app, "not</b> fraud detection", "the synthetic caveat does not travel with the number");
  includes(app, "evaluate_ml.py", "the page does not say what measured this");
});

test("an export that did not measure ML says so instead of showing nothing", () => {
  const data = DATA();
  data.measurements.ml = { method: "not run in this export" };
  const app = render(data).getElementById("app").innerHTML;
  includes(app, "not run in this export", "an unmeasured model reads as though it has no figures");
  excludes(app, "Precision</dt>", "a precision row appeared without a measurement");
});

test("the limits section no longer claims precision was never evaluated", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  excludes(app, "were never evaluated", "a stale 'never evaluated' claim survives on the page");
  includes(app, "separation on generated data", "the limits section drops the synthetic caveat");
});

test("the limits section describes this release's step-up and transport, not earlier ones", () => {
  // Both retired on 2026-09-18: failed proofs no longer end a challenge (D1),
  // and the legacy unsigned /transact is closed by default (D5).
  const app = render(DATA()).getElementById("app").innerHTML;
  excludes(app, "Three invalid step-up proofs", "the retired 3-attempt denial is still listed as a limit");
  excludes(app, "stays open unless", "the legacy /transact is still described as open by default");
  excludes(app, "No TLS anywhere", "the limits section ignores the loopback-only transport policy");
  includes(app, "No production TLS", "the limits section drops the TLS limitation");
});

// ---- 2026-09-22: held-out and public evaluations, accessibility, limits ----

function withEvaluations() {
  const data = DATA();
  data.measurements.ml.held_out = {
    test: { cases: 560, anomalies: 240, negatives: 320, roc_auc: 0.8997, average_precision: 0.926,
      at_medium_and_above: { confusion_matrix: { tp: 200, fp: 3, fn: 40, tn: 317 },
        precision: 0.9852, recall: 0.8333, f1: 0.9029, false_positive_rate: 0.0094 },
      recall_by_family: { burst: 0.0, amount_spike: 1.0 } },
  };
  data.measurements.ml_public_benchmark = {
    method: "recorded", dataset: "Credit Card Fraud Detection (ULB)", rows: 284807, frauds: 492,
    roc_auc: 0.9337, average_precision: 0.1132,
    at_high_only: { precision: 0.0523, recall: 0.6566 },
    source: "scripts/benchmark_public_dataset.py on 2026-09-22 — recorded, not re-measured by this export",
  };
  return data;
}

test("held-out ML figures appear with the synthetic caveat and the burst weakness", () => {
  const app = render(withEvaluations()).getElementById("app").innerHTML;
  includes(app, "ML, held-out test", "the held-out panel is missing");
  includes(app, "0.90", "the held-out ROC-AUC is not shown");
  includes(app, "<b>not</b> fraud detection", "the held-out figures lost their caveat");
  includes(app, "The Isolation Forest itself catches bursts of payments", "the burst weakness is hidden");
});

test("the public benchmark is labelled recorded and says it is not ATLAS's model", () => {
  const app = render(withEvaluations()).getElementById("app").innerHTML;
  includes(app, "Public benchmark", "the public benchmark panel is missing");
  includes(app, "not re-measured by this export", "the benchmark is not labelled as recorded");
  includes(app, "<b>not</b> ATLAS's per-customer model", "the benchmark overclaims what it measured");
});

test("panels that were not measured are left out rather than invented", () => {
  const data = DATA();
  delete data.measurements.ml_public_benchmark;
  if (data.measurements.ml) delete data.measurements.ml.held_out;
  const app = render(data).getElementById("app").innerHTML;
  excludes(app, "ML, held-out test", "a held-out panel appeared without held-out data");
  excludes(app, "Public benchmark", "a benchmark panel appeared without a recorded benchmark");
});

test("banners use hidden SVG icons, never emoji", () => {
  const data = DATA();
  data.warnings = ["a warning to display"];
  const app = render(data).getElementById("app").innerHTML;
  assert(!/[☀-➿]|\uD83C|\uD83D|\uD83E/.test(app), "an emoji is used as an icon");
  includes(app, 'aria-hidden="true"', "banner icons are exposed to screen readers");
  includes(app, 'role="alert"', "export warnings are not announced as an alert");
});

test("scenario controls declare the pane they control", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  includes(app, 'aria-controls="detail"', "scenario buttons do not reference the detail pane");
  includes(app, 'aria-label="Scenarios"', "the scenario list has no accessible name");
});

test("the limits section describes this release's real history behaviour", () => {
  // Updated 2026-09-23, when decisions started reading real payment history. The page
  // must no longer claim the old limitation, and must still name the two that remain:
  // an ungraded customer below the history threshold, and a detector that misses bursts.
  const app = render(DATA()).getElementById("app").innerHTML;
  excludes(app, "modelled history, not their live payments",
    "the limits still claim decisions read modelled history");
  includes(app, "own persisted payments", "the limits no longer say history is real");
  includes(app, "INSUFFICIENT_HISTORY, which is not LOW", "the cold-start state is not stated honestly");
  includes(app, "does not catch bursts", "the detector's burst limitation is missing");
  excludes(app, "self-signed development one", "the limits still describe the retired TLS setup");
});

// ---- 2026-09-25: the production transport profile, and scope boundaries ----

test("the limits section states what the production profile does and does not make true", () => {
  const app = render(DATA()).getElementById("app").innerHTML;
  includes(app, "No production TLS", "the limits section claims production TLS");
  includes(app, "production profile adds TLS 1.3 only", "the limits omit the tested production profile");
  includes(app, "the CA, its CRL and the pin are local", "the limits imply a public PKI");
  includes(app, "external requirement", "the PKI gap is not labelled as external");
  includes(app, "Scope boundary, by design", "physical hardware is not labelled as a frozen scope boundary");
  includes(app, "never on a physical ESP32", "the limits drop the no-hardware statement");
});

// ---- 2026-09-25: the two approved ML specification changes ----

test("an unjudged customer is shown as not judged, never as LOW", () => {
  const data = DATA();
  const row = data.sweep.rows[0];
  row.ml = { risk_band: "INSUFFICIENT_HISTORY", anomaly_score: null,
             reasons: ["not enough payment history yet to judge this transaction (3 of 200 payments known)"] };
  const doc = render(data);
  doc.querySelectorAll("#scn button")[0].click();
  const detail = doc.getElementById("detail").innerHTML;
  includes(detail, "INSUFFICIENT_HISTORY — not judged, not LOW", "the state is not explained");
  includes(detail, "not scored", "an unscored customer shows a score");
});

test("the burst signal is reported as separate evidence, never as the forest's result", () => {
  const data = DATA();
  data.measurements.ml = data.measurements.ml || {};
  data.measurements.ml.held_out = data.measurements.ml.held_out || {};
  data.measurements.ml.held_out.test = data.measurements.ml.held_out.test || {
    cases: 560, negatives: 320, roc_auc: 0.9, at_medium_and_above: {}, recall_by_family: { burst: 0 } };
  data.measurements.ml.held_out.beyond_observed_range = {
    selected_multiplier: 6, test: { burst_recall: 1, bursts: 40, fired_on_negatives: 0, negatives: 320 } };
  const app = render(data).getElementById("app").innerHTML;
  includes(app, "The Isolation Forest itself catches bursts", "the forest's own burst figure is gone");
  includes(app, "<b>separate</b> evidence signal", "the signal is not labelled as separate");
  includes(app, "40 of 40 held-out bursts", "the signal's test figure is missing");
  includes(app, "chosen on the validation split only", "the calibration split is not stated");
  includes(app, "changes no risk band and no decision", "the signal reads as a decision");
});

test("a scenario's burst evidence is shown, fired or not, and never as a decision", () => {
  const data = DATA();
  data.sweep.rows[0].ml = { risk_band: "LOW", anomaly_score: -0.3, reasons: [],
    range_signal: { name: "beyond_observed_range", fired: true, current_24h: 13, observed_max_24h: 2, multiplier: 6 } };
  data.sweep.rows[1].ml = { risk_band: "INSUFFICIENT_HISTORY", anomaly_score: null, reasons: [], range_signal: null };
  const doc = render(data);
  const buttons = doc.querySelectorAll("#scn button");
  buttons[0].click();
  const fired = doc.getElementById("detail").innerHTML;
  includes(fired, "beyond_observed_range FIRED", "a fired signal is not visible");
  includes(fired, "13 payments in 24 h; busiest earlier 24 h 2", "the signal's numbers are missing");
  includes(fired, "evidence only, no decision effect", "the signal reads as a decision");
  buttons[1].click();
  includes(doc.getElementById("detail").innerHTML, "not evaluated (the ML layer did not operate)",
    "an unevaluated signal is not labelled");
});

test("the export this repository ships renders without error", () => {
  const doc = render(SHIPPED);
  const app = doc.getElementById("app").innerHTML;
  assert(app.length > 2000, "the shipped export produced almost no page");
  includes(app, "What actually happened on this machine", "the shipped export lost its headline section");
  const rows = (SHIPPED.sweep || {}).rows || [];
  assert(doc.querySelectorAll("#scn button").length === rows.length,
    "the shipped export's rows and the page's controls disagree");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
