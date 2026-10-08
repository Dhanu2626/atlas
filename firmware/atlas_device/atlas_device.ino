/*
 * atlas_device.ino -- the ATLAS edge device, for a simulated ESP32 (Wokwi).
 *
 * ===========================================================================
 *  NOT COMPILED-AND-RUN BY THE TEST SUITE.
 *  This file compiles (verified with arduino-cli), but it has never been
 *  EXECUTED by the environment that wrote it. Its canonical-serialisation
 *  template is pinned byte-for-byte against the backend by
 *  tests/test_f3_firmware_parity.py, and its logic is mirrored by
 *  firmware/virtual_device.py, which IS executed. Treat "this firmware runs
 *  correctly" as unverified until it has actually run in Wokwi.
 * ===========================================================================
 *
 * F3: this device now speaks the SAME protocol as virtual_device.py --
 * a signed DeviceEnvelope to /v2/transact. Before F3 it sent a bare
 * Transaction to the legacy unsigned /transact endpoint.
 *
 * Implements docs/ATLAS-Blueprint.md 24.3, which already specified this:
 *   "Device identity: a key pair generated on-device ... an atlas_key_id-
 *    equivalent identifies THIS DEVICE, distinct from the subject's ATLAS
 *    policy identity"
 *   "Authentication: every request signed with the device's private key
 *    (secure_sign()); atlas_service verifies against a previously-enrolled
 *    public key"
 * No new authentication architecture is invented here.
 *
 * WHAT THIS DEVICE MUST NEVER DO (frozen; Blueprint 24.2/24.3)
 *   No ALLOW/DENY/STEP_UP decision. No ML scoring. No policy evaluation. No
 *   ATLAS assertion signing (that is a DIFFERENT key, held by atlas_service,
 *   for the bank leg). It is a witness and a display, never a judge.
 *
 * WHAT A VALID SIGNATURE FROM THIS DEVICE PROVES
 *   Possession of the enrolled private key. NOTHING MORE.
 *   It does NOT prove physical-device identity: DEVICE_KEY_SEED_HEX below is
 *   an ordinary compile-time constant living in ordinary flash, readable with
 *   esptool by anyone with physical access. Hardware-rooted identity needs an
 *   ATECC608-class secure element where the key provably never leaves the
 *   chip. That does not exist here and Wokwi cannot simulate it.
 *
 * GNSS (2026-10-09). A GNSS receiver on UART2 (GPIO16 RX / GPIO17 TX, 9600 baud) feeds
 * gnss_nmea.h, which checks every NMEA sentence and keeps the last good fix. Each
 * payment signs that reading as `location` evidence; atlas_service grades it and the
 * customer's policy decides. In Wokwi the receiver is SIMULATED
 * (chips/atlas-gnss.chip.c): no satellite is received and every coordinate is
 * scripted. The device never judges its own location -- it reports, ATLAS grades.
 *
 * WHAT WOKWI PROVES / DOES NOT PROVE
 *   Proves: firmware behaviour, protocol integration, signing/verification
 *   round-trip, replay behaviour, fail-closed behaviour.
 *   Does NOT prove: secure boot, eFuse security, flash encryption, physical
 *   tamper resistance, key-extraction resistance, hardware-rooted identity.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_random.h>
#include <sodium.h>
#include <time.h>
#include "gnss_nmea.h"

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASS = "";

// The Wokwi private gateway resolves host.wokwi.internal to 10.13.37.254 and
// NATs that to 127.0.0.1 on the machine running the simulator (wokwigw's
// config.go: DNS zone "wokwi.internal." + NAT{10.13.37.254: 127.0.0.1}). So
// this reaches an atlas_service bound to loopback with NO tunnel, NO LAN
// address and NO public exposure -- and it keeps working when the Wi-Fi
// network or the host's IP changes. Requires the gateway on :9011; see
// ../README.md. A real ESP32 on real hardware needs a real address instead.
//
// HTTPS since 2026-09-27. The device verifies atlas_service's certificate
// against ATLAS_CA_PEM -- the local test CA, from the gitignored atlas_ca.h
// (scripts/make_dev_ca.py --firmware-header) -- and checks that it names
// host.wokwi.internal. A server that fails either check gets nothing: the
// request is not sent and the device fails closed. There is no plain-HTTP
// fallback and no setInsecure(). The envelope is still Ed25519-signed end to
// end; TLS adds confidentiality in transit and proves which server answered.
#include "atlas_ca.h"
static const char *ATLAS_URL = "https://host.wokwi.internal:8000";

// --- device identity ------------------------------------------------------
// DEVICE_KEY_SEED_HEX, DEVICE_KEY_ID and DEVICE_ID come from secrets.h, which
// is GITIGNORED because it holds a real private key seed. Copy
// secrets.example.h to secrets.h and follow the commands written in it.
//
// This sketch is tracked, so a seed pasted here would be one `git commit -a`
// away from history and the only defence would be remembering to revert it.
// The include removes that hazard entirely.
//
// SECURITY REALITY is unchanged: the seed is still plaintext in flash and
// readable with esptool. A valid signature proves possession of THIS KEY, not
// the identity of THIS DEVICE. Documented, not worked around.
#include "secrets.h"
static const char *SUBJECT               = "user-demo-1";
static const char *CURRENCY              = "INR";
static const char *LOCATION              = "Bengaluru,IN";
static const char *AUTHENTICATION_METHOD = "device_button";
static const char *RAIL                  = "UPI";

// Pins
static const int PIN_LED_GREEN  = 25;
static const int PIN_LED_AMBER  = 26;
static const int PIN_LED_RED    = 27;
static const int PIN_BTN_SELECT = 14;
static const int PIN_BTN_SEND   = 12;

// GNSS receiver on UART2. Named apart from the PIN_ constants above, which are the
// LEDs and buttons; tests/test_firmware_behaviour.py checks both sets against the circuit.
static const int GNSS_UART_RX_PIN = 16;   // ESP32 receives here <- receiver TX
static const int GNSS_UART_TX_PIN = 17;   // ESP32 sends here    -> receiver RX (unused)
static const unsigned long GNSS_BAUD = 9600;

struct Preset { const char *beneficiary; long amountMinor; };

// Integer minor units only -- no float goes near money on an MCU. These three
// exercise ALLOW / STEP_UP / DENY against the shipped user-demo-1 policy.
static const Preset PRESETS[] = {
  { "ben-mother",  150000L   },  // 1500.00   -> ALLOW
  { "ben-newshop", 6000000L  },  // 60000.00  -> STEP_UP (large_amount)
  { "ben-newshop", 15000000L },  // 150000.00 -> DENY (hard_cap)
};
static const int PRESET_COUNT = sizeof(PRESETS) / sizeof(PRESETS[0]);

enum DeviceState {
  STATE_IDLE, STATE_APPROVED, STATE_REFUSED,
  STATE_ATTENTION, STATE_UNRESOLVED, STATE_FAIL_CLOSED
};

static Preferences g_prefs;
static int  g_selectedPreset = 0;
static char g_bootId[9] = "00000000";
static unsigned char g_sk[crypto_sign_SECRETKEYBYTES];

// GNSS reader state (gnss_nmea.h) and the sentence being assembled from UART bytes.
static GnssState g_gnss;
static char   g_nmeaLine[GNSS_MAX_SENTENCE + 2];
static size_t g_nmeaLen = 0;
static bool   g_nmeaTooLong = false;
static bool   g_gnssFixShown = false;
static unsigned long g_gnssRejectsShown = 0, g_gnssLastNote = 0;

// --------------------------------------------------------------------------
// LAYER 1: EVENT ACQUISITION -- knows nothing about ATLAS
// --------------------------------------------------------------------------

// `epoch` is carried alongside `pressedAt` for DISPLAY ONLY (local-time
// rendering in the decision trace). `pressedAt` remains the single value that
// goes into the signed canonical bytes -- nothing here changes what is signed.
struct RawEvent { int presetId; long counter; char pressedAt[32]; time_t epoch; };

// What the decision trace needs from the device side; backend-side values are
// read straight out of the parsed response. Declared up here, next to the other
// structs, because the Arduino build auto-generates function prototypes and
// inserts them BEFORE the first function definition -- a struct declared lower
// down would not be visible to those generated prototypes.
struct TxDisplay {
  int         presetId;
  const char *amount;        // exactly as sent, e.g. "60000.00"
  const char *beneficiary;
  const char *location;      // the transaction's place label (not GNSS)
  time_t      epoch;
  const char *txnId;
  const char *gnss;          // this device's own GNSS reading, described
};

// 2026-01-01T00:00:00Z. An ESP32 boots with its clock at epoch 0 (1970), so any
// value below this means NTP has not set the clock yet. This is a sanity floor,
// NOT a trust anchor -- see nowIso8601() on why device time is never trusted.
static const time_t MIN_VALID_EPOCH = 1767225600;

static bool clockIsSet() { return time(nullptr) >= MIN_VALID_EPOCH; }

// Bounded wait for SNTP. Returns false on timeout rather than blocking forever:
// unlike a missing signing key, a missing clock can recover later, so this
// degrades to "refuse to transact" instead of "halt permanently".
static bool waitForClock(unsigned long timeoutMs) {
  unsigned long start = millis();
  while (!clockIsSet()) {
    if (millis() - start > timeoutMs) return false;
    delay(250);
  }
  return true;
}

static void nowIso8601(char *out, size_t len) {
  // A device clock is not automatically trustworthy. This timestamp feeds
  // ATLAS's TIME_WINDOW policy rules, so a wrong clock changes which rules
  // fire. NTP here is a demo convenience, not a trusted time source.
  time_t nowSecs = time(nullptr);
  struct tm timeinfo;
  gmtime_r(&nowSecs, &timeinfo);
  strftime(out, len, "%Y-%m-%dT%H:%M:%S+00:00", &timeinfo);
}

static bool pressed(int pin) {
  if (digitalRead(pin) == LOW) {
    delay(50);
    if (digitalRead(pin) == LOW) {
      while (digitalRead(pin) == LOW) { delay(10); }
      return true;
    }
  }
  return false;
}

// Monotonic counter, PERSISTED IN NVS before use. Persisting first is
// deliberate: if the device dies between issuing and recording, the counter
// has already moved, so a value is never reused. Losing a value is harmless;
// reusing one is a replay window.
static long nextCounter() {
  long next = g_prefs.getLong("counter", 0) + 1;
  g_prefs.putLong("counter", next);
  return next;
}

static RawEvent readEvent(int presetId) {
  RawEvent e;
  e.presetId = presetId;
  e.counter  = nextCounter();
  nowIso8601(e.pressedAt, sizeof(e.pressedAt));
  e.epoch    = time(nullptr);   // display only; pressedAt is what gets signed
  return e;
}

// --------------------------------------------------------------------------
// LAYER 1b: GNSS -- reads the receiver, judges nothing
//
// Bytes from UART2 are assembled into sentences and handed to gnss_nmea.h, which
// refuses anything malformed or with a wrong checksum and keeps the last good fix,
// stamped with this device's clock. A line too long for NMEA (or cut short when the
// UART buffer overflowed during a slow HTTPS call) is refused the same way.
// --------------------------------------------------------------------------

static void gnssNote() {
  // State changes only, and at most every five seconds for refusals, so the serial
  // trace stays readable.
  if (g_gnss.have_fix && g_gnss.fix_now && !g_gnssFixShown) {
    Serial.printf("[GNSS] fix: %d satellites (receiver over UART2; SIMULATED in Wokwi)\r\n", g_gnss.fix_sats);
    g_gnssFixShown = true;
  } else if (g_gnssFixShown && !g_gnss.fix_now) {
    Serial.println("[GNSS] receiver reports no fix -- the last fix is kept and keeps ageing");
    g_gnssFixShown = false;
  }
  unsigned long refused = g_gnss.rejected_checksum + g_gnss.rejected_malformed;
  if (refused != g_gnssRejectsShown && millis() - g_gnssLastNote > 5000) {
    Serial.printf("[GNSS] refused %lu sentence(s) so far (%lu bad checksum, %lu malformed)\r\n",
                  refused, g_gnss.rejected_checksum, g_gnss.rejected_malformed);
    g_gnssRejectsShown = refused;
    g_gnssLastNote = millis();
  }
}

static void pollGnss() {
  while (Serial2.available() > 0) {
    char c = (char)Serial2.read();
    if (c == '\n') {
      if (!g_nmeaTooLong) {
        g_nmeaLine[g_nmeaLen] = '\0';
        gnss_feed_line(&g_gnss, g_nmeaLine, (long long)time(nullptr));
      } else {
        g_gnss.rejected_malformed++;
      }
      g_nmeaLen = 0;
      g_nmeaTooLong = false;
    } else if (g_nmeaLen < sizeof(g_nmeaLine) - 1) {
      g_nmeaLine[g_nmeaLen++] = c;
    } else {
      g_nmeaTooLong = true;
    }
  }
  gnssNote();
}

// What the payment's trace shows about the device's OWN reading (ATLAS's grade is
// shown separately, from the response).
static void describeGnss(char *out, size_t len) {
  if (!g_gnss.any_valid) { snprintf(out, len, "no receiver data"); return; }
  if (!g_gnss.have_fix) { snprintf(out, len, "no fix (%d satellites)", g_gnss.sats_now); return; }
  long age = (long)((long long)time(nullptr) - g_gnss.fix_epoch);
  char acc[24];
  if (g_gnss.fix_acc_dm < 0) snprintf(acc, sizeof(acc), "accuracy not given");
  else snprintf(acc, sizeof(acc), "+/-%ld.%ld m", g_gnss.fix_acc_dm / 10, g_gnss.fix_acc_dm % 10);
  snprintf(out, len, "fix, %d satellites, %s, %lds old", g_gnss.fix_sats, acc, age < 0 ? 0L : age);
}

// --------------------------------------------------------------------------
// LAYER 2: CANONICAL SERIALISATION
//
// Built BY HAND, not with ArduinoJson, because the backend derives the signed
// bytes with json.dumps(sort_keys=True, separators=(",",":")) and ArduinoJson
// does not guarantee key order. Every key below is in the exact sorted order
// Python produces, every default is spelled out, and there is no whitespace.
//
// The template is bracketed by the sentinels below so
// tests/test_f3_firmware_parity.py can extract it from this source file and
// prove, in Python, that filling it produces byte-identical output to
// contracts.canonical_envelope_bytes(). If either side ever drifts, that test
// fails.
//
// `location` (2026-10-09) is the GNSS reader's evidence, inserted whole by %s:
// gnss_evidence_json() writes it already canonical -- sorted keys, no spaces,
// coordinates as quoted strings (F1) -- or the bare word null when the receiver
// has said nothing yet. `health` stays null (Phase 3.5 is not built).
// --------------------------------------------------------------------------

// CANONICAL_FORMAT_BEGIN
static const char CANONICAL_FMT[] =
  "{\"boot_id\":\"%s\","
  "\"counter\":%ld,"
  "\"device_id\":\"%s\","
  "\"device_key_id\":\"%s\","
  "\"health\":null,"
  "\"issued_at\":\"%s\","
  "\"location\":%s,"
  "\"nonce\":\"%s\","
  "\"transaction\":{"
  "\"amount\":\"%s\","
  "\"authentication_method\":\"%s\","
  "\"beneficiary\":\"%s\","
  "\"currency\":\"%s\","
  "\"declared_travel_mode\":false,"
  "\"device_id\":\"%s\","
  "\"is_emergency_request\":false,"
  "\"is_international\":false,"
  "\"is_new_beneficiary\":false,"
  "\"is_new_device\":false,"
  "\"location\":\"%s\","
  "\"merchant_category\":null,"
  "\"subject\":\"%s\","
  "\"timestamp\":\"%s\","
  "\"transaction_id\":\"%s\"}}";
// CANONICAL_FORMAT_END

static void formatMinorUnits(long minor, char *out, size_t len) {
  snprintf(out, len, "%ld.%02ld", minor / 100, labs(minor % 100));
}

static void randomHex(char *out, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++) sprintf(out + i * 2, "%02x", (unsigned)(esp_random() & 0xFF));
  out[nbytes * 2] = '\0';
}

// Returns false (fail closed) for an unconfigured preset -- a stray press
// must never become some default payment.
static bool buildCanonical(const RawEvent &e, const char *locationJson, char *out, size_t len,
                           char *transactionIdOut, size_t tidLen) {
  if (e.presetId < 0 || e.presetId >= PRESET_COUNT) return false;
  const Preset &p = PRESETS[e.presetId];

  char amount[32];
  formatMinorUnits(p.amountMinor, amount, sizeof(amount));
  snprintf(transactionIdOut, tidLen, "%s-%s-%04ld", DEVICE_ID, g_bootId, e.counter);

  char nonce[33];
  randomHex(nonce, 16);

  int written = snprintf(out, len, CANONICAL_FMT,
    g_bootId, e.counter, DEVICE_ID, DEVICE_KEY_ID, e.pressedAt, locationJson, nonce,
    amount, AUTHENTICATION_METHOD, p.beneficiary, CURRENCY, DEVICE_ID,
    LOCATION, SUBJECT, e.pressedAt, transactionIdOut);
  return written > 0 && (size_t)written < len;
}

// --------------------------------------------------------------------------
// LAYER 2b: SIGNING -- Ed25519 over the canonical bytes, via libsodium
// (bundled in ESP32 core 3.3.11; byte-compatible with Python's
// cryptography.Ed25519, which the backend verifies with).
// --------------------------------------------------------------------------

static bool hexToBytes(const char *hex, unsigned char *out, size_t nbytes) {
  if (strlen(hex) != nbytes * 2) return false;
  for (size_t i = 0; i < nbytes; i++) {
    unsigned v;
    if (sscanf(hex + i * 2, "%2x", &v) != 1) return false;
    out[i] = (unsigned char)v;
  }
  return true;
}

static bool initIdentity() {
  unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
  if (!hexToBytes(DEVICE_KEY_SEED_HEX, seed, 32)) return false;
  // Derives the same keypair Python gets from the same 32-byte seed.
  return crypto_sign_seed_keypair(pk, g_sk, seed) == 0;
}

static void signCanonical(const char *canonical, char *sigHexOut) {
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, NULL, (const unsigned char *)canonical,
                       strlen(canonical), g_sk);
  for (size_t i = 0; i < crypto_sign_BYTES; i++) sprintf(sigHexOut + i * 2, "%02x", sig[i]);
  sigHexOut[crypto_sign_BYTES * 2] = '\0';
}

// The request body is the canonical bytes with the signature appended. JSON
// object member order is irrelevant to a parser, so this stays valid while
// leaving the SIGNED bytes untouched -- the backend re-derives them by
// dropping `signature` and re-sorting.
static void buildRequestBody(const char *canonical, const char *sigHex, String &out) {
  size_t n = strlen(canonical);
  out = "";
  out.reserve(n + 160);
  out.concat(canonical, n - 1);            // strip the final '}'
  out += ",\"signature\":\"";
  out += sigHex;
  out += "\"}";
}

// --------------------------------------------------------------------------
// LAYER 3: NETWORK + RESPONSE HANDLING -- the fail-closed core
// --------------------------------------------------------------------------

// Whitelist, deliberately not a blacklist. Anything unrecognised -- a status
// ATLAS adds later, a typo, a truncated body, an injected value -- becomes
// STATE_FAIL_CLOSED rather than being optimistically read.
static DeviceState interpretStatus(const char *finalStatus) {
  if (finalStatus == nullptr)                    return STATE_FAIL_CLOSED;
  if (strcmp(finalStatus, "ALLOW")       == 0)   return STATE_APPROVED;
  if (strcmp(finalStatus, "DENY")        == 0)   return STATE_REFUSED;
  if (strcmp(finalStatus, "STEP_UP")     == 0)   return STATE_ATTENTION;
  if (strcmp(finalStatus, "DELAY")       == 0)   return STATE_ATTENTION;
  if (strcmp(finalStatus, "PENDING")     == 0)   return STATE_UNRESOLVED;
  if (strcmp(finalStatus, "FAIL_CLOSED") == 0)   return STATE_FAIL_CLOSED;
  return STATE_FAIL_CLOSED;
}

// REFUSED and FAIL_CLOSED both light red, but stay distinct in the model and
// in the log: "something deliberately said no" and "no trustworthy answer
// existed" are different facts.
static const char *stateLabel(DeviceState s) {
  switch (s) {
    case STATE_APPROVED:    return "APPROVED";
    case STATE_REFUSED:     return "REFUSED";
    case STATE_ATTENTION:   return "ATTENTION";
    case STATE_UNRESOLVED:  return "UNRESOLVED";
    case STATE_FAIL_CLOSED: return "FAIL_CLOSED";
    default:                return "IDLE";
  }
}

// ==========================================================================
// PRESENTATION LAYER  (display only -- decides nothing)
//
// Everything below FORMATS values that atlas_service already returned. It
// evaluates no rule, applies no threshold, and changes no behaviour. The rule
// names it recognises are display labels for strings that arrive inside the
// response's decision.matched_rules[]; the device still holds no copy of the
// policy and still cannot decide anything for itself (Blueprint 24.2).
//
// A check shown as PASS means "this rule name was NOT in matched_rules".
// The device cannot distinguish "the rule ran and passed" from "the policy
// does not contain that rule" -- only the backend knows the ruleset.
// ==========================================================================

// 1 = also dump the raw signed envelope and internal ids. Off for demos.
#define ATLAS_TRACE_VERBOSE 0

// UTF-8 box drawing. The VS Code serial panel renders these correctly (the
// earlier alignment problem was bare LF, not the character set). If a terminal
// ever shows mojibake, swap these two lines back to '=' and '-'.
static void heavyRule() { Serial.println("══════════════════════════════════════════════════"); }
static void lightRule() { Serial.println("──────────────────────────────────────────────────"); }

static void row(const char *label, const char *value) {
  Serial.printf("%-20s: %s\r\n", label, value);
}

// "150000.00" -> "1,50,000.00"  (Indian grouping: last 3, then pairs)
static void groupIndian(const char *amount, char *out, size_t len) {
  const char *dot = strchr(amount, '.');
  int intLen = dot ? (int)(dot - amount) : (int)strlen(amount);
  if (intLen <= 0 || intLen > 20) { snprintf(out, len, "%s", amount); return; }

  char rev[48]; int r = 0;
  for (int i = intLen - 1, c = 0; i >= 0 && r < (int)sizeof(rev) - 2; i--) {
    rev[r++] = amount[i];
    c++;
    if (i > 0 && (c == 3 || (c > 3 && (c - 3) % 2 == 0))) rev[r++] = ',';
  }
  char grouped[48]; int g = 0;
  for (int i = r - 1; i >= 0; i--) grouped[g++] = rev[i];
  grouped[g] = '\0';
  snprintf(out, len, "%s%s", grouped, dot ? dot : "");
}

static void groupIndian_fromMinor(long minor, char *out, size_t len) {
  char raw[32];
  formatMinorUnits(minor, raw, sizeof(raw));
  groupIndian(raw, out, len);
}

// Renders the SAME instant the device signed, shifted to IST for reading.
// Display only: pressedAt (UTC) is what was signed and sent. IST is shown
// because the policy's TIME_WINDOW rules are evaluated in Asia/Kolkata.
static void istStamp(time_t utc, char *out, size_t len) {
  time_t ist = utc + 19800;   // +05:30
  struct tm t;
  gmtime_r(&ist, &t);
  strftime(out, len, "%d %b %Y, %H:%M IST", &t);
}

static bool ruleMatched(JsonArrayConst rules, const char *name) {
  if (rules.isNull()) return false;
  for (JsonVariantConst v : rules) {
    const char *s = v.as<const char *>();
    if (s && strcmp(s, name) == 0) return true;
  }
  return false;
}

static void checkRow(const char *label, JsonArrayConst rules, const char *rule) {
  row(label, ruleMatched(rules, rule) ? "TRIGGERED" : "PASS");
}

static void printContext(const TxDisplay &d, JsonArrayConst reasons) {
  char amt[48], when[48];
  groupIndian(d.amount, amt, sizeof(amt));
  istStamp(d.epoch, when, sizeof(when));

  bool newBen = false, newDev = false;
  if (!reasons.isNull()) {
    for (JsonVariantConst v : reasons) {
      const char *s = v.as<const char *>();
      if (!s) continue;
      if (strstr(s, "new beneficiary")) newBen = true;
      if (strstr(s, "new device"))      newDev = true;
    }
  }

  Serial.println();
  Serial.println("1. TRANSACTION CONTEXT");
  lightRule();
  char buf[24];
  snprintf(buf, sizeof(buf), "%d", d.presetId);
  row("Preset", buf);
  char rs[64];
  snprintf(rs, sizeof(rs), "₹%s", amt);   // UTF-8 rupee sign
  row("Amount", rs);
  row("Place Label", d.location);
  row("Transaction Time", when);
  Serial.println();
  row("Beneficiary", d.beneficiary);
  // Sourced from the backend's ML evidence, NOT from the device's own claim:
  // the device always sends is_new_beneficiary=false and the policy engine
  // recomputes it from history, ignoring what the device asserted.
  row("Beneficiary Status", newBen ? "New (first seen)" : "Existing");
  row("Device Status",      newDev ? "New (first seen)" : "Recognised");
  row("Transaction Type",   "Domestic");
  // NOTE: authentication_method ("device_button") is sent in the envelope but
  // no rule in user-demo-1.yaml consumes it, so it is deliberately NOT shown
  // here -- displaying it would imply an influence it does not have.
}

static void printDecisionTrace(const TxDisplay &d, JsonDocument &doc,
                               const char *finalStatus, const char *reason,
                               DeviceState st) {
  JsonObjectConst risk  = doc["risk"].as<JsonObjectConst>();
  JsonObjectConst dec   = doc["decision"].as<JsonObjectConst>();
  JsonArrayConst  rules = dec["matched_rules"].as<JsonArrayConst>();
  JsonArrayConst  reasons = risk["reasons"].as<JsonArrayConst>();

  Serial.println();
  heavyRule();
  Serial.println("                 ATLAS DECISION TRACE");
  heavyRule();
  // Architectural honesty: this device did not decide anything. It assembled
  // and signed the transaction, sent it to atlas_service, and is rendering the
  // verdict it received. Every value below section 1 came back over the wire.
  Serial.println("  Decision made by: atlas_service (backend policy engine)");
  Serial.println("  Role of ESP32   : sign, submit, and display the result");

  printContext(d, reasons);

  Serial.println();
  Serial.println("2. RISK CHECK RESULTS");
  lightRule();
  // Displayed verbatim from the backend response. atlas_service computed this
  // band and already sends it in /v2/transact's "risk" object; the device
  // renders the string and does nothing else with it. It is never compared,
  // never branched on, and never influences the LED -- interpretStatus() maps
  // ONLY final_status. The parity suite pins this boundary directly (see
  // tests/test_f3_firmware_parity.py) rather than banning the word outright.
  JsonVariantConst bandVar = risk["risk_band"];
  const char *band = bandVar.is<const char *>() ? bandVar.as<const char *>() : "NOT REPORTED";
  row("ML Risk Level", band);
  checkRow("Amount Threshold",   rules, "large_amount");
  checkRow("Hard Cap Check",     rules, "hard_cap");
  checkRow("Beneficiary Check",  rules, "new_beneficiary_meaningful_amount");
  checkRow("Velocity Check",     rules, "velocity_burst");
  checkRow("ML Risk Check",      rules, "high_ml_risk");
  checkRow("International Chk",  rules, "international_txn");
  checkRow("Time Window Check",  rules, "odd_hours");

  Serial.println();
  Serial.println("3. LOCATION AND TIME CONTEXT");
  lightRule();
  char when2[48];
  istStamp(d.epoch, when2, sizeof(when2));
  // The device's own GNSS reading, then ATLAS's grade of it -- read from the
  // response and displayed, never compared or acted on here. Whether location
  // changed the decision is read from matched_rules, like every other check.
  JsonObjectConst where = doc["location"].as<JsonObjectConst>();
  row("Location Source", "GNSS receiver on UART2 (SIMULATED in Wokwi)");
  row("Device Reading", d.gnss);
  if (where.isNull()) {
    row("ATLAS Grade", "NOT REPORTED");
  } else {
    char graded[96], dist[48];
    snprintf(graded, sizeof(graded), "%s confidence", where["confidence"] | "?");
    row("ATLAS Grade", graded);
    row("Home Area", where["geofence"] | "?");
    JsonVariantConst km = where["distance_from_home_km"];
    if (km.is<float>()) {
      snprintf(dist, sizeof(dist), "%.1f km from its centre", km.as<float>());
      row("Distance", dist);
    }
    row("Impossible Travel", where["implausible_travel"] | false ? "YES (evidence only)" : "NO");
    JsonArrayConst why = where["reasons"].as<JsonArrayConst>();
    for (JsonVariantConst v : why) {
      const char *s = v.as<const char *>();
      if (s) Serial.printf("  - %s\r\n", s);
    }
  }
  bool awayHit = ruleMatched(rules, "outside_home_area");
  row("Home Area Check", awayHit ? "TRIGGERED" : "PASS");
  row("Location Influence", awayHit ? "Raised this transaction to STEP_UP"
                                    : "NONE (location can only add friction)");
  Serial.println();
  // Time IS genuinely evaluated -- odd_hours (TIME_WINDOW 22:00-06:00,
  // evaluated in Asia/Kolkata per the policy's `timezone` field).
  bool timeHit = ruleMatched(rules, "odd_hours");
  row("Transaction Time", when2);
  row("Time Check", timeHit ? "TRIGGERED" : "PASS");
  if (timeHit) {
    row("Time Influence", "ELEVATED RISK");
    row("Rule Involved", "odd_hours (TIME_WINDOW 22:00-06:00 IST)");
    row("Effect", "Raised this transaction to STEP_UP");
  } else {
    row("Time Influence", "NONE");
    row("Rule Involved", "odd_hours (TIME_WINDOW 22:00-06:00 IST)");
    row("Effect", "Outside the window, so no risk added");
  }

  Serial.println();
  Serial.println("4. DECISION ANALYSIS");
  lightRule();
  // The backend also returns an ML band and score. They are deliberately NOT
  // shown here: tests/test_f3_firmware_parity.py's
  // test_firmware_never_contains_decision_logic bans those field names from
  // this file outright (Blueprint 24.2 -- no decision authority below the
  // policy layer). Weakening that guard to prettify a demo is not a trade
  // worth making silently, so the trace reports the backend's own
  // plain-language observations instead, which carry the same evidence.
  if (!reasons.isNull() && reasons.size() > 0) {
    row("ML Assessment", "See observations below");
    Serial.println();
    Serial.println("ML Observations (from backend):");
    for (JsonVariantConst v : reasons) {
      const char *s = v.as<const char *>();
      if (s) Serial.printf("  - %s\r\n", s);
    }
  }

  Serial.println();
  size_t n = rules.isNull() ? 0 : rules.size();
  if (n == 0) {
    row("Triggered Condition", "NONE");
  } else {
    Serial.println("Triggered Conditions:");
    for (JsonVariantConst v : rules) {
      const char *s = v.as<const char *>();
      if (s) Serial.printf("  - %s\r\n", s);
    }
    Serial.println();
    // The backend now names the rule that supplied the winning action, in
    // decision.deciding_rule. Read, not derived: the device still holds no
    // copy of the policy and still cannot tell which rule outranks which.
    // If an older atlas_service omits the field, the honest fallback below
    // is used rather than guessing from the rule names.
    JsonVariantConst decidingVar = dec["deciding_rule"];
    const char *deciding = decidingVar.is<const char *>()
                             ? decidingVar.as<const char *>() : nullptr;
    if (deciding != nullptr) {
      row("Priority Rule", deciding);
      if (n > 1) {
        row("Conflict Resolution", "MOST RESTRICTIVE WINS");
        row("Priority Order", "DENY > DELAY > STEP_UP > ALLOW");
      }
    } else if (n == 1) {
      // Exactly one rule matched, so it is unambiguously the one that decided.
      // No policy knowledge is needed to say that.
      const char *only = rules[0].as<const char *>();
      row("Priority Rule", only ? only : "UNKNOWN");
    } else {
      // Older backend, several rules matched, no deciding_rule reported. The
      // response carries only rule NAMES, not each rule's action, so naming a
      // winner here would be a guess. Reported honestly instead of invented.
      row("Priority Rule", "NOT REPORTED BY BACKEND");
      row("Conflict Resolution", "MOST RESTRICTIVE WINS");
      row("Priority Order", "DENY > DELAY > STEP_UP > ALLOW");
    }
  }

  Serial.println();
  Serial.println("5. FINAL RESULT");
  lightRule();
  row("ATLAS Decision", finalStatus);
  row("LED Status", st == STATE_APPROVED  ? "GREEN"
                  : st == STATE_ATTENTION ? "YELLOW"
                  : st == STATE_UNRESOLVED? "YELLOW" : "RED");
  row("Decision Reason", reason);

  // Step-up: a STEP_UP that carries a challenge is PAUSED, not refused. The
  // device says so and stops. It does not collect the second factor, does not
  // poll, and never sees a PIN, OTP or biometric -- the customer confirms out
  // of band and atlas_service resolves it. Read from the response; nothing
  // here is derived.
  JsonVariantConst chalVar = doc["challenge_id"];
  if (chalVar.is<const char *>()) {
    row("Step-Up", "AWAITING CUSTOMER CONFIRMATION");
    row("Challenge Ref", chalVar.as<const char *>());
    JsonVariantConst expVar = doc["step_up_expires_at"];
    if (expVar.is<const char *>()) {
      row("Challenge Expires", expVar.as<const char *>());
    }
    Serial.println("  Confirmation happens on the customer's own authenticator.");
    Serial.println("  This device cannot collect it and holds no credential.");
  }
  Serial.println();
  Serial.println("Explanation:");
  if      (!strcmp(reason, "POLICY_ALLOW"))   Serial.println("  No policy rule was triggered. The transaction stayed\r\n  within every configured threshold, so ATLAS approved it.");
  else if (!strcmp(reason, "POLICY_STEP_UP")) Serial.println("  At least one rule raised the risk level, but none reached\r\n  a denial condition. ATLAS requires additional verification\r\n  before this transaction may proceed.");
  else if (!strcmp(reason, "POLICY_DENY"))    Serial.println("  A denial rule was triggered. Under most-restrictive-wins\r\n  it overrides every lesser outcome, so ATLAS refused the\r\n  transaction outright.");
  else if (!strcmp(reason, "POLICY_DELAY"))   Serial.println("  ATLAS deferred the transaction rather than deciding now.");
  else if (!strcmp(reason, "BANK_REJECTED"))  Serial.println("  ATLAS permitted the transaction but the bank refused it.\r\n  The refusal came from the bank, not from ATLAS policy.");
  else                                        Serial.printf("  %s\r\n", reason);
  heavyRule();
  Serial.println();
}

// ATLAS was reachable and DELIBERATELY refused before policy ran: bad
// signature, replayed counter/nonce, stale clock, revoked device. This is the
// security layer working, NOT infrastructure failure and NOT a policy DENY.
static void printSecurityRejection(const TxDisplay &d, const char *reason) {
  char amt[48], when[48];
  groupIndian(d.amount, amt, sizeof(amt));
  istStamp(d.epoch, when, sizeof(when));

  Serial.println();
  heavyRule();
  Serial.println("ATLAS SECURITY REJECTION");
  heavyRule();
  Serial.println();
  Serial.println("TRANSACTION CONTEXT");
  lightRule();
  char buf[24]; snprintf(buf, sizeof(buf), "%d", d.presetId);
  row("Preset", buf);
  char rs[64]; snprintf(rs, sizeof(rs), "INR %s", amt);
  row("Amount", rs);
  row("Transaction Time", when);

  Serial.println();
  Serial.println("SECURITY VERIFICATION");
  lightRule();
  row("ATLAS Service", "REACHABLE");
  row("Evaluation Stage", "REJECTED BEFORE POLICY");
  row("Security Reason", reason);

  Serial.println();
  Serial.println("FINAL RESULT");
  lightRule();
  row("Transaction Status", "REJECTED");
  row("LED Status", "RED");
  Serial.println();
  Serial.println("Explanation:");
  Serial.println("  ATLAS received this request and refused it at the device");
  Serial.println("  authentication layer, before any policy rule was applied.");
  Serial.println("  This is NOT a policy DENY and NOT a service outage: the");
  Serial.println("  request failed verification and was correctly rejected.");
  heavyRule();
  Serial.println();
}

// ATLAS could not be reached or gave no usable answer. Nothing was evaluated.
static void printInfraFailure(const TxDisplay &d, const char *reason) {
  char amt[48];
  groupIndian(d.amount, amt, sizeof(amt));

  Serial.println();
  heavyRule();
  Serial.println("ATLAS SYSTEM STATUS");
  heavyRule();
  Serial.println();
  Serial.println("TRANSACTION CONTEXT");
  lightRule();
  char buf[24]; snprintf(buf, sizeof(buf), "%d", d.presetId);
  row("Preset", buf);
  char rs[64]; snprintf(rs, sizeof(rs), "INR %s", amt);
  row("Amount", rs);

  Serial.println();
  Serial.println("SYSTEM CONNECTION");
  lightRule();
  row("ATLAS Service", "UNAVAILABLE");
  row("Security Mode", "FAIL-CLOSED");
  row("System Reason", reason);

  Serial.println();
  Serial.println("FINAL SYSTEM STATUS");
  lightRule();
  row("Transaction Status", "BLOCKED");
  row("LED Status", "RED");
  Serial.println();
  Serial.println("System Reason:");
  Serial.println("  ATLAS could not complete transaction evaluation.");
  Serial.println("  The transaction was blocked because the system is");
  Serial.println("  configured to fail safely rather than approve an");
  Serial.println("  unverified transaction. No decision was made.");
  heavyRule();
  Serial.println();
}

// The DEVICE refused before anything was sent. Not an ATLAS decision and not
// an ATLAS outage -- the request never left the device.
static void printDeviceRefusal(const char *reason, const char *detail) {
  Serial.println();
  heavyRule();
  Serial.println("ATLAS DEVICE STATUS");
  heavyRule();
  Serial.println();
  row("Transaction Status", "NOT SUBMITTED");
  row("LED Status", "RED");
  row("Device Reason", reason);
  Serial.println();
  Serial.println("Explanation:");
  Serial.printf("  %s\r\n", detail);
  Serial.println("  Nothing was sent to ATLAS, so no decision was made.");
  heavyRule();
  Serial.println();
}

// Reasons that mean "ATLAS refused at the security layer" rather than
// "ATLAS was unreachable". Sourced from contracts.DecisionReason.
static bool isSecurityRejection(const char *r) {
  static const char *kSec[] = {
    "INVALID_DEVICE_SIGNATURE", "MISSING_DEVICE_SIGNATURE", "DEVICE_ID_MISMATCH",
    "DEVICE_SUBJECT_MISMATCH", "DEVICE_UNKNOWN", "DEVICE_REVOKED",
    "DEVICE_SUSPENDED", "STALE_REQUEST", "FUTURE_TIMESTAMP",
    "COUNTER_REGRESSION", "REPLAYED_NONCE", "DEVICE_AUTH_REQUIRED",
    "MALFORMED_ENVELOPE", "DUPLICATE_TRANSACTION_ID",
  };
  for (size_t i = 0; i < sizeof(kSec) / sizeof(kSec[0]); i++)
    if (!strcmp(r, kSec[i])) return true;
  return false;
}

static DeviceState submitEnvelope(const String &body, const TxDisplay &disp) {
  const char *txnId = disp.txnId;
  if (WiFi.status() != WL_CONNECTED) {
    printInfraFailure(disp, "ATLAS_UNREACHABLE");
    return STATE_FAIL_CLOSED;
  }

  // Declared before `http` so it outlives it: HTTPClient borrows this client.
  WiFiClientSecure tls;
  tls.setCACert(ATLAS_CA_PEM);        // verify the chain AND the host name
  tls.setHandshakeTimeout(30);        // seconds; the simulator is slow at ECDSA
  HTTPClient http;
  String url = String(ATLAS_URL) + "/v2/transact?rail=" + RAIL;
  if (!http.begin(tls, url)) {
    printInfraFailure(disp, "ATLAS_UNREACHABLE");
    return STATE_FAIL_CLOSED;
  }
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(8000);

  // No retry. A device silently retrying a payment is exactly the "never
  // blindly retry" mistake the frozen failure-mode table warns against.
  int code = http.POST(body);
  String payload = http.getString();
  http.end();

  if (code != 200) {
    JsonDocument err;
    if (!deserializeJson(err, payload) && err["decision_reason"].is<const char *>()) {
      const char *r = err["decision_reason"];
      // ATLAS answered and refused, vs. ATLAS gave no usable answer.
      if (isSecurityRejection(r)) printSecurityRejection(disp, r);
      else                        printInfraFailure(disp, r);
    } else {
      printInfraFailure(disp, "ATLAS_UNREACHABLE");
    }
    return STATE_FAIL_CLOSED;
  }

  JsonDocument doc;
  if (deserializeJson(doc, payload) || !doc["final_status"].is<const char *>()) {
    printInfraFailure(disp, "MALFORMED_RESPONSE");
    return STATE_FAIL_CLOSED;
  }

  const char *finalStatus = doc["final_status"];
  const char *reason = doc["decision_reason"].is<const char *>()
                         ? (const char *)doc["decision_reason"] : "UNSPECIFIED";
  DeviceState st = interpretStatus(finalStatus);

  // A 200 can still carry FAIL_CLOSED: ATLAS evaluated nothing because the
  // envelope failed verification. Route it by reason, never by status alone,
  // so a security refusal is never dressed up as a policy DENY.
  if (st == STATE_FAIL_CLOSED) {
    if (isSecurityRejection(reason)) printSecurityRejection(disp, reason);
    else                             printInfraFailure(disp, reason);
  } else {
    printDecisionTrace(disp, doc, finalStatus, reason, st);
  }

#if ATLAS_TRACE_VERBOSE
  Serial.printf("[DEBUG] txn=%s http=%d state=%s\r\n", txnId, code, stateLabel(st));
#else
  (void)txnId; (void)code;
#endif
  return st;
}

// --------------------------------------------------------------------------
// Indicators
// --------------------------------------------------------------------------

static void showState(DeviceState state) {
  digitalWrite(PIN_LED_GREEN, LOW);
  digitalWrite(PIN_LED_AMBER, LOW);
  digitalWrite(PIN_LED_RED,   LOW);
  switch (state) {
    case STATE_APPROVED:                                 // the ONLY green path
      digitalWrite(PIN_LED_GREEN, HIGH); break;
    case STATE_ATTENTION:
    case STATE_UNRESOLVED:
      digitalWrite(PIN_LED_AMBER, HIGH); break;
    case STATE_REFUSED:
    case STATE_FAIL_CLOSED:
      digitalWrite(PIN_LED_RED, HIGH);   break;
    default: break;
  }
}

static void blinkSelection(int presetId) {
  for (int i = 0; i <= presetId; i++) {
    digitalWrite(PIN_LED_AMBER, HIGH); delay(120);
    digitalWrite(PIN_LED_AMBER, LOW);  delay(120);
  }
}

// --------------------------------------------------------------------------
// Arduino entry points
// --------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_AMBER, OUTPUT);
  pinMode(PIN_LED_RED,   OUTPUT);
  pinMode(PIN_BTN_SELECT, INPUT_PULLUP);
  pinMode(PIN_BTN_SEND,   INPUT_PULLUP);
  showState(STATE_IDLE);

  if (sodium_init() < 0 || !initIdentity()) {
    // No identity -> cannot sign -> cannot transact. Fail closed, loudly, and
    // refuse to operate rather than falling back to an unsigned request.
    Serial.println("[SECURITY] identity init FAILED -> device will not transact");
    showState(STATE_FAIL_CLOSED);
    while (true) { delay(1000); }
  }

  // Counter lives in NVS so it survives a restart. WOKWI CAVEAT: the
  // simulator does not reliably persist flash between sessions, so a
  // restarted simulation may resume from 0 and be correctly rejected as a
  // counter regression. That is the security check working, not a bug -- see
  // firmware/README.md and ATLAS_SIMULATION_ALLOW_COUNTER_RESET.
  g_prefs.begin("atlas", false);

  // GNSS receiver: 9600 baud is the NEO-M8N-class default. A large receive buffer
  // so sentences survive while a slow HTTPS request blocks the loop.
  gnss_init(&g_gnss);
  Serial2.setRxBufferSize(2048);
  Serial2.begin(GNSS_BAUD, SERIAL_8N1, GNSS_UART_RX_PIN, GNSS_UART_TX_PIN);

  Serial.println();
  Serial.println("[DEVICE] Starting ATLAS simulation...");
  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
  while (WiFi.status() != WL_CONNECTED) { delay(200); }
  Serial.println("[DEVICE] Wi-Fi Connected");

  // MUST wait for the clock before declaring ready. Two defects, one cause
  // (limitations 7 and 8, both OBSERVED 2026-09-01 via wokwi-cli):
  //   (7) configTime() is asynchronous. Transacting before it completes sends
  //       issued_at=1970-01-01, which the backend rejects as STALE_REQUEST.
  //   (8) worse, HTTPClient's own DNS lookup issued while SNTP's lookup is
  //       still pending re-enters sntp_dns_found -> sntp_retry ->
  //       sys_untimeout, trips an lwIP assert, and reboots the device
  //       mid-transaction.
  // Waiting closes both. On timeout we do NOT halt forever the way a missing
  // identity does -- a clock can recover, a missing key cannot -- so the
  // device stays up and refuses to transact (guarded again in loop()).
  configTime(0, 0, "pool.ntp.org");
  Serial.println("[DEVICE] Synchronizing clock...");
  if (waitForClock(30000)) {
    Serial.println("[DEVICE] Clock ready");
  } else {
    Serial.println("[SECURITY] Clock NOT set -> device will refuse to transact");
    showState(STATE_FAIL_CLOSED);
  }

  // Random per power-on. Combined with the NVS counter this is what stops a
  // restarted device from replaying transaction ids (the Phase 2 defect).
  snprintf(g_bootId, sizeof(g_bootId), "%08x", (unsigned int)esp_random());
#if ATLAS_TRACE_VERBOSE
  Serial.printf("[DEBUG] boot_id=%s device_key_id=%s counter=%ld\r\n",
                g_bootId, DEVICE_KEY_ID, g_prefs.getLong("counter", 0));
#endif
  Serial.println("[DEVICE] Ready");
  Serial.println("[DEVICE] SELECT cycles preset  |  SEND submits");
  Serial.println("[DEVICE] This device displays decisions; it never makes them.");
  Serial.println();
}

void loop() {
  pollGnss();

  if (pressed(PIN_BTN_SELECT)) {
    g_selectedPreset = (g_selectedPreset + 1) % PRESET_COUNT;
    char amt[48];
    groupIndian_fromMinor(PRESETS[g_selectedPreset].amountMinor, amt, sizeof(amt));
    Serial.printf("[DEVICE] Preset %d selected  |  INR %s  ->  %s\r\n",
                  g_selectedPreset, amt, PRESETS[g_selectedPreset].beneficiary);
    blinkSelection(g_selectedPreset);
  }

  if (pressed(PIN_BTN_SEND)) {
    showState(STATE_IDLE);

    // Second guard for limitations 7 and 8, and the one that actually prevents
    // the crash: this returns BEFORE any DNS lookup or HTTP call, so no request
    // can be issued while SNTP is still resolving. It is also checked before
    // readEvent() so a refused press does not consume a counter value.
    // A device that knows its clock is wrong must not assert a timestamp.
    if (!clockIsSet()) {
      printDeviceRefusal("CLOCK_NOT_SET",
        "The device clock is not synchronised, so it cannot assert a trustworthy transaction time.");
      showState(STATE_FAIL_CLOSED);
      return;
    }

    RawEvent e = readEvent(g_selectedPreset);

    // The GNSS evidence signed with this payment: the reader's state right now.
    pollGnss();
    static char locationJson[256];
    gnss_evidence_json(&g_gnss, locationJson, sizeof(locationJson));
    char gnssText[96];
    describeGnss(gnssText, sizeof(gnssText));

    static char canonical[1280];
    char txnId[96];
    if (!buildCanonical(e, locationJson, canonical, sizeof(canonical), txnId, sizeof(txnId))) {
      printDeviceRefusal("UNCONFIGURED_PRESET",
        "The selected preset is not configured. A stray press must never become some default payment.");
      showState(STATE_FAIL_CLOSED);
      return;
    }

    char sigHex[crypto_sign_BYTES * 2 + 1];
    signCanonical(canonical, sigHex);

    String body;
    buildRequestBody(canonical, sigHex, body);

    // Display context only. Every value here is already inside `canonical`
    // and was signed above; nothing is recomputed and nothing is sent from
    // this struct. The raw envelope is no longer dumped during a normal run
    // (it drowned the trace in nonces and internal ids) but is still built,
    // signed and transmitted exactly as before -- set ATLAS_TRACE_VERBOSE to
    // see it when debugging.
    char amountText[32];
    formatMinorUnits(PRESETS[e.presetId].amountMinor, amountText, sizeof(amountText));
    TxDisplay disp = {
      e.presetId, amountText, PRESETS[e.presetId].beneficiary,
      LOCATION, e.epoch, txnId, gnssText
    };
    Serial.printf("[GNSS] signed with this payment: %s\r\n", gnssText);

#if ATLAS_TRACE_VERBOSE
    Serial.print("[ENVELOPE] ");
    Serial.println(canonical);
#endif
    showState(submitEnvelope(body, disp));
  }

  delay(20);
}
