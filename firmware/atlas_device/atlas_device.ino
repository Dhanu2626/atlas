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
 * WHAT WOKWI PROVES / DOES NOT PROVE
 *   Proves: firmware behaviour, protocol integration, signing/verification
 *   round-trip, replay behaviour, fail-closed behaviour.
 *   Does NOT prove: secure boot, eFuse security, flash encryption, physical
 *   tamper resistance, key-extraction resistance, hardware-rooted identity.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_random.h>
#include <sodium.h>
#include <time.h>

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASS = "";

// Replace with the public tunnel URL. DEMO-ONLY: a tunnel provides no
// authentication of any kind, and the URL changes on every restart.
static const char *ATLAS_URL = "http://replace-me.example.com";

// --- device identity ------------------------------------------------------
// Produced by:  python scripts/provision_device.py firmware-config --device-id ...
//
// SECURITY REALITY: this seed is plaintext in flash. A valid signature proves
// possession of THIS KEY, not the identity of THIS DEVICE. Documented, not
// worked around -- see the header comment.
static const char *DEVICE_KEY_SEED_HEX =
    "0000000000000000000000000000000000000000000000000000000000000000";
static const char *DEVICE_KEY_ID = "dev-replace-me";

static const char *DEVICE_ID             = "esp32-atlas-demo-01";
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

// --------------------------------------------------------------------------
// LAYER 1: EVENT ACQUISITION -- knows nothing about ATLAS
// --------------------------------------------------------------------------

struct RawEvent { int presetId; long counter; char pressedAt[32]; };

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
  return e;
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
// NOTE ON `location` AND `health`: both are null here. F1 made the coordinate
// fields Decimal-as-string precisely so that populating them later stays
// deterministic across C and Python; F3 does not populate them (that is
// Phase 3.4 and out of scope).
// --------------------------------------------------------------------------

// CANONICAL_FORMAT_BEGIN
static const char CANONICAL_FMT[] =
  "{\"boot_id\":\"%s\","
  "\"counter\":%ld,"
  "\"device_id\":\"%s\","
  "\"device_key_id\":\"%s\","
  "\"health\":null,"
  "\"issued_at\":\"%s\","
  "\"location\":null,"
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
static bool buildCanonical(const RawEvent &e, char *out, size_t len,
                           char *transactionIdOut, size_t tidLen) {
  if (e.presetId < 0 || e.presetId >= PRESET_COUNT) return false;
  const Preset &p = PRESETS[e.presetId];

  char amount[32];
  formatMinorUnits(p.amountMinor, amount, sizeof(amount));
  snprintf(transactionIdOut, tidLen, "%s-%s-%04ld", DEVICE_ID, g_bootId, e.counter);

  char nonce[33];
  randomHex(nonce, 16);

  int written = snprintf(out, len, CANONICAL_FMT,
    g_bootId, e.counter, DEVICE_ID, DEVICE_KEY_ID, e.pressedAt, nonce,
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

static DeviceState submitEnvelope(const String &body, const char *txnId) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[SECURITY] final_status=FAIL_CLOSED decision_reason=ATLAS_UNREACHABLE");
    return STATE_FAIL_CLOSED;
  }

  HTTPClient http;
  String url = String(ATLAS_URL) + "/v2/transact?rail=" + RAIL;
  if (!http.begin(url)) {
    Serial.println("[SECURITY] final_status=FAIL_CLOSED decision_reason=ATLAS_UNREACHABLE");
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
      Serial.printf("[SECURITY] txn=%s http=%d final_status=FAIL_CLOSED decision_reason=%s\n",
                    txnId, code, (const char *)err["decision_reason"]);
    } else {
      Serial.printf("[SECURITY] txn=%s http=%d final_status=FAIL_CLOSED decision_reason=ATLAS_UNREACHABLE\n",
                    txnId, code);
    }
    return STATE_FAIL_CLOSED;
  }

  JsonDocument doc;
  if (deserializeJson(doc, payload) || !doc["final_status"].is<const char *>()) {
    Serial.printf("[SECURITY] txn=%s final_status=FAIL_CLOSED decision_reason=MALFORMED_RESPONSE\n", txnId);
    return STATE_FAIL_CLOSED;
  }

  const char *finalStatus = doc["final_status"];
  const char *reason = doc["decision_reason"].is<const char *>()
                         ? (const char *)doc["decision_reason"] : "UNSPECIFIED";
  DeviceState st = interpretStatus(finalStatus);
  Serial.printf("[POLICY] txn=%s final_status=%s decision_reason=%s state=%s\n",
                txnId, finalStatus, reason, stateLabel(st));
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

  Serial.print("[DEVICE] connecting to wifi");
  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
  while (WiFi.status() != WL_CONNECTED) { delay(200); Serial.print("."); }
  Serial.println(" connected");

  configTime(0, 0, "pool.ntp.org");

  // Random per power-on. Combined with the NVS counter this is what stops a
  // restarted device from replaying transaction ids (the Phase 2 defect).
  snprintf(g_bootId, sizeof(g_bootId), "%08x", (unsigned int)esp_random());
  Serial.printf("[DEVICE] boot_id=%s device_key_id=%s counter=%ld\n",
                g_bootId, DEVICE_KEY_ID, g_prefs.getLong("counter", 0));
  Serial.println("[DEVICE] ready. SELECT cycles preset, SEND submits.");
  Serial.println("[DEVICE] this device displays decisions; it never makes them.");
}

void loop() {
  if (pressed(PIN_BTN_SELECT)) {
    g_selectedPreset = (g_selectedPreset + 1) % PRESET_COUNT;
    Serial.printf("[DEVICE] preset %d selected\n", g_selectedPreset);
    blinkSelection(g_selectedPreset);
  }

  if (pressed(PIN_BTN_SEND)) {
    showState(STATE_IDLE);
    RawEvent e = readEvent(g_selectedPreset);

    static char canonical[1024];
    char txnId[96];
    if (!buildCanonical(e, canonical, sizeof(canonical), txnId, sizeof(txnId))) {
      Serial.println("[SECURITY] final_status=FAIL_CLOSED decision_reason=UNCONFIGURED_PRESET");
      showState(STATE_FAIL_CLOSED);
      return;
    }

    char sigHex[crypto_sign_BYTES * 2 + 1];
    signCanonical(canonical, sigHex);

    String body;
    buildRequestBody(canonical, sigHex, body);
    Serial.printf("[DEVICE] txn=%s counter=%ld submitting signed envelope\n", txnId, e.counter);
    showState(submitEnvelope(body, txnId));
  }

  delay(20);
}
