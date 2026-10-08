/*
 * atlas-gnss.chip.c -- a SIMULATED multi-GNSS receiver for the Wokwi simulator.
 *
 * NOTHING HERE RECEIVES A SATELLITE. Wokwi has no GNSS part and no sky, so this chip
 * plays the role of one: once a second it writes NMEA 0183 sentences over UART at 9600
 * baud, the way a u-blox NEO-M8N-class receiver does by default, with the "GN" talker
 * a receiver uses when it combines several constellations (GPS, Galileo, GLONASS,
 * BeiDou). Every coordinate is scripted. What it lets the simulation show is the real
 * part -- the ESP32 reading a UART, checking each sentence, signing what it read, and
 * atlas_service grading it -- never where anyone is.
 *
 * Seven scenarios, picked with the chip's "scenario" slider while the simulation runs
 * (or its `scenario` attribute in diagram.json):
 *
 *   0 HOME            the configured home area (Hyderabad), +-2 m wander, 12 satellites
 *   1 OUTSIDE HOME    about 50 km away (Sangareddy)
 *   2 IMPOSSIBLE      Delhi, about 1,250 km away. Pay once at HOME first: the jump is
 *                     then faster than any real journey
 *   3 NO FIX          the receiver tracks 2 satellites and says it has no position
 *   4 SILENT          the receiver stops talking, so the last fix stops being refreshed
 *                     and ages (STALE once it is more than five minutes old)
 *   5 POOR ACCURACY   home, but the receiver's own error estimate is about 1.8 km
 *   6 BAD NMEA        home sentences damaged on the wire: wrong checksums and a
 *                     latitude changed after its checksum was computed
 *
 * This chip's clock is the simulator's, not real UTC. The device stamps every fix with
 * its own NTP-set clock (gnss_nmea.h), so the times written here only pair each GGA
 * with its GST.
 *
 * Built to chips/atlas-gnss.chip.wasm by .github/workflows/device-build.yml; wokwi.toml
 * loads it.
 */
#include "wokwi-api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { HOME = 0, OUTSIDE_HOME, IMPOSSIBLE, NO_FIX, SILENT, POOR_ACCURACY, BAD_NMEA, SCENARIOS };

static const char *NAMES[SCENARIOS] = {
  "HOME", "OUTSIDE HOME", "IMPOSSIBLE TRAVEL", "NO FIX", "SILENT", "POOR ACCURACY", "BAD NMEA",
};

/* Millionths of a degree. Public city-centre coordinates, nobody's address. */
static const long HOME_LAT = 17385044, HOME_LON = 78486671;      /* Hyderabad */
static const long AWAY_LAT = 17624800, AWAY_LON = 78086700;      /* Sangareddy, ~50 km */
static const long FAR_LAT  = 28613939, FAR_LON  = 77209023;      /* Delhi, ~1,250 km */

typedef struct {
  uart_dev_t uart;
  uint32_t   scenario_attr;
  uint32_t   seconds;
  int        last_scenario;
  char       out[512];
} chip_state_t;

static unsigned char checksum(const char *body) {
  unsigned char sum = 0;
  for (; *body; body++) sum ^= (unsigned char)*body;
  return sum;
}

/* Appends "$<body>*hh\r\n". `corrupt` writes a wrong checksum. */
static void add(chip_state_t *chip, const char *body, int corrupt) {
  size_t used = strlen(chip->out);
  unsigned char sum = checksum(body) ^ (corrupt ? 0x5A : 0);
  snprintf(chip->out + used, sizeof(chip->out) - used, "$%s*%02X\r\n", body, sum);
}

/* ddmm.mmmmm from millionths of a degree: minutes x 1e5 = remainder x 6, exactly. */
static void nmea_coord(long e6, int deg_digits, char *out, size_t len) {
  long a = e6 < 0 ? -e6 : e6;
  long min_e5 = (a % 1000000L) * 6;
  snprintf(out, len, deg_digits == 2 ? "%02ld%02ld.%05ld" : "%03ld%02ld.%05ld",
           a / 1000000L, min_e5 / 100000L, min_e5 % 100000L);
}

static void emit(void *user_data) {
  chip_state_t *chip = (chip_state_t *)user_data;
  uint32_t value = attr_read(chip->scenario_attr);
  int scenario = value < SCENARIOS ? (int)value : HOME;
  if (scenario != chip->last_scenario) {
    printf("atlas-gnss (simulated): scenario %d, %s\n", scenario, NAMES[scenario]);
    chip->last_scenario = scenario;
  }
  chip->seconds++;
  if (scenario == SILENT) return;

  char utc[16], body[96], lat[16], lon[16];
  uint32_t t = chip->seconds;
  snprintf(utc, sizeof(utc), "%02lu%02lu%02lu.00",
           (unsigned long)((t / 3600) % 24), (unsigned long)((t / 60) % 60), (unsigned long)(t % 60));
  chip->out[0] = '\0';

  if (scenario == NO_FIX) {
    snprintf(body, sizeof(body), "GNRMC,%s,V,,,,,,,010126,,,N", utc);
    add(chip, body, 0);
    snprintf(body, sizeof(body), "GNGGA,%s,,,,,0,02,99.99,,,,,,", utc);
    add(chip, body, 0);
  } else {
    long la = HOME_LAT, lo = HOME_LON;
    if (scenario == OUTSIDE_HOME) { la = AWAY_LAT; lo = AWAY_LON; }
    if (scenario == IMPOSSIBLE)   { la = FAR_LAT;  lo = FAR_LON; }
    long wander = (long)(t % 20) - 10;              /* a few metres, like a real fix */
    nmea_coord(la + wander * 2, 2, lat, sizeof(lat));
    nmea_coord(lo - wander * 2, 3, lon, sizeof(lon));
    int poor = scenario == POOR_ACCURACY, bad = scenario == BAD_NMEA;

    snprintf(body, sizeof(body), "GNRMC,%s,A,%s,N,%s,E,0.02,,010126,,,A", utc, lat, lon);
    add(chip, body, bad);
    snprintf(body, sizeof(body), "GNGGA,%s,%s,N,%s,E,1,%s,%s,542.0,M,-73.6,M,,",
             utc, lat, lon, poor ? "04" : "12", poor ? "12.4" : "0.8");
    if (bad) {
      /* Checksum computed first, then one latitude digit changed: what a tampered or
       * noisy line looks like. The device must refuse it. */
      size_t used = strlen(chip->out);
      add(chip, body, 0);
      char *digit = strchr(chip->out + used + 18, '1');
      if (digit) *digit = '9';
    } else {
      add(chip, body, 0);
    }
    snprintf(body, sizeof(body), "GNGST,%s,%s,%s,%s,45.0,%s,%s,%s", utc,
             poor ? "1650.0" : "2.1", poor ? "1800.0" : "1.6", poor ? "1500.0" : "1.2",
             poor ? "1800.0" : "1.8", poor ? "1500.0" : "2.3", poor ? "2500.0" : "3.9");
    add(chip, body, bad);
  }
  uart_write(chip->uart, (uint8_t *)chip->out, (uint32_t)strlen(chip->out));
}

void chip_init(void) {
  chip_state_t *chip = calloc(1, sizeof(chip_state_t));
  chip->last_scenario = -1;
  chip->scenario_attr = attr_init("scenario", HOME);
  const uart_config_t uart = {
    .tx = pin_init("TX", INPUT_PULLUP),
    .rx = pin_init("RX", INPUT),          /* wired, like a real module; nothing is read */
    .baud_rate = 9600,
    .user_data = chip,
  };
  chip->uart = uart_init(&uart);
  const timer_config_t timer = { .callback = emit, .user_data = chip };
  timer_start(timer_init(&timer), 1000000, true);   /* one burst of sentences a second */
  printf("atlas-gnss: SIMULATED receiver ready (no satellites; scripted positions)\n");
}
