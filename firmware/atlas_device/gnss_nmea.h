/*
 * gnss_nmea.h -- turns a GNSS receiver's NMEA sentences into location EVIDENCE.
 *
 * Plain C99 with no Arduino types, so the same file compiles in the ESP32 sketch and,
 * on GitHub's Linux machines, in tests/c/gnss_parity.c -- where its output is compared
 * byte for byte with firmware/gnss.py (the Python twin) on the same input.
 *
 * WHAT IT DOES
 *   * checks every sentence: starts with '$', at most 80 characters, ends in a "*hh"
 *     checksum that matches the XOR of everything between '$' and '*'
 *   * GGA -> position, fix quality, satellites in use
 *   * RMC -> the receiver's own word on whether it has a fix (A) or not (V)
 *   * GST -> the receiver's own error estimate (1-sigma, metres), used as accuracy
 *   * keeps the last good fix with the DEVICE clock time it arrived at, so a fix that
 *     stops being refreshed ages honestly instead of looking current
 *
 * WHAT IT NEVER DOES
 *   Decide anything. No home area, no confidence grade, no rule. It reports what the
 *   receiver said; atlas_service grades it (atlas_service/device/location.py). The
 *   receiver is not authenticated either: a sentence that passes its checksum proves
 *   only that it was not garbled on the wire, never that the position is true.
 *
 * Integer arithmetic only. Coordinates are millionths of a degree and accuracy tenths of
 * a metre, so C and Python print identical text with no floating-point rounding anywhere
 * -- the F1 lesson: numbers inside signed bytes must be spelled the same on both sides.
 */
#ifndef ATLAS_GNSS_NMEA_H
#define ATLAS_GNSS_NMEA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GNSS_MAX_SENTENCE 80   /* NMEA 0183: 82 characters including the CR LF */
#define GNSS_MAX_FIELDS   24

enum { GNSS_OK = 0, GNSS_IGNORED = 1, GNSS_BAD_CHECKSUM = 2, GNSS_MALFORMED = 3 };

typedef struct {
  bool      any_valid;          /* the receiver has sent at least one good sentence */
  bool      have_fix;           /* a position has been fixed at least once */
  bool      fix_now;            /* the receiver's latest word: fix or no fix */
  long      fix_lat_e6;         /* millionths of a degree, signed */
  long      fix_lon_e6;
  long      fix_acc_dm;         /* tenths of a metre; -1 when the receiver gave none */
  int       fix_sats;
  char      fix_utc[12];        /* the receiver's hhmmss.ss for that fix (pairs it with GST) */
  long long fix_epoch;          /* DEVICE clock when the fix arrived */
  int       sats_now;           /* satellites in use, latest GGA */
  long      gst_acc_dm;
  char      gst_utc[12];
  unsigned long accepted, rejected_checksum, rejected_malformed;
} GnssState;

static void gnss_init(GnssState *s) {
  memset(s, 0, sizeof(*s));
  s->fix_acc_dm = -1;
  s->gst_acc_dm = -1;
}

static int gnss_hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static bool gnss_digits(const char *s, size_t n) {
  if (n == 0) return false;
  for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return false;
  return true;
}

/* A whole number of 1-9 digits. */
static bool gnss_uint(const char *s, long *out) {
  size_t n = strlen(s);
  if (n == 0 || n > 9 || !gnss_digits(s, n)) return false;
  long v = 0;
  for (size_t i = 0; i < n; i++) v = v * 10 + (s[i] - '0');
  *out = v;
  return true;
}

/* "ddmm.mmmmm" (latitude, 2 degree digits) or "dddmm.mmmmm" (longitude, 3) to signed
 * millionths of a degree. Minutes are read to 5 decimals (further digits are dropped),
 * then degrees = minutes / 60, rounded half up: (minutes_e5 + 3) / 6. */
static bool gnss_coord(const char *f, const char *hemi, int deg_digits, long max_deg,
                       char pos, char neg, long *out) {
  size_t n = strlen(f);
  if (n < (size_t)deg_digits + 2 || !gnss_digits(f, (size_t)deg_digits + 2)) return false;
  long deg = 0;
  for (int i = 0; i < deg_digits; i++) deg = deg * 10 + (f[i] - '0');
  long mm = (f[deg_digits] - '0') * 10 + (f[deg_digits + 1] - '0');
  if (mm >= 60) return false;
  long frac = 0;
  int got = 0;
  const char *p = f + deg_digits + 2;
  if (*p == '.') {
    p++;
    if (*p == '\0') return false;
    for (; *p; p++) {
      if (*p < '0' || *p > '9') return false;
      if (got < 5) { frac = frac * 10 + (*p - '0'); got++; }
    }
  } else if (*p != '\0') {
    return false;
  }
  for (; got < 5; got++) frac *= 10;
  long e6 = deg * 1000000L + (mm * 100000L + frac + 3) / 6;
  if (e6 > max_deg * 1000000L) return false;
  if (strlen(hemi) != 1 || (hemi[0] != pos && hemi[0] != neg)) return false;
  *out = (hemi[0] == neg && e6 != 0) ? -e6 : e6;
  return true;
}

/* An error estimate in metres ("2.34") to tenths of a metre, rounded half up on the
 * second decimal; further digits are dropped. */
static bool gnss_err_dm(const char *f, long *out) {
  const char *dot = strchr(f, '.');
  size_t ilen = dot ? (size_t)(dot - f) : strlen(f);
  if (ilen == 0 || ilen > 7 || !gnss_digits(f, ilen)) return false;
  long v = 0;
  for (size_t i = 0; i < ilen; i++) v = v * 10 + (f[i] - '0');
  int d1 = 0, d2 = 0;
  if (dot) {
    size_t flen = strlen(dot + 1);
    if (flen == 0 || !gnss_digits(dot + 1, flen)) return false;
    d1 = dot[1] - '0';
    d2 = flen > 1 ? dot[2] - '0' : 0;
  }
  *out = v * 10 + d1 + (d2 >= 5 ? 1 : 0);
  return true;
}

/* hhmmss with optional .ss, or empty (a receiver with no time yet). */
static bool gnss_utc(const char *f) {
  size_t n = strlen(f);
  if (n == 0) return true;
  if (n < 6 || n > 11 || !gnss_digits(f, 6)) return false;
  if (n == 6) return true;
  return f[6] == '.' && gnss_digits(f + 7, n - 7);
}

static int gnss_reject(GnssState *s) { s->rejected_malformed++; return GNSS_MALFORMED; }

/* Feeds one sentence (with or without its trailing CR/LF). `device_epoch` is the device
 * clock now, in seconds since 1970 UTC: it stamps a new fix. */
static int gnss_feed_line(GnssState *s, const char *line, long long device_epoch) {
  char buf[GNSS_MAX_SENTENCE + 1];
  size_t n = strlen(line);
  while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
  if (n == 0) return GNSS_IGNORED;
  if (n > GNSS_MAX_SENTENCE || line[0] != '$') return gnss_reject(s);
  memcpy(buf, line, n);
  buf[n] = '\0';

  char *star = strchr(buf, '*');
  if (star == NULL || (size_t)(star - buf) != n - 3) return gnss_reject(s);
  int hi = gnss_hex(star[1]), lo = gnss_hex(star[2]);
  if (hi < 0 || lo < 0) return gnss_reject(s);
  unsigned char sum = 0;
  for (char *p = buf + 1; p < star; p++) sum ^= (unsigned char)*p;
  if (sum != (unsigned char)(hi * 16 + lo)) { s->rejected_checksum++; return GNSS_BAD_CHECKSUM; }
  *star = '\0';

  char *field[GNSS_MAX_FIELDS];
  int count = 0;
  char *p = buf + 1;
  field[count++] = p;
  for (; *p; p++) {
    if (*p == ',') {
      if (count == GNSS_MAX_FIELDS) return gnss_reject(s);
      *p = '\0';
      field[count++] = p + 1;
    }
  }

  const char *type = field[0];
  if (type[0] == 'P') { s->accepted++; s->any_valid = true; return GNSS_IGNORED; }  /* proprietary */
  if (strlen(type) != 5) return gnss_reject(s);
  for (int i = 0; i < 5; i++) if (type[i] < 'A' || type[i] > 'Z') return gnss_reject(s);
  const char *kind = type + 2;   /* the first two letters name the constellation (GN = several) */

  if (strcmp(kind, "GGA") == 0) {
    if (count < 9 || !gnss_utc(field[1])) return gnss_reject(s);
    long quality, sats = 0;
    if (strlen(field[6]) != 1 || !gnss_uint(field[6], &quality)) return gnss_reject(s);
    if (field[7][0] != '\0' && !gnss_uint(field[7], &sats)) return gnss_reject(s);
    if (sats > 99) return gnss_reject(s);
    /* 1-5 are satellite fixes (GPS, differential, PPS, RTK fixed, RTK float); 0 is none,
     * and 6 (dead reckoning), 7 (manual) and 8 (simulator) are not satellite fixes. */
    if (quality < 1 || quality > 5) {
      s->accepted++; s->any_valid = true; s->fix_now = false; s->sats_now = (int)sats;
      return GNSS_OK;
    }
    long lat, lon;
    if (!gnss_coord(field[2], field[3], 2, 90, 'N', 'S', &lat)) return gnss_reject(s);
    if (!gnss_coord(field[4], field[5], 3, 180, 'E', 'W', &lon)) return gnss_reject(s);
    s->accepted++; s->any_valid = true; s->fix_now = true; s->sats_now = (int)sats;
    s->have_fix = true;
    s->fix_lat_e6 = lat;
    s->fix_lon_e6 = lon;
    s->fix_sats = (int)sats;
    s->fix_epoch = device_epoch;
    snprintf(s->fix_utc, sizeof(s->fix_utc), "%s", field[1]);
    s->fix_acc_dm = (field[1][0] != '\0' && strcmp(s->gst_utc, field[1]) == 0) ? s->gst_acc_dm : -1;
    return GNSS_OK;
  }

  if (strcmp(kind, "RMC") == 0) {
    if (count < 3 || !gnss_utc(field[1])) return gnss_reject(s);
    if (strcmp(field[2], "A") != 0 && strcmp(field[2], "V") != 0) return gnss_reject(s);
    s->accepted++; s->any_valid = true; s->fix_now = (field[2][0] == 'A');
    return GNSS_OK;
  }

  if (strcmp(kind, "GST") == 0) {
    if (count < 8 || !gnss_utc(field[1])) return gnss_reject(s);
    long lat_dm, lon_dm;
    if (!gnss_err_dm(field[6], &lat_dm) || !gnss_err_dm(field[7], &lon_dm)) return gnss_reject(s);
    s->accepted++; s->any_valid = true;
    s->gst_acc_dm = lat_dm > lon_dm ? lat_dm : lon_dm;
    snprintf(s->gst_utc, sizeof(s->gst_utc), "%s", field[1]);
    /* A receiver may send GST after the GGA of the same second: pair them by time. */
    if (s->have_fix && field[1][0] != '\0' && strcmp(s->fix_utc, field[1]) == 0) s->fix_acc_dm = s->gst_acc_dm;
    return GNSS_OK;
  }

  s->accepted++; s->any_valid = true;   /* a good sentence of a kind ATLAS does not use */
  return GNSS_IGNORED;
}

static void gnss_degrees(long e6, char *out, size_t len) {
  long a = e6 < 0 ? -e6 : e6;
  snprintf(out, len, "%s%ld.%06ld", e6 < 0 ? "-" : "", a / 1000000L, a % 1000000L);
}

/* The LocationEvidence the device signs, as canonical JSON (keys sorted, no spaces) --
 * exactly what contracts.canonical_envelope_bytes() derives for the same values:
 *   "null"                       the receiver has said nothing valid yet
 *   coordinates null             it talks, but has never had a fix
 *   the last fix                 with the device time it arrived at, so ATLAS sees its age */
static int gnss_evidence_json(const GnssState *s, char *out, size_t len) {
  if (!s->any_valid) return snprintf(out, len, "null");
  if (!s->have_fix) {
    return snprintf(out, len,
      "{\"accuracy_m\":null,\"captured_at\":null,\"latitude\":null,\"longitude\":null,"
      "\"satellites\":%d,\"source\":\"GNSS\"}", s->sats_now);
  }
  char lat[24], lon[24], acc[24], when[40];
  gnss_degrees(s->fix_lat_e6, lat, sizeof(lat));
  gnss_degrees(s->fix_lon_e6, lon, sizeof(lon));
  if (s->fix_acc_dm < 0) snprintf(acc, sizeof(acc), "null");
  else snprintf(acc, sizeof(acc), "\"%ld.%ld\"", s->fix_acc_dm / 10, s->fix_acc_dm % 10);
  time_t t = (time_t)s->fix_epoch;
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%S+00:00", &tm);
  return snprintf(out, len,
    "{\"accuracy_m\":%s,\"captured_at\":\"%s\",\"latitude\":\"%s\",\"longitude\":\"%s\","
    "\"satellites\":%d,\"source\":\"GNSS\"}", acc, when, lat, lon, s->fix_sats);
}

#endif /* ATLAS_GNSS_NMEA_H */
