/*
 * gnss_parity.c -- runs the ESP32's own NMEA reader (firmware/atlas_device/gnss_nmea.h)
 * on a script, so tests/test_gnss.py can compare it with the Python twin.
 *
 * Built and run by tests/test_gnss.py with the host C compiler (GitHub's Linux machines
 * have one; this Windows PC does not). Reads lines from stdin:
 *   F <device_epoch> <sentence>   feed one sentence; prints its result code
 *   Q                             prints the evidence JSON and the three counters
 * The Python twin prints the same transcript for the same script.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../firmware/atlas_device/gnss_nmea.h"

int main(void) {
  GnssState s;
  gnss_init(&s);
  char line[512], json[512];
  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == 'F' && line[1] == ' ') {
      char *end;
      long long epoch = strtoll(line + 2, &end, 10);
      const char *sentence = (*end == ' ') ? end + 1 : end;
      printf("%d\n", gnss_feed_line(&s, sentence, epoch));
    } else if (line[0] == 'Q') {
      gnss_evidence_json(&s, json, sizeof(json));
      printf("%s %lu %lu %lu\n", json, s.accepted, s.rejected_checksum, s.rejected_malformed);
    }
  }
  return 0;
}
