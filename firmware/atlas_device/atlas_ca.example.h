// atlas_ca.example.h -- TEMPLATE, tracked. The real atlas_ca.h is generated:
//
//     python scripts/make_dev_ca.py --firmware-header
//
// which writes this machine's local test CA certificate (PUBLIC, never a key)
// to firmware/atlas_device/atlas_ca.h, gitignored. The ESP32 verifies
// atlas_service against it on every request.
//
// The placeholder below is deliberately NOT a certificate. A build made with it
// compiles, but every TLS handshake fails, so the device lights red
// (ATLAS_UNREACHABLE) and sends nothing -- it never falls back to plain HTTP
// and never skips verification.
#pragma once

static const char ATLAS_CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "REPLACE-ME--run-scripts/make_dev_ca.py--firmware-header\n"
    "-----END CERTIFICATE-----\n";
