// secrets.example.h -- TEMPLATE. Copy to secrets.h and fill in.
//
//     cp secrets.example.h secrets.h      (Windows: copy secrets.example.h secrets.h)
//
// secrets.h is gitignored. This file is not, and must never contain a real
// seed -- the zeros below are the placeholder and are meant to stay zeros.
//
// Generate the real values with:
//
//     python scripts/provision_device.py enroll \
//         --device-id esp32-atlas-fw-NN --subject user-demo-1
//     python scripts/provision_device.py firmware-config \
//         --device-id esp32-atlas-fw-NN
//
// WHY THIS FILE EXISTS: the seed used to live in atlas_device.ino, which is
// tracked. Every provisioning run therefore put a live private key into a
// file one `git commit -a` away from history, and the only defence was
// remembering to revert it first. Moving it here removes that hazard: the
// tracked sketch never holds a seed, so there is nothing to remember.
//
// WHAT THIS DOES NOT FIX: the seed is still plaintext in flash on the device
// and readable with esptool. A valid signature proves possession of THIS KEY,
// not the identity of THIS DEVICE. Hardware-rooted identity needs an
// ATECC608-class secure element. Keeping the seed out of git is hygiene, not
// a trust anchor.

#pragma once

static const char *DEVICE_KEY_SEED_HEX =
    "0000000000000000000000000000000000000000000000000000000000000000";
static const char *DEVICE_KEY_ID = "dev-replace-me";
static const char *DEVICE_ID     = "esp32-atlas-demo-01";
