// secrets.example.h -- PLACEHOLDER. Copy to secrets.h to compile the sketch.
//
//     cp secrets.example.h secrets.h      (Windows: copy secrets.example.h secrets.h)
//
// secrets.h is gitignored. This file is not, and must never contain a real
// seed -- the zeros below are the placeholder and are meant to stay zeros.
//
// ATLAS is software-only from 2026-10-12, and the command that produced the real
// values (provision_device.py firmware-config) is retired: it reads and prints no
// key. The supported device is the firmware's Python twin (virtual_device.py),
// whose key never leaves the keystore. GitHub Actions compiles the sketch with
// this placeholder; nothing should fill in a real seed.
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
