# Vendored: Espressif's NVS partition generator

`nvs_partition_gen.py` is Espressif Systems' official NVS partition image generator,
copied **unchanged** from the PyPI package `esp-idf-nvs-partition-gen` **0.3.0**
(Apache License 2.0, the `LICENSE` file beside it; source
https://github.com/espressif/esp-idf-nvs-partition-gen).

| What | SHA-256 |
|---|---|
| `esp_idf_nvs_partition_gen-0.3.0-py3-none-any.whl` (as published on PyPI) | `071c09b838cacb5562362e18e1cdf056d86a2611bb99e7d50de2b5054de33ac9` |
| `nvs_partition_gen.py` (this file, LF line endings) | `eed5a178ef3513757cd841f2d05425a852c723974156df0ccf9218850028f696` |
| `LICENSE` | `02ff931bfa172520949584836d00cb2cf16dc3872c9021a3699a9312e438c241` |

Downloaded once, 2026-10-09, with the owner's permission, so that building the ESP32's
identity image (`scripts/provision_nvs.py`) is reproducible and needs no network.
`tests/test_nvs_identity.py` fails if the file changes.

Only its in-memory API is used (`nvs_open`, `write_entry`, `nvs_close`); its command-line
front end needs two packages (`rich-click`, `esp-pylib`) that were deliberately **not**
installed. `firmware/nvs_identity.py` supplies inert stand-ins for those imports while the
module loads; its logger stand-in prints nothing, so no value can be echoed.
