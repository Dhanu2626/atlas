"""Checks a compiled Wokwi custom chip (.wasm) before anyone loads it (2026-10-09).

    python scripts/wasm_exports.py chips/atlas-gnss.chip.wasm chipInit __wokwi_api_version_1

Reads the WebAssembly file's import and export sections with nothing but the standard
library -- it never runs the module -- and prints them. Fails if a named export is missing,
or if the module imports from anywhere other than the simulator's chip API ("env") and the
standard WASI system interface the C library uses for printf ("wasi_snapshot_preview1").
Used by .github/workflows/device-build.yml on the freshly built chip, and runnable on a
downloaded copy before putting it in the simulator.
"""

from __future__ import annotations

import sys
from pathlib import Path

ALLOWED_IMPORT_MODULES = {"env", "wasi_snapshot_preview1"}


def _uleb(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, i
        shift += 7


def _name(data: bytes, i: int) -> tuple[str, int]:
    n, i = _uleb(data, i)
    return data[i:i + n].decode("utf-8"), i + n


def read(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    data = path.read_bytes()
    if data[:4] != b"\0asm":
        raise ValueError(f"{path} is not a WebAssembly module")
    imports, exports, i = [], [], 8
    while i < len(data):
        section, i = data[i], i + 1
        size, i = _uleb(data, i)
        end = i + size
        if section == 2:                                   # imports
            count, j = _uleb(data, i)
            for _ in range(count):
                module, j = _name(data, j)
                field, j = _name(data, j)
                kind, j = data[j], j + 1
                if kind == 0:                              # function: type index
                    _, j = _uleb(data, j)
                elif kind == 1:                            # table: elem type + limits
                    j += 1
                    flags, j = _uleb(data, j)
                    _, j = _uleb(data, j)
                    if flags & 1:
                        _, j = _uleb(data, j)
                elif kind == 2:                            # memory: limits
                    flags, j = _uleb(data, j)
                    _, j = _uleb(data, j)
                    if flags & 1:
                        _, j = _uleb(data, j)
                elif kind == 3:                            # global: type + mutability
                    j += 2
                imports.append((module, field))
        elif section == 7:                                 # exports
            count, j = _uleb(data, i)
            for _ in range(count):
                field, j = _name(data, j)
                j += 1
                _, j = _uleb(data, j)
                exports.append(field)
        i = end
    return imports, exports


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    imports, exports = read(Path(argv[1]))
    print("imports:", ", ".join(f"{m}.{f}" for m, f in imports) or "none")
    print("exports:", ", ".join(exports) or "none")
    problems = [f"missing export {name}" for name in argv[2:] if name not in exports]
    problems += [f"unexpected import module {m!r}" for m in sorted({m for m, _ in imports} - ALLOWED_IMPORT_MODULES)]
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
