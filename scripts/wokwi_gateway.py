"""The Wokwi private IoT gateway, started deterministically -- never bypassing Windows.

    python scripts/wokwi_gateway.py check      # diagnose everything; start nothing
    python scripts/wokwi_gateway.py status     # is a verified gateway answering on 9011?
    python scripts/wokwi_gateway.py start      # verify, start (detached), wait, confirm
    python scripts/wokwi_gateway.py stop       # stop only the gateway ATLAS started

The simulated ESP32 reaches atlas_service through wokwigw: it resolves
host.wokwi.internal to 10.13.37.254 and NATs that to 127.0.0.1 on THIS machine, so
nothing is exposed to the LAN or the internet. The VS Code Wokwi extension reads
`[net] gateway = "ws://localhost:9011"` from firmware/atlas_device/wokwi.toml and,
when the simulator starts, connects to it. If nothing is listening there it shows
"Failed to connect to the IoT Gateway at ws://localhost:9011". Nothing starts the
gateway for it -- that is what this script is for.

WHAT IT CHECKS, IN ORDER (and stops at the first thing it cannot honestly accept):
  1. wokwi.toml names exactly a loopback ws:// gateway. A public host, a tunnel or a
     LAN address is refused; the file is never edited.
  2. The gateway binary exists and its SHA-256 equals the pinned value below -- the
     official Wokwi release v2.0.1, verified byte-for-byte against the zip GitHub
     publishes. A different file is refused, not run.
  3. Port 9011 is free, OR already held by that same verified binary (then it is
     reused, never duplicated). Any other owner is reported by name and PID and left
     alone.
  4. It starts the binary and waits for the port, then performs the WebSocket
     handshake the extension needs (the gateway answers 403 to a client that sends
     no Origin). Only a correct 101 counts as READY.

WINDOWS APPLICATION CONTROL / SMART APP CONTROL. The binary is unsigned, so Windows
decides by reputation. If Windows refuses to run it (error 4551 or 1260) this script
reports exactly that and stops. It does not retry, does not look for a way round it,
and does not suggest weakening protection -- that decision is the owner's alone.

`stop` ends only a process this script recorded, and only after confirming that
process's executable is still the verified binary. A gateway it did not start is
never touched.

Contains no secrets. Binds nothing; it only connects to 127.0.0.1.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HOST = "127.0.0.1"                       # the only address this script ever connects to
PORT = 9011
GATEWAY_URL = "ws://localhost:9011"      # what wokwi.toml must say, exactly
ORIGIN = "http://localhost:9011"         # the gateway refuses a handshake without a matching Origin
LOOPBACK_NAMES = {"localhost", "127.0.0.1"}
WOKWI_TOML = ATLAS_ROOT / "firmware" / "atlas_device" / "wokwi.toml"
DEFAULT_BINARY = Path.home() / ".wokwi" / "wokwigw.exe"
RUN_DIR = Path.home() / ".atlas" / "run"             # outside the repository and OneDrive

#: Official Wokwi IoT Gateway v2.0.1 (git 21453cb, built 2025-07-31). Verified 2026-10-01:
#: wokwigw_v2.0.1_Windows_64bit.zip from github.com/wokwi/wokwigw/releases has SHA-256
#: e2152107d94121c3cf9f34054cd9c947d17a25c2c95d8b7e91bba36a3536e485, the digest GitHub
#: publishes for that asset, and the wokwigw.exe inside it hashes to the value below --
#: byte-identical to the one installed in ~/.wokwi. A public hash, not a secret.
EXPECTED_VERSION = "v2.0.1"
EXPECTED_SHA256 = "76bbd0d9be5069ff3df70c4b56dd7057a04df4256be2f3e223ffd48b6c3c4a01"

#: Windows errors meaning "policy refused to run this file".
BLOCKED_WINERRORS = {4551, 1260}         # APPLOCKER/Application Control block; blocked by group policy
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# states
STOPPED, READY, ALREADY_RUNNING = "STOPPED", "READY", "ALREADY_RUNNING"
OCCUPIED, UNVERIFIED, UNAVAILABLE = "OCCUPIED", "UNVERIFIED_OWNER", "UNAVAILABLE"
CONFIG_ERROR, MISSING, HASH_MISMATCH = "CONFIG_ERROR", "BINARY_MISSING", "BINARY_HASH_MISMATCH"
BLOCKED, EXITED_EARLY, START_FAILED = "BLOCKED_BY_WINDOWS", "EXITED_EARLY", "START_FAILED"
STOPPED_OK, NOT_OURS, NOT_STARTED_BY_ATLAS = "STOPPED_OK", "NOT_VERIFIED", "NOTHING_TO_STOP"


class GatewayConfigError(Exception):
    pass


@dataclass
class Result:
    state: str
    message: str
    pid: int | None = None
    process: subprocess.Popen | None = field(default=None, repr=False)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.state in (READY, ALREADY_RUNNING)


# --------------------------------------------------------------------------- config

def read_configured_gateway(toml_path: Path = WOKWI_TOML) -> tuple[str, int]:
    """The gateway wokwi.toml asks for, or GatewayConfigError. Read-only: this file is
    the one fact the extension trusts, and it is never rewritten to hide an error."""
    try:
        data = tomllib.loads(Path(toml_path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GatewayConfigError(f"cannot read {toml_path}: {exc}") from exc
    url = (data.get("net") or {}).get("gateway")
    if not isinstance(url, str):
        raise GatewayConfigError(f"{toml_path} has no [net] gateway -- the private gateway is required")
    m = re.fullmatch(r"ws://([A-Za-z0-9.\-]+):(\d{1,5})", url)
    if not m:
        raise GatewayConfigError(
            f"gateway {url!r} is not a plain ws://host:port URL; ATLAS uses only the local private gateway")
    host, port = m.group(1), int(m.group(2))
    if host not in LOOPBACK_NAMES:
        raise GatewayConfigError(
            f"gateway host {host!r} is not this machine. A public or LAN gateway would expose ATLAS; "
            f"the project's gateway is {GATEWAY_URL}")
    return url, port


# --------------------------------------------------------------------------- binary

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locate_binary(candidates: list[Path] | None = None) -> Path | None:
    if candidates is None:
        candidates = [DEFAULT_BINARY]
        on_path = shutil.which("wokwigw")
        if on_path:
            candidates.append(Path(on_path))
    return next((c for c in candidates if Path(c).is_file()), None)


def verify_binary(path: Path | None, expected: str = EXPECTED_SHA256) -> Result | None:
    """None when the binary is the pinned official one; otherwise the refusal."""
    if path is None or not Path(path).is_file():
        return Result(MISSING, f"wokwigw.exe not found at {DEFAULT_BINARY} or on PATH. Download "
                      f"wokwigw_{EXPECTED_VERSION}_Windows_64bit.zip from github.com/wokwi/wokwigw/releases, "
                      f"extract wokwigw.exe to {DEFAULT_BINARY.parent}, and run this again.")
    actual = sha256_file(path)
    if actual != expected:
        return Result(HASH_MISMATCH, f"{path} is not the pinned official {EXPECTED_VERSION} gateway "
                      f"(SHA-256 {actual[:16]}..., expected {expected[:16]}...). Refusing to run it. If you "
                      "deliberately upgraded, verify the new release against GitHub's published digest and "
                      "update EXPECTED_SHA256 in scripts/wokwi_gateway.py.")
    return None


# --------------------------------------------------------------------------- the port

def port_listening(port: int = PORT, host: str = HOST, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ws_handshake(port: int = PORT, host: str = HOST, origin: str = ORIGIN, timeout: float = 3.0) -> str:
    """The extension's handshake. 'gateway' only for a correct 101 (Sec-WebSocket-Accept
    verified); 'closed' = nothing listening; 'no_answer'; or 'not_gateway: <status line>'."""
    key = base64.b64encode(os.urandom(16)).decode()
    request = (f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: {origin}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request.encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "no_answer"
    except OSError as exc:
        return f"closed: {type(exc).__name__}"
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.splitlines()
    if not lines:
        return "no_answer"
    if not lines[0].startswith("HTTP/1.1 101"):
        return f"not_gateway: {lines[0][:60]}"
    accept = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("sec-websocket-accept")), "")
    expected = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
    return "gateway" if accept == expected else "not_gateway: bad Sec-WebSocket-Accept"


def _winapi_path(pid: int) -> str | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = wintypes.HANDLE
    handle = k32.OpenProcess(0x1000, False, pid)            # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        ok = k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        return buf.value if ok else None
    finally:
        k32.CloseHandle(handle)


def process_path(pid: int) -> Path | None:
    p = _winapi_path(pid)
    return Path(p) if p else None


def owner_of_port(port: int = PORT) -> tuple[int, Path | None] | None:
    """(pid, executable) of whatever LISTENS on the port, from netstat; None if nobody,
    or if the owner cannot be read (non-Windows)."""
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3].upper() == "LISTENING" and parts[1].rsplit(":", 1)[-1] == str(port):
            pid = int(parts[4])
            return pid, process_path(pid)
    return None


def same_file(a: Path | None, b: Path | None) -> bool:
    if a is None or b is None:
        return False
    try:
        return os.path.samefile(a, b)
    except OSError:
        return str(a).lower() == str(b).lower()


def port_state(binary: Path, port: int = PORT, host: str = HOST, owner=owner_of_port, handshake=ws_handshake) -> Result:
    """Who is on the port, and may it be reused?"""
    if not port_listening(port, host):
        return Result(STOPPED, f"nothing is listening on {host}:{port}")
    who = owner(port)
    pid, exe = who if who else (None, None)
    answer = handshake(port, host)
    label = f"pid {pid} ({exe})" if pid else "an unknown process"
    if answer != "gateway":
        return Result(OCCUPIED, f"port {port} is held by {label}, which does not answer as a Wokwi gateway "
                      f"({answer}). It is left alone. Close it, or free the port, and run this again.", pid)
    if same_file(exe, binary):
        return Result(ALREADY_RUNNING, f"the verified gateway is already running ({label})", pid)
    return Result(UNVERIFIED, f"port {port} answers as a Wokwi gateway but belongs to {label}, not the "
                  f"verified {binary}. It is not reused, because it cannot be verified. Stop it and run this again.", pid)


# --------------------------------------------------------------------------- running it

def _blocked_message(path: Path, exc: OSError) -> str:
    return (f"BLOCKED BY WINDOWS: Application Control refused to run {path} "
            f"(Windows error {getattr(exc, 'winerror', '?')}: {exc.strerror or exc}). Nothing was started. "
            "ATLAS does not work around this and does not suggest turning protection off -- Windows decides. "
            "The rule that matched is in Event Viewer > Applications and Services Logs > Microsoft > Windows > "
            "CodeIntegrity > Operational (events 3077 / 3033).")


def _pidfile(run_dir: Path) -> Path:
    return Path(run_dir) / "wokwigw.json"


def start_gateway(*, toml_path: Path = WOKWI_TOML, binary: Path | None = None, run_dir: Path = RUN_DIR,
                  detached: bool = False, timeout: float = 20.0, port: int | None = None,
                  expected_sha256: str = EXPECTED_SHA256, popen=subprocess.Popen,
                  owner=owner_of_port, handshake=ws_handshake) -> Result:
    """Verify, start if needed, wait, confirm. detached=True lets the gateway outlive this
    process (the `start` command); False returns the child for the caller to supervise."""
    try:
        _url, configured_port = read_configured_gateway(toml_path)
    except GatewayConfigError as exc:
        return Result(CONFIG_ERROR, str(exc))
    port = configured_port if port is None else port
    exe = binary if binary is not None else locate_binary()
    refusal = verify_binary(exe, expected_sha256)
    if refusal:
        return refusal

    state = port_state(exe, port, HOST, owner, handshake)
    if state.state != STOPPED:
        return state                                    # reuse, or refuse -- never a second gateway

    Path(run_dir).mkdir(parents=True, exist_ok=True)
    log = Path(run_dir) / "wokwigw.log"
    kwargs: dict = {"cwd": str(ATLAS_ROOT)}
    if detached:
        kwargs["stdin"] = subprocess.DEVNULL
        kwargs["stdout"] = log.open("wb")
        kwargs["stderr"] = subprocess.STDOUT
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000   # DETACHED | NEW_GROUP | NO_WINDOW
    try:
        proc = popen([str(exe)], **kwargs)
        if detached:
            kwargs["stdout"].close()                    # the child holds its own copy
    except OSError as exc:
        if getattr(exc, "winerror", None) in BLOCKED_WINERRORS:
            return Result(BLOCKED, _blocked_message(exe, exc))
        return Result(START_FAILED, f"could not start {exe}: {type(exc).__name__}: {exc}")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = ""
            if detached and log.exists():
                tail = " Its output: " + log.read_text(encoding="utf-8", errors="replace").strip()[-300:]
            return Result(EXITED_EARLY, f"the gateway exited immediately with code {proc.returncode}.{tail}")
        if port_listening(port, HOST):
            break
        time.sleep(0.2)
    else:
        proc.kill()
        return Result(UNAVAILABLE, f"the gateway started but port {port} did not open within {timeout:.0f}s; it was stopped")

    answer = handshake(port, HOST)
    if answer != "gateway":
        proc.kill()
        return Result(UNAVAILABLE, f"port {port} opened but the WebSocket handshake failed ({answer}); the gateway was stopped")
    if detached:
        _pidfile(run_dir).write_text(json.dumps({"pid": proc.pid, "exe": str(exe),
                                                 "started_at": time.time()}), encoding="utf-8")
    return Result(READY, f"gateway {EXPECTED_VERSION} is up on {GATEWAY_URL} (pid {proc.pid}); WebSocket handshake verified",
                  proc.pid, None if detached else proc)


def stop_gateway(*, run_dir: Path = RUN_DIR, binary: Path | None = None, killer=None, path_of=process_path) -> Result:
    """Stops the gateway THIS tool recorded, if its executable is still the verified binary."""
    pidfile = _pidfile(run_dir)
    if not pidfile.exists():
        return Result(NOT_STARTED_BY_ATLAS, "no gateway started by ATLAS is recorded; nothing was touched")
    try:
        record = json.loads(pidfile.read_text(encoding="utf-8"))
        pid = int(record["pid"])
    except (ValueError, KeyError, OSError):
        pidfile.unlink(missing_ok=True)
        return Result(NOT_STARTED_BY_ATLAS, "the record of a started gateway was unreadable and was removed; nothing was touched")
    exe = binary if binary is not None else locate_binary()
    actual = path_of(pid)
    if actual is None:
        pidfile.unlink(missing_ok=True)
        return Result(NOT_STARTED_BY_ATLAS, f"pid {pid} is no longer running; the record was removed")
    if not same_file(actual, exe):
        return Result(NOT_OURS, f"pid {pid} is now {actual}, not the verified gateway; it was NOT stopped "
                      "(the record is stale)")
    if killer is not None:
        killer(pid)
    else:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=15)
    pidfile.unlink(missing_ok=True)
    return Result(STOPPED_OK, f"stopped the gateway ATLAS started (pid {pid})", pid)


# --------------------------------------------------------------------------- diagnosis

def smart_app_control_state() -> str:
    if sys.platform != "win32":
        return "not Windows"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CI\Policy") as k:
            value, _ = winreg.QueryValueEx(k, "VerifiedAndReputablePolicyState")
        return {0: "off", 1: "enforcement", 2: "evaluation"}.get(value, f"state {value}")
    except OSError:
        return "unknown"


def check(toml_path: Path = WOKWI_TOML, out=print) -> int:
    """Everything read-only: 0 when a verified gateway already answers, 1 when it can be
    started, 2 when something must be fixed first."""
    problems = 0
    try:
        url, port = read_configured_gateway(toml_path)
        out(f"[wokwi-gw] OK   wokwi.toml: gateway = \"{url}\" (private, loopback)")
    except GatewayConfigError as exc:
        out(f"[wokwi-gw] FAIL {exc}")
        return 2
    exe = locate_binary()
    refusal = verify_binary(exe)
    if refusal:
        out(f"[wokwi-gw] FAIL {refusal.message}")
        problems += 1
    else:
        out(f"[wokwi-gw] OK   binary {exe} is the pinned official {EXPECTED_VERSION} (SHA-256 verified)")
    out(f"[wokwi-gw] INFO Smart App Control: {smart_app_control_state()} (the gateway is unsigned; Windows decides by reputation)")
    if refusal:
        return 2
    state = port_state(exe, port)
    out(f"[wokwi-gw] {'OK  ' if state.ok else 'INFO' if state.state == STOPPED else 'FAIL'} port {port}: {state.message}")
    if state.state in (OCCUPIED, UNVERIFIED):
        problems += 1
    if state.ok:
        return 0
    return 2 if problems else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=["check", "status", "start", "stop"])
    args = ap.parse_args(argv)
    if args.action == "check":
        return check()
    if args.action == "stop":
        result = stop_gateway()
        print(f"[wokwi-gw] {result.state}: {result.message}")
        return 0 if result.state in (STOPPED_OK, NOT_STARTED_BY_ATLAS) else 2
    if args.action == "status":
        try:
            _, port = read_configured_gateway()
        except GatewayConfigError as exc:
            print(f"[wokwi-gw] {CONFIG_ERROR}: {exc}")
            return 2
        exe = locate_binary()
        refusal = verify_binary(exe)
        if refusal:
            print(f"[wokwi-gw] {refusal.state}: {refusal.message}")
            return 2
        state = port_state(exe, port)
        print(f"[wokwi-gw] {state.state}: {state.message}")
        return 0 if state.ok else 1
    result = start_gateway(detached=True)
    print(f"[wokwi-gw] {result.state}: {result.message}")
    if result.ok:
        print("[wokwi-gw] Now start Wokwi: F1 -> \"Wokwi: Start Simulator\". Stop the gateway later with: "
              "python scripts/wokwi_gateway.py stop")
        return 0
    return 3 if result.state == BLOCKED else 2


if __name__ == "__main__":
    raise SystemExit(main())
