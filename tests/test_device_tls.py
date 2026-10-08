"""The ESP32 -> atlas_service hop over TLS (2026-09-27).

Until this change the Wokwi device sent its signed envelopes over plain HTTP
through the loopback gateway: readable in transit, though not alterable. Now the
firmware connects to https://host.wokwi.internal:8000 and verifies ATLAS against
the local test CA (firmware/atlas_device/atlas_ca.h), host name included.

These tests stand in for the device with Python's TLS client configured the way
the firmware configures mbedTLS: trust only ca.crt, check the host name
host.wokwi.internal, present no client certificate. The firmware's own
handshake is observed only in Wokwi; nothing here claims it.
"""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from cryptography import x509
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from atlas_service import tls

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_dev_ca  # noqa: E402
import run_sim  # noqa: E402

SKETCH_DIR = ROOT / "firmware" / "atlas_device"
DEVICE_HOST = "host.wokwi.internal"


@pytest.fixture
def pki(tmp_path):
    folder = tmp_path / "pki"
    make_dev_ca.create_pki(folder)
    return folder


@pytest.fixture
def other_pki(tmp_path):
    """An unrelated CA -- what an impostor server would have."""
    folder = tmp_path / "other-pki"
    make_dev_ca.create_pki(folder)
    return folder


def _app():
    return Starlette(routes=[Route("/ping", lambda request: PlainTextResponse("atlas"))])


class _Served:
    """atlas_service's listener settings (tls.server_settings, as `--tls` uses
    them) on a free loopback port, serving a stub app: the handshake is what is
    under test, not the API behind it."""

    def __init__(self, pki_dir: Path):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        settings = tls.server_settings("atlas", pki_dir, require_client_cert=False)
        self.server = uvicorn.Server(uvicorn.Config(_app(), host="127.0.0.1", port=self.port,
                                                    log_level="warning", **settings))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("TLS test server did not start")
            time.sleep(0.05)
        return self.port

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=15)


def _device_context(ca_dir: Path) -> ssl.SSLContext:
    """What the firmware does: setCACert(ca.crt), host name checked, no client cert."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_dir / "ca.crt"))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _device_get(port: int, ca_dir: Path, host: str = DEVICE_HOST) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with _device_context(ca_dir).wrap_socket(raw, server_hostname=host) as s:
            s.sendall(f"GET /ping HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            reply = b""
            while chunk := s.recv(4096):
                reply += chunk
    return reply.decode("latin-1")


def _pem_from_header(text: str) -> str:
    return "\n".join(re.findall(r'"([^"]*)\\n"', text))


# --- the certificate --------------------------------------------------------

def test_a_new_atlas_certificate_names_the_device_host_and_the_bank_does_not(pki):
    atlas = x509.load_pem_x509_certificate((pki / "atlas.crt").read_bytes())
    bank = x509.load_pem_x509_certificate((pki / "bank.crt").read_bytes())
    assert set(make_dev_ca.dns_names(atlas)) == {"localhost", DEVICE_HOST}
    assert make_dev_ca.dns_names(bank) == ["localhost"]      # least privilege: only ATLAS needs it


# --- the handshake the device makes -----------------------------------------

def test_the_device_reaches_atlas_over_verified_tls(pki):
    with _Served(pki) as port:
        reply = _device_get(port, pki)
    assert reply.startswith("HTTP/1.1 200") and reply.endswith("atlas")


def test_the_device_refuses_a_server_from_another_ca(pki, other_pki):
    with _Served(other_pki) as port:
        with pytest.raises(ssl.SSLCertVerificationError):
            _device_get(port, pki)


def test_the_device_refuses_a_server_that_does_not_carry_its_name(pki):
    with _Served(pki) as port:
        with pytest.raises(ssl.SSLCertVerificationError):
            _device_get(port, pki, host="atlas.attacker.example")


def test_plain_http_to_the_tls_listener_gets_no_decision(pki):
    with _Served(pki) as port:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(b"POST /v2/transact HTTP/1.1\r\nHost: host.wokwi.internal\r\n"
                      b"Content-Length: 2\r\nConnection: close\r\n\r\n{}")
            try:
                reply = s.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError):
                reply = b""
    assert b"final_status" not in reply and not reply.startswith(b"HTTP/1.1 200")


# --- upgrading a PKI that already exists --------------------------------------

def test_reissue_adds_the_name_and_changes_nothing_else(pki):
    make_dev_ca.issue(pki, "atlas", "localhost", server=True)       # an atlas.crt from before 2026-09-27
    assert not make_dev_ca.atlas_names_device_host(pki)
    untouched = ("ca.crt", "ca.key", "bank.crt", "bank.key", "atlas-client.crt",
                 "atlas-client.key", make_dev_ca.PASSWORD_FILE)
    before = {n: (pki / n).read_bytes() for n in untouched}
    old = {n: (pki / n).read_bytes() for n in ("atlas.crt", "atlas.key")}

    written = make_dev_ca.reissue_atlas(pki)

    assert make_dev_ca.atlas_names_device_host(pki)
    assert {n: (pki / n).read_bytes() for n in untouched} == before
    for name in ("atlas.crt", "atlas.key"):
        backup = [w for w in written if w.startswith(name + ".replaced-")]
        assert len(backup) == 1 and (pki / backup[0]).read_bytes() == old[name]
    assert b"ENCRYPTED PRIVATE KEY" in (pki / "atlas.key").read_bytes()
    with _Served(pki) as port:                                       # and it really serves
        assert _device_get(port, pki).endswith("atlas")


# --- the header the firmware compiles in --------------------------------------

def test_the_firmware_header_is_exactly_the_public_ca(pki, other_pki, tmp_path):
    header = make_dev_ca.firmware_header(pki, tmp_path / "atlas_ca.h")
    text = header.read_text(encoding="ascii")
    assert _pem_from_header(text) == (pki / "ca.crt").read_text(encoding="ascii").strip()
    assert "PRIVATE" not in text and "ATLAS_CA_PEM" in text
    assert make_dev_ca.firmware_header_is_current(pki, header)
    assert not make_dev_ca.firmware_header_is_current(other_pki, header)


def test_no_ca_header_is_tracked_and_the_identity_folder_is_ignored():
    """2026-10-09: the tracked atlas_ca.example.h placeholder was removed with the
    compiled-in CA; the device reads the real CA from NVS. Both the old header name and
    the identity image's folder stay git-ignored."""
    assert not (SKETCH_DIR / "atlas_ca.example.h").exists()
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "firmware/atlas_device/atlas_ca.h" in ignored and "firmware/atlas_device/local/" in ignored
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "firmware/atlas_device"],
                             capture_output=True, text=True, check=True).stdout.split()
    assert "firmware/atlas_device/atlas_ca.h" not in tracked


# --- the firmware source --------------------------------------------------------

def test_the_sketch_sends_only_over_verified_https():
    src = (SKETCH_DIR / "atlas_device.ino").read_text(encoding="utf-8")
    code = re.sub(r"(^|\s)//[^\n]*", r"\1", src)                 # comments may mention anything
    assert 'ATLAS_URL = "https://host.wokwi.internal:8000"' in code
    assert "http://" not in code
    # Since 2026-10-09 the CA's public certificate is loaded from NVS with the device
    # identity (scripts/provision_nvs.py) instead of the gitignored atlas_ca.h, so a
    # firmware built anywhere carries no machine-specific material. Still verified on
    # every request; still no fallback.
    assert '#include "atlas_ca.h"' not in code and "#include <WiFiClientSecure.h>" in code
    assert 'id.getString("ca_pem", ATLAS_CA_PEM, sizeof(ATLAS_CA_PEM))' in code
    assert "tls.setCACert(ATLAS_CA_PEM);" in code
    assert "setInsecure" not in code and "setCACertBundle" not in code
    assert "http.begin(tls, url)" in code and "http.begin(url)" not in code
    assert code.index("WiFiClientSecure tls;") < code.index("HTTPClient http;")   # outlives http


# --- the simulation launcher ---------------------------------------------------

def test_run_sim_serves_atlas_over_tls():
    src = (ROOT / "scripts" / "run_sim.py").read_text(encoding="utf-8")
    assert '("atlas_service", ["atlas", "--port", "8000", "--tls"])' in src
    assert "http://127.0.0.1:8000" not in src


def test_run_sim_names_the_command_that_fixes_missing_device_tls(pki, tmp_path):
    """Since 2026-10-09 the device reads the CA from its NVS identity image, so the
    preflight checks that image's public manifest instead of atlas_ca.h."""
    import hashlib
    import json
    make_dev_ca.issue(pki, "atlas", "localhost", server=True)       # old certificate, no image
    manifest = tmp_path / "identity.json"
    problems = run_sim.device_tls_problems(pki, manifest)
    assert len(problems) == 2
    assert "--reissue-atlas" in problems[0] and "provision_nvs.py" in problems[1]
    make_dev_ca.reissue_atlas(pki)
    manifest.write_text(json.dumps({"ca_sha256": "0" * 64}), encoding="utf-8")       # another CA
    assert run_sim.device_tls_problems(pki, manifest) == [problems[1]]
    ca_sha = hashlib.sha256((pki / "ca.crt").read_text(encoding="ascii").encode("ascii")).hexdigest()
    manifest.write_text(json.dumps({"ca_sha256": ca_sha}), encoding="utf-8")
    assert run_sim.device_tls_problems(pki, manifest) == []
