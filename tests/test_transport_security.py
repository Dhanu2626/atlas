"""D6 (2026-09-18): insecure transport must be a deliberate, checked choice.

ATLAS is a loopback prototype and does not claim a production TLS deployment.
What these tests pin is that it cannot drift into one by accident: a
non-loopback address without TLS is refused rather than served, the escape
hatch is explicit and named, no source file points at a plaintext remote host,
and a refused step-up still hands back no risk evidence.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from atlas_service.transport import (
    ALLOW_INSECURE_ENV,
    InsecureTransportError,
    allow_insecure_http,
    check_bind,
    check_outbound_url,
    is_loopback,
)

ATLAS_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("atlas_service", "bank_service", "scripts", "firmware", "tests")


@pytest.fixture(autouse=True)
def _no_insecure_flag(monkeypatch):
    """Every test states its own posture; none inherits the developer's shell."""
    monkeypatch.delenv(ALLOW_INSECURE_ENV, raising=False)


@pytest.mark.parametrize("host,loopback", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True), ("127.5.6.7", True),
    ("host.wokwi.internal", True), ("0.0.0.0", False), ("192.168.1.10", False),
    ("bank.example.com", False), ("", False), (None, False),
])
def test_what_counts_as_staying_on_this_machine(host, loopback):
    assert is_loopback(host) is loopback


@pytest.mark.parametrize("url", [
    "https://bank.example.com", "https://127.0.0.1:8100",
    "http://127.0.0.1:8100", "http://localhost:8100", "http://host.wokwi.internal:8000",
])
def test_tls_or_loopback_is_allowed(url):
    assert check_outbound_url(url)


@pytest.mark.parametrize("url", [
    "http://bank.example.com:8100", "http://192.168.1.10:8100", "http://0.0.0.0:8100",
])
def test_plaintext_to_a_remote_host_is_refused(url):
    with pytest.raises(InsecureTransportError, match="plain HTTP"):
        check_outbound_url(url)


@pytest.mark.parametrize("url", ["ftp://bank.example.com", "file:///etc/passwd", "bank.example.com"])
def test_a_url_that_is_neither_http_nor_https_is_refused(url):
    with pytest.raises(InsecureTransportError):
        check_outbound_url(url)


def test_the_escape_hatch_is_explicit_named_and_off_by_default(monkeypatch):
    assert allow_insecure_http() is False
    with pytest.raises(InsecureTransportError):
        check_outbound_url("http://192.168.1.10:8100")

    monkeypatch.setenv(ALLOW_INSECURE_ENV, "1")

    assert allow_insecure_http() is True
    assert "INSECURE" in check_outbound_url("http://192.168.1.10:8100"), (
        "the allowed-but-insecure case must still announce itself"
    )


@pytest.mark.parametrize("value", ["", "0", "yes", "true", "TRUE"])
def test_only_exactly_one_opens_the_escape_hatch(monkeypatch, value):
    monkeypatch.setenv(ALLOW_INSECURE_ENV, value)
    with pytest.raises(InsecureTransportError):
        check_outbound_url("http://192.168.1.10:8100")


def test_a_listener_off_loopback_needs_tls():
    assert check_bind("127.0.0.1", tls=False)
    assert check_bind("0.0.0.0", tls=True)
    with pytest.raises(InsecureTransportError, match="without TLS"):
        check_bind("0.0.0.0", tls=False)


def test_the_service_refuses_to_start_pointed_at_a_plaintext_remote_bank(monkeypatch):
    """The check runs first in the lifespan, before anything is published or
    settled, so an insecure deployment fails at startup instead of after its
    first signed decision has already crossed the network."""
    import atlas_service.main as main_mod

    monkeypatch.setattr(main_mod, "BANK_SERVICE_URL", "http://bank.example.com:8100")
    monkeypatch.setattr(main_mod, "publish_public_key",
                        lambda *a, **k: pytest.fail("startup continued past the transport check"))
    monkeypatch.setattr(main_mod, "resolve_stale_step_ups",
                        lambda *a, **k: pytest.fail("startup continued past the transport check"))

    with pytest.raises(InsecureTransportError):
        from fastapi.testclient import TestClient
        with TestClient(main_mod.app):
            pass


def test_the_shipped_default_bank_url_is_tls_to_loopback():
    """Strengthened 2026-09-22. It used to pin plain HTTP on loopback; the default
    is now HTTPS (verified, mutual TLS -- atlas_service/tls.py) and must still
    point at this machine."""
    from urllib.parse import urlsplit

    import atlas_service.main as main_mod

    assert main_mod.BANK_SERVICE_URL.startswith("https://")
    assert "TLS to" in check_outbound_url(main_mod.BANK_SERVICE_URL)
    assert is_loopback(urlsplit(main_mod.BANK_SERVICE_URL).hostname)


def _plaintext_urls(path: Path) -> list[str]:
    """Plaintext URLs that could reach a network host.

    A single-label host with no dot -- "http://atlas", "http://bank" -- is an
    in-process ASGI base URL handed to a TestClient transport; nothing is
    resolved and no socket is opened. Loopback names and addresses stay on this
    machine. Anything else is a real destination.
    """
    found = []
    for match in re.finditer(r"http://([A-Za-z0-9_.\-]+)", path.read_text(encoding="utf-8", errors="replace")):
        host = match.group(1)
        if is_loopback(host) or "." not in host:
            continue
        found.append(match.group(0))
    return found


@pytest.mark.parametrize("folder", SOURCE_DIRS)
def test_no_source_file_points_at_a_plaintext_remote_host(folder):
    """A hardcoded http:// URL to somewhere other than this machine is how a
    prototype quietly ends up shipping cleartext. Documentation and tests may
    name example.com; code may not reach it."""
    offenders = {}
    for directory, subdirectories, files in os.walk(ATLAS_ROOT / folder):
        # Prune rather than filter. Walking into a key directory or the build
        # output lists a developer's private material even when nothing is
        # read, and reading secrets.h to look for URLs is what the file-access
        # audit caught this scan doing on 2026-09-18.
        subdirectories[:] = [d for d in subdirectories
                             if d not in ("__pycache__", "build", "keys", "shared_keys")
                             and not d.startswith("device_keys")]
        for name in files:
            if not name.endswith((".py", ".ino", ".h", ".cpp")):
                continue
            if name in ("test_transport_security.py", "secrets.h"):
                continue  # one names example.com on purpose, the other is a private seed
            path = Path(directory) / name
            urls = _plaintext_urls(path)
            if urls:
                offenders[str(path.relative_to(ATLAS_ROOT))] = urls

    assert offenders == {}, f"plaintext remote URLs in source: {offenders}"


def test_the_firmware_says_its_transport_is_simulation_only():
    """The sketch talks to the Wokwi gateway in the clear. That is a documented
    simulation posture, and the file has to say so where the URL is set."""
    sketch = (ATLAS_ROOT / "firmware" / "atlas_device" / "atlas_device.ino").read_text(
        encoding="utf-8", errors="replace")
    url_line = next(line for line in sketch.splitlines() if "ATLAS_URL" in line and "http" in line)
    host = re.search(r"http://([A-Za-z0-9_.\-]+)", url_line).group(1)

    assert is_loopback(host), f"the firmware points at {host}, which is not this machine"
    assert re.search(r"no TLS|not encrypted|simulation only|plaintext", sketch, re.I), (
        "the sketch does not state that its transport is unencrypted"
    )
