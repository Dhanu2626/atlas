"""The PRODUCTION transport profile, against real TLS servers (2026-09-25).

ATLAS_TRANSPORT_PROFILE=production (atlas_service/tls.py): TLS 1.3 only, the CA's
CRL checked on every handshake in both directions, the bank's public key pinned
before any request byte is written, no plain HTTP at all, and refusal -- never
degradation -- when any of that material is missing.

Every test runs a real uvicorn server on loopback with a throwaway PKI from
scripts/make_dev_ca.py. Where it matters, a DEVELOPMENT-profile control is run
against the same server, so each test shows which production setting made the
difference rather than something else failing.

What this does not show, and the documentation says so: a publicly or
enterprise-trusted certificate, OCSP run by an institution, or a CA key in an HSM.
The CA, its CRL and the pin are all local.
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from atlas_service import crypto, tls, transport
from atlas_service import main as atlas_main
from bank_service.main import app as bank_app
from bank_service.main import get_atlas_public_key, get_replay_cache
from bank_service.replay_cache import ReplayCache
from contracts import TxnState
from tests.test_tls import _payment, _pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import make_dev_ca  # noqa: E402
import serve  # noqa: E402


@pytest.fixture
def pki(tmp_path):
    """A fresh PKI per test: some tests revoke certificates."""
    folder = tmp_path / "pki"
    make_dev_ca.create_pki(folder)
    return folder


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv(tls.PROFILE_ENV, "production")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    """A real uvicorn server from a prepared (possibly hardened) Config."""

    def __init__(self, config: uvicorn.Config):
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = config.port

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("TLS test server did not start")
            time.sleep(0.05)
        return f"https://127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=15)


@pytest.fixture
def bank_calls(tmp_path):
    """Wires the bank to a throwaway ATLAS key and COUNTS /verify requests that
    reached the application -- the proof that a refused handshake sent nothing."""
    keys = tmp_path / "atlas-keys"
    crypto.init_device(keys_dir=keys)
    public_key = crypto.get_public_key(keys_dir=keys)
    calls = {"verify": 0, "keys": keys}

    def counted_key():
        calls["verify"] += 1
        return public_key

    bank_app.dependency_overrides[get_atlas_public_key] = counted_key
    bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
    yield calls
    bank_app.dependency_overrides.clear()
    atlas_main.app.dependency_overrides.clear()


def _bank_config(pki: Path, *, cert: str = "bank", harden: bool, max_tls12: bool = False):
    settings = tls.server_settings("bank", pki, require_client_cert=True)
    settings["ssl_certfile"] = str(pki / f"{cert}.crt")
    settings["ssl_keyfile"] = str(pki / f"{cert}.key")
    config = uvicorn.Config(bank_app, host="127.0.0.1", port=_free_port(), log_level="warning",
                            **settings)
    if harden:
        tls.harden_server_config(config, pki)
    if max_tls12:
        if not config.loaded:
            config.load()
        config.ssl.maximum_version = ssl.TLSVersion.TLSv1_2
    return config


def _production_client(pki: Path) -> httpx.Client:
    return httpx.Client(transport=tls.pinned_bank_transport(pki))


def _development_client(pki: Path) -> httpx.Client:
    return httpx.Client(verify=tls.client_context(pki, production=False))


def _pay(monkeypatch, tmp_path, url, client, keys, txn_id):
    store = _pipeline(monkeypatch, tmp_path, url, client, keys)
    body = TestClient(atlas_main.app).post("/transact", json=_payment(txn_id)).json()
    state = store.get_state(txn_id)
    store.close()
    return body, state


# ---- the profile working ------------------------------------------------------------

def test_a_payment_completes_under_the_production_profile_over_tls_1_3(
        monkeypatch, tmp_path, pki, production, bank_calls):
    with _Server(_bank_config(pki, harden=True)) as url:
        with _production_client(pki) as client:
            body, state = _pay(monkeypatch, tmp_path, url, client, bank_calls["keys"], "prod-ok-1")
        ctx = tls.client_context(pki, production=True)
        with socket.create_connection(("127.0.0.1", int(url.rsplit(":", 1)[1])), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls_sock:
                negotiated = tls_sock.version()
    assert body["final_status"] == "ALLOW" and body["bank_verdict"]["approved"] is True
    assert state == TxnState.CONFIRMED
    assert negotiated == "TLSv1.3"


def test_the_real_bank_client_dependency_uses_the_pinned_transport(
        monkeypatch, pki, production, bank_calls):
    """Not a hand-built client: atlas_service's own get_bank_client(), in the
    production profile, against a server presenting a certificate the CA really
    issued -- but not the pinned one."""
    make_dev_ca.issue(pki, "bank-rogue", "localhost", server=True)
    monkeypatch.setattr(tls, "DEFAULT_CERTS_DIR", pki)
    with _Server(_bank_config(pki, cert="bank-rogue", harden=True)) as url:
        monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", url)
        generator = atlas_main.get_bank_client()
        client = next(generator)
        try:
            with pytest.raises(httpx.ConnectError, match="pinned public key"):
                client.get(f"{url}/status/x")
        finally:
            generator.close()
    assert bank_calls["verify"] == 0


# ---- pinning -------------------------------------------------------------------------

def test_a_certificate_the_ca_mis_issued_is_refused_by_the_pin_before_anything_is_sent(
        monkeypatch, tmp_path, pki, production, bank_calls):
    make_dev_ca.issue(pki, "bank-rogue", "localhost", server=True)
    with _Server(_bank_config(pki, cert="bank-rogue", harden=True)) as url:
        with _development_client(pki) as control:              # CA-valid, not revoked
            assert control.get(f"{url}/status/x").status_code == 200
        with _production_client(pki) as client:
            body, state = _pay(monkeypatch, tmp_path, url, client, bank_calls["keys"], "prod-pin-1")
    assert (body["final_status"], body["decision_reason"]) == ("PENDING", "BANK_UNREACHABLE")
    assert body["bank_verdict"] is None and state == TxnState.UNKNOWN
    assert bank_calls["verify"] == 0, "the signed assertion reached a server that failed the pin"


# ---- revocation ----------------------------------------------------------------------

def test_a_revoked_bank_certificate_is_refused(monkeypatch, tmp_path, pki, production, bank_calls):
    make_dev_ca.revoke(pki, "bank")
    with _Server(_bank_config(pki, harden=False)) as url:
        with _development_client(pki) as control:              # no CRL: still connects
            assert control.get(f"{url}/status/x").status_code == 200
        with _production_client(pki) as client:
            with pytest.raises(httpx.ConnectError, match="revoked"):
                client.get(f"{url}/status/x")
            body, state = _pay(monkeypatch, tmp_path, url, client, bank_calls["keys"], "prod-rev-1")
    assert (body["final_status"], body["decision_reason"]) == ("PENDING", "BANK_UNREACHABLE")
    assert state == TxnState.UNKNOWN


def test_a_revoked_atlas_client_certificate_is_refused_by_the_hardened_bank(pki, bank_calls):
    make_dev_ca.revoke(pki, "atlas-client")
    with _Server(_bank_config(pki, harden=False)) as url:       # control: no CRL server-side
        with _development_client(pki) as client:
            assert client.get(f"{url}/status/x").status_code == 200
    with _Server(_bank_config(pki, harden=True)) as url:
        with _development_client(pki) as client:
            with pytest.raises(httpx.TransportError):
                client.get(f"{url}/status/x")


def test_an_expired_bank_certificate_is_refused(pki, production, bank_calls):
    make_dev_ca.issue(pki, "bank-expired", "localhost", server=True, expired=True)
    make_dev_ca.write_pin(pki, "bank-expired")
    (pki / "bank-expired.pin").replace(pki / "bank.pin")        # the pin is not what stops it
    with _Server(_bank_config(pki, cert="bank-expired", harden=True)) as url:
        with _production_client(pki) as client:
            with pytest.raises(httpx.ConnectError, match="expired"):
                client.get(f"{url}/status/x")


# ---- TLS 1.3 only --------------------------------------------------------------------

def test_a_server_that_only_speaks_tls_1_2_is_refused(pki, production, bank_calls):
    with _Server(_bank_config(pki, harden=False, max_tls12=True)) as url:
        with _development_client(pki) as control:
            assert control.get(f"{url}/status/x").status_code == 200
        with _production_client(pki) as client:
            with pytest.raises(httpx.ConnectError):
                client.get(f"{url}/status/x")


def test_the_hardened_bank_refuses_a_tls_1_2_client(pki, bank_calls):
    ctx = tls.client_context(pki, production=False)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with _Server(_bank_config(pki, harden=True)) as url:
        with httpx.Client(verify=ctx) as client:
            with pytest.raises(httpx.TransportError):
                client.get(f"{url}/status/x")


def test_the_launcher_hardens_the_bank_in_the_production_profile(pki, production):
    config, posture = serve.build_config("bank", "127.0.0.1", _free_port(), use_tls=True,
                                         require_client_cert=True, certs_dir=pki)
    assert config.ssl.minimum_version == ssl.TLSVersion.TLSv1_3
    assert config.ssl.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert "production profile" in posture


# ---- no plain HTTP, and refusal on missing material ------------------------------------

def test_production_refuses_plain_http_even_on_loopback_and_ignores_the_override(
        monkeypatch, production):
    monkeypatch.setenv(transport.ALLOW_INSECURE_ENV, "1")
    with pytest.raises(transport.InsecureTransportError):
        transport.check_outbound_url("http://127.0.0.1:8100", what="bank client")
    with pytest.raises(transport.InsecureTransportError):
        transport.check_bind("127.0.0.1", tls=False)
    with pytest.raises(transport.InsecureTransportError):
        serve.build_config("atlas", "127.0.0.1", 8000, use_tls=False, require_client_cert=False)


def test_development_is_unchanged_by_the_production_code(monkeypatch):
    monkeypatch.delenv(tls.PROFILE_ENV, raising=False)
    assert "loopback" in transport.check_outbound_url("http://127.0.0.1:8100")
    assert "loopback" in transport.check_bind("127.0.0.1", tls=False)


@pytest.mark.parametrize("missing", [tls.CRL_FILE, tls.BANK_PIN_FILE])
def test_missing_production_material_refuses_instead_of_degrading(
        monkeypatch, pki, production, missing):
    (pki / missing).unlink()
    with pytest.raises(tls.TLSMaterialError):
        tls.pinned_bank_transport(pki)
    monkeypatch.setattr(tls, "DEFAULT_CERTS_DIR", pki)
    monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", "https://127.0.0.1:1")
    generator = atlas_main.get_bank_client()
    client = next(generator)
    try:
        with pytest.raises(httpx.ConnectError, match="TLS to the bank unavailable"):
            client.post("https://127.0.0.1:1/verify", json={})
    finally:
        generator.close()


def test_the_service_refuses_to_start_without_production_material(monkeypatch, pki, production):
    (pki / tls.BANK_PIN_FILE).unlink()
    monkeypatch.setattr(tls, "DEFAULT_CERTS_DIR", pki)
    monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", "https://127.0.0.1:1")
    with pytest.raises(tls.TLSMaterialError):
        with TestClient(atlas_main.app):
            pass


def test_production_refuses_a_plain_http_bank_url(monkeypatch, production):
    monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", "http://127.0.0.1:8100")
    generator = atlas_main.get_bank_client()
    client = next(generator)
    try:
        with pytest.raises(httpx.ConnectError, match="plain HTTP"):
            client.post("http://127.0.0.1:8100/verify", json={})
    finally:
        generator.close()


def test_an_unknown_profile_value_never_reads_as_development(monkeypatch):
    monkeypatch.setenv(tls.PROFILE_ENV, "prod")                  # a typo
    with pytest.raises(tls.TLSMaterialError):
        tls.transport_profile()
    generator = atlas_main.get_bank_client()
    client = next(generator)
    try:
        with pytest.raises(httpx.ConnectError):
            client.post("http://127.0.0.1:8100/verify", json={})
    finally:
        generator.close()
