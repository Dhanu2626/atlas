"""ATLAS -> bank over TLS with mutual authentication (2026-09-22).

Every test here talks to a REAL uvicorn server on loopback, speaking real TLS
with certificates from a throwaway copy of the local test PKI
(scripts/make_dev_ca.py) -- no mocked handshake. What is pinned:

  * a verified mutual-TLS handshake succeeds;
  * an untrusted server certificate, a hostname mismatch, a missing client
    certificate and a client certificate from another CA all fail;
  * plain HTTP to the TLS port gets nowhere, and missing TLS material makes the
    client refuse instead of falling back to http;
  * the normal payment path completes over mutual TLS, and a TLS failure settles
    PENDING -- never an approval;
  * every TLS private key is encrypted PEM whose password is keystore-protected,
    and the certificates carry no near-term expiry that would break the project.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from fastapi.testclient import TestClient

import keystore
from atlas_service import crypto, tls
from atlas_service import main as atlas_main
from atlas_service.db import TransactionStore
from bank_service.main import app as bank_app
from bank_service.main import get_atlas_public_key, get_replay_cache
from bank_service.replay_cache import ReplayCache
from contracts import TxnState

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import make_dev_ca  # noqa: E402
import serve  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pki")
    make_dev_ca.create_pki(folder)
    return folder


@pytest.fixture(scope="module")
def other_pki(tmp_path_factory):
    """A second, unrelated CA -- what an impostor would have."""
    folder = tmp_path_factory.mktemp("other-pki")
    make_dev_ca.create_pki(folder)
    return folder


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _LiveServer:
    def __init__(self, app, **ssl_settings):
        self.port = _free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port,
                                                    log_level="warning", **ssl_settings))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

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
def atlas_keys(tmp_path):
    keys = tmp_path / "atlas-keys"
    crypto.init_device(keys_dir=keys)
    return keys


@pytest.fixture
def tls_bank(pki, atlas_keys, tmp_path):
    public_key = crypto.get_public_key(keys_dir=atlas_keys)
    bank_app.dependency_overrides[get_atlas_public_key] = lambda: public_key
    bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
    try:
        with _LiveServer(bank_app, **tls.server_settings("bank", pki, require_client_cert=True)) as url:
            yield url
    finally:
        bank_app.dependency_overrides.clear()
        atlas_main.app.dependency_overrides.clear()


def test_a_verified_mutual_tls_handshake_succeeds(pki, tls_bank):
    with httpx.Client(verify=tls.client_context(pki)) as client:
        reply = client.get(f"{tls_bank}/status/never-seen")
    assert reply.status_code == 200 and reply.json()["status"] == "NOT_FOUND"


def test_an_untrusted_server_certificate_is_refused(pki, other_pki, tls_bank):
    with httpx.Client(verify=tls.client_context(other_pki)) as client:
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
            client.get(f"{tls_bank}/status/x")


def test_a_hostname_mismatch_is_refused(pki, tls_bank):
    port = int(tls_bank.rsplit(":", 1)[1])
    ctx = tls.client_context(pki)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(sock, server_hostname="not-the-bank.example")


def test_a_client_without_a_certificate_is_refused(pki, tls_bank):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    with httpx.Client(verify=ctx) as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"{tls_bank}/status/x")


def test_a_client_certificate_from_another_ca_is_refused(pki, other_pki, tls_bank):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    ctx.load_cert_chain(str(other_pki / "atlas-client.crt"), str(other_pki / "atlas-client.key"),
                        password=tls.key_password(other_pki))
    with httpx.Client(verify=ctx) as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"{tls_bank}/status/x")


def test_plain_http_to_the_tls_port_gets_no_answer(tls_bank):
    with httpx.Client(timeout=5) as client:
        try:
            reply = client.get(tls_bank.replace("https://", "http://") + "/status/x")
        except httpx.TransportError:
            return
    assert reply.status_code >= 400 or "status" not in reply.text


def _payment(txn_id: str) -> dict:
    return {
        "transaction_id": txn_id, "subject": "user-demo-1", "amount": "1500.00", "currency": "INR",
        "beneficiary": "ben-mother", "location": "Hyderabad,IN", "device_id": "device-primary-01",
        "merchant_category": "transfer", "authentication_method": "pin",
        "is_new_beneficiary": False, "is_new_device": False, "is_international": False,
        "declared_travel_mode": False, "is_emergency_request": False,
        "timestamp": "2026-09-22T04:30:00+00:00",   # 10:00 IST: no odd_hours rule
    }


def _pipeline(monkeypatch, tmp_path, url, client, atlas_keys):
    store = TransactionStore(tmp_path / "atlas.db")
    monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", url)
    atlas_main.app.dependency_overrides.update({
        atlas_main.get_bank_client: lambda: client,
        atlas_main.get_transaction_store: lambda: store,
        atlas_main.get_signing_keys_dir: lambda: atlas_keys,
        atlas_main.get_require_device_auth: lambda: False,
    })
    return store


def test_the_payment_path_completes_over_mutual_tls(monkeypatch, tmp_path, pki, tls_bank, atlas_keys):
    with httpx.Client(verify=tls.client_context(pki)) as client:
        store = _pipeline(monkeypatch, tmp_path, tls_bank, client, atlas_keys)
        body = TestClient(atlas_main.app).post("/transact", json=_payment("tls-e2e-1")).json()
    assert body["final_status"] == "ALLOW"
    assert body["bank_verdict"]["approved"] is True
    assert store.get_state("tls-e2e-1") == TxnState.CONFIRMED
    store.close()


def test_a_tls_failure_settles_pending_never_approval(monkeypatch, tmp_path, other_pki, tls_bank, atlas_keys):
    with httpx.Client(verify=tls.client_context(other_pki)) as impostor_trust:
        store = _pipeline(monkeypatch, tmp_path, tls_bank, impostor_trust, atlas_keys)
        body = TestClient(atlas_main.app).post("/transact", json=_payment("tls-fail-1")).json()
    assert (body["final_status"], body["decision_reason"]) == ("PENDING", "BANK_UNREACHABLE")
    assert body["bank_verdict"] is None
    assert store.get_state("tls-fail-1") == TxnState.UNKNOWN
    store.close()


def test_missing_tls_material_refuses_instead_of_falling_back(monkeypatch, tmp_path):
    monkeypatch.setattr(tls, "DEFAULT_CERTS_DIR", tmp_path / "no-certs")
    monkeypatch.setattr(atlas_main, "BANK_SERVICE_URL", "https://127.0.0.1:1")
    monkeypatch.setitem(atlas_main._BANK_TLS, "context", None)
    generator = atlas_main.get_bank_client()
    client = next(generator)
    try:
        with pytest.raises(httpx.ConnectError, match="TLS to the bank unavailable"):
            client.post("https://127.0.0.1:1/verify", json={})
        assert not isinstance(client._transport, httpx.HTTPTransport), \
            "the client fell back to an ordinary (plaintext-capable) transport"
    finally:
        generator.close()


def test_tls_private_keys_are_encrypted_and_their_password_is_protected(pki):
    for key_file in sorted(pki.glob("*.key")):
        if key_file.name == tls.PASSWORD_FILE:
            continue
        assert key_file.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"), key_file.name
    assert keystore.is_protected(pki / tls.PASSWORD_FILE)
    ctx = ssl.create_default_context()
    with pytest.raises(ssl.SSLError):
        ctx.load_cert_chain(str(pki / "atlas-client.crt"), str(pki / "atlas-client.key"), password=b"wrong")


def test_the_local_pki_carries_no_near_term_expiry(pki):
    horizon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=9 * 365)
    for cert_file in sorted(pki.glob("*.crt")):
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        assert cert.not_valid_after_utc > horizon, f"{cert_file.name} would expire and break the project"


def test_the_launcher_refuses_plain_http_off_loopback_and_serves_tls(pki):
    from atlas_service.transport import InsecureTransportError
    with pytest.raises(InsecureTransportError):
        serve.build_config("atlas", "0.0.0.0", 8000, use_tls=False, require_client_cert=False)
    config, posture = serve.build_config("bank", "0.0.0.0", 8100, use_tls=True,
                                         require_client_cert=True, certs_dir=pki)
    assert "TLS" in posture and "certificate from the local CA" in posture
    assert config.ssl_cert_reqs == ssl.CERT_REQUIRED
