"""Serve one ATLAS service with uvicorn, over TLS unless told otherwise.

    python scripts/serve.py bank  --port 8100 --tls --require-client-cert
    python scripts/serve.py atlas --port 8000 --tls
    python scripts/serve.py atlas --port 8000              # plain HTTP, loopback only

run_dev.py and run_sim.py start the services through this script rather than
`python -m uvicorn ... --ssl-keyfile-password ...`, because the password that
unlocks the TLS private keys must not appear on a command line (where any
process listing shows it) or in an environment variable. Here it is decrypted by
keystore.py inside the serving process and handed straight to uvicorn.

atlas_service/transport.py still decides what may be served in the clear:
plain HTTP only on loopback (or with the named development override).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

APPS = {"atlas": "atlas_service.main:app", "bank": "bank_service.main:app"}


def build_config(service: str, host: str, port: int, *, use_tls: bool,
                 require_client_cert: bool, certs_dir: Path | None = None):
    import uvicorn

    from atlas_service import tls, transport

    posture = transport.check_bind(host, tls=use_tls, what=f"{service}_service listener")
    settings = (tls.server_settings(service, certs_dir, require_client_cert=require_client_cert)
                if use_tls else {})
    config = uvicorn.Config(APPS[service], host=host, port=port, log_level="info", **settings)
    mtls = " (clients must present a certificate from the local CA)" if use_tls and require_client_cert else ""
    if tls.is_production():
        # TLS 1.3 only, client certificates checked against the CRL (2026-09-25).
        tls.harden_server_config(config, certs_dir)
        posture += "; production profile: TLS 1.3 only, CRL checked"
    return config, posture + mtls


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    from atlas_service.tls import TLSMaterialError
    from atlas_service.transport import InsecureTransportError

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("service", choices=sorted(APPS))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tls", action="store_true", help="serve HTTPS with the local test CA's certificate")
    ap.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    args = ap.parse_args(argv)
    try:
        config, posture = build_config(args.service, args.host, args.port, use_tls=args.tls,
                                       require_client_cert=args.require_client_cert)
    except (InsecureTransportError, TLSMaterialError) as exc:
        print(f"[serve] {exc}")
        return 2
    print(f"[serve] {posture}")
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
