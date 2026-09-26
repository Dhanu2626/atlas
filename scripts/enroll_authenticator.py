"""Enrol a customer's out-of-band step-up authenticator, and sign proofs with it.

WHAT THIS STANDS IN FOR
-----------------------
In a real deployment the authenticator is the customer's phone: it holds the
key in a secure enclave, and a fingerprint or face unlocks the ability to sign.
ATLAS never sees the biometric -- it sees a signature.

Here it is a key in a gitignored directory, encrypted at rest by keystore.py
(since 2026-09-22), driven from the command line. That
proves the PROTOCOL, not that a real second factor was present, exactly the
same honesty the project applies to `secure_element_present=False`. Do not
present a demo of this as evidence of real multi-factor authentication.

WHAT ATLAS STORES
-----------------
The PUBLIC key only. No PIN, no OTP secret, no biometric template ever reaches
the service, so none can leak from it.

USAGE
-----
    python scripts/enroll_authenticator.py enroll --subject user-demo-1
    python scripts/enroll_authenticator.py sign \\
        --challenge-id <id> --transaction-id <id> --envelope-hash <hex>
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

import keystore  # noqa: E402
from atlas_service.main import STEP_UP_DB_PATH  # noqa: E402
from atlas_service.step_up.db import StepUpStore  # noqa: E402
from atlas_service.step_up.service import proof_message  # noqa: E402

#: Gitignored via the existing `device_keys*/` rule.
DEFAULT_KEYS_DIR = ATLAS_ROOT / "firmware" / "device_keys_authenticator"


def _key_path(keys_dir: Path) -> Path:
    return keys_dir / "authenticator_ed25519.key"


def _load_or_create(keys_dir: Path) -> Ed25519PrivateKey:
    path = _key_path(keys_dir)
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(
            keystore.read_secret(path, "authenticator-signing"))
    key = Ed25519PrivateKey.generate()
    keystore.write_secret(path, key.private_bytes_raw(), "authenticator-signing")
    return key


def cmd_enroll(args: argparse.Namespace) -> int:
    keys_dir = Path(args.keys_dir)
    key = _load_or_create(keys_dir)
    public_hex = key.public_key().public_bytes_raw().hex()

    store = StepUpStore(args.db)
    store.enroll_authenticator(
        args.subject, public_hex, datetime.now(timezone.utc).isoformat()
    )
    print("  [DEMO AUTHENTICATOR -- proves key possession, not a real second factor]")
    print(f"  subject     : {args.subject}")
    print(f"  public key  : {public_hex[:32]}...")
    print(f"  private key : {_key_path(keys_dir)}")
    print("                ^ ORDINARY FILE. A real authenticator keeps this in a")
    print("                  secure enclave behind a biometric. This one does not.")
    print("  ATLAS stores the PUBLIC key only. It never had the private one.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key = _load_or_create(Path(args.keys_dir))
    message = proof_message(args.challenge_id, args.transaction_id, args.envelope_hash)
    print(key.sign(message).hex())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=str(STEP_UP_DB_PATH))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("enroll", help="register this authenticator's PUBLIC key")
    p.add_argument("--subject", required=True)
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("sign", help="sign a step-up challenge; prints the proof hex")
    p.add_argument("--challenge-id", required=True)
    p.add_argument("--transaction-id", required=True)
    p.add_argument("--envelope-hash", required=True)
    p.set_defaults(func=cmd_sign)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
