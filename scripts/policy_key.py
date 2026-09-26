"""Policy owner keys: create, sign, enrol, verify (2026-09-27).

    python scripts/policy_key.py create user-demo-1     # new owner key, keystore-protected
    python scripts/policy_key.py sign   user-demo-1     # writes policies/user-demo-1.yaml.sig and .pub
    python scripts/policy_key.py enroll user-demo-1     # trusts policies/user-demo-1.pub in ATLAS's state
    python scripts/policy_key.py verify user-demo-1     # checks the signature against the enrolled key

Every policy ATLAS decides under must be signed by its owner (atlas_service/policy/
signing.py). The private key never enters the repository: it is written, encrypted by
keystore.py (purpose "policy-signing"), to ~/.atlas/policy-keys/<subject>.key, or to
ATLAS_POLICY_KEY_DIR. Nothing here prints key material.

`enroll` is the one deliberate act of trust. It copies the public key from
policies/<subject>.pub into the policy-state file (atlas_service/atlas_policy_state.db,
or $ATLAS_STATE_DIR/, or --state-dir) and refuses to replace a different enrolled key
unless --replace is passed. After enrolment ATLAS reads the key only from its own
state, never from the policies folder.

Editing a policy: change it, raise its `version`, then `sign` it again. An edit that
keeps the version is refused as tampering; an unsigned or wrongly signed edit is
refused before that.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import keystore  # noqa: E402
from atlas_service.policy import signing  # noqa: E402
from atlas_service.policy.engine import POLICIES_DIR, load_policy  # noqa: E402

PURPOSE = "policy-signing"


def key_dir() -> Path:
    explicit = os.environ.get("ATLAS_POLICY_KEY_DIR")
    return Path(explicit) if explicit else Path.home() / ".atlas" / "policy-keys"


def key_file(subject: str, directory: Path | None = None) -> Path:
    return (directory or key_dir()) / f"{subject}.key"


def public_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw).hex()


def create(subject: str, directory: Path | None = None) -> Path:
    path = key_file(subject, directory)
    if path.exists():
        raise FileExistsError(f"{path} already exists; a policy owner key is never overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    keystore.write_secret(path, raw, PURPOSE)
    return path


def load_private(subject: str, directory: Path | None = None) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(keystore.read_secret(key_file(subject, directory), PURPOSE))


def sign(subject: str, policies_dir: Path = POLICIES_DIR, directory: Path | None = None) -> tuple[Path, Path]:
    policy_path = policies_dir / f"{subject}.yaml"
    load_policy(policy_path)                                     # refuse to sign an unparsable policy
    key = load_private(subject, directory)
    sig = signing.signature_path(policy_path)
    pub = signing.public_key_path(policy_path)
    sig.write_text(signing.sign(key, subject, policy_path.read_bytes()) + "\n", encoding="ascii")
    pub.write_text(public_hex(key) + "\n", encoding="ascii")
    return sig, pub


def state_db(state_dir: Path | None) -> Path:
    if state_dir:
        return Path(state_dir) / "atlas_policy_state.db"
    env = os.environ.get("ATLAS_STATE_DIR")
    base = Path(env) if env else ATLAS_ROOT / "atlas_service"
    return base / "atlas_policy_state.db"


def enroll(subject: str, state_dir: Path | None = None, *, replace: bool = False,
           policies_dir: Path = POLICIES_DIR) -> str:
    from atlas_service.policy.version_store import PolicyVersionStore
    pub = signing.public_key_path(policies_dir / f"{subject}.yaml").read_text(encoding="ascii").strip()
    store = PolicyVersionStore(state_db(state_dir))
    try:
        store.enroll_owner(subject, pub, replace=replace)
    finally:
        store.close()
    return pub[:16]


def verify(subject: str, state_dir: Path | None = None, policies_dir: Path = POLICIES_DIR) -> None:
    from atlas_service.policy.version_store import PolicyVersionStore
    store = PolicyVersionStore(state_db(state_dir))
    try:
        owner = store.owner_key(subject)
    finally:
        store.close()
    if owner is None:
        raise SystemExit(f"no enrolled owner for {subject}; run: python scripts/policy_key.py enroll {subject}")
    signing.verify_file(policies_dir / f"{subject}.yaml", subject, owner)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=["create", "sign", "enroll", "verify"])
    ap.add_argument("subject")
    ap.add_argument("--state-dir", type=Path, help="policy state folder (default: the service's)")
    ap.add_argument("--replace", action="store_true", help="enroll: replace a different enrolled key")
    args = ap.parse_args(argv)
    try:
        if args.action == "create":
            print(f"[policy_key] created a protected owner key for {args.subject} at {create(args.subject)}")
        elif args.action == "sign":
            sig, pub = sign(args.subject)
            print(f"[policy_key] signed {args.subject}: wrote {sig.name} and {pub.name}")
        elif args.action == "enroll":
            prefix = enroll(args.subject, args.state_dir, replace=args.replace)
            print(f"[policy_key] enrolled the owner of {args.subject} (public key {prefix}…) "
                  f"in {state_db(args.state_dir)}")
        else:
            verify(args.subject, args.state_dir)
            print(f"[policy_key] {args.subject}: signature valid for the enrolled owner")
    except (FileExistsError, FileNotFoundError, ValueError, keystore.KeystoreError,
            signing.PolicySignatureError) as exc:
        print(f"[policy_key] {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
