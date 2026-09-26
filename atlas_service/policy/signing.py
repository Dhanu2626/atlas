"""Signed policy updates (2026-09-27).

The non-rollback check (version_store.py) refuses an OLDER policy, but until this
change it trusted any HIGHER-numbered one: anyone who could write
policies/<subject>.yaml could raise the version and loosen every rule. The frozen
threat table's answer to "malicious policy update" is "user auth + versioning +
secure storage for updates"; this is the user-auth half.

    policies/<subject>.yaml        the policy, exactly as before
    policies/<subject>.yaml.sig    Ed25519 signature by the policy's OWNER
    policies/<subject>.pub         the owner's public key -- a convenience for
                                   enrolment only, never trusted from here

The key ATLAS trusts is the one ENROLLED in its own policy-state file
(version_store.py, table policy_owners) with scripts/policy_key.py. It is not read
from the policies folder at decision time, so whoever can edit that folder cannot
swap the key along with the policy. The owner's private key is keystore-protected
(purpose "policy-signing") and lives outside the repository.

What is signed: b"ATLAS-POLICY-v1|" + subject + b"|" + the file's bytes with CRLF
normalised to LF (a Windows checkout and a Linux one must verify the same file).
Binding the subject means a valid signature for one customer's policy cannot be
moved onto another's.

Together with the version check: a forged or edited file fails here; an OLD file
that the owner really signed passes here and is refused there as a rollback.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b"ATLAS-POLICY-v1|"


class PolicySignatureError(Exception):
    """`reason` is the machine-readable refusal: policy_unsigned or
    policy_signature_invalid. Never carries key material."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


def signature_path(policy_path: Path) -> Path:
    return policy_path.with_name(policy_path.name + ".sig")


def public_key_path(policy_path: Path) -> Path:
    return policy_path.with_name(policy_path.stem + ".pub")


def normalise(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def signed_message(subject: str, data: bytes) -> bytes:
    return DOMAIN + subject.encode("utf-8") + b"|" + normalise(data)


def sign(private_key: Ed25519PrivateKey, subject: str, data: bytes) -> str:
    return private_key.sign(signed_message(subject, data)).hex()


def verify_file(policy_path: Path, subject: str, public_key_hex: str) -> bytes:
    """Returns the verified, normalised policy bytes -- the caller parses THESE,
    never a second read of the file -- or raises PolicySignatureError."""
    data = policy_path.read_bytes()
    sig_file = signature_path(policy_path)
    if not sig_file.exists():
        raise PolicySignatureError("policy_unsigned", f"{policy_path.name} has no signature file")
    try:
        signature = bytes.fromhex(sig_file.read_text(encoding="ascii").strip())
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(signature, signed_message(subject, data))
    except (InvalidSignature, ValueError) as exc:
        raise PolicySignatureError("policy_signature_invalid",
                                   f"{policy_path.name} is not signed by its enrolled owner") from exc
    return normalise(data)
