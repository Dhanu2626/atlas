"""Transport security policy: what ATLAS refuses to send or serve in the clear.

ATLAS is a software-first prototype. Since 2026-09-22 the service-to-service
path is TLS by default: atlas_service calls bank_service over https with the
bank's certificate verified against a local test CA and mutual TLS
(atlas_service/tls.py, scripts/make_dev_ca.py). That is a TLS-enabled
prototype on a local test PKI, not a production deployment -- no public CA and no
HSM; revocation and pinning exist only in the production profile, as a local CRL and
a local pin. Since 2026-09-29 the firmware source connects to atlas_service over HTTPS
too, verifying it against the same local CA (tested against a stand-in for its
checks; its simulator run is pending). What this module does is make insecure
transport a DELIBERATE,
CHECKED choice instead of a silent default (D6, 2026-09-18):

  * loopback HTTP is allowed. The bytes never reach a network interface, and
    this is the documented development and simulation posture.
  * anything else must be HTTPS. Binding a service to a non-loopback address,
    or calling a bank URL that is not loopback, over plain HTTP is refused --
    the service does not start, rather than quietly serving signed financial
    decisions and risk evidence in the clear.
  * ATLAS_ALLOW_INSECURE_HTTP=1 overrides the refusal for one specific,
    documented case: a development gateway in front of the simulator. It is
    logged loudly every time, and it is never the default.

What travels on these paths and matters: the customer's risk band and score,
the matched policy rules, the signed assertion the bank verifies, and the
device envelope. Challenge and transaction identifiers are NOT secrets -- since
D1 nothing an observer can do with them changes a payment -- but the risk
evidence is private, and a step-up refusal carries none of it (main.py).

ATLAS_TRANSPORT_PROFILE=production (2026-09-25) removes both allowances: no plain
HTTP at all, loopback included, and the development override is ignored.
Every certificate here comes from ATLAS's own local certificate authority.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

#: Set to "1" to permit plain HTTP on a non-loopback address. Development only:
#: it is what the Wokwi gateway path uses, and it is logged every start.
ALLOW_INSECURE_ENV = "ATLAS_ALLOW_INSECURE_HTTP"

#: Hostnames that reach this machine and no network. host.wokwi.internal is the
#: simulator's alias for the host, resolved by wokwigw on the developer's own
#: machine; the packets do not leave it.
LOOPBACK_NAMES = frozenset({"localhost", "host.wokwi.internal", "host.docker.internal"})


class InsecureTransportError(RuntimeError):
    """Raised instead of serving or calling a non-loopback endpoint in the clear."""


def _production() -> bool:
    """The production transport profile (atlas_service/tls.py). An unrecognised
    profile value raises there, so it can never read as development."""
    from atlas_service.tls import is_production
    return is_production()


def allow_insecure_http() -> bool:
    return os.environ.get(ALLOW_INSECURE_ENV, "") == "1"


def is_loopback(host: str | None) -> bool:
    """True when traffic to this host stays on this machine."""
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_outbound_url(url: str, *, what: str = "outbound URL") -> str:
    """Approves a URL this service will call, or raises.

    Returns a one-line description of the posture, for the startup log.
    """
    parts = urlsplit(url)
    if parts.scheme == "https":
        return f"{what}: TLS to {parts.hostname}"
    if parts.scheme != "http":
        raise InsecureTransportError(f"{what} {url!r} is neither http nor https")
    if _production():
        raise InsecureTransportError(
            f"{what} {url!r}: the production transport profile never sends plain HTTP, "
            f"loopback included, and ignores {ALLOW_INSECURE_ENV}")
    if is_loopback(parts.hostname):
        return f"{what}: plain HTTP to {parts.hostname} (loopback, never leaves this machine)"
    if allow_insecure_http():
        return (f"{what}: INSECURE plain HTTP to {parts.hostname} -- allowed only by "
                f"{ALLOW_INSECURE_ENV}=1, development use only")
    raise InsecureTransportError(
        f"{what} {url!r} sends signed decisions and risk evidence over plain HTTP to a "
        f"non-loopback host. Use https://, keep it on loopback, or set "
        f"{ALLOW_INSECURE_ENV}=1 for a development gateway."
    )


def check_bind(host: str, *, tls: bool, what: str = "listener") -> str:
    """Approves the address a service is about to listen on, or raises."""
    if tls:
        return f"{what}: TLS on {host}"
    if _production():
        raise InsecureTransportError(
            f"refusing to serve {what} on {host!r} without TLS: the production transport "
            f"profile serves TLS only, loopback included, and ignores {ALLOW_INSECURE_ENV}")
    if is_loopback(host):
        return f"{what}: plain HTTP on {host} (loopback, never leaves this machine)"
    if allow_insecure_http():
        return (f"{what}: INSECURE plain HTTP on {host} -- allowed only by "
                f"{ALLOW_INSECURE_ENV}=1, development use only")
    raise InsecureTransportError(
        f"refusing to serve {what} on {host!r} without TLS: anyone on the network would see "
        f"risk evidence and signed assertions. Pass a certificate and key, bind 127.0.0.1, "
        f"or set {ALLOW_INSECURE_ENV}=1 for a development gateway."
    )
