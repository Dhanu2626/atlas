"""Device envelope verification (Phase 3.3).

Turns "a device_id string in a JSON body" into "a registered key provably
authored these exact bytes, recently, exactly once".

CHECK ORDER IS A SECURITY PROPERTY, NOT STYLE
---------------------------------------------
Every field in an envelope -- device_id included -- is attacker-controlled
data until the signature verifies. So nothing that grants trust or mutates
state happens before step 3.

  1. lookup by device_key_id   HINT ONLY. Finding a candidate public key is
                               not trusting anything; if step 3 fails, nothing
                               was granted. Lookup is keyed on device_key_id
                               (high-entropy, generated) rather than the
                               human-readable device_id, so the not-found
                               reply is not a practical enumeration oracle.
  2. envelope well-formed      structural only
  3. SIGNATURE                 <-- the trust boundary. Nothing above this line
                                   is believed; nothing below runs without it.
  4. device_id matches         a valid key may not claim to be another device
  5. status ACTIVE             revoked/suspended checked AFTER signature, so
                               an unsigned probe cannot map device status
  6. subject binding           this device may only move ITS OWN account's money
  7. timestamp freshness       stale / future
  8. counter strictly rises    the anti-replay backbone
  9. nonce unused              second replay layer, independent of the counter
 10. (caller) transaction_id   Phase 2's duplicate check, still enforced

Steps 8, 9 and 10 are three INDEPENDENT replay defences. The Wokwi counter
affordance below relaxes exactly one of them and never touches the other two.

WHAT THIS DOES NOT PROVE
------------------------
A valid signature proves possession of an enrolled private key. It does not
prove which physical device holds it, because that key sits in ordinary flash
(firmware/device_identity.py explains why). Hardware-backed identity requires
a secure element and is not implemented or simulated anywhere in this project.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from atlas_service.device.db import DeviceStore
from contracts import DecisionReason, DeviceEnvelope, DeviceStatus, canonical_envelope_bytes

#: How far out of step a device clock may be. Wide enough for NTP jitter and
#: simulator drift, narrow enough that a captured envelope is not indefinitely
#: replayable if the counter and nonce layers were somehow both defeated.
MAX_CLOCK_SKEW = timedelta(minutes=5)

_STATUS_REASONS = {
    DeviceStatus.REVOKED.value: DecisionReason.DEVICE_REVOKED,
    DeviceStatus.SUSPENDED.value: DecisionReason.DEVICE_SUSPENDED,
}


@dataclass(frozen=True)
class EnvelopeVerdict:
    ok: bool
    reason: DecisionReason | None = None
    detail: str = ""
    #: The registry's own record. Populated only on success, so callers cannot
    #: accidentally read device attributes from a request that failed to
    #: authenticate.
    device: dict | None = None


def _fail(reason: DecisionReason, detail: str = "") -> EnvelopeVerdict:
    return EnvelopeVerdict(ok=False, reason=reason, detail=detail)


def verify_envelope(
    envelope: DeviceEnvelope,
    store: DeviceStore,
    *,
    now: datetime | None = None,
    allow_counter_reset: bool = False,
) -> EnvelopeVerdict:
    """Runs the pipeline above. Returns a verdict; never raises for an
    untrusted envelope, so a malformed or hostile request can never surface
    as an unhandled 500.

    `allow_counter_reset` is the Wokwi affordance -- see accept_counter().
    It defaults to False, which is real-device behaviour.
    """
    now = now or datetime.now(timezone.utc)
    ts = now.isoformat()

    # --- 1. lookup (hint only, grants nothing) ---------------------------
    row = store.get_by_key_id(envelope.device_key_id)
    if row is None:
        return _fail(DecisionReason.DEVICE_UNKNOWN,
                     f"no enrolled key {envelope.device_key_id!r}")
    device = dict(row)

    # --- 2. structural ----------------------------------------------------
    if not envelope.signature:
        return _fail(DecisionReason.MISSING_DEVICE_SIGNATURE)

    # --- 3. SIGNATURE -- the trust boundary -------------------------------
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(device["public_key"]))
        public_key.verify(bytes.fromhex(envelope.signature), canonical_envelope_bytes(envelope))
    except (InvalidSignature, ValueError):
        store.record_event(device["device_id"], "AUTH_FAILURE", "invalid_signature", ts)
        return _fail(DecisionReason.INVALID_DEVICE_SIGNATURE)

    # ===== everything below here is authenticated =========================

    # --- 4. the key may not impersonate another device --------------------
    if envelope.device_id != device["device_id"]:
        store.record_event(device["device_id"], "AUTH_FAILURE",
                           f"device_id_mismatch claimed={envelope.device_id}", ts)
        return _fail(DecisionReason.DEVICE_ID_MISMATCH,
                     f"key belongs to {device['device_id']!r}")

    # --- 5. standing ------------------------------------------------------
    if device["status"] != DeviceStatus.ACTIVE.value:
        store.record_event(device["device_id"], "AUTH_FAILURE",
                           f"status={device['status']}", ts)
        return _fail(_STATUS_REASONS.get(device["status"], DecisionReason.DEVICE_UNKNOWN),
                     f"device status is {device['status']}")

    # --- 6. account binding -----------------------------------------------
    # A device enrolled against one account must not be able to move another
    # account's money, even with a perfectly valid signature.
    if envelope.transaction.subject != device["bound_subject"]:
        store.record_event(device["device_id"], "AUTH_FAILURE",
                           f"subject_mismatch claimed={envelope.transaction.subject}", ts)
        return _fail(DecisionReason.DEVICE_SUBJECT_MISMATCH,
                     f"device is bound to {device['bound_subject']!r}")

    # --- 7. freshness -----------------------------------------------------
    try:
        issued = datetime.fromisoformat(envelope.issued_at)
    except ValueError:
        return _fail(DecisionReason.MALFORMED_ENVELOPE, "unparseable issued_at")
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)

    if issued - now > MAX_CLOCK_SKEW:
        return _fail(DecisionReason.FUTURE_TIMESTAMP, f"issued_at {envelope.issued_at}")
    if now - issued > MAX_CLOCK_SKEW:
        return _fail(DecisionReason.STALE_REQUEST, f"issued_at {envelope.issued_at}")

    # --- 8. monotonic counter (ATOMIC claim) -------------------------------
    # F2: this was read -> decide -> write across three separate calls, which
    # is check-then-act. Two threads could both read last=4, both accept
    # counter=5, and both proceed. claim_counter() collapses the compare and
    # the advance into one indivisible step, so exactly one caller can ever
    # win a given counter value.
    device_id = device["device_id"]
    counter_row = store.get_counter(device_id)
    reset_accepted = False
    if counter_row is not None and envelope.counter <= counter_row["last_counter"]:
        last = counter_row["last_counter"]
        if not _may_accept_counter_reset(
            envelope, counter_row["last_boot_id"], allow_counter_reset
        ):
            store.record_event(device_id, "AUTH_FAILURE",
                               f"counter_regression got={envelope.counter} last={last}", ts)
            return _fail(DecisionReason.COUNTER_REGRESSION,
                         f"counter {envelope.counter} <= last seen {last}")
        reset_accepted = True
        # Loudly recorded, never silent -- this is a deliberately relaxed
        # check and must be visible in the audit trail every single time.
        store.record_event(
            device_id, "COUNTER_RESET_ACCEPTED",
            f"simulation_mode=true boot_id={envelope.boot_id} "
            f"got={envelope.counter} last={last}", ts,
        )

    if reset_accepted:
        # The simulation path deliberately moves the counter BACKWARDS, which
        # claim_counter() refuses by design, so it is set directly.
        store.set_counter(device_id, envelope.counter, envelope.boot_id, ts)
    elif not store.claim_counter(device_id, envelope.counter, envelope.boot_id, ts):
        # Lost the race to a concurrent request carrying the same or a higher
        # counter -- indistinguishable from a replay, and treated as one.
        store.record_event(device_id, "AUTH_FAILURE",
                           f"counter_regression_concurrent got={envelope.counter}", ts)
        return _fail(DecisionReason.COUNTER_REGRESSION,
                     f"counter {envelope.counter} lost to a concurrent request")

    # --- 9. nonce (ATOMIC claim) ------------------------------------------
    # Same fix: nonce_seen() followed by consume_nonce() was check-then-act.
    # claim_nonce() returns True only for the caller that actually inserted it.
    #
    # Note the counter has already advanced by this point. That is deliberate
    # and harmless: a device never reuses a nonce, so the only envelope that
    # reaches here and fails is a replay, and the legitimate device's next
    # request carries a higher counter regardless. Failing before this point
    # (steps 1-8) still touches neither the counter nor the nonce.
    if not store.claim_nonce(device_id, envelope.nonce, ts):
        store.record_event(device_id, "AUTH_FAILURE",
                           f"replayed_nonce {envelope.nonce}", ts)
        return _fail(DecisionReason.REPLAYED_NONCE)

    store.touch_last_seen(device_id, ts)
    return EnvelopeVerdict(ok=True, device=device)


def _may_accept_counter_reset(
    envelope: DeviceEnvelope, last_boot_id: str | None, allow: bool
) -> bool:
    """The Wokwi-only affordance, deliberately narrow.

    WHY IT EXISTS: the correct anti-replay counter lives in NVS. Wokwi does
    not reliably persist flash between sessions, so a restarted simulation
    sends counter=1 and is correctly rejected -- the demo dies. Rather than
    weaken the check for everyone, this accepts a regression ONLY when:

        * the operator explicitly enabled simulation mode, AND
        * the envelope carries a boot_id different from the last one seen,
          AND that boot_id is inside the SIGNED bytes, so an attacker cannot
          bolt one onto a captured envelope.

    A replayed envelope therefore still fails: its boot_id matches the one
    already recorded. And even if this check is bypassed entirely, the nonce
    layer and Phase 2's transaction_id layer both still apply -- replay
    protection degrades from three independent layers to two, never to zero.

    DEFAULT OFF. Real devices persist the counter and never take this path.
    """
    if not allow:
        return False
    return bool(envelope.boot_id) and envelope.boot_id != last_boot_id
