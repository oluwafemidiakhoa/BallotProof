from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ballotproof.models import AttestationPayload, SignedAttestation
from ballotproof.provenance import canonical_json_bytes


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def sign_attestation(
    payload: AttestationPayload,
    private_key: Ed25519PrivateKey,
) -> SignedAttestation:
    message = canonical_json_bytes(payload.model_dump(mode="json"))
    signature = private_key.sign(message)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return SignedAttestation(
        payload=payload,
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_attestation(attestation: SignedAttestation) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(attestation.public_key_b64, validate=True)
        )
        signature = base64.b64decode(attestation.signature_b64, validate=True)
        message = canonical_json_bytes(attestation.payload.model_dump(mode="json"))
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
