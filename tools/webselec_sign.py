#!/usr/bin/env python3
"""Create and verify WebSelec ECDSA P-256 release signatures.

Requires: python -m pip install cryptography

The signature is ECDSA over SHA-256. The .sig file contains base64 of the
64-byte IEEE-P1363 signature (r || s), suitable for Web Crypto verification.
Sign the exact bytes of the manifest; do not reformat it after signing.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, NoEncryption, load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)


def keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)
    if private_path.exists() or public_path.exists():
        raise SystemExit("Refusing to overwrite an existing key file.")
    password = getpass.getpass("New private-key password (minimum 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Use a password of at least 12 characters.")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        BestAvailableEncryption(password.encode("utf-8")),
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_text(json.dumps({
        "algorithm": "ECDSA-P256-SHA256",
        "publicKeySpkiBase64": base64.b64encode(public_bytes).decode("ascii"),
        "note": "Public key only. Safe to publish and embed in WebSelec."
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Private key saved to: {private_path}")
    print(f"Public key saved to:  {public_path}")
    print("IMPORTANT: keep the private key and its password out of GitHub and out of the HTML.")
    return 0


def load_private(path: str):
    password = getpass.getpass("Private-key password: ").encode("utf-8")
    return load_pem_private_key(Path(path).read_bytes(), password=password)


def sign(args: argparse.Namespace) -> int:
    key = load_private(args.private_key)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SystemExit("Expected an ECDSA P-256 private key.")
    manifest = Path(args.manifest).read_bytes()
    der_sig = key.sign(manifest, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    Path(args.signature).write_text(base64.b64encode(raw_sig).decode("ascii") + "\n", encoding="ascii")
    print(f"Signed exact manifest bytes: {len(manifest)}")
    print(f"Signature written to: {args.signature}")
    return 0


def verify(args: argparse.Namespace) -> int:
    public_obj = json.loads(Path(args.public_key).read_text(encoding="utf-8"))
    public_bytes = base64.b64decode(public_obj["publicKeySpkiBase64"], validate=True)
    key = load_pem_public_key(
        serialization.Encoding.PEM,
        # This branch intentionally replaced below; PEM public keys are accepted directly.
    ) if False else serialization.load_der_public_key(public_bytes)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SystemExit("Expected an ECDSA P-256 public key.")
    raw_sig = base64.b64decode(Path(args.signature).read_text(encoding="ascii").strip(), validate=True)
    if len(raw_sig) != 64:
        raise SystemExit("Signature must decode to exactly 64 bytes.")
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), Path(args.manifest).read_bytes(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("INVALID: signature verification failed.", file=sys.stderr)
        return 1
    print("VALID: manifest signature verified.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("keygen", help="create a password-protected signing key pair")
    p.add_argument("--private-key", default="webselec-private-key.pem")
    p.add_argument("--public-key", default="webselec-public-key.json")
    p.set_defaults(func=keygen)
    p = commands.add_parser("sign", help="sign exact manifest bytes")
    p.add_argument("--private-key", default="webselec-private-key.pem")
    p.add_argument("--manifest", default="release-manifest.json")
    p.add_argument("--signature", default="release-manifest.sig")
    p.set_defaults(func=sign)
    p = commands.add_parser("verify", help="verify a manifest signature locally")
    p.add_argument("--public-key", default="webselec-public-key.json")
    p.add_argument("--manifest", default="release-manifest.json")
    p.add_argument("--signature", default="release-manifest.sig")
    p.set_defaults(func=verify)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
