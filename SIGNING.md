# WebSelec release signing (initial tooling)

This is the first step toward replacing the v0.1.2 preview's demo activation
keys with real release signatures.

## Security model

- ECDSA P-256 with SHA-256 signs the **exact bytes** of a release manifest.
- The public key can be embedded in the HTML; the private key must stay offline
  and must never be committed to this repository or placed in the HTML.
- A valid signature proves that the signed manifest was signed by the matching
  private key and that its bytes have not changed. It does not prove the HTML
  runtime itself has not been edited.
- A single-file browser app cannot securely enforce activation against someone
  who can edit its source or browser storage. A server is needed for robust
  entitlement enforcement and revocation.

## Create a signing key

Install Python 3 and the `cryptography` package:

```sh
python -m pip install cryptography
python tools/webselec_sign.py keygen
```

Keep `webselec-private-key.pem` and its password in a safe offline location.
Never upload the private key. The generated `webselec-public-key.json` is safe
to publish; its `publicKeySpkiBase64` value is the key to embed in WebSelec.

## Sign a manifest

Create a UTF-8 `release-manifest.json` containing the release version, publish
timestamp, and asset names, URLs, and SHA-256 digests. Then run:

```sh
python tools/webselec_sign.py sign
python tools/webselec_sign.py verify
```

The generated `release-manifest.sig` is base64 of the 64-byte P-256
IEEE-P1363 signature, the format accepted by Web Crypto's ECDSA verifier.
Do not reformat or edit the manifest after signing; any byte change invalidates
the signature.

## Current status

This commit adds signing and local verification tooling only. It does not claim
that the existing HTML is already cryptographically signed, and it does not
replace the demo activation gate until the public key is generated and the
browser verifier is wired in and tested.
