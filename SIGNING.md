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


## GitHub Actions automation

The repository includes `.github/workflows/sign-release.yml`. It can sign a newly
published release automatically, or be run manually to sign an existing tag.

1. Run `python tools/webselec_sign.py keygen` on your own computer.
2. Keep the private-key file and password in a safe place. Do not upload the
   private-key file to GitHub.
3. Create a base64 copy of the encrypted PEM for the GitHub Actions secret.
   On macOS, run `base64 < webselec-private-key.pem | tr -d '\\n'`.
4. In GitHub, open **Settings → Secrets and variables → Actions → New repository
   secret** and add:
   - `WEBSELEC_PRIVATE_KEY_B64`: the base64 text from step 3.
   - `WEBSELEC_SIGNING_PASSWORD`: the password used when generating the key.
5. Open **Actions → Sign published WebSelec releases → Run workflow**, enter the
   release tag (for example `0.1.2`), and run it. The workflow downloads the
   release assets, hashes them, signs the manifest, and uploads
   `release-manifest.json` and `release-manifest.sig` to that release.

The workflow does not embed a public key in the HTML and does not replace the
current demo activation screen yet. The next step is to embed the generated
public key in the app and connect browser-side signature verification and the
24-hour eligibility policy. Do that only after the public key is generated and
confirmed, otherwise users would be unable to verify the signed manifest.
