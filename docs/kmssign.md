# git-kmssign

`git-kmssign` is a fork of [smimesign](https://github.com/github/smimesign) that
signs Git commits and tags with a key held in a Key Management Service (KMS)
instead of a local private key. The first (and currently only) supported backend
is **Azure Key Vault**.

Because the private key never leaves the KMS, `git-kmssign` also runs on
**Linux**, where upstream smimesign intentionally does not build (it depends on
the macOS/Windows OS certificate stores).

## Architecture and design choices

### One seam: the signer
smimesign obtains an identity from a `certstore.Identity`, whose interface is:

```go
type Identity interface {
    Certificate() (*x509.Certificate, error)
    CertificateChain() ([]*x509.Certificate, error)
    Signer() (crypto.Signer, error)   // <- the only thing we replace
    Delete() error
    Close()
}
```

`command_sign.go` calls `Signer()` and hands the result to the CMS layer. We
replace **only** that signer. Everything else from smimesign is carried over
unchanged:

- certificate discovery / `--local-user` matching,
- CMS `SignedData` construction (`ietf-cms`),
- the gpgsm-compatible Git protocol and status output (`SIG_CREATED`, etc.),
- signature verification (`--verify`).

### Azure Key Vault signer (`azuresign/`)
`azuresign.Signer` implements `crypto.Signer`. Its `Public()` returns the RSA
public key from the configured certificate (so the CMS layer can match it to the
leaf), and `Sign()` forwards the digest to Key Vault's `Sign` operation via the
[`azkeys`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys)
SDK.

Crypto policy (intentionally strict for this POC):

- **RSA + SHA-256 only.** Non-SHA-256 hashes and non-RSA keys are rejected.
- A plain `crypto.Hash` maps to **RS256** (RSASSA-PKCS#1 v1.5).
- An `*rsa.PSSOptions` maps to **PS256** (RSASSA-PSS).
- **A PSS request is never silently downgraded to PKCS#1 v1.5.**
- No ECDSA.

### Configuration via environment variables
Key selection and the certificate location are passed via environment variables
rather than being encoded into git's `user.signingKey` (which stays as an email
or fingerprint used only for discovery):

| Variable                     | Required | Meaning                                             |
| ---------------------------- | -------- | --------------------------------------------------- |
| `GIT_KMSSIGN_VAULT_URL`      | yes      | Key Vault base URL, e.g. `https://v.vault.azure.net/` |
| `GIT_KMSSIGN_KEY_NAME`       | yes      | Key Vault key name (same name as the certificate)   |
| `GIT_KMSSIGN_KEY_VERSION`    | no       | Pin a key version; empty = latest                   |
| `GIT_KMSSIGN_CERT`           | yes      | Path to the public certificate PEM (leaf first)     |
| `GIT_KMSSIGN_INCLUDE_CERTS`  | no       | Overrides `--include-certs`; see below              |

The **public certificate** is loaded from a local PEM file. The private key
stays in Key Vault; only the certificate (needed for CMS construction and
verification) is read locally.

### Authentication
Client authentication uses
[`azidentity.DefaultAzureCredential`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#DefaultAzureCredential),
which we chose deliberately: it prefers a service-principal **client secret** from
the standard `AZURE_*` environment variables (convenient for local testing) and
otherwise falls back to a **system- or user-assigned managed identity** (the
intended production default). No custom auth code is required.

| Variable              | Meaning                          |
| --------------------- | -------------------------------- |
| `AZURE_TENANT_ID`     | Directory (tenant) ID            |
| `AZURE_CLIENT_ID`     | Service principal appId          |
| `AZURE_CLIENT_SECRET` | Service principal password       |

The signing identity needs the **Key Vault Crypto User** role on the key.

### Certificate inclusion (`GIT_KMSSIGN_INCLUDE_CERTS`)
smimesign's `--include-certs` controls which certificates are embedded in the
signature (default `-2`: all certs except the root). When Git drives the program
it uses a fixed argument list and cannot inject flags, so this policy is also
exposed as `GIT_KMSSIGN_INCLUDE_CERTS`. An explicit `--include-certs` flag still
takes precedence.

- Use the default `-2` for normal, CA-issued certificates (leaf embedded, root
  stripped).
- Use `-1` for a **self-signed** certificate, so the whole chain (including the
  self-signed cert) is embedded and the signature verifies standalone.

### Linux support
Upstream smimesign fails to compile on Linux on purpose (two undefined-symbol
`init()` stubs). We removed the root stub and reimplemented
`certstore/certstore_linux.go` as an Azure Key Vault-backed store: its single
identity exposes the PEM certificate/chain plus the `azuresign.Signer`. `Import`
and `Delete` are unsupported (the key is managed in Key Vault). macOS and Windows
keep the original OS-store behavior; the KMS backend is Linux-only for now.

## Building

The tool is built inside a container using a multi-stage, minimal
[Wolfi](https://github.com/wolfi-dev) image. The Linux/KMS path has no cgo
dependencies, so the result is a fully static binary shipped on a distroless
runtime (which still provides the CA roots needed for TLS to
`*.vault.azure.net`).

```sh
docker buildx build --platform linux/amd64 \
  --build-arg VERSION=$(git describe --tags --always) \
  -t git-kmssign:dev --load .
```

The resulting image is ~11.6 MB.

## Preparing a certificate in Azure Key Vault

`git-kmssign` needs an X.509 certificate whose key is the Key Vault key. The
simplest way is to have Key Vault create the certificate (the key is generated
and stays in the vault), then download only the public certificate:

`policy.json`:

```json
{
  "issuerParameters": { "name": "Self" },
  "keyProperties": {
    "exportable": false, "keyType": "RSA", "keySize": 2048, "reuseKey": false
  },
  "secretProperties": { "contentType": "application/x-pkcs12" },
  "x509CertificateProperties": {
    "subject": "CN=Your Name",
    "subjectAlternativeNames": { "emails": ["you@example.com"] },
    "keyUsage": ["digitalSignature"],
    "ekus": ["1.3.6.1.5.5.7.3.4"],
    "validityInMonths": 12
  }
}
```

```sh
az keyvault certificate create --vault-name <vault> --name <cert-name> \
  --policy @policy.json

az keyvault certificate download --vault-name <vault> --name <cert-name> \
  --file signer.pem --encoding PEM
```

The underlying key is created with `keyOps` including `sign`, so the Crypto User
role is sufficient to sign. Use `<cert-name>` as `GIT_KMSSIGN_KEY_NAME` and the
downloaded `signer.pem` as `GIT_KMSSIGN_CERT`. Note that renewing the certificate
creates a new key version; pin `GIT_KMSSIGN_KEY_VERSION` if you need stability.

## Running

### List the configured identity

`--list-keys` does not contact Key Vault; it just parses the certificate:

```sh
docker run --rm \
  -e GIT_KMSSIGN_VAULT_URL="https://<vault>.vault.azure.net/" \
  -e GIT_KMSSIGN_KEY_NAME="<cert-name>" \
  -e GIT_KMSSIGN_CERT="/certs/signer.pem" \
  -v "$PWD/signer.pem:/certs/signer.pem:ro" \
  git-kmssign:dev --list-keys
```

### Sign a message (live)

Signs over stdin and writes a detached, armored signature. Fill in the Azure
values; the service principal must have Crypto User on the key.

```sh
echo "hello from git-kmssign" | docker run --rm -i \
  -e AZURE_TENANT_ID="<tenant-id>" \
  -e AZURE_CLIENT_ID="<sp-appId>" \
  -e AZURE_CLIENT_SECRET="<sp-password>" \
  -e GIT_KMSSIGN_VAULT_URL="https://<vault>.vault.azure.net/" \
  -e GIT_KMSSIGN_KEY_NAME="<cert-name>" \
  -e GIT_KMSSIGN_CERT="/certs/signer.pem" \
  -e GIT_KMSSIGN_INCLUDE_CERTS="-1" \
  -v "$PWD/signer.pem:/certs/signer.pem:ro" \
  git-kmssign:dev -s -b -a -u "you@example.com" > sig.pem
```

`-s` sign, `-b` detached, `-a` armored, `-u` selects the identity by email.
`GIT_KMSSIGN_INCLUDE_CERTS=-1` embeds the self-signed cert so the signature
verifies on its own.

The helper script `scripts/live-sign-test.sh` wraps this command; set
`TENANT_ID`, `APP_ID`, `PASSWORD`, `VAULT_URL`, `KEY_NAME` (and optionally
`CERT_PEM`, `SIGN_EMAIL`, `MESSAGE`, `INCLUDE_CERTS`) and run it.

### Verify

```sh
# Detached: signature file + original data
git-kmssign --verify sig.pem data.txt
```

Or with OpenSSL (convert the `SIGNED MESSAGE` PEM to DER first):

```sh
sed '/-----/d' sig.pem | base64 -d > sig.der
openssl cms -verify -inform DER -in sig.der -content data.txt -binary \
  -CAfile signer.pem -purpose any -out /dev/null
```

## Signing real commits with `git commit -S`

To use `git-kmssign` as git's signing program, run it as a native binary. Extract
the static binary from the built image:

```sh
cid=$(docker create git-kmssign:dev)
docker cp "$cid":/usr/bin/git-kmssign /tmp/signing-test/git-kmssign
docker rm "$cid"
```

Then point git at it (a throwaway or repo-local config avoids touching your
global git config), export the same environment the signer reads, and commit:

```sh
git config gpg.format x509
git config gpg.x509.program /tmp/signing-test/git-kmssign
git config user.signingkey you@example.com   # must match the cert's email

export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...
export GIT_KMSSIGN_VAULT_URL=https://<vault>.vault.azure.net/
export GIT_KMSSIGN_KEY_NAME=<cert-name>
export GIT_KMSSIGN_CERT=/tmp/git-signing-crt-01.pem
export GIT_KMSSIGN_INCLUDE_CERTS=-1

git commit -S -m "test: signed via Azure Key Vault"
git --no-pager log --show-signature -1
git verify-commit HEAD
```

The helper script `scripts/live-commit-test.sh` automates this: it extracts
nothing itself (point `BIN` at the binary), sets up a throwaway repo with
repo-local x509 config, exports the environment, and drops you into an
interactive shell to run the git commands yourself. Set the same variables as
`live-sign-test.sh` (`TENANT_ID`, `APP_ID`, `PASSWORD`, `VAULT_URL`,
`KEY_NAME`, plus optional `CERT_PEM`, `SIGN_EMAIL`, `INCLUDE_CERTS`, `BIN`).

Note: a self-signed test certificate is not chained to a trusted root, so
`git verify-commit` may report the signer as untrusted even though the CMS
signature itself is valid.

## Scope and limitations

- Azure Key Vault only; RSA/SHA-256 only; RS256 and PS256.
- KMS backend is Linux-only (macOS/Windows keep the OS store).
- The certificate is supplied as a local PEM; fetching it directly from Key
  Vault Certificates is a possible future enhancement.
