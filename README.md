# OCI-Sync

`ocisync` is a CLI for mirroring selected OCI artifacts into OCI registries.

## Features

- Filters tags with an optional regex and/or semver constraint
- Supports both container images and other OCI artifacts such as Helm charts
- Supports classic Helm chart repositories as a source
- Copies tags to the target registry only when missing by default
- Supports credentials from inline `token`, `token-env`, `token-command` or fallback to `.config/containers/auth.json`
  - with `username`, the token is used as password (basic auth / token exchange, required by e.g. Docker Hub, Harbor, GHCR with a PAT); without it, the token is sent as bearer token
- Verifies Helm chart downloads against the `digest` from `index.yaml`
- Optionally patches container images before pushing them, e.g. to inject private CA certificates (see [Patches](#patches))

## Installation

...

## Usage

```bash
ocisync ocisync.yaml
```

Add this at the top of your config for editor validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cidverse/ocisync/main/configschema/v1.json
```

## Example Config

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cidverse/ocisync/main/configschema/v1.json
registries:
  vendor-ghcr:
    type: oci
    registry: ghcr.io
    username: my-user
    token-env: SOURCE_GHCR_TOKEN

  partner-charts:
    type: helm-repo
    url: https://charts.partner.example.com

  internal-mirror:
    type: oci
    registry: registry.internal.example.com
    token-env: TARGET_REGISTRY_TOKEN

images:
  vendor-controller:
    source-registry: vendor-ghcr
    target-registry: internal-mirror
    source-repository: vendor/controller
    regex: '^v?1\..*'
    semver:
      constraint: ">= 1.5.0, < 2.0.0"

  platform-chart:
    source-type: helm-repo
    source-registry: partner-charts
    target-registry: internal-mirror
    source-repository: platform
    target-repository: helm/platform
    semver:
      constraint: ">= 2.3.1"
      include-prerelease: false

  base-image:
    source-registry: vendor-ghcr
    target-registry: internal-mirror
    source-repository: vendor/base
    target-repository: corp/base
    patches: [corp-ca]

patches:
  corp-ca:
    ca-certificates:
      files: [certs/corp-root.pem]   # relative to the config file
      env: false                     # set CA env vars for runtimes with their own CA store
      on-missing-bundle: fail        # fail | skip | create
      base: image                    # image | system
      java: replace                  # replace | env | none
```

## Patches

Images can reference named `patches`, which modify the image while it gets copied. The source layers are copied as-is,
the patch adds one layer and updates the image config. Patched images therefore get new digests, so signatures and
attestations of the source don't apply to them (attestation manifests are dropped from patched indexes). Mirror patched
images to their own repository, so it's clear they aren't the upstream image.

Every platform of a multi-arch image is patched (linux only). Windows images and other artifacts are copied unchanged.
The applied patches are recorded in the image config labels `io.cidverse.ocisync.patch.fingerprint` and
`io.cidverse.ocisync.patch.names`. With `push-strategy: IfNotPresent`, a tag gets re-synced when its fingerprint
doesn't match the current patch configuration, for example after you add or rotate a certificate.

### `ca-certificates`

Adds CA certificates to the system trust store, without running anything inside the image:

- Adds the certificates to every CA bundle found in the image. With `base: image` (default), they're appended to the
  image's own bundle. With `base: system`, each bundle is replaced by the CA bundle of the system running ocisync
  (`$SSL_CERT_FILE`, or the first existing path below) plus the certificates. Since that bundle is part of the
  fingerprint, changing it on the host re-syncs the images. Symlinks are resolved, so each file is patched only once:

  | Path | Distributions |
  |------|---------------|
  | `/etc/ssl/certs/ca-certificates.crt` | Debian, Ubuntu, Alpine, Gentoo, Wolfi/Chainguard, distroless, BusyBox |
  | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | RHEL, CentOS, Fedora, UBI, Rocky, Alma, Amazon Linux, Oracle Linux |
  | `/etc/pki/tls/certs/ca-bundle.crt` | RHEL/Fedora (legacy), Photon OS, Amazon Linux 2, Azure Linux |
  | `/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt`, `/etc/pki/tls/certs/ca-bundle.trust.crt` | RHEL/Fedora (OpenSSL trusted bundle) |
  | `/var/lib/ca-certificates/ca-bundle.pem`, `/etc/ssl/ca-bundle.pem` | openSUSE, SLES, SLE BCI |
  | `/etc/ca-certificates/extracted/tls-ca-bundle.pem` | Arch Linux |
  | `/etc/ssl/cert.pem` | Alpine, Arch, Void (OpenSSL/LibreSSL default) |
  | `/usr/lib/ssl/cert.pem` | Debian/Ubuntu (OpenSSL default) |
  | `/etc/ssl/certs/ca-bundle.crt`, `/etc/pki/tls/cacert.pem` | older Fedora/RHEL, OpenELEC |
  | files referenced by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, `HEX_CACERTS_PATH`, `DENO_CERT` | any |

- Writes each certificate as `ocisync-<patch>.crt` (or `ocisync-<patch>-<n>.crt` for several) to the anchor directories of the distribution tooling, so the
  certificates survive an `update-ca-certificates` / `update-ca-trust` in derived images. Files are only written to
  directories that already exist in the image:
  `/usr/local/share/ca-certificates` (Debian, Ubuntu, Alpine), `/etc/pki/ca-trust/source/anchors` (RHEL family),
  `/etc/pki/trust/anchors` (SUSE), `/etc/ca-certificates/trust-source/anchors` (Arch).
- With `env: true`, sets environment variables for runtimes and tools that ship their own CA store. Variables the image
  already sets are left alone.

  | Variable | Value | Used by |
  |----------|-------|---------|
  | `SSL_CERT_FILE` | patched bundle | OpenSSL, Go, .NET, Ruby, httpx |
  | `REQUESTS_CA_BUNDLE` | patched bundle | Python requests, Azure CLI, Conda |
  | `AWS_CA_BUNDLE` | patched bundle | AWS CLI, boto3/botocore |
  | `PIP_CERT` | patched bundle | pip |
  | `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` | patched bundle | Google Cloud SDK |
  | `HEX_CACERTS_PATH` | patched bundle | Hex (Elixir) |
  | `DENO_TLS_CA_STORE` | `system` | Deno |
  | `NODE_EXTRA_CA_CERTS` | `/etc/ssl/certs/ocisync-<patch>.pem` (only the added certificates) | Node.js, npm, yarn |

  Runtimes that read the system bundle (Go, OpenSSL-based C/C++, Ruby, PHP, .NET, curl, git, Rust with
  native-tls/rustls-native-certs) don't need any of these.
- Java truststores are built from the patched bundle (the bundle the image or the system provides, plus the
  certificates), the way `ca-certificates-java` and `update-ca-trust` do on Debian and RHEL. Images without a
  JDK/JRE are not changed. The `java` option controls it:
  - `replace` (default): overwrites every truststore in the image: `$JAVA_HOME/lib/security/cacerts` of every JDK/JRE
    (found anywhere, e.g. `/opt/java/openjdk`, `/usr/lib/jvm/*`, JDK 8 `jre/lib/security/cacerts`),
    `/etc/ssl/certs/java/cacerts` (Debian, Ubuntu, Alpine, Arch), `/etc/pki/ca-trust/extracted/java/cacerts` (RHEL
    family), `/var/lib/ca-certificates/java-cacerts` (SUSE), and the truststore selected by
    `-Djavax.net.ssl.trustStore` in `JAVA_TOOL_OPTIONS`. Symlinks are resolved, so a JDK linked to the distribution
    truststore is patched once.
  - `env`: writes `/etc/ssl/certs/java/ocisync-<patch>.jks` and appends `-Djavax.net.ssl.trustStore=…
    -Djavax.net.ssl.trustStoreType=JKS -Djavax.net.ssl.trustStorePassword=changeit` to `JAVA_TOOL_OPTIONS`. The
    JDK files stay untouched, but every JVM prints `Picked up JAVA_TOOL_OPTIONS: …` to stderr, and launchers that
    set `-Djavax.net.ssl.trustStore` themselves win. If the image already selects a truststore in `JAVA_TOOL_OPTIONS`,
    that file is replaced instead.
  - `none`: leaves Java alone.

  The truststore is written as JKS with the password `changeit`, or the `-Djavax.net.ssl.trustStorePassword` from
  `JAVA_TOOL_OPTIONS`. Every JDK from 8 on reads JKS, and JDK 9+ also detects it where PKCS12 is expected (the
  default `cacerts`). A store that a JVM loads without a password skips the integrity check. With `on-missing-bundle:
  create` and `base: image`, Java truststores are left alone, because they would contain only the configured
  certificates.
- If no bundle is found (for example in `scratch` images), `on-missing-bundle` decides what happens: `fail` (default),
  `skip` (copy without certificate changes), or `create` (create `/etc/ssl/certs/ca-certificates.crt` with the
  configured certificates, on top of the system bundle with `base: system`).

Not covered: Python code using the `certifi` bundle directly (`certifi.where()`),
binaries with compiled-in roots (e.g. Rust `webpki-roots`), the OpenSSL hashed certificate directories (`/etc/ssl/certs/<hash>.0`), and
other applications that bundle their own CA store (beyond those covered by `env`). Layers compressed with
zstd can't be patched yet.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
