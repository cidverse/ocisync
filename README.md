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

Images can reference named `patches`, which modify the image while it gets copied. A patch adds one layer on top of
the unchanged source layers, so patched images get new digests and upstream signatures/attestations no longer apply.
Mirror them to their own repository. With `push-strategy: IfNotPresent`, a tag is re-synced when the patch
configuration changes (tracked via the `io.cidverse.ocisync.patch.fingerprint` label).

### `ca-certificates`

Adds CA certificates to the image's trust store, without running anything inside the image:

- appends the certificates to every CA bundle in the image (Debian, RHEL, SUSE, Alpine, Arch, distroless, …)
- drops them into the distribution's anchor directory, so they survive `update-ca-certificates` in derived images
- updates Java truststores (`cacerts`) of any JDK/JRE in the image

| Option | Values | Description |
|--------|--------|-------------|
| `files` | list of paths | PEM files to add, relative to the config file |
| `base` | `image` (default), `system` | extend the image's bundle, or replace it with the host's bundle plus the certificates |
| `java` | `replace` (default), `env`, `none` | overwrite Java truststores, point `JAVA_TOOL_OPTIONS` to a separate truststore, or leave Java alone |
| `env` | `false` (default), `true` | set CA env vars (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, …) for runtimes with their own CA store |
| `on-missing-bundle` | `fail` (default), `skip`, `create` | what to do if the image has no CA bundle, e.g. `scratch` |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
