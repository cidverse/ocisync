# OCI-Sync

`ocisync` is a CLI for mirroring selected OCI artifacts into OCI registries.

## Features

- Filters tags with an optional regex and/or semver constraint
- Supports both container images and other OCI artifacts such as Helm charts
- Supports classic Helm chart repositories as a source
- Copies tags to the target registry only when missing by default
- Supports credentials from inline `token`, `token-env`, `token-command` or fallback to `.config/containers/auth.json`

## Usage

```bash
ocisync ocisync.example.yaml
```

Add this at the top of your config for editor validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cidverse/ocisync/main/configschema/v1.json
```

## Example config

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cidverse/ocisync/main/configschema/v1.json
registries:
  vendor-ghcr:
    type: oci
    registry: ghcr.io
    token-env: SOURCE_GHCR_TOKEN

  partner-charts:
    type: helm-repo
    url: https://charts.partner.example.com

  internal-prod:
    type: oci
    registry: registry.internal.example.com
    token-env: TARGET_REGISTRY_TOKEN

images:
  vendor-controller:
    source-registry: vendor-ghcr
    target-registry: internal-prod
    source-repository: vendor/controller
    regex: '^v?1\..*'
    semver:
      constraint: '>= 1.5.0, < 2.0.0'

  platform-chart:
    source-type: helm-repo
    source-registry: partner-charts
    target-registry: internal-prod
    source-repository: platform
    target-repository: helm/platform
    semver:
      constraint: '>= 2.3.1'
      include-prerelease: false
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
