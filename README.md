# dpm-registry

`dpm-registry` is a small hostable npm-compatible registry for publishing and
installing immutable package versions. It uses only the Go standard library.

## Configuration

Copy `config.example.json` to `config.json`. Tokens are stored only as SHA-256
hashes, never as plaintext. `scopes` accepts `*` for all packages or a scoped
prefix such as `@acme/*`.

```json
{
  "data_dir": "./registry-data",
  "public_url": "https://registry.dusk.night-x.com",
  "read_auth": false,
  "tokens": [
    {
      "hash": "SHA256_HEX_OF_THE_BEARER_TOKEN",
      "user": "publisher",
      "scopes": ["@acme/*"]
    }
  ]
}
```

Generate the hash without persisting the token:

```sh
printf %s "$DPM_REGISTRY_TOKEN" | sha256sum | cut -d' ' -f1
```

Set `read_auth` to `true` to require the same bearer tokens for packument and
tarball reads. `/-/ping` remains public; `/-/whoami` always requires a token.
Publishing always requires a bearer token.

Set `public_url` to the externally reachable registry URL. It must be an
absolute HTTP(S) URL without a query or fragment and may include a base path,
such as `https://packages.example/npm`. Published packuments then contain
absolute `dist.tarball` URLs using that base path. Omitting it preserves the
legacy root-relative URL behavior.

## Run

```sh
go run ./cmd/dpm-registry -config config.json -listen :4873
```

## Migrate Legacy Tarball URLs

After setting `public_url`, stop the registry service and run this once against
the same configuration and data directory:

```sh
dpm-registry migrate-tarballs -config /etc/dpm-registry/config.json
```

The command atomically rewrites only root-relative persisted `dist.tarball`
URLs. It leaves absolute URLs unchanged, reports the number rewritten, and is
safe to run again. For example, it upgrades the persisted `tar@0.1.0`
packument without changing its tarball or integrity metadata.

## Deploy `registry.dusk.night-x.com`

`Caddyfile` proxies the public HTTPS domain to a registry process listening on
`127.0.0.1:4873`. Install the built binary at `/usr/local/bin/dpm-registry`,
install `dpm-registry.service` at `/etc/systemd/system/dpm-registry.service`,
and place the real configuration at `/etc/dpm-registry/config.json`. Create a
`dpm-registry` system user, then run `systemctl daemon-reload` and
`systemctl enable --now dpm-registry`.

The Caddy host must have public DNS for `registry.dusk.night-x.com` and permit
ports 80 and 443 so Caddy can obtain and renew TLS certificates. These files
are deployable host configuration examples; committing them cannot reconfigure
the already-live external domain, DNS, Caddy instance, firewall, or service.
Set `public_url` in `/etc/dpm-registry/config.json` to
`https://registry.dusk.night-x.com` before publishing or migrating packages.

After deployment, run these exact health checks:

```sh
curl --fail --show-error --silent https://registry.dusk.night-x.com/-/ping
curl --fail --show-error --silent https://registry.dusk.night-x.com/
curl --fail --show-error --silent https://registry.dusk.night-x.com/@acme%2Fwidget
```

The ping response must be `{"ok":true}`. The catalog response must be HTML.
The package check must return a non-empty JSON packument for a package that has
already been published; replace `@acme/widget` with an actual package name.

The server bounds request headers, request and connection time, and publish
bodies (32 MiB). Package metadata is atomically replaced under a SHA-256
package directory; tarballs are deduplicated by SHA-256 content digest. Each
write syncs its file before the atomic rename and then syncs the parent
directory so the rename is durable.

## Public Catalog And Search

With the default `"read_auth": false`, open the registry URL in a browser for
a no-dependency package catalog. It searches public packages and displays an
install command using that registry's origin.

Clients can also use `GET /-/v1/search?q=<query>&from=<offset>&size=<limit>`.
Results are sorted by package name and return the matching package name,
description, latest version, dist-tags, and total result count. The durable
`index.json` is updated with every publish. Registries created before the
index existed are also enumerated from their hashed `metadata.json` files.

## DPM

Install from this registry with:

```sh
dpm install @acme/widget --registry http://localhost:4873
```

Publish with an authorized bearer token configured by your DPM client. The
registry accepts npm publish documents with base64 `_attachments`, calculates
the authoritative SHA-512 SRI integrity value, and never permits replacing an
existing version.

For a portable non-client publish workflow, set `DPM_REGISTRY_URL` to this
registry's public URL and `DPM_REGISTRY_TOKEN` to the plaintext bearer token,
then run the archive package release script:

```sh
export DPM_REGISTRY_URL='https://registry.example'
export DPM_REGISTRY_TOKEN='registry-operator-supplied-token'
node ../dpm-browser-archive-packages/scripts/release-archive-packages.mjs
```

The script validates the archived package manifests, bin entries, and SHA-512
SRI values before it sends any authenticated publish request. Run it with
`--dry-run` to perform only those release checks.
