# Azure Dev Proxy

A reverse proxy that allows you to open APIs or webpages using your existing
Azure CLI sign-in. It forwards requests through a local loopback endpoint and
injects `Authorization: Bearer` tokens for configured HTTPS destinations.

The browser UI provides URL navigation, host-to-token-audience mappings, and
GraphiQL. Command-line clients use the same forwarding routes. HTTP destinations
are supported, but never receive an Azure token.

## Get started

You need Python 3.11 or newer and Azure CLI available as `az` on your path.
Install from PyPI, sign in, and start the proxy as a non-root user:

```sh
python -m pip install azure-dev-proxy
az login
azure-dev-proxy
```

The proxy listens on loopback interfaces at port 8080, not on the local network.
Shared-key authentication protects access to the proxy separately from upstream
Azure authentication. On first use, it creates an `auth-token` file beside its
configuration and reuses the key across restarts.

### Browser

1. Open a ready-to-use URL from the startup logs, or visit
   `http://localhost:8080/` and enter the key.
2. Add a [host mapping](#configure-host-mappings) if your service is not covered
   by the defaults.
3. Paste the destination URL and select **Open URL**.

### curl

With the proxy running, open another terminal. In a POSIX shell, replace
`/path/to/auth-token` with the key-file path printed at startup and send a GET
request:

```sh
PROXY_KEY=$(cat /path/to/auth-token)

curl --fail-with-body \
  -H "X-Azure-Dev-Proxy-Token: $PROXY_KEY" \
  "http://127.0.0.1:8080/https://api.example.com/path"
```

To POST JSON:

```sh
curl --fail-with-body \
  -H "X-Azure-Dev-Proxy-Token: $PROXY_KEY" \
  -H "Content-Type: application/json" \
  --data '{"name":"example"}' \
  "http://127.0.0.1:8080/https://api.example.com/items"
```

Replace the example URLs with your API and configure a matching host mapping
if it needs an Azure token. If you use `--config` or `--token-file`, read the
key file shown at startup instead.

The header authenticates to the local proxy; the host mapping selects the
upstream bearer token. Embed the destination URL in the request path rather
than using `curl --proxy`. Use `127.0.0.1` to avoid the `localhost` redirect.

> [!WARNING]
> **Keep the proxy key and startup logs private.** Startup URLs intentionally
> include the key for convenient sign-in. Anyone with the key and access to the
> local listener can use your Azure identity through the proxy. Keys can also
> appear in browser history, command traces, or process listings. The proxy does
> not isolate malicious applications running as your own user.

## Configure host mappings

A host mapping allowlists an HTTPS destination for token injection and selects
the token resource, or audience, requested through Azure CLI. Use the audience
required by the API; it may differ from the API's URL.

On `localhost`, expand **Host mappings and temporary overrides**, enter a
hostname and resource, and select **Save temporary override**. A blank resource
uses the destination's HTTPS origin.

Temporary rules apply immediately and disappear on process exit. **Save to
persisted** writes a rule to the configuration file; **Delete persisted**
removes a saved rule. Persisted edits require a writable file and apply without
a restart. Failed writes leave the active rules unchanged.

Alternatively, supply JSON:

```json
{
  "token_rules": [
    {"host": "api.example.com", "resource": "https://identity.example.com"},
    {"host": "*.example.org"}
  ],
  "trusted_origins": []
}
```

```sh
azure-dev-proxy --config ./config.json
azure-dev-proxy --config ./config.json --check-config
```

Replace the placeholder domains with your service settings. Exact hosts take
priority over wildcards; the longest wildcard suffix wins. Wildcards match
subdomains, not the bare domain. A missing or `null` resource uses the
destination's HTTPS origin. Unmatched hosts are forwarded without an Azure
token. Temporary overrides take priority over persisted rules.

Configuration uses the native per-user directory:

| Platform | Default configuration file |
|---|---|
| Linux | `$XDG_CONFIG_HOME/azure-dev-proxy/config.json`, or `~/.config/azure-dev-proxy/config.json` when unset. |
| Windows | `%APPDATA%\azure-dev-proxy\config.json`, or `~\AppData\Roaming\azure-dev-proxy\config.json` when unset. |
| macOS | `~/Library/Application Support/azure-dev-proxy/config.json` |

The generated `auth-token` lives beside the configuration unless `--token-file`
is supplied. `XDG_CONFIG_HOME` applies only on Linux and other non-Windows,
non-macOS platforms. Missing files receive bundled defaults; existing files
define the complete rule list and are never merged with updated defaults.

On Windows and macOS, existing files under `~/.config` are not moved
automatically. Use `--config` with the old path to retain those settings and
the adjacent key, or move both files to the native directory.

### Bundled mappings

The [default configuration](azure_dev_proxy/default-config.json) includes
public-cloud mappings for management, storage, secrets, messaging, analytics,
AI, monitoring, and productivity APIs. It is a curated allowlist, not a
wildcard for every Azure-hosted service. Your signed-in user still needs the
service's permissions and consent; supply any additional API-required headers.

Event Hubs and Service Bus share `*.servicebus.windows.net` but require
different audiences. The default selects Service Bus. For Event Hubs, add an
exact hostname override with resource `https://eventhubs.azure.net`.

## Forwarding and GraphQL

Forwarding routes embed the upstream URL in the local path:

```text
http://127.0.0.1:8080/https://api.example.com/path
http://127.0.0.1:8080/http://localhost:4000/path
```

The URL-entry page defaults to HTTPS when the scheme is omitted. Forwarding
routes on `localhost` redirect to `127.0.0.1`, separating upstream pages from
the configuration editor. Only `localhost` permits configuration edits;
IP-loopback origins expose read-only mappings.

For GraphiQL, open:

```text
http://localhost:8080/:graphiql/https://api.example.com/graphql
```

### Browser applications

To permit cross-origin forwarding from a local application, add its exact
origin to `trusted_origins`, for example `["http://localhost:3000"]`. Include
nondefault ports; paths, wildcards, and opaque (`null`) origins are rejected.
Only trusted origins receive forwarding CORS headers.

The application must also authenticate with `X-Azure-Dev-Proxy-Token`; origin
trust does not replace authentication or enable cross-site session cookies.
By default, only the proxy's own loopback origins are trusted.

**Trust only applications and forwarded pages that may use your Azure
identity.** Forwarded pages share the IP-loopback origin; host mappings do not
isolate those pages from one another.

## Security and sessions

Azure tokens are injected only for mapped HTTPS destinations. Redirects are
evaluated independently, and HTTP forwarding is always anonymous. Caller
`Authorization` headers, cookies, and proxy credentials are stripped upstream.
Request and response bodies are streamed without automatic decompression.

Browser-origin checks run before forwarding or token acquisition. Configuration
mutations additionally require same-origin access and an anti-CSRF token.
Browsers must support Fetch Metadata. Clients without browser provenance
headers are treated as CLI clients but still require proxy authentication.

The reserved `azure-dev-proxy-token=KEY` query parameter also authenticates
requests and establishes a session. It is stripped before forwarding.
Browser navigations redirect to a key-free URL; API requests receive their
response directly. Other query parameters retain their encoding and order.

Sessions use HttpOnly, SameSite=Lax, host-only cookies. A short-lived, single-use
handoff pairs sessions across `localhost` and `127.0.0.1`. Sessions can survive
restarts with the same key and port; rotate the key and restart to invalidate
them.

On POSIX, the key must be a regular file owned by the current user with no
group or other permissions. Symlinks are rejected, and validation and reading
use the same file descriptor to prevent pathname-replacement races. On Windows,
protect the containing directory's inherited permissions. Request logs omit
the reserved key parameter; startup logs intentionally include it.

## Runtime options

| Option | Purpose |
|---|---|
| `--port 8080` | Set the loopback port. |
| `--az-path /path/to/az` | Select the Azure CLI executable; defaults to `az` on `PATH`. |
| `--config FILE` | Select a JSON configuration file. |
| `--check-config` | Validate configuration without listening; creates defaults if missing. |
| `--idle-timeout 300` | Exit after five idle minutes; default `0` disables idle shutdown. |
| `--token-file FILE` | Select a protected key file. |
| `--token KEY` | Supply the proxy key directly. |
| `--no-auth` | Disable proxy authentication and key-file creation. |

`AZURE_DEV_PROXY_TOKEN` also supplies a key; explicit `--token` or
`--token-file` options take precedence. **With `--no-auth`, other local users
and applications can use the proxy without a key.**

Active requests and streams prevent idle shutdown; open pages and unused
keep-alive connections do not. Temporary rules and acquired tokens are
memory-only.

Systemd socket activation accepts one or two loopback TCP listeners through
`LISTEN_PID` and `LISTEN_FDS`; their ports must match `--port`. Otherwise, the
proxy binds IPv4 and available IPv6 loopback interfaces.

## Development

From a local checkout:

```sh
python -m pip install -e .
```

Install [Hatch](https://hatch.pypa.io/latest/install/), then run:

```sh
hatch run tests
hatch run format
hatch build
```

`tests` runs pytest with a 100% Python line-and-branch coverage gate, including
CLI subprocesses, followed by Ruff lint and format checks and ty type checking.
`format` applies Ruff fixes and formatting. For a focused run, use
`hatch run unit-test -k token -v`.

Use `hatch run coverage` for the coverage report alone. While adding tests,
`hatch run coverage --cov-fail-under=0` reports remaining gaps without enforcing
the gate. Add `--cov-report=html` for a browsable report in `htmlcov/`.

The import namespace is `azure_dev_proxy`. Configuration, authentication, token
acquisition, and listeners are separate modules. `Proxy` loads configuration,
initializes the token provider and local authentication, and owns the aiohttp
application and lifecycle, with routes in `azure_dev_proxy.routers`. Callers
can also supply configuration, a token provider, or authentication explicitly.
