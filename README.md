# Aidenix Atlas client

Atlas is a map of verified real-world data sources — registries, APIs and datasets — with
runnable recipes. It returns *where the data lives and how to call it*, not the data. This
package runs those recipes on your machine: requests go from you straight to the source, with
your own credentials where a source needs them.

<!-- mcp-name: com.aidenix/atlas -->

## Install

```bash
pip install aidenix-atlas            # runtime, signature verification, datasets
pip install "aidenix-atlas[all]"     # + HTML scraping
```

Some recipes read a published file — CSV, Excel, JSON, XML, Parquet, or an archive of them —
instead of an API. The runtime downloads it once, lays it out as a local DuckDB table and reads
it from disk afterwards; a newer file is downloaded again, an unchanged one is not. The cache
lives in `~/.cache/aidenix-atlas/datasets` (`ATLAS_DATASET_CACHE`), capped at 5 GB
(`ATLAS_DATASET_CACHE_GB`). After the refresh interval expires, an unchanged `Last-Modified`
keeps the cached file; a changed or missing date triggers a new download even if the file size
is unchanged.

## Use

Get a personal API key at https://atlas.aidenix.com and set `ATLAS_API_KEY`, then:

```python
from aidenix_atlas import search, fetch

route = search("Legal entity, LEI and subsidiaries of Siemens Aktiengesellschaft")
# {"id": "<chain id>", "inputs": {"company_name": "Siemens Aktiengesellschaft"}, "abstain": False, ...}
if route["id"]:
    result = fetch(route["id"], route["inputs"])
    print(result["data"]["bundle"])   # the data, fetched from the sources on your machine
    print(result["provenance"])       # per step: source, records, when Atlas last verified it
```

`search` asks Atlas which chain answers the task and uses one request from your monthly
allowance. When Atlas abstains, `id` is None and `reason` says why; nearby `candidates` are not
an answer. `fetch` gets the recipe and runs it here.

Lower level:

```python
from aidenix_atlas import run_recipe, run_chain_recipe

run_recipe(endpoint, {"type": "none"}, {"q": "acme"})   # one source endpoint
run_chain_recipe(recipe, {"domain": "stripe.com"})       # multi-step chain, deterministic
```

Concurrent `run_chain_recipe` calls use separate runtime function bindings. An executor
installed by one recipe stays local to that run, including its worker threads; other chains
and direct `run_recipe` calls keep their own execution behavior.

From an AI agent, connect the hosted MCP server instead: `https://atlas.aidenix.com/mcp`
(see https://atlas.aidenix.com/connect).

Every field a recipe can carry — endpoints, auth, pagination, chains, verification status —
is documented at https://atlas.aidenix.com/recipe-format.

## Safety

- The declarative HTTP runner checks the destination before each request. By default it
  blocks private, loopback and link-local addresses. When a proxy resolves the hostname,
  the client can check only local names and literal IP addresses. Set
  `ATLAS_ALLOW_PRIVATE_ADDRESSES=1` only for your own test servers.
- Chain code runs automatically only with `code_trust="verified"`, an integer
  `code_revision` and a valid Atlas Ed25519 signature. The SDK checks the entire
  recipe against a public key shipped with the package before any request or code
  runs. Signatures expire after 24 hours; fetch a fresh recipe when one expires.
- A changed recipe, an unknown key or an invalid/expired signature raises
  `ValueError` from `run_chain_recipe` or `fetch` before execution, including when
  `allow_untrusted_code=True`. The default `run_with_fallback` executor records a
  failed attempt with `code="ValueError"` without sending its HTTP request.
  `allow_untrusted_code=True` (or `ATLAS_ALLOW_UNTRUSTED_CODE=1`) is an explicit
  local opt-in for your own **unsigned** code. Do not enable it for agent-supplied
  or third-party recipes. Unsigned anonymous declarative recipes still work.
- Signatures confirm that Atlas issued the recipe; Python code still runs with
  your process permissions. Verification is not a sandbox. The SDK never accepts
  a public key supplied inside a recipe.
- Declarative HTTP steps that use credentials require an independent `ep.signature` binding
  the complete endpoint and `auth`. Preserve both exactly as Atlas issued them.
  This includes explicit `api_key`, environment keys, passwords and managed auth headers.
- Credential recipients in declarative HTTP steps must use fixed HTTPS origins. Host/port substitutions,
  cross-origin redirects and disabling TLS certificate checks are refused,
  including resource alternatives, fanout and login. `allow_untrusted_code` does
  not bypass credential authorization. Chains with credentials also require the
  complete chain signature.
- Fresh endpoint signatures are required after 24 hours. Regenerate standalone
  exports and refetch recipes issued before 0.7.0; do not remove signatures to
  bypass a failure. Existing unsigned custom endpoints can make anonymous requests.
- Python connectors can call `dataset.fetch` or `dataset.Session.fetch` with their own headers
  and request body. Starting in `0.9.5`, these helpers follow HTTP redirects only within
  the original scheme, hostname and port. Choose a trusted HTTPS URL for the initial request when sending credentials.
  A connector runs with the permissions of the local Python process.

## Run reports

A chain recipe issued by atlas.aidenix.com carries a one-time report address. After the run,
`run_chain_recipe` sends Atlas a short summary so we can see which recipes work for real users
and fix the ones that do not: the outcome (`ok`, `partial`, `empty`, `failed`, `blocked`), per
step the source id, status, HTTP code, record count and truncation, the names of filled outputs
and the duration. Error messages and reasons can contain inputs or secrets, so they
stay in the local execution result and are omitted from reports. Set `ATLAS_TELEMETRY=0` to turn it off. Recipes without a report address send nothing.

The SDK sends reports only to `https://atlas.aidenix.com/v1/runs/<token>` on
port 443. It refuses other hosts, credentials in the URL, other paths, query
strings and fragments. Redirects are never followed. An invalid report address
or a failed send leaves the recipe's execution result unchanged. This recipient
restriction also applies to unsigned recipes; telemetry needs no extra signature.

## Runtime resource limits

Local settings define the resource ceilings. A recipe may lower response size,
request deadline or fanout width; it cannot raise a locally configured ceiling.
Set these environment variables in the process that runs the recipe:

| Variable | Default | Scope |
| --- | --- | --- |
| `ATLAS_BODY_CAP_MB` | 256 MiB | Downloaded bytes and decoded HTTP response bytes per fetch |
| `ATLAS_FETCH_DEADLINE_S` | 300 seconds | One network budget per logical fetch, including queues, redirects and retries |
| `ATLAS_MAX_CONCURRENCY` | 6 | Active runtime HTTP/FTP operations shared across sync/async calls and nested fanouts |
| `ATLAS_UNPACK_CAP_MB` | 256 MiB | Archive output; used ZIP members share a read budget, workbooks are preflighted before library parsing |

For example, a user may set `ATLAS_BODY_CAP_MB=1024` and
`ATLAS_UNPACK_CAP_MB=1024` for larger datasets. Values must be finite and
positive. Invalid values fall back to the defaults. Settings are read at runtime.
Recipe `body_cap_mb`, `deadline_s` and fanout `concurrency` only narrow local values.
Requests have a minimum deadline setting of one second.

HTTP requests negotiate `gzip` and `deflate` (including raw DEFLATE). Decoding is
bounded before output allocation, including intermediate encoding layers and
login responses. Nonempty responses using other encodings fail explicitly.
ZIP stored and DEFLATE members are supported. ZIP BZIP2/LZMA and other methods
are refused because their stdlib ZIP adapters do not bound decoder output on
Python 3.12. Standalone `.bz2` files retain bounded decoding in the table reader.
CPG and ODS mimetype metadata are read as short prefixes; ODS manifests have a
64 KiB ceiling. Unused members of an ordinary ZIP do not consume its read budget.
For XLSX, all member sizes and compression methods are preflighted because
openpyxl owns the subsequent internal reads.

Archive output limits return `truncated: true`, `truncated_by: "unpack_cap"`
and no parsed records in the runtime. Unsupported ZIP methods instead use
`truncated_by: "unsupported_compression"`. HTTP body truncation keeps the existing
`body_cap` marker. Incomplete results must not be treated as an empty complete dataset.

The fetch deadline starts once, before waiting for a source/network slot. It covers
connection and response setup, body reads, redirects, retry backoff and subsequent
attempts. New bytes do not reset it. Expiry closes active connections and returns
`truncated: true`, `truncated_by: "deadline"`; safe complete CSV rows may be retained.
Login uses the same deadline setting and raises `httpx.ReadTimeout` on expiry.
Each pagination fetch has its own budget; the setting is not a whole-chain limit.

Successful bodies are parsed once after downloading, outside the network budget.
Parsing, connector code and other CPU work do not have a hard execution limit here.
Synchronous HTTP/1.1 requests use owned, short-lived connections so that cancelling
one request cannot close another request's connection. This can require additional
TLS handshakes. An untracked idle connection is closed before sending request bytes
and the same unsent request is retried within the original budget.

Blocking OS name resolution may finish in the background after cancellation, but
its late result cannot send an HTTP request. These are network, byte and active-operation
limits, not a process memory sandbox. Python objects and parsing require additional
memory. Arbitrary connector code and other libraries' transports are outside these
runtime guards.

## License

MIT
