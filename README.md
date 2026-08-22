<div align="center">
<img src="assets/ct-hulhu.png" alt="ct-hulhu logo" width="20%"/>
<h1>ct-hulhu</h1>

<p>Direct Certificate Transparency reconnaissance with RFC6962 and cryptographically verified Static CT API support.</p>
</div>

> This repository is the `da-beda/ct-hulhu` fork. It extends the original ct-hulhu with loss-aware collection, modern Chrome `tiled_logs`, Static CT API v1.1, Merkle/checkpoint verification, durable monitoring state, and evidence-preserving malformed-entry handling.

## Why this fork exists

Traditional direct CT clients read RFC6962 `get-sth` / `get-entries` endpoints. The public CT ecosystem now also contains Static CT API logs, whose monitoring interface is checkpoint + immutable hash/data tiles rather than RFC6962 read endpoints.

This fork supports both generations through one reader model while making an important distinction explicit:

| Path | Discovery / reading | Cryptographic verification in this fork |
| --- | --- | --- |
| Static CT API | Chrome `operators[].tiled_logs`, checkpoint, data/hash tiles | **Yes** — log key/LogID, checkpoint signature, Merkle root, per-entry inclusion, append-only consistency |
| RFC6962 | Chrome `operators[].logs`, `get-sth`, `get-entries` | **Not yet** — transport/parser checked and emitted as `verified: false` |

A JSON result therefore carries an explicit `verified` field. Do not erase that distinction downstream.

## Install

The fork deliberately retains the original Go module path while the implementation is being stabilized, so build it from a clone rather than using `go install github.com/da-beda/...@latest`:

```bash
git clone https://github.com/da-beda/ct-hulhu.git
cd ct-hulhu
make build
```

or:

```bash
go install ./cmd/ct-hulhu
```

The project uses only the Go standard library. The current `go.mod` declares Go 1.24.7.

## Quick start

### Inspect the current trusted log set

```bash
ct-hulhu -ls
ct-hulhu -ls -json
```

Auto-discovery understands both traditional and tiled logs. The fork default is:

```text
-log-state trusted
```

where `trusted` means:

```text
usable + qualified + readonly
```

Individual `usable`, `qualified`, `readonly`, `retired`, and `all` selectors remain available.

### Bounded recent discovery

```bash
ct-hulhu \
  -d example.com \
  -from-end \
  -n 10000 \
  -json \
  -o ct-example.jsonl
```

`-n` is applied per selected log. Without `-from-end`, `-n 10000` begins at entry zero; it does **not** mean the newest 10,000 entries.

### Explicit RFC6962 log

`-lu` intentionally remains RFC6962-only because a Static log needs a coherent submission URL, monitoring URL, LogID, and public key. Auto-discovery supplies those values from Chrome's log list instead of guessing them from one URL.

```bash
ct-hulhu \
  -lu https://ct.googleapis.com/logs/us1/argon2025h1/ \
  -d example.com \
  -from-end \
  -n 5000 \
  -json
```

Results from this path currently carry `"verified": false`.

## Static CT verification model

For an auto-discovered Static CT log, an entry is accepted through this chain:

```text
Chrome tiled_logs descriptor
        |
        +--> parse SubjectPublicKeyInfo
        +--> SHA256(SPKI DER) == advertised LogID
        |
        v
signed Static checkpoint
        |
        +--> C2SP note key ID matches LogID/origin
        +--> RFC6962 TreeHeadSignature verifies
        |
        v
Static hash tiles
        |
        +--> reconstruct signed checkpoint Merkle root
        |
        v
Static data TileLeaf
        |
        +--> RFC6962 leaf hash
        +--> inclusion path reconstructs checkpoint root
        |
        v
verified CT observation
```

When a newer checkpoint is observed, the reader also reconstructs the previous tree-size prefix from the newer tree and requires it to equal the previously verified root. Persistent monitor state can seed that previous `(tree_size, root)` after a process restart, so append-only checking does not reset merely because ct-hulhu restarted.

The unauthenticated Static CT compact-name extension is deliberately not used.

## Monitoring and restart safety

Start future-only monitoring:

```bash
ct-hulhu \
  -m \
  -d example.com \
  -json \
  -o example-monitor.jsonl
```

The initial current tree position for every selected log is persisted privately. To replay anything added while the process was down and continue from the saved position:

```bash
ct-hulhu \
  -m \
  -resume \
  -d example.com \
  -json \
  -o example-monitor.jsonl
```

Runtime state is versioned and bound to:

- protocol, LogID, and read URL;
- `verified` trust level;
- normalized target-domain selection;
- JSON / field-output semantics;
- output and malformed-evidence destinations;
- scrape range semantics where applicable.

Changing those semantics causes state reuse to fail closed rather than silently skipping entries that were never evaluated under the new configuration.

Scrape and monitor state use separate SHA-256-derived filenames under `-state-dir` (default `~/.ct-hulhu`). State files are `0600`; the state directory is restricted to `0700`.

## Malformed certificate evidence

A CT leaf can be cryptographically included while containing certificate material that Go's normal X.509 parser rejects. Such a leaf must not disappear, but it must not permanently wedge monitoring either.

This fork preserves parser failures to append-only JSONL evidence before checkpoint progress is allowed to advance. The default path is:

```text
<output>.malformed.jsonl
```

or, when stdout is used:

```text
<state-dir>/malformed.jsonl
```

Override it with:

```bash
-malformed-output path/to/malformed.jsonl
```

Each event records source protocol, LogID/URL, verification status, entry index, parse error, normalized raw `leaf_input` / `extra_data`, and Static issuer fingerprints when available. The file is `0600` and is flushed + `fsync`'d before a batch containing malformed observations can advance its persistent checkpoint.

## Output durability and provenance

When `-o` is used, output files are restricted to `0600`, including pre-existing files. `Flush()` is a durability boundary: it flushes the Go buffer and `fsync`s the output before persistent progress may advance.

JSON output includes fields such as:

```json
{
  "domains": ["api.example.com"],
  "protocol": "static-ct-api",
  "log_id": "...",
  "log_url": "https://.../monitoring/",
  "index": 12345,
  "timestamp": "2026-08-22T12:34:56.789Z",
  "leaf_hash": "...",
  "cert_sha256": "...",
  "issuer_fingerprints": ["..."],
  "verified": true
}
```

Certificate serial numbers are metadata only. Dedup identity uses protocol + log identity + entry index rather than `serial + log_url`, because certificate serials are issuer-scoped and are not globally unique.

## Failure semantics

The collector is intentionally loss-aware:

- failed/non-empty ranges are errors, not warning-only success;
- zero-entry, nil, or oversized logical responses fail closed;
- out-of-order worker completion cannot advance resume state across a gap;
- monitor positions move only after the corresponding output/evidence is durable and the new monitor state is persisted;
- a failed monitor delta retains the previous position and is retried on a later poll;
- monitor startup fails if any selected log cannot initialize, rather than quietly claiming partial coverage as complete.

Retries and HTTP responses are bounded. `-rl` caps underlying CT HTTP requests. Static CT applies the cap inside the reader because one logical range can require checkpoint, data-tile, and hash-tile traffic.

## Scope and downstream use

Certificate Transparency is an observation source, not proof of present ownership, live DNS, bounty scope, or authorization to probe a hostname.

A safe workflow is:

```text
CT evidence
    -> identifier normalization
    -> program scope / ownership decision
    -> inventory + change classification
    -> explicitly authorized active probing
```

Do not pipe newly observed CT names directly into broad active scanners unless an external authorization/scope layer has already made that decision.

## Important remaining limitation

The Static CT path is cryptographically verified. The traditional RFC6962 path currently is not: it retrieves STHs and entries but does not yet verify the log public key, STH signature, consistency proof, and per-entry audit proof. Those JSON observations are explicitly marked:

```json
"verified": false
```

Implementing RFC6962 proof parity is a worthwhile follow-up, but the fork does not hide the current difference.

## Development validation

The repository CI workflow runs:

```bash
go vet ./...
go build ./cmd/ct-hulhu/
go test -race ./...
```

On a newly created GitHub fork, Actions may require a one-time manual enable before PR workflows execute.

## References

- RFC 6962 — Certificate Transparency v1
- C2SP Static CT API v1.1
- Chrome Certificate Transparency Log Policy
- Chrome CT log list v3

## License

[MIT](LICENSE.md)
