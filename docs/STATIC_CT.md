# Static CT API implementation notes

This document describes how the da-beda fork maps C2SP Static CT API v1.1.0 onto ct-hulhu's protocol-neutral reader contract.

## Protocol model

Traditional RFC6962 and Static CT expose the same logical append-only Merkle tree through different read APIs.

```text
RFC6962                         Static CT API
---------------------------    --------------------------------
get-sth                        <monitoring>/checkpoint
get-entries                    <monitoring>/tile/data/...
Merkle audit APIs              <monitoring>/tile/<level>/...
certificate chain DER          issuer SHA-256 fingerprints + /issuer/<hash>
```

The runner consumes both through:

```go
type Reader interface {
    EntryReader
    Protocol() Protocol
    Source() EntrySource
    GetTreeHead(context.Context) (*TreeHead, error)
}
```

Readers that can authenticate a new tree against a previously persisted verified tree additionally implement:

```go
type ConsistencyAnchorer interface {
    SetConsistencyAnchor(TreeHead) error
}
```

This is intentionally the seam for future protocol variants rather than scattering protocol tests throughout the runner.

## Discovery

Chrome's v3 log list contains traditional logs under `operators[].logs` and Static CT logs under `operators[].tiled_logs`.

For tiled logs ct-hulhu preserves:

- log description;
- RFC6962 LogID;
- SubjectPublicKeyInfo key;
- submission prefix;
- monitoring prefix;
- MMD;
- state;
- temporal interval.

The default state filter is `trusted`, meaning `usable + qualified + readonly`.

## Checkpoint identity

For Static CT v1.1, the expected checkpoint note origin is the submission prefix without scheme and trailing slash.

The note-key ID is:

```text
first_4_bytes(
    SHA256(
        origin || "\n" || 0x05 || RFC6962_LogID
    )
)
```

The fork requires a matching note signature line and extracts:

```text
uint64 timestamp
DigitallySigned tree_head_signature
```

The secure constructor also requires:

```text
RFC6962_LogID == SHA256(SubjectPublicKeyInfo DER)
```

before trusting the log-list key.

## RFC6962 TreeHeadSignature verification

The signed input is exactly:

```text
Version(0)
SignatureType(tree_hash = 1)
uint64 timestamp
uint64 tree_size
opaque root_hash[32]
```

The fork accepts SHA-256 with:

- P-256 ECDSA;
- RSA PKCS#1 v1.5 with a >= 2048-bit key.

Unsupported key/hash/signature combinations fail closed.

## Hash tiles

Static hash tiles are 256 hashes wide.

```text
<monitoring>/tile/<L>/<N>
<monitoring>/tile/<L>/<N>.p/<W>
```

where `W` is 1..255 for a partial right-edge tile.

The fork supports Static levels 0..5. A hash at Static level `L` represents a complete RFC6962 subtree of height `8*L`.

An arbitrary RFC6962 node of height `h` is reconstructed by:

```text
L = h / 8
r = h % 8
```

then fetching `2^r` consecutive hashes from Static level `L` and combining them with RFC6962 node hashing.

Because `2^r <= 128` and is aligned to its own width, such a node never crosses a 256-hash Static tile boundary.

## Merkle hashing

The fork implements RFC6962 domain separation directly:

```text
MTH({}) = SHA256("")
leaf    = SHA256(0x00 || MerkleTreeLeaf)
node    = SHA256(0x01 || left || right)
```

For a non-power-of-two range, recursive splitting uses the largest power of two strictly smaller than the range length, matching RFC6962's Merkle Tree Hash construction.

## Checkpoint-root verification

After verifying the checkpoint signature, the secure Static client reconstructs the full tree root from hash tiles:

```text
rangeRoot(0, tree_size)
```

and requires it to equal the signed checkpoint root.

This verifies that the hash-tile view is consistent with the signed checkpoint without downloading all certificates.

## Data tiles

Data tiles are addressed as:

```text
<monitoring>/tile/data/<N>
<monitoring>/tile/data/<N>.p/<W>
```

The fork supports both identity and gzip content encodings. It explicitly advertises gzip support and also handles logs that send gzip without prior negotiation, as required by the Static CT specification.

The parser decodes each `TileLeaf` as:

```text
TimestampedEntry
[pre_certificate]       // precert entries only
issuer_fingerprint[]
```

It then normalizes the authenticated entry back to the RFC6962 `MerkleTreeLeaf` representation expected by the existing certificate parser.

For precertificates, the Static `pre_certificate` is used to synthesize the RFC6962 `extra_data` prefix containing the complete precertificate. Issuer fingerprints are kept separately rather than pretending the Static tile contains the RFC6962 DER chain.

## Per-entry authentication

For each data entry at absolute index `i`:

1. decode the normalized RFC6962 `MerkleTreeLeaf`;
2. compute `SHA256(0x00 || leaf)`;
3. recursively obtain sibling subtree roots from Static hash tiles;
4. combine the supplied leaf and sibling roots to reconstruct the complete tree root;
5. require equality with the signed checkpoint root.

A syntactically valid but modified data tile therefore fails.

## Append-only verification

The secure client retains the last checkpoint it accepted in the current process.

For the next checkpoint:

```text
new_size < old_size
    -> reject

new_size == old_size && new_root != old_root
    -> reject

new_size > old_size
    -> reconstruct rangeRoot(0, old_size) using the NEW tree
    -> require it equals old_root
```

Because CT leaves and completed hash-tile prefixes are immutable, matching the old prefix root proves the newer tree contains the previous tree unchanged.

### Across process restarts

Continuous monitoring and one-shot `--resume` persist the last verified `(tree_size, root)` along with protocol, LogID, verification status, and contiguous position.

Before a fresh process accepts its first new Static checkpoint, the runner passes that saved tree to `ConsistencyAnchorer.SetConsistencyAnchor`. The secure Static client then applies the same append-only-prefix test above before making the new checkpoint current.

This closes the process-restart gap that would otherwise reset append-only continuity each time ct-hulhu starts.

Scrape and monitor state use different SHA-256-derived filenames so their range semantics cannot overwrite each other.

## Historical partial tiles

A partial tile URL can disappear after the tile becomes full. This applies to both hash tiles and data tiles.

When a requested historical partial tile is unavailable, the fork requests the immutable full tile and uses its first `W` hashes/entries.

Fallback does not weaken length validation:

- full hash tiles must contain exactly 256 SHA-256 hashes;
- full data tiles must decode to exactly 256 entries;
- direct partial responses must match the checkpoint-requested width.

## Request pacing

The outer worker pool rate limiter operates on logical range fetches, but a verified Static range can internally require multiple HTTP requests: checkpoint, data tile, hash tiles, retries, and optional issuer objects.

Therefore the Static client also enforces `--rate-limit` at the individual HTTP-request boundary. Every request reserves a slot before it is sent, including retries. The outer limiter remains as a conservative second bound.

## Bounded immutable-object cache

Hash tiles and on-demand issuer objects are immutable and useful to cache during verification, but partial tile URLs can change as a log grows.

The in-process cache is therefore bounded to 4096 entries with oldest-entry eviction. This prevents a long-running monitor from accumulating every historical `.p/W` variant indefinitely.

## Issuer objects

A Static `TileLeaf` carries SHA-256 issuer fingerprints instead of the RFC6962 chain DER.

`GetIssuer` requests:

```text
<monitoring>/issuer/<lowercase-sha256>
```

and requires:

```text
SHA256(response DER) == requested fingerprint
```

before parsing the response as an X.509 certificate.

Issuer objects are immutable/cacheable and are not fetched during normal hostname enumeration.

## Malformed entries

A verified CT leaf can still contain a certificate that the X.509 parser cannot interpret.

Silently dropping it loses evidence. Refusing to advance forever wedges monitoring. The fork therefore uses a third state:

```text
verified CT leaf
    -> certificate parses
       -> normal output

    -> certificate does not parse
       -> raw malformed JSONL event
       -> fsync
       -> progress may advance
```

If malformed-event persistence fails, the batch remains incomplete and progress does not advance.

The old raw-DER domain-string prefilter is not used as a correctness gate. Every fetched leaf reaches the certificate parser first, ensuring malformed observations cannot vanish merely because the target string was not present in raw bytes.

## Durable monitor state

Monitor mode persists per-log state automatically; it does not require `--resume`.

On first start, the current verified checkpoint becomes the future-monitoring baseline. On restart:

1. load the last durable monitor state;
2. validate protocol, LogID, and verification level;
3. seed the Static consistency anchor from its saved root;
4. verify the current checkpoint extends it;
5. replay `[saved_next_index, current_tree_size)`;
6. fsync normal and malformed evidence;
7. atomically replace the monitor state;
8. only then advance the in-memory position.

This gives at-least-once behavior after a late local state-write failure: duplicate observations are possible, silent gaps are not intentionally accepted.

## Verification provenance

`EntrySource.Verified`, JSON `verified`, and saved state distinguish authenticated Static observations from currently unauthenticated RFC6962 observations.

Verified and unverified state histories cannot be resumed into each other.

## Explicit non-goals

The current Static implementation does not:

- use the unauthenticated compact-name extension;
- mirror complete CT history;
- treat CT presence as proof of current DNS existence or ownership;
- claim end-to-end RFC6962 entry verification for traditional logs.

The last item is a deliberate remaining parity task rather than an ambiguity in output: RFC6962 observations are marked `verified: false`.
