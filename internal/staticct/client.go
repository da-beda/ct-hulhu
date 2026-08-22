package staticct

import (
	"compress/gzip"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

const (
	maxStaticResponseSize = 64 << 20
	maxStaticCacheEntries = 4096
)

type Client struct {
	submissionURL string
	monitoringURL string
	logID         string
	httpClient    *http.Client
	retries       int

	secure    bool
	publicKey crypto.PublicKey

	headMu  sync.RWMutex
	current *Checkpoint
	anchor  *Checkpoint

	cacheMu    sync.RWMutex
	cache      map[string][]byte
	cacheOrder []string

	rateMu          sync.Mutex
	requestInterval time.Duration
	nextRequest     time.Time
}

// NewClient creates a structural Static CT reader. It is retained for isolated
// decoder tests. Production/autodiscovered use should call NewClientWithKey.
func NewClient(submissionURL, monitoringURL, logID string, timeout time.Duration, retries int) (*Client, error) {
	return newClient(submissionURL, monitoringURL, logID, timeout, retries)
}

// NewClientWithKey creates a cryptographically verifying Static CT reader.
// The log ID must equal SHA-256(SubjectPublicKeyInfo), as required by RFC6962.
func NewClientWithKey(submissionURL, monitoringURL, logID, keyBase64 string, timeout time.Duration, retries int) (*Client, error) {
	client, err := newClient(submissionURL, monitoringURL, logID, timeout, retries)
	if err != nil {
		return nil, err
	}
	pub, err := parseLogPublicKey(keyBase64, logID)
	if err != nil {
		return nil, err
	}
	client.secure = true
	client.publicKey = pub
	return client, nil
}

func newClient(submissionURL, monitoringURL, logID string, timeout time.Duration, retries int) (*Client, error) {
	submission, err := normalizeURL(submissionURL)
	if err != nil {
		return nil, fmt.Errorf("submission URL: %w", err)
	}
	monitoring, err := normalizeURL(monitoringURL)
	if err != nil {
		return nil, fmt.Errorf("monitoring URL: %w", err)
	}
	if _, err := checkpointOrigin(submission); err != nil {
		return nil, err
	}
	return &Client{
		submissionURL: submission,
		monitoringURL: monitoring,
		logID:         logID,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				DisableCompression:   true,
			},
		},
		retries: retries,
		cache:   make(map[string][]byte),
	}, nil
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo is not allowed in CT log URLs")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("query/fragment not allowed")
	}
	value := u.String()
	if !strings.HasSuffix(value, "/") {
		value += "/"
	}
	return value, nil
}

func (c *Client) Protocol() ctlog.Protocol { return ctlog.ProtocolStaticCT }
func (c *Client) Source() ctlog.EntrySource {
	return ctlog.EntrySource{
		Protocol: ctlog.ProtocolStaticCT,
		LogID:    c.logID,
		LogURL:   c.monitoringURL,
		Verified: c.secure,
	}
}
func (c *Client) Secure() bool { return c.secure }

// SetRequestRateLimit caps all Static CT HTTP requests, including checkpoint,
// data-tile, hash-tile and retry traffic. A value of zero disables the cap.
func (c *Client) SetRequestRateLimit(requestsPerSecond int) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	if requestsPerSecond <= 0 {
		c.requestInterval = 0
		c.nextRequest = time.Time{}
		return
	}
	c.requestInterval = time.Second / time.Duration(requestsPerSecond)
	if c.requestInterval <= 0 {
		c.requestInterval = time.Nanosecond
	}
	c.nextRequest = time.Time{}
}

func (c *Client) waitRequestSlot(ctx context.Context) error {
	c.rateMu.Lock()
	interval := c.requestInterval
	if interval <= 0 {
		c.rateMu.Unlock()
		return nil
	}
	now := time.Now()
	slot := now
	if c.nextRequest.After(now) {
		slot = c.nextRequest
	}
	c.nextRequest = slot.Add(interval)
	c.rateMu.Unlock()

	wait := time.Until(slot)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SeedConsistencyAnchor restores the last verified checkpoint root from
// durable monitor state. It is intentionally separate from current so the
// client cannot serve entries against an unsigned/incomplete synthetic head.
func (c *Client) SeedConsistencyAnchor(treeSize int64, rootHash []byte) error {
	if !c.secure {
		return fmt.Errorf("cannot seed consistency anchor on an unverified Static CT client")
	}
	if treeSize < 0 {
		return fmt.Errorf("negative consistency-anchor tree size %d", treeSize)
	}
	if len(rootHash) != sha256.Size {
		return fmt.Errorf("consistency-anchor root has %d bytes, want %d", len(rootHash), sha256.Size)
	}
	c.headMu.Lock()
	defer c.headMu.Unlock()
	if c.current != nil {
		return fmt.Errorf("cannot seed consistency anchor after a current checkpoint was accepted")
	}
	c.anchor = &Checkpoint{TreeSize: treeSize, RootHash: append([]byte(nil), rootHash...)}
	return nil
}

func (c *Client) GetTreeHead(ctx context.Context) (*ctlog.TreeHead, error) {
	body, err := c.getWithRetry(ctx, c.monitoringURL+"checkpoint")
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	cp, err := ParseCheckpoint(body, c.submissionURL, c.logID)
	if err != nil {
		return nil, err
	}

	if c.secure {
		if err := verifyCheckpointSignature(c.publicKey, cp); err != nil {
			return nil, fmt.Errorf("verifying checkpoint signature: %w", err)
		}
		root, err := c.rangeRoot(ctx, 0, cp.TreeSize, cp.TreeSize)
		if err != nil {
			return nil, fmt.Errorf("reconstructing checkpoint root: %w", err)
		}
		if !cryptoBytesEqual(root[:], cp.RootHash) {
			return nil, fmt.Errorf("hash tiles reconstruct root %x, checkpoint signs %x", root, cp.RootHash)
		}
		if err := c.verifyConsistency(ctx, cp); err != nil {
			return nil, err
		}
	}

	c.headMu.Lock()
	c.current = cp
	if c.secure {
		c.anchor = cp
	}
	c.headMu.Unlock()
	return cp.TreeHead(), nil
}

func (c *Client) verifyConsistency(ctx context.Context, next *Checkpoint) error {
	c.headMu.RLock()
	previous := c.current
	if previous == nil {
		previous = c.anchor
	}
	c.headMu.RUnlock()
	if previous == nil {
		return nil
	}
	if next.TreeSize < previous.TreeSize {
		return fmt.Errorf("checkpoint tree size regressed from %d to %d", previous.TreeSize, next.TreeSize)
	}
	if next.TreeSize == previous.TreeSize {
		if !cryptoBytesEqual(next.RootHash, previous.RootHash) {
			return fmt.Errorf("same-size checkpoints disagree on Merkle root")
		}
		return nil
	}
	oldPrefix, err := c.rangeRoot(ctx, 0, previous.TreeSize, next.TreeSize)
	if err != nil {
		return fmt.Errorf("verifying append-only prefix: %w", err)
	}
	if !cryptoBytesEqual(oldPrefix[:], previous.RootHash) {
		return fmt.Errorf("new checkpoint does not contain previous tree as an identical prefix")
	}
	return nil
}

func (c *Client) currentCheckpoint(ctx context.Context) (*Checkpoint, error) {
	c.headMu.RLock()
	cp := c.current
	c.headMu.RUnlock()
	if cp != nil {
		return cp, nil
	}
	if _, err := c.GetTreeHead(ctx); err != nil {
		return nil, err
	}
	c.headMu.RLock()
	defer c.headMu.RUnlock()
	if c.current == nil {
		return nil, fmt.Errorf("tree-head fetch produced no checkpoint")
	}
	return c.current, nil
}

func (c *Client) getDataTile(ctx context.Context, tileIndex uint64, width int) ([]ctlog.RawEntry, error) {
	path, err := dataTilePath(tileIndex, width)
	if err != nil {
		return nil, err
	}
	body, fetchErr := c.getWithRetry(ctx, c.monitoringURL+path)
	usedFullFallback := false
	if fetchErr != nil && width < tileWidth {
		fullPath, pathErr := dataTilePath(tileIndex, tileWidth)
		if pathErr != nil {
			return nil, pathErr
		}
		body, err = c.getWithRetry(ctx, c.monitoringURL+fullPath)
		if err != nil {
			return nil, fmt.Errorf("partial data tile %s unavailable (%v); full fallback failed: %w", path, fetchErr, err)
		}
		usedFullFallback = true
	} else if fetchErr != nil {
		return nil, fetchErr
	}

	entries, err := parseDataTile(body)
	if err != nil {
		return nil, err
	}
	if usedFullFallback {
		if len(entries) < width {
			return nil, fmt.Errorf("full fallback data tile contains %d entries, need %d", len(entries), width)
		}
		return append([]ctlog.RawEntry(nil), entries[:width]...), nil
	}
	if len(entries) != width {
		return nil, fmt.Errorf("data tile decoded %d entries, checkpoint requires %d", len(entries), width)
	}
	return entries, nil
}

func (c *Client) GetRawEntries(ctx context.Context, start, end int64) (*ctlog.GetEntriesResponse, error) {
	if start < 0 || end < start {
		return nil, fmt.Errorf("invalid entry range [%d-%d]", start, end)
	}
	cp, err := c.currentCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if end >= cp.TreeSize {
		return nil, fmt.Errorf("range end %d is outside checkpoint tree size %d", end, cp.TreeSize)
	}

	entries := make([]ctlog.RawEntry, 0, end-start+1)
	absoluteIndexes := make([]int64, 0, end-start+1)
	for current := start; current <= end; {
		tileIndex := uint64(current / tileWidth)
		tileStart := int64(tileIndex * tileWidth)
		offset := int(current - tileStart)
		width := tileWidth
		fullTiles := cp.TreeSize / tileWidth
		remainder := int(cp.TreeSize % tileWidth)
		if int64(tileIndex) == fullTiles && remainder > 0 {
			width = remainder
		}

		tileEntries, err := c.getDataTile(ctx, tileIndex, width)
		if err != nil {
			return nil, fmt.Errorf("data tile %d: %w", tileIndex, err)
		}
		remaining := int(end - current + 1)
		available := width - offset
		take := min(remaining, available)
		for i := 0; i < take; i++ {
			entries = append(entries, tileEntries[offset+i])
			absoluteIndexes = append(absoluteIndexes, current+int64(i))
		}
		current += int64(take)
	}

	if c.secure {
		for i, entry := range entries {
			leaf, err := decodedLeafHash(entry.LeafInput)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", absoluteIndexes[i], err)
			}
			root, err := c.rootWithLeaf(ctx, 0, cp.TreeSize, absoluteIndexes[i], leaf, cp.TreeSize)
			if err != nil {
				return nil, fmt.Errorf("entry %d inclusion verification: %w", absoluteIndexes[i], err)
			}
			if !cryptoBytesEqual(root[:], cp.RootHash) {
				return nil, fmt.Errorf("entry %d does not authenticate to checkpoint root", absoluteIndexes[i])
			}
		}
	}
	return &ctlog.GetEntriesResponse{Entries: entries}, nil
}

func (c *Client) getCached(ctx context.Context, relativePath string) ([]byte, error) {
	c.cacheMu.RLock()
	cached, ok := c.cache[relativePath]
	c.cacheMu.RUnlock()
	if ok {
		return append([]byte(nil), cached...), nil
	}
	body, err := c.getWithRetry(ctx, c.monitoringURL+relativePath)
	if err != nil {
		return nil, err
	}

	c.cacheMu.Lock()
	if existing, exists := c.cache[relativePath]; exists {
		body = existing
	} else {
		if len(c.cacheOrder) >= maxStaticCacheEntries {
			oldest := c.cacheOrder[0]
			c.cacheOrder = c.cacheOrder[1:]
			delete(c.cache, oldest)
		}
		c.cache[relativePath] = append([]byte(nil), body...)
		c.cacheOrder = append(c.cacheOrder, relativePath)
	}
	c.cacheMu.Unlock()
	return append([]byte(nil), body...), nil
}

func (c *Client) getWithRetry(ctx context.Context, target string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		body, err := c.get(ctx, target)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all %d retries exhausted: %w", c.retries, lastErr)
}

func (c *Client) get(ctx context.Context, target string) ([]byte, error) {
	if err := c.waitRequestSlot(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ct-hulhu")
	req.Header.Set("Accept-Encoding", "gzip, identity")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, target)
	}

	var reader io.Reader = resp.Body
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("opening gzip response: %w", err)
		}
		defer gz.Close()
		reader = gz
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", resp.Header.Get("Content-Encoding"))
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxStaticResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxStaticResponseSize {
		return nil, fmt.Errorf("response exceeds %d bytes", maxStaticResponseSize)
	}
	return body, nil
}
