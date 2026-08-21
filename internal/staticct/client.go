package staticct

import (
	"compress/gzip"
	"context"
	"crypto"
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

const maxStaticResponseSize = 64 << 20

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

	cacheMu sync.RWMutex
	cache   map[string][]byte
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
	return ctlog.EntrySource{Protocol: ctlog.ProtocolStaticCT, LogID: c.logID, LogURL: c.monitoringURL}
}
func (c *Client) Secure() bool { return c.secure }

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
	c.headMu.Unlock()
	return cp.TreeHead(), nil
}

func (c *Client) verifyConsistency(ctx context.Context, next *Checkpoint) error {
	c.headMu.RLock()
	previous := c.current
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
		path, err := dataTilePath(tileIndex, width)
		if err != nil {
			return nil, err
		}
		body, err := c.getWithRetry(ctx, c.monitoringURL+path)
		if err != nil {
			return nil, fmt.Errorf("data tile %d: %w", tileIndex, err)
		}
		tileEntries, err := parseDataTile(body)
		if err != nil {
			return nil, fmt.Errorf("data tile %d: %w", tileIndex, err)
		}
		if len(tileEntries) != width {
			return nil, fmt.Errorf("data tile %d decoded %d entries, checkpoint requires %d", tileIndex, len(tileEntries), width)
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
		c.cache[relativePath] = append([]byte(nil), body...)
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
