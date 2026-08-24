package loglist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

const DefaultLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
const maxLogListSize = 4 << 20

var evidenceConfig struct {
	sync.RWMutex
	path string
}

// SetEvidenceOutput configures a process-local path where FetchDefault writes
// the exact signed response bytes it parses. An empty path disables
// persistence. Signature, reviewed public-key and verification-manifest
// sidecars use deterministic suffixes on the configured path.
func SetEvidenceOutput(path string) {
	evidenceConfig.Lock()
	evidenceConfig.path = path
	evidenceConfig.Unlock()
}

func evidenceOutput() string {
	evidenceConfig.RLock()
	defer evidenceConfig.RUnlock()
	return evidenceConfig.path
}

type Fetcher struct {
	client                 *http.Client
	defaultLogListURL      string
	defaultSignatureURL    string
	verifyDefaultSignature func([]byte, []byte) (*SignatureVerificationEvidence, error)
}

func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		client:                 &http.Client{Timeout: timeout},
		defaultLogListURL:      DefaultLogListURL,
		defaultSignatureURL:    DefaultLogListSignatureURL,
		verifyDefaultSignature: verifyChromeLogListSignature,
	}
}

func (f *Fetcher) fetchRawBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "ct-hulhu")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body from %s: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", url, limit)
	}
	return body, nil
}

func parseLogList(body []byte) (*LogList, error) {
	var ll LogList
	if err := json.Unmarshal(body, &ll); err != nil {
		return nil, fmt.Errorf("parsing log list JSON: %w", err)
	}
	return &ll, nil
}

// FetchRaw returns both the parsed log list and the exact response body bytes
// for an explicitly supplied URL. This generic API does not infer a detached
// signature URL; callers that need Chrome's signed default list should use
// FetchDefaultRaw.
func (f *Fetcher) FetchRaw(ctx context.Context, url string) (*LogList, []byte, error) {
	body, err := f.fetchRawBytes(ctx, url, maxLogListSize)
	if err != nil {
		return nil, nil, err
	}
	ll, err := parseLogList(body)
	if err != nil {
		return nil, nil, err
	}
	return ll, body, nil
}

func (f *Fetcher) Fetch(ctx context.Context, url string) (*LogList, error) {
	ll, _, err := f.FetchRaw(ctx, url)
	return ll, err
}

// FetchDefaultRaw fetches Chrome's default list and detached signature,
// verifies the exact JSON bytes against the reviewed embedded Chrome key, then
// parses and optionally persists the verified evidence set.
func (f *Fetcher) FetchDefaultRaw(ctx context.Context) (*LogList, []byte, error) {
	body, err := f.fetchRawBytes(ctx, f.defaultLogListURL, maxLogListSize)
	if err != nil {
		return nil, nil, err
	}
	signature, err := f.fetchRawBytes(ctx, f.defaultSignatureURL, maxLogListSignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching Chrome log-list signature: %w", err)
	}
	if f.verifyDefaultSignature == nil {
		return nil, nil, fmt.Errorf("default log-list signature verifier is not configured")
	}
	verification, err := f.verifyDefaultSignature(body, signature)
	if err != nil {
		return nil, nil, err
	}
	ll, err := parseLogList(body)
	if err != nil {
		return nil, nil, err
	}
	if path := evidenceOutput(); path != "" {
		if err := persistSignedLogListEvidence(path, body, signature, verification); err != nil {
			return nil, nil, fmt.Errorf("persisting signed log-list evidence: %w", err)
		}
	}
	return ll, body, nil
}

func (f *Fetcher) FetchDefault(ctx context.Context) (*LogList, error) {
	ll, _, err := f.FetchDefaultRaw(ctx)
	return ll, err
}

func persistEvidence(path string, body []byte) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	if resolvedParent != parent {
		return "", fmt.Errorf("log-list evidence parent contains a symlink: %s", parent)
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("log-list evidence destination is not a regular file: %s", absolute)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	tmp, err := os.CreateTemp(parent, ".log-list-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, absolute); err != nil {
		return "", err
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return "", err
	}
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// FilterLogs preserves the original RFC6962-only API for callers/tests that
// explicitly need traditional logs.
func FilterLogs(logList *LogList, stateFilter string) []LogWithOperator {
	var result []LogWithOperator
	for _, op := range logList.Operators {
		for _, logEntry := range op.Logs {
			if logEntry.MatchesState(stateFilter) {
				result = append(result, LogWithOperator{Log: logEntry, Operator: op.Name})
			}
		}
	}
	return result
}

type LogWithOperator struct {
	Log      Log
	Operator string
}

// FilterDescriptors returns both RFC6962 and Static CT logs through one stable
// descriptor model. Ordering follows the source log list: each operator's
// traditional logs first, then tiled logs.
func FilterDescriptors(logList *LogList, stateFilter string) []Descriptor {
	var result []Descriptor
	for _, op := range logList.Operators {
		for _, l := range op.Logs {
			if !l.MatchesState(stateFilter) {
				continue
			}
			result = append(result, Descriptor{
				Operator:    op.Name,
				Description: l.Description,
				LogID:       l.LogID,
				Key:         l.Key,
				Protocol:    ctlog.ProtocolRFC6962,
				URL:         l.FullURL(),
				MMD:         l.MMD,
				State:       l.CurrentState(),
			})
		}
		for _, l := range op.TiledLogs {
			if !l.MatchesState(stateFilter) {
				continue
			}
			result = append(result, Descriptor{
				Operator:      op.Name,
				Description:   l.Description,
				LogID:         l.LogID,
				Key:           l.Key,
				Protocol:      ctlog.ProtocolStaticCT,
				SubmissionURL: l.FullSubmissionURL(),
				MonitoringURL: l.FullMonitoringURL(),
				MMD:           l.MMD,
				State:         l.CurrentState(),
			})
		}
	}
	return result
}
