package runner

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitorBaselineIsDurableBeforeFirstPoll(t *testing.T) {
	root := t.TempDir()
	baselinePath := filepath.Join(root, "evidence", "baseline.json")
	secondRequest := make(chan struct{}, 1)
	var requests atomic.Int32

	rootHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-sth" {
			http.NotFound(w, r)
			return
		}
		request := requests.Add(1)
		if request == 2 {
			if _, err := os.Stat(baselinePath); err != nil {
				t.Errorf("first poll reached the log before baseline durability: %v", err)
			}
			select {
			case secondRequest <- struct{}{}:
			default:
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":            0,
			"timestamp":            1,
			"sha256_root_hash":     rootHash,
			"tree_head_signature": "",
		})
	}))
	defer server.Close()

	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(root, "test-root.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certificatePath)

	stateDir := filepath.Join(root, "state")
	outputPath := filepath.Join(root, "results.jsonl")
	malformedPath := filepath.Join(root, "malformed.jsonl")
	runner := &Runner{opts: &Options{
		Domain:                stringSlice{"example.com"},
		LogURL:                stringSlice{server.URL},
		Workers:               1,
		ParseWorkers:          1,
		BatchSize:             1,
		Timeout:               5,
		Retries:               0,
		Output:                outputPath,
		MalformedOutput:       malformedPath,
		JSON:                  true,
		Fields:                "domains",
		Silent:                true,
		Monitor:               true,
		PollInterval:          60,
		MonitorBaselineOutput: baselinePath,
		Resume:                true,
		StateDir:              stateDir,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		select {
		case <-secondRequest:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := runner.monitorWithBaseline(ctx); err != nil {
		t.Fatalf("monitorWithBaseline: %v", err)
	}
	if requests.Load() < 2 {
		t.Fatalf("expected initialization and first-poll tree heads, got %d request(s)", requests.Load())
	}
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var baseline monitorBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) != 1 {
		t.Fatalf("new monitor expected one initialized state file, got %d", len(baseline.Files))
	}
}
