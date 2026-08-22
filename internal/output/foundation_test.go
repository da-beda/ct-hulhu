package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestJSONIdentityUsesLogIndexNotCertificateSerial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewWriter(path, true, "domains")
	if err != nil { t.Fatal(err) }
	base := ctlog.CertResult{Serial: "same-serial", Protocol: ctlog.ProtocolRFC6962, LogURL: "https://log.example/", Domains: []string{"a.example"}, Timestamp: time.Unix(1, 0).UTC()}
	first := base; first.Index = 10
	second := base; second.Index = 11; second.Domains = []string{"b.example"}
	w.WriteResult(&first); w.WriteResult(&second)
	if err := w.Close(); err != nil { t.Fatal(err) }
	lines := strings.Split(strings.TrimSpace(string(mustRead(t, path))), "\n")
	if len(lines) != 2 { t.Fatalf("JSON lines = %d, want 2; content=%q", len(lines), strings.Join(lines, "\n")) }
}

func TestJSONEmitsProtocolTimestampAndHashes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewWriter(path, true, "domains"); if err != nil { t.Fatal(err) }
	w.WriteResult(&ctlog.CertResult{Index: 42, Timestamp: time.Date(2026, 8, 21, 20, 0, 0, 123000000, time.UTC), Domains: []string{"api.example.com"}, Protocol: ctlog.ProtocolRFC6962, LogID: "log-id", LogURL: "https://log.example/", LeafHash: "leaf", CertificateSHA256: "cert"})
	if err := w.Close(); err != nil { t.Fatal(err) }
	var got map[string]any
	if err := json.Unmarshal(mustRead(t, path), &got); err != nil { t.Fatal(err) }
	if got["protocol"] != "rfc6962" || got["log_id"] != "log-id" || got["leaf_hash"] != "leaf" || got["cert_sha256"] != "cert" { t.Fatalf("missing provenance fields: %#v", got) }
	if got["timestamp"] != "2026-08-21T20:00:00.123Z" { t.Fatalf("timestamp = %#v", got["timestamp"]) }
}

func TestAppendModePreservesPreviousResumeOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	first, err := NewWriter(path, false, "domains"); if err != nil { t.Fatal(err) }
	first.WriteResult(&ctlog.CertResult{Domains: []string{"first.example"}}); if err := first.Close(); err != nil { t.Fatal(err) }
	second, err := NewWriterWithOptions(path, false, "domains", WriterOptions{Append: true}); if err != nil { t.Fatal(err) }
	second.WriteResult(&ctlog.CertResult{Domains: []string{"second.example"}}); if err := second.Close(); err != nil { t.Fatal(err) }
	if got := string(mustRead(t, path)); got != "first.example\nsecond.example\n" { t.Fatalf("content = %q", got) }
}

func TestWriterCreatesPrivateOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	w, err := NewWriter(path, false, "domains"); if err != nil { t.Fatal(err) }
	if err := w.Close(); err != nil { t.Fatal(err) }
	info, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if got := info.Mode().Perm(); got&0o077 != 0 { t.Fatalf("output mode = %o, expected no group/other access", got) }
}

func mustRead(t *testing.T, path string) []byte { t.Helper(); data, err := os.ReadFile(path); if err != nil { t.Fatal(err) }; return data }
