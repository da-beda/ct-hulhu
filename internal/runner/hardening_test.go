package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/certparser"
	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
	"github.com/TheArqsz/ct-hulhu/internal/evidence"
	"github.com/TheArqsz/ct-hulhu/internal/output"
)

func TestSelectionHashCanonicalizesDomainOrderAndBindsSemantics(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{opts: &Options{
		StateDir: dir,
		Output:   filepath.Join(dir, "results.jsonl"),
		JSON:     true,
		Fields:   "domains",
		Start:    -1,
		Count:    100,
		FromEnd:  true,
	}}
	first, err := r.selectionHash("scrape", []string{" Example.COM ", ".api.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.selectionHash("scrape", []string{"api.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent selections hashed differently: %s != %s", first, second)
	}

	r.opts.Fields = "certs"
	changed, err := r.selectionHash("scrape", []string{"example.com", "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("changing output semantics must change the selection hash")
	}
}

func TestHashedStatePathsSeparateKindsAndAvoidLegacyCollision(t *testing.T) {
	r := &Runner{opts: &Options{StateDir: t.TempDir()}}
	a := ctlog.EntrySource{Protocol: ctlog.ProtocolRFC6962, LogURL: "https://example.test/a:b/"}
	b := ctlog.EntrySource{Protocol: ctlog.ProtocolRFC6962, LogURL: "https://example.test/a_b/"}
	if r.stateFilePath(a.LogURL) != r.stateFilePath(b.LogURL) {
		t.Fatal("test setup expected a collision in the legacy sanitized path")
	}
	if r.scrapeStatePath(a) == r.scrapeStatePath(b) {
		t.Fatal("hashed scrape state paths must not collide")
	}
	if r.scrapeStatePath(a) == r.monitorStatePath(a) {
		t.Fatal("scrape and monitor state paths must be distinct")
	}
}

func TestScrapeProgressV3BindsSelectionAndTrust(t *testing.T) {
	r := &Runner{opts: &Options{StateDir: t.TempDir()}}
	source := ctlog.EntrySource{
		Protocol: ctlog.ProtocolStaticCT,
		LogID:    "log-id",
		LogURL:   "https://monitor.example/",
		Verified: true,
	}
	selection := "selection-a"
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	if err := r.saveScrapeProgress(source, selection, 1000, hexString(root), 100, 900, 500); err != nil {
		t.Fatal(err)
	}
	loaded, err := r.loadScrapeProgress(source, selection)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Version != 3 || !loaded.Verified || loaded.SelectionHash != selection || loaded.NextIndex != 500 {
		t.Fatalf("unexpected progress: %#v", loaded)
	}
	if _, err := r.loadScrapeProgress(source, "selection-b"); err == nil {
		t.Fatal("selection mismatch must fail closed")
	}
	unverified := source
	unverified.Verified = false
	if _, err := r.loadScrapeProgress(unverified, selection); err == nil {
		t.Fatal("trust-level mismatch must fail closed")
	}
}

func TestMonitorProgressPersistsVerifiedRoot(t *testing.T) {
	r := &Runner{opts: &Options{StateDir: t.TempDir()}}
	source := ctlog.EntrySource{
		Protocol: ctlog.ProtocolStaticCT,
		LogID:    "id",
		LogURL:   "https://monitor.example/",
		Verified: true,
	}
	root := make([]byte, 32)
	root[0] = 0x42
	head := &ctlog.TreeHead{TreeSize: 1234, RootHash: root}
	if err := r.saveMonitorProgress(source, "selection", head); err != nil {
		t.Fatal(err)
	}
	loaded, err := r.loadMonitorProgress(source, "selection")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.TreeSize != 1234 || !loaded.Verified || loaded.RootHash != hexString(root) {
		t.Fatalf("unexpected monitor progress: %#v", loaded)
	}
	info, err := os.Stat(r.monitorStatePath(source))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("monitor state is not private: %o", info.Mode().Perm())
	}
}

func TestParseBatchPreservesMalformedEntryWithoutWedge(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{opts: &Options{ParseWorkers: 1}}
	writer, err := output.NewWriter(filepath.Join(dir, "out.jsonl"), true, "domains")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	malformedPath := filepath.Join(dir, "malformed.jsonl")
	malformed, err := evidence.NewWriter(malformedPath)
	if err != nil {
		t.Fatal(err)
	}

	source := ctlog.EntrySource{
		Protocol: ctlog.ProtocolStaticCT,
		LogID:    "log-id",
		LogURL:   "https://monitor.example/",
		Verified: true,
	}
	batch := ctlog.EntryBatch{
		StartIndex: 77,
		Entries: []ctlog.RawEntry{{LeafInput: "!!!not-base64!!!", ExtraData: ""}},
	}
	written, err := r.parseBatch(batch, certparser.New(nil), writer, malformed, source, make(chan struct{}, 1), nil)
	if err != nil {
		t.Fatalf("malformed entry should be preservable rather than wedge progress: %v", err)
	}
	if !written {
		t.Fatal("expected malformed evidence to be written")
	}
	if err := malformed.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := malformed.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(malformedPath)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Index    int64 `json:"index"`
		Verified bool  `json:"verified"`
		Leaf     string `json:"leaf_input"`
	}
	if err := json.Unmarshal(bytesTrimSpace(data), &event); err != nil {
		t.Fatalf("malformed evidence is not valid JSON: %v\n%s", err, data)
	}
	if event.Index != 77 || !event.Verified || event.Leaf != "!!!not-base64!!!" {
		t.Fatalf("unexpected malformed evidence: %#v", event)
	}
}

func hexString(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[2*i] = digits[b>>4]
		out[2*i+1] = digits[b&0xf]
	}
	return string(out)
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
