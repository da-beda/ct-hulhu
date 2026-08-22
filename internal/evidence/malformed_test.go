package evidence

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestMalformedWriterPersistsPrivateEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "malformed.jsonl")
	writer, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	source := ctlog.EntrySource{
		Protocol: ctlog.ProtocolStaticCT,
		LogID:    "id",
		LogURL:   "https://monitor.example/",
		Verified: true,
	}
	entry := ctlog.RawEntry{LeafInput: "leaf", ExtraData: "extra", IssuerFingerprints: []string{"aa"}}
	if err := writer.Append(source, 9, entry, errors.New("parse failed")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode=%o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event MalformedEvent
	if err := json.Unmarshal(trimSpace(data), &event); err != nil {
		t.Fatal(err)
	}
	if event.Index != 9 || !event.Verified || event.LeafInput != "leaf" || event.Error != "parse failed" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func trimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
