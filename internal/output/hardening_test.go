package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestJSONOutputIncludesVerificationStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	writer, err := NewWriter(path, true, "domains")
	if err != nil {
		t.Fatal(err)
	}
	result := testResult([]string{"example.com"})
	result.Protocol = ctlog.ProtocolStaticCT
	result.LogID = "log-id"
	result.Verified = true
	writer.WriteResult(result)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytesTrimSpace(data), &decoded); err != nil {
		t.Fatal(err)
	}
	verified, ok := decoded["verified"].(bool)
	if !ok || !verified {
		t.Fatalf("verified provenance missing or false: %#v", decoded)
	}
}

func TestWriterRestrictsExistingFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	writer, err := NewWriterWithOptions(path, false, "domains", WriterOptions{Append: true})
	if err != nil {
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
		t.Fatalf("output permissions = %o, want 600", info.Mode().Perm())
	}
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
