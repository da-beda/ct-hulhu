package runner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteMonitorBaselinePreservesInitializedState(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "monitor-abc.json")
	stateData := []byte(`{"version":3,"selection_hash":"` + strings.Repeat("0", 64) + `"}`)
	if err := os.WriteFile(statePath, stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "evidence", "baseline.json")
	selection := hex.EncodeToString(make([]byte, sha256.Size))
	if err := writeMonitorBaseline(output, stateDir, selection, []string{statePath}); err != nil {
		t.Fatalf("writeMonitorBaseline: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	var baseline monitorBaseline
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SchemaVersion != monitorBaselineSchema || baseline.SelectionHash != selection {
		t.Fatalf("unexpected baseline identity: %+v", baseline)
	}
	if len(baseline.Files) != 1 || baseline.Files[0].Path != "monitor-abc.json" {
		t.Fatalf("unexpected files: %+v", baseline.Files)
	}
	decoded, err := base64.StdEncoding.DecodeString(baseline.Files[0].DataBase64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(stateData) {
		t.Fatalf("decoded state differs: %q", decoded)
	}
	sum := sha256.Sum256(stateData)
	if baseline.Files[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("state digest mismatch")
	}
}

func TestWriteMonitorBaselineAllowsNoNewStateFiles(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "baseline.json")
	selection := hex.EncodeToString(make([]byte, sha256.Size))
	if err := writeMonitorBaseline(output, stateDir, selection, nil); err != nil {
		t.Fatalf("writeMonitorBaseline: %v", err)
	}
	var baseline monitorBaseline
	data, _ := os.ReadFile(output)
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) != 0 {
		t.Fatalf("files = %+v, want empty", baseline.Files)
	}
}

func TestWriteMonitorBaselineRejectsExistingDestination(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	selection := hex.EncodeToString(make([]byte, sha256.Size))
	if err := writeMonitorBaseline(output, stateDir, selection, nil); err == nil {
		t.Fatal("expected existing-destination error")
	}
}

func TestWriteMonitorBaselineRejectsEscapingStatePath(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "monitor-outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	selection := hex.EncodeToString(make([]byte, sha256.Size))
	if err := writeMonitorBaseline(filepath.Join(root, "baseline.json"), stateDir, selection, []string{outside}); err == nil {
		t.Fatal("expected escaping-state error")
	}
}
