package loglist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogMatchesState(t *testing.T) {
	tests := []struct {
		state  LogState
		filter string
		want   bool
	}{
		{LogState{Usable: &StateInfo{}}, "usable", true},
		{LogState{Usable: &StateInfo{}}, "readonly", false},
		{LogState{Usable: &StateInfo{}}, "all", true},
		{LogState{ReadOnly: &ReadOnlyInfo{}}, "readonly", true},
		{LogState{ReadOnly: &ReadOnlyInfo{}}, "usable", false},
		{LogState{Retired: &StateInfo{}}, "retired", true},
		{LogState{Qualified: &StateInfo{}}, "qualified", true},
		{LogState{}, "usable", false},
		{LogState{}, "all", true},
	}

	for _, tt := range tests {
		log := Log{State: tt.state}
		got := log.MatchesState(tt.filter)
		if got != tt.want {
			t.Errorf("MatchesState(%+v, %q) = %v, want %v", tt.state, tt.filter, got, tt.want)
		}
	}
}

func TestLogCurrentState(t *testing.T) {
	tests := []struct {
		state LogState
		want  string
	}{
		{LogState{Usable: &StateInfo{}}, "usable"},
		{LogState{ReadOnly: &ReadOnlyInfo{}}, "readonly"},
		{LogState{Retired: &StateInfo{}}, "retired"},
		{LogState{Qualified: &StateInfo{}}, "qualified"},
		{LogState{Pending: &StateInfo{}}, "pending"},
		{LogState{Rejected: &StateInfo{}}, "rejected"},
		{LogState{}, "unknown"},
	}

	for _, tt := range tests {
		log := Log{State: tt.state}
		got := log.CurrentState()
		if got != tt.want {
			t.Errorf("CurrentState(%+v) = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestLogFullURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"ct.googleapis.com/logs/us1/argon2025h1/", "https://ct.googleapis.com/logs/us1/argon2025h1/"},
		{"ct.googleapis.com/logs/us1/argon2025h1", "https://ct.googleapis.com/logs/us1/argon2025h1/"},
	}

	for _, tt := range tests {
		log := Log{URL: tt.url}
		got := log.FullURL()
		if got != tt.want {
			t.Errorf("FullURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestFilterLogs(t *testing.T) {
	logList := &LogList{
		Operators: []Operator{
			{
				Name: "Google",
				Logs: []Log{
					{Description: "Argon", State: LogState{Usable: &StateInfo{}}},
					{Description: "Retired", State: LogState{Retired: &StateInfo{}}},
				},
			},
		},
	}

	usable := FilterLogs(logList, "usable")
	if len(usable) != 1 || usable[0].Log.Description != "Argon" {
		t.Errorf("expected 1 usable log (Argon), got %d", len(usable))
	}

	all := FilterLogs(logList, "all")
	if len(all) != 2 {
		t.Errorf("expected 2 logs for 'all', got %d", len(all))
	}

	retired := FilterLogs(logList, "retired")
	if len(retired) != 1 || retired[0].Log.Description != "Retired" {
		t.Errorf("expected 1 retired log, got %d", len(retired))
	}
}

const testLogListJSON = `{
	"version": "3",
	"operators": [{
		"name": "TestOp",
		"email": ["test@example.com"],
		"logs": [{
			"description": "TestLog",
			"log_id": "abc123",
			"url": "ct.example.com/log/",
			"mmd": 86400,
			"state": {"usable": {"timestamp": "2025-01-01T00:00:00Z"}}
		}]
	}]
}`

func testLogListServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testLogListJSON))
	}))
}

func TestFetch(t *testing.T) {
	srv := testLogListServer(t)
	defer srv.Close()

	fetcher := NewFetcher(5 * time.Second)
	logList, err := fetcher.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if logList.Version != "3" {
		t.Errorf("Version = %q, want '3'", logList.Version)
	}
	if len(logList.Operators) != 1 {
		t.Fatalf("expected 1 operator, got %d", len(logList.Operators))
	}
	if logList.Operators[0].Name != "TestOp" {
		t.Errorf("operator name = %q", logList.Operators[0].Name)
	}
	if len(logList.Operators[0].Logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logList.Operators[0].Logs))
	}
	if logList.Operators[0].Logs[0].Description != "TestLog" {
		t.Errorf("log description = %q", logList.Operators[0].Logs[0].Description)
	}
}

func TestFetchRawPreservesExactResponseBytes(t *testing.T) {
	srv := testLogListServer(t)
	defer srv.Close()

	fetcher := NewFetcher(5 * time.Second)
	logList, raw, err := fetcher.FetchRaw(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchRaw error: %v", err)
	}
	if logList.Version != "3" {
		t.Fatalf("version = %q", logList.Version)
	}
	if string(raw) != testLogListJSON {
		t.Fatalf("raw response bytes changed before parsing/preservation")
	}
}

func TestPersistEvidenceIsExactPrivateAndDigestBound(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "log-list.json")
	body := []byte(testLogListJSON)
	digest, err := persistEvidence(path, body)
	if err != nil {
		t.Fatalf("persistEvidence: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatal("persisted log-list bytes differ from fetched bytes")
	}
	sum := sha256.Sum256(body)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %s, want %x", digest, sum)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestPersistEvidenceRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := persistEvidence(filepath.Join(link, "log-list.json"), []byte(testLogListJSON)); err == nil {
		t.Fatal("expected symlink-parent rejection")
	}
}

func TestEvidenceOutputSetting(t *testing.T) {
	SetEvidenceOutput("/tmp/ct-hulhu-log-list-evidence")
	t.Cleanup(func() { SetEvidenceOutput("") })
	if got := evidenceOutput(); got != "/tmp/ct-hulhu-log-list-evidence" {
		t.Fatalf("evidenceOutput = %q", got)
	}
}

func TestFetch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fetcher := NewFetcher(5 * time.Second)
	_, err := fetcher.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestFetch_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	fetcher := NewFetcher(5 * time.Second)
	_, err := fetcher.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewFetcher(t *testing.T) {
	f := NewFetcher(10 * time.Second)
	if f.client == nil {
		t.Fatal("expected non-nil client")
	}
	if f.client.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", f.client.Timeout)
	}
}
