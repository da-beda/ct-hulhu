package ctlog

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetTreeHeadNormalizesRFC6962Metadata(t *testing.T) {
	root := make([]byte, 32)
	for i := range root { root[i] = byte(i) }
	sig := []byte{4, 3, 2, 1}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tree_size":17,"timestamp":1234,"sha256_root_hash":"`+base64.StdEncoding.EncodeToString(root)+`","tree_head_signature":"`+base64.StdEncoding.EncodeToString(sig)+`"}`))
	}))
	defer srv.Close()
	c := NewClientWithLogID(srv.URL, "log-id", 5*time.Second, 0)
	head, err := c.GetTreeHead(context.Background())
	if err != nil { t.Fatal(err) }
	if head.TreeSize != 17 || head.Timestamp != 1234 || len(head.RootHash) != 32 || string(head.Signature) != string(sig) { t.Fatalf("unexpected tree head: %#v", head) }
	if c.Protocol() != ProtocolRFC6962 || c.Source().LogID != "log-id" || c.Source().LogURL != srv.URL { t.Fatalf("unexpected source: %#v", c.Source()) }
}

func TestGetTreeHeadRejectsInvalidRootLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tree_size":17,"sha256_root_hash":"YQ==","tree_head_signature":""}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, 5*time.Second, 0).GetTreeHead(context.Background()); err == nil { t.Fatal("expected invalid root length error") }
}

func TestSourceIdentityDoesNotGainRequestTrailingSlash(t *testing.T) {
	c := NewClient("https://example.com/log", 5*time.Second, 0)
	if c.baseURL != "https://example.com/log/" { t.Fatalf("request base = %q", c.baseURL) }
	if c.Source().LogURL != "https://example.com/log" { t.Fatalf("source URL = %q", c.Source().LogURL) }
}
