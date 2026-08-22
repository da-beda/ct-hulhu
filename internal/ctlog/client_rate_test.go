package ctlog

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRequestRateLimitCoversUnderlyingRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tree_size":1,"timestamp":1,"sha256_root_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","tree_head_signature":""}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, time.Second, 0)
	client.SetRequestRateLimit(10)
	started := time.Now()
	if _, err := client.doRequest(t.Context(), server.URL+"/one"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.doRequest(t.Context(), server.URL+"/two"); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 75*time.Millisecond {
		t.Fatalf("underlying requests were not rate limited; elapsed=%v", elapsed)
	}
}
