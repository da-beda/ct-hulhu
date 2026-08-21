package staticct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestSetRequestRateConfiguresInternalPacing(t *testing.T) {
	client, err := NewClient("https://submit.example/", "https://monitor.example/", "", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetRequestRate(5); err != nil {
		t.Fatal(err)
	}
	if client.requestInterval != 200*time.Millisecond {
		t.Fatalf("request interval = %v, want 200ms", client.requestInterval)
	}
	if err := client.SetRequestRate(0); err != nil {
		t.Fatal(err)
	}
	if client.requestInterval != 0 {
		t.Fatalf("zero rate should disable pacing, got %v", client.requestInterval)
	}
	if err := client.SetRequestRate(-1); err == nil {
		t.Fatal("expected negative rate rejection")
	}
}

func TestDataPartialTileFallsBackToFullImmutableTile(t *testing.T) {
	full := make([]byte, 0)
	for i := 0; i < tileWidth; i++ {
		full = append(full, x509TileLeaf([]byte{byte(i)}, nil)...)
	}
	partialRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/tile/data/000.p/3":
			partialRequests++
			http.NotFound(w, r)
		case "/m/tile/data/000":
			_, _ = w.Write(full)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL+"/s/", server.URL+"/m/", "", 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := client.fetchDataTile(context.Background(), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || partialRequests != 1 {
		t.Fatalf("fallback entries=%d partial requests=%d", len(entries), partialRequests)
	}
}

func TestStaticCacheIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cached"))
	}))
	defer server.Close()
	client, err := NewClient(server.URL+"/s/", server.URL+"/m/", "", 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxStaticCacheEntries+17; i++ {
		if _, err := client.getCached(context.Background(), "fixture/"+itoa(uint64(i))); err != nil {
			t.Fatal(err)
		}
	}
	client.cacheMu.RLock()
	defer client.cacheMu.RUnlock()
	if len(client.cache) > maxStaticCacheEntries || len(client.cacheOrder) > maxStaticCacheEntries {
		t.Fatalf("cache grew beyond bound: map=%d order=%d", len(client.cache), len(client.cacheOrder))
	}
}

func TestPersistedConsistencyAnchorAcceptsAppendOnlyGrowth(t *testing.T) {
	key := newTestLogKey(t)
	_, oldHashes := tileAndHashes(t, []byte{1}, []byte{2})
	oldRoot := testMerkleRoot(oldHashes)
	_, newHashes := tileAndHashes(t, []byte{1}, []byte{2}, []byte{3})
	newRoot := testMerkleRoot(newHashes)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/checkpoint":
			_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 3, newRoot, 2))
		case "/m/tile/0/000.p/3":
			_, _ = w.Write(hashTileBytes(newHashes))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetConsistencyAnchor(ctlog.TreeHead{TreeSize: 2, RootHash: oldRoot[:], Verified: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTreeHead(context.Background()); err != nil {
		t.Fatalf("valid growth rejected from persisted anchor: %v", err)
	}
}

func TestPersistedConsistencyAnchorRejectsRewrittenPrefix(t *testing.T) {
	key := newTestLogKey(t)
	_, oldHashes := tileAndHashes(t, []byte{1}, []byte{2})
	oldRoot := testMerkleRoot(oldHashes)
	_, rewritten := tileAndHashes(t, []byte{9}, []byte{2}, []byte{3})
	rewrittenRoot := testMerkleRoot(rewritten)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/checkpoint":
			_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 3, rewrittenRoot, 2))
		case "/m/tile/0/000.p/3":
			_, _ = w.Write(hashTileBytes(rewritten))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetConsistencyAnchor(ctlog.TreeHead{TreeSize: 2, RootHash: oldRoot[:], Verified: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTreeHead(context.Background()); err == nil {
		t.Fatal("expected rewritten historical prefix to be rejected")
	}
}
