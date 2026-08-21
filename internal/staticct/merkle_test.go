package staticct

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHashTilePath(t *testing.T) {
	tests := []struct {
		level int
		index uint64
		width int
		want  string
	}{
		{0, 0, 256, "tile/0/000"},
		{0, 1234, 17, "tile/0/x001/234.p/17"},
		{2, 1234067, 256, "tile/2/x001/x234/067"},
	}
	for _, tt := range tests {
		got, err := hashTilePath(tt.level, tt.index, tt.width)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("hashTilePath(%d,%d,%d) = %q, want %q", tt.level, tt.index, tt.width, got, tt.want)
		}
	}
}

func TestMerkleHashFunctionsMatchRFC6962DomainSeparation(t *testing.T) {
	leaf := []byte("leaf")
	gotLeaf := hashLeaf(leaf)
	manualLeaf := sha256.Sum256(append([]byte{0}, leaf...))
	if gotLeaf != manualLeaf {
		t.Fatal("leaf hash domain separation mismatch")
	}
	left := hashLeaf([]byte("left"))
	right := hashLeaf([]byte("right"))
	input := append([]byte{1}, left[:]...)
	input = append(input, right[:]...)
	manualNode := sha256.Sum256(input)
	if got := hashChildren(left, right); got != manualNode {
		t.Fatal("node hash domain separation mismatch")
	}
}

func TestRangeRootUsesHigherHashTileLevels(t *testing.T) {
	// A 256-leaf complete subtree is represented by one hash in level 1.
	leaves := make([]merkleHash, 256)
	for i := range leaves {
		leaves[i] = hashLeaf([]byte{byte(i)})
	}
	expected := testMerkleRoot(leaves)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m/tile/1/000.p/1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(expected[:])
	}))
	defer server.Close()
	client, err := NewClient(server.URL+"/s/", server.URL+"/m/", "", 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.rangeRoot(context.Background(), 0, 256, 256)
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("root = %x, want %x", got, expected)
	}
}

func TestHashTilePartialFallsBackToFullImmutableTile(t *testing.T) {
	hashes := make([]merkleHash, 256)
	for i := range hashes {
		hashes[i] = hashLeaf([]byte{byte(i)})
	}
	full := hashTileBytes(hashes)
	var partialRequests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/tile/0/000.p/3":
			partialRequests++
			http.NotFound(w, r)
		case "/m/tile/0/000":
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
	got, err := client.getHashTile(context.Background(), 0, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != hashes[2] || partialRequests != 1 {
		t.Fatalf("fallback result incorrect: len=%d partial=%d", len(got), partialRequests)
	}
}
