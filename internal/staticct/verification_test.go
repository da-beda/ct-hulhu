package staticct

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testLogKey struct {
	private *ecdsa.PrivateKey
	keyB64  string
	logID   string
}

func newTestLogKey(t *testing.T) testLogKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(der)
	return testLogKey{
		private: private,
		keyB64:  base64.StdEncoding.EncodeToString(der),
		logID:   base64.StdEncoding.EncodeToString(id[:]),
	}
}

func buildSignedCheckpoint(t *testing.T, key testLogKey, submissionURL string, treeSize int64, root merkleHash, timestamp int64) []byte {
	t.Helper()
	cp := &Checkpoint{TreeSize: treeSize, RootHash: root[:], Timestamp: timestamp}
	digest := sha256.Sum256(treeHeadSignatureInput(cp))
	signature, err := ecdsa.SignASN1(rand.Reader, key.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	ds := make([]byte, 4+len(signature))
	ds[0] = tlsHashSHA256
	ds[1] = tlsSignatureECDSA
	binary.BigEndian.PutUint16(ds[2:4], uint16(len(signature)))
	copy(ds[4:], signature)

	origin, err := checkpointOrigin(submissionURL)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := expectedNoteKeyID(origin, key.logID)
	if err != nil {
		t.Fatal(err)
	}
	noteSig := make([]byte, 4+8+len(ds))
	copy(noteSig[:4], keyID[:])
	binary.BigEndian.PutUint64(noteSig[4:12], uint64(timestamp))
	copy(noteSig[12:], ds)
	return []byte(fmt.Sprintf("%s\n%d\n%s\n\n— %s %s\n",
		origin,
		treeSize,
		base64.StdEncoding.EncodeToString(root[:]),
		origin,
		base64.StdEncoding.EncodeToString(noteSig),
	))
}

func tileAndHashes(t *testing.T, leafPayloads ...[]byte) ([]byte, []merkleHash) {
	t.Helper()
	var tile []byte
	for _, payload := range leafPayloads {
		tile = append(tile, x509TileLeaf(payload, nil)...)
	}
	entries, err := parseDataTile(tile)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]merkleHash, len(entries))
	for i, entry := range entries {
		hashes[i], err = decodedLeafHash(entry.LeafInput)
		if err != nil {
			t.Fatal(err)
		}
	}
	return tile, hashes
}

func testMerkleRoot(hashes []merkleHash) merkleHash {
	if len(hashes) == 0 {
		return hashEmpty()
	}
	if len(hashes) == 1 {
		return hashes[0]
	}
	leftCount := int(largestPowerOfTwoLessThan(int64(len(hashes))))
	return hashChildren(testMerkleRoot(hashes[:leftCount]), testMerkleRoot(hashes[leftCount:]))
}

func hashTileBytes(hashes []merkleHash) []byte {
	out := make([]byte, 0, len(hashes)*sha256.Size)
	for _, hash := range hashes {
		out = append(out, hash[:]...)
	}
	return out
}

func TestNewClientWithKeyRejectsLogIDMismatch(t *testing.T) {
	key := newTestLogKey(t)
	wrongID := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if wrongID == key.logID {
		t.Fatal("test setup unexpectedly produced matching IDs")
	}
	if _, err := NewClientWithKey("https://submit.example/", "https://monitor.example/", wrongID, key.keyB64, time.Second, 0); err == nil {
		t.Fatal("expected log-ID/public-key mismatch")
	}
}

func TestSecureClientVerifiesCheckpointAndEntries(t *testing.T) {
	key := newTestLogKey(t)
	dataTile, hashes := tileAndHashes(t, []byte{1}, []byte{2}, []byte{3})
	root := testMerkleRoot(hashes)
	hashTile := hashTileBytes(hashes)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/monitor/checkpoint":
			_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/submit/", 3, root, 12345))
		case "/monitor/tile/0/000.p/3":
			_, _ = w.Write(hashTile)
		case "/monitor/tile/data/000.p/3":
			_, _ = w.Write(dataTile)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClientWithKey(server.URL+"/submit/", server.URL+"/monitor/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !client.Secure() {
		t.Fatal("expected secure client")
	}
	head, err := client.GetTreeHead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if head.TreeSize != 3 || !cryptoBytesEqual(head.RootHash, root[:]) {
		t.Fatalf("unexpected verified head: %#v", head)
	}
	resp, err := client.GetRawEntries(t.Context(), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(resp.Entries))
	}
}

func TestSecureClientRejectsTamperedDataTile(t *testing.T) {
	key := newTestLogKey(t)
	originalTile, hashes := tileAndHashes(t, []byte{1}, []byte{2})
	_, _ = originalTile, hashes
	root := testMerkleRoot(hashes)
	hashTile := hashTileBytes(hashes)
	tamperedTile, _ := tileAndHashes(t, []byte{9}, []byte{2})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/checkpoint":
			_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 2, root, 1))
		case "/m/tile/0/000.p/2":
			_, _ = w.Write(hashTile)
		case "/m/tile/data/000.p/2":
			_, _ = w.Write(tamperedTile)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTreeHead(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRawEntries(t.Context(), 0, 1); err == nil {
		t.Fatal("expected tampered data tile to fail inclusion verification")
	}
}

func TestSecureClientRejectsTamperedHashTile(t *testing.T) {
	key := newTestLogKey(t)
	_, hashes := tileAndHashes(t, []byte{1}, []byte{2})
	root := testMerkleRoot(hashes)
	badHashes := append([]merkleHash(nil), hashes...)
	badHashes[0][0] ^= 0xff

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m/checkpoint":
			_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 2, root, 1))
		case "/m/tile/0/000.p/2":
			_, _ = w.Write(hashTileBytes(badHashes))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTreeHead(t.Context()); err == nil {
		t.Fatal("expected checkpoint root reconstruction to fail")
	}
}

func TestSecureClientEnforcesAppendOnlyCheckpointGrowth(t *testing.T) {
	key := newTestLogKey(t)
	_, firstHashes := tileAndHashes(t, []byte{1}, []byte{2})
	firstRoot := testMerkleRoot(firstHashes)
	_, goodSecondHashes := tileAndHashes(t, []byte{1}, []byte{2}, []byte{3})
	goodSecondRoot := testMerkleRoot(goodSecondHashes)
	_, badSecondHashes := tileAndHashes(t, []byte{9}, []byte{2}, []byte{3})
	badSecondRoot := testMerkleRoot(badSecondHashes)

	var generation atomic.Int32
	var inconsistent atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gen := generation.Load()
		switch r.URL.Path {
		case "/m/checkpoint":
			if gen == 0 {
				_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 2, firstRoot, 1))
				return
			}
			if inconsistent.Load() {
				_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 3, badSecondRoot, 2))
			} else {
				_, _ = w.Write(buildSignedCheckpoint(t, key, server.URL+"/s/", 3, goodSecondRoot, 2))
			}
		case "/m/tile/0/000.p/2":
			_, _ = w.Write(hashTileBytes(firstHashes))
		case "/m/tile/0/000.p/3":
			if inconsistent.Load() {
				_, _ = w.Write(hashTileBytes(badSecondHashes))
			} else {
				_, _ = w.Write(hashTileBytes(goodSecondHashes))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTreeHead(t.Context()); err != nil {
		t.Fatal(err)
	}
	generation.Store(1)
	if _, err := client.GetTreeHead(t.Context()); err != nil {
		t.Fatalf("valid append-only growth rejected: %v", err)
	}

	// Use a fresh client so its previous checkpoint is the original 2-entry
	// tree, then present a signed but rewritten 3-entry tree.
	client2, err := NewClientWithKey(server.URL+"/s/", server.URL+"/m/", key.logID, key.keyB64, 5*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	generation.Store(0)
	if _, err := client2.GetTreeHead(t.Context()); err != nil {
		t.Fatal(err)
	}
	inconsistent.Store(true)
	generation.Store(1)
	if _, err := client2.GetTreeHead(t.Context()); err == nil {
		t.Fatal("expected rewritten prefix to fail append-only consistency")
	}
}
