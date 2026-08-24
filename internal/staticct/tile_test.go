package staticct

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func putOpaque24(dst []byte, value []byte) []byte {
	n := len(value)
	dst = append(dst, byte(n>>16), byte(n>>8), byte(n))
	return append(dst, value...)
}

func putOpaque16(dst []byte, value []byte) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(value)))
	dst = append(dst, b[:]...)
	return append(dst, value...)
}

func timestamped(entryType uint16, signed []byte, ext []byte) []byte {
	var b [10]byte
	binary.BigEndian.PutUint64(b[:8], 1234)
	binary.BigEndian.PutUint16(b[8:], entryType)
	out := append([]byte(nil), b[:]...)
	out = append(out, signed...)
	return putOpaque16(out, ext)
}

func x509TileLeaf(cert []byte, fps []byte) []byte {
	return putOpaque16(timestamped(0, putOpaque24(nil, cert), nil), fps)
}

func precertTileLeaf(tbs, precert, fps []byte) []byte {
	signed := make([]byte, 32)
	signed = putOpaque24(signed, tbs)
	out := timestamped(1, signed, nil)
	out = putOpaque24(out, precert)
	return putOpaque16(out, fps)
}

func TestTileIndexPath(t *testing.T) {
	tests := map[uint64]string{
		0:       "000",
		1:       "001",
		67:      "067",
		999:     "999",
		1000:    "x001/000",
		1234067: "x001/x234/067",
	}
	for n, want := range tests {
		if got := tileIndexPath(n); got != want {
			t.Errorf("tileIndexPath(%d)=%q want %q", n, got, want)
		}
	}
}

func TestDataTilePath(t *testing.T) {
	if got, _ := dataTilePath(0, 256); got != "tile/data/000" {
		t.Fatalf("got %q", got)
	}
	if got, _ := dataTilePath(1234, 17); got != "tile/data/x001/234.p/17" {
		t.Fatalf("got %q", got)
	}
	if _, err := dataTilePath(0, 0); err == nil {
		t.Fatal("expected width error")
	}
}

func TestParseDataTileX509AndPrecert(t *testing.T) {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	tile := append(
		x509TileLeaf([]byte{1, 2, 3}, fp),
		precertTileLeaf([]byte{4, 5}, []byte{6, 7, 8}, fp)...,
	)

	entries, err := parseDataTile(tile)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d", len(entries))
	}

	leaf0, err := base64.StdEncoding.DecodeString(entries[0].LeafInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf0) < 2 || leaf0[0] != 0 || leaf0[1] != 0 {
		t.Fatalf("bad MerkleTreeLeaf prefix: %x", leaf0)
	}
	if len(entries[0].IssuerFingerprints) != 1 || len(entries[0].IssuerFingerprints[0]) != 64 {
		t.Fatalf("fingerprints=%#v", entries[0].IssuerFingerprints)
	}

	extra1, err := base64.StdEncoding.DecodeString(entries[1].ExtraData)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra1) < 6 || extra1[2] != 3 || extra1[3] != 6 || extra1[4] != 7 || extra1[5] != 8 {
		t.Fatalf("bad synthesized precert extra_data: %x", extra1)
	}
}

func TestParseDataTileRejectsBadFingerprintVector(t *testing.T) {
	bad := x509TileLeaf([]byte{1}, []byte{1, 2, 3})
	if _, err := parseDataTile(bad); err == nil {
		t.Fatal("expected fingerprint vector error")
	}
}

func TestParseDataTileRejectsTruncation(t *testing.T) {
	if _, err := parseDataTile([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected truncation error")
	}
}
