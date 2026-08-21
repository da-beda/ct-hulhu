package runner

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

type anchorReader struct {
	anchor *ctlog.TreeHead
}

func (a *anchorReader) Protocol() ctlog.Protocol { return ctlog.ProtocolStaticCT }
func (a *anchorReader) Source() ctlog.EntrySource {
	return ctlog.EntrySource{Protocol: ctlog.ProtocolStaticCT, LogURL: "https://m/", Verified: true}
}
func (a *anchorReader) GetTreeHead(context.Context) (*ctlog.TreeHead, error) { return &ctlog.TreeHead{}, nil }
func (a *anchorReader) GetRawEntries(context.Context, int64, int64) (*ctlog.GetEntriesResponse, error) {
	return &ctlog.GetEntriesResponse{}, nil
}
func (a *anchorReader) SetConsistencyAnchor(head ctlog.TreeHead) error {
	copy := head
	a.anchor = &copy
	return nil
}

func TestSeedConsistencyAnchorUsesPersistedVerifiedRoot(t *testing.T) {
	root := make([]byte, 32)
	for i := range root { root[i] = byte(i) }
	reader := &anchorReader{}
	progress := &ctlog.ScrapeProgress{Verified: true, TreeSize: 123, RootHash: hex.EncodeToString(root)}
	if err := seedConsistencyAnchor(reader, progress); err != nil { t.Fatal(err) }
	if reader.anchor == nil || reader.anchor.TreeSize != 123 || !reader.anchor.Verified || string(reader.anchor.RootHash) != string(root) {
		t.Fatalf("unexpected anchor: %#v", reader.anchor)
	}
}

func TestSeedConsistencyAnchorRejectsBadPersistedRoot(t *testing.T) {
	reader := &anchorReader{}
	progress := &ctlog.ScrapeProgress{Verified: true, TreeSize: 123, RootHash: "abcd"}
	if err := seedConsistencyAnchor(reader, progress); err == nil { t.Fatal("expected invalid root rejection") }
}
