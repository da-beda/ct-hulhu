package ctlog

import "context"

type Protocol string

const (
	ProtocolRFC6962 Protocol = "rfc6962"
	ProtocolStaticCT Protocol = "static-ct-api"
)

type EntrySource struct {
	Protocol Protocol `json:"protocol"`
	LogID    string   `json:"log_id,omitempty"`
	LogURL   string   `json:"log_url"`
	Verified bool     `json:"verified"`
}

func (s EntrySource) Identity() string {
	if s.LogID != "" {
		return string(s.Protocol) + ":" + s.LogID
	}
	return string(s.Protocol) + ":" + s.LogURL
}

type TreeHead struct {
	TreeSize   int64
	Timestamp  int64
	RootHash   []byte
	Signature  []byte
	Checkpoint []byte
}

type EntryReader interface {
	GetRawEntries(ctx context.Context, start, end int64) (*GetEntriesResponse, error)
}

type Reader interface {
	EntryReader
	Protocol() Protocol
	Source() EntrySource
	GetTreeHead(ctx context.Context) (*TreeHead, error)
}
