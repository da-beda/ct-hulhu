package ctlog

import (
	"crypto/x509"
	"time"
)

type STH struct {
	TreeSize          int64  `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

type RawEntry struct {
	LeafInput          string   `json:"leaf_input"`
	ExtraData          string   `json:"extra_data"`
	IssuerFingerprints []string `json:"-"`
}

type GetEntriesResponse struct {
	Entries []RawEntry `json:"entries"`
}

type CertResult struct {
	Index              int64     `json:"index"`
	Timestamp          time.Time `json:"timestamp"`
	Domains            []string  `json:"domains"`
	IPs                []string  `json:"ips,omitempty"`
	Emails             []string  `json:"emails,omitempty"`
	CommonName         string    `json:"common_name"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsPrecert          bool      `json:"is_precert"`
	Protocol           Protocol  `json:"protocol,omitempty"`
	LogID              string    `json:"log_id,omitempty"`
	LogURL             string    `json:"log_url,omitempty"`
	Verified           bool      `json:"verified"`
	Serial             string    `json:"serial,omitempty"`
	LeafHash           string    `json:"leaf_hash,omitempty"`
	CertificateSHA256  string    `json:"cert_sha256,omitempty"`
	IssuerFingerprints []string  `json:"issuer_fingerprints,omitempty"`
}

type CertInfo struct {
	Cert      *x509.Certificate
	IsPrecert bool
	Index     int64
	Timestamp time.Time
	LeafHash  string
}

type ScrapeProgress struct {
	Version       int       `json:"version,omitempty"`
	Protocol      Protocol  `json:"protocol,omitempty"`
	LogID         string    `json:"log_id,omitempty"`
	LogURL        string    `json:"log_url"`
	Verified      bool      `json:"verified"`
	SelectionHash string    `json:"selection_hash,omitempty"`
	TreeSize      int64     `json:"tree_size"`
	RootHash      string    `json:"root_hash,omitempty"`
	RangeStart    int64     `json:"range_start,omitempty"`
	RangeEnd      int64     `json:"range_end,omitempty"`
	LastIndex     int64     `json:"last_index"`
	NextIndex     int64     `json:"next_index,omitempty"`
	EntriesDone   int64     `json:"entries_done"`
	LastUpdated   time.Time `json:"last_updated"`
}

func (p *ScrapeProgress) SafeResumeIndex(requestedStart, requestedEnd int64) (int64, bool) {
	if p == nil || requestedStart < 0 || requestedEnd < requestedStart {
		return requestedStart, false
	}
	if p.Version >= 2 {
		if p.NextIndex < p.RangeStart || p.NextIndex > p.RangeEnd {
			return requestedStart, false
		}
		if requestedStart < p.RangeStart || requestedStart >= p.NextIndex {
			return requestedStart, false
		}
		return min(p.NextIndex, requestedEnd), true
	}
	if requestedStart != 0 || p.LastIndex < 0 {
		return requestedStart, false
	}
	next := p.LastIndex + 1
	if next <= requestedStart {
		return requestedStart, false
	}
	return min(next, requestedEnd), true
}

type MonitorProgress struct {
	Version       int       `json:"version"`
	Protocol      Protocol  `json:"protocol"`
	LogID         string    `json:"log_id,omitempty"`
	LogURL        string    `json:"log_url"`
	Verified      bool      `json:"verified"`
	SelectionHash string    `json:"selection_hash"`
	TreeSize      int64     `json:"tree_size"`
	RootHash      string    `json:"root_hash"`
	LastUpdated   time.Time `json:"last_updated"`
}
