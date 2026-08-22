package certparser

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

type Parser struct {
	domainFilter      []string
	domainFilterBytes [][]byte
}

type MalformedEntryError struct {
	Kind string
	Err  error
}

func (e *MalformedEntryError) Error() string { return fmt.Sprintf("malformed %s: %v", e.Kind, e.Err) }
func (e *MalformedEntryError) Unwrap() error { return e.Err }

func New(domains []string) *Parser {
	lower := make([]string, len(domains))
	lowerBytes := make([][]byte, len(domains))
	for i, d := range domains {
		lower[i] = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "."))
		lowerBytes[i] = []byte(lower[i])
	}
	return &Parser{domainFilter: lower, domainFilterBytes: lowerBytes}
}

func (p *Parser) ParseEntry(entry ctlog.RawEntry, index int64, logURL string) (*ctlog.CertResult, error) {
	return p.ParseEntryFromSource(entry, index, ctlog.EntrySource{Protocol: ctlog.ProtocolRFC6962, LogURL: logURL})
}

func (p *Parser) ParseEntryFromSource(entry ctlog.RawEntry, index int64, source ctlog.EntrySource) (*ctlog.CertResult, error) {
	leafBytes, err := base64.StdEncoding.DecodeString(entry.LeafInput)
	if err != nil {
		return nil, fmt.Errorf("decoding leaf_input: %w", err)
	}

	// Do not use the raw-DER substring matcher as an authoritative negative
	// filter. It is useful as a benchmark/heuristic, but certificate names can
	// be represented in ways that do not safely preserve the user's literal
	// filter bytes (for example internationalized names). Parse first and make
	// the actual X.509 identifiers authoritative.
	certInfo, err := p.parseMerkleTreeLeaf(leafBytes, entry.ExtraData)
	if err != nil {
		return nil, err
	}
	if certInfo == nil || certInfo.Cert == nil {
		return nil, &MalformedEntryError{Kind: "certificate", Err: fmt.Errorf("parser returned no certificate")}
	}
	certInfo.Index = index
	leafHash := sha256.Sum256(append([]byte{0}, leafBytes...))
	certInfo.LeafHash = hex.EncodeToString(leafHash[:])
	result := p.buildResult(certInfo, source)
	if len(p.domainFilter) > 0 && !p.resultMatchesDomain(result) {
		return nil, nil
	}
	return result, nil
}

// rawBytesMatchDomain remains available for benchmarks and non-authoritative
// hints. Callers must never treat a false result as proof that an X.509 entry
// does not contain a matching identifier.
func (p *Parser) rawBytesMatchDomain(data []byte) bool {
	for _, domainBytes := range p.domainFilterBytes {
		if containsFoldASCII(data, domainBytes) {
			return true
		}
	}
	return false
}

func containsFoldASCII(data, pattern []byte) bool {
	n := len(pattern)
	if n == 0 {
		return true
	}
	if len(data) < n {
		return false
	}
	const primeRK uint32 = 16777619
	var hashPat, hashData, pow uint32 = 0, 0, 1
	limit := len(data) - n
	for i := range n {
		pow *= primeRK
		pb := pattern[i]
		if pb >= 'A' && pb <= 'Z' {
			pb += 0x20
		}
		hashPat = hashPat*primeRK + uint32(pb)
		db := data[i]
		if db >= 'A' && db <= 'Z' {
			db += 0x20
		}
		hashData = hashData*primeRK + uint32(db)
	}
	for i := 0; i <= limit; i++ {
		if hashData == hashPat {
			match := true
			for j := 0; j < n; j++ {
				db := data[i+j]
				if db >= 'A' && db <= 'Z' {
					db += 0x20
				}
				pb := pattern[j]
				if pb >= 'A' && pb <= 'Z' {
					pb += 0x20
				}
				if db != pb {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		if i < limit {
			oldByte := data[i]
			if oldByte >= 'A' && oldByte <= 'Z' {
				oldByte += 0x20
			}
			newByte := data[i+n]
			if newByte >= 'A' && newByte <= 'Z' {
				newByte += 0x20
			}
			hashData *= primeRK
			hashData += uint32(newByte)
			hashData -= pow * uint32(oldByte)
		}
	}
	return false
}

func (p *Parser) parseMerkleTreeLeaf(data []byte, extraDataB64 string) (*ctlog.CertInfo, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("leaf data too short: %d bytes", len(data))
	}
	timestamp := binary.BigEndian.Uint64(data[2:10])
	if timestamp > math.MaxInt64 {
		return nil, fmt.Errorf("timestamp overflow: %d", timestamp)
	}
	ts := time.UnixMilli(int64(timestamp))
	entryType := binary.BigEndian.Uint16(data[10:12])
	switch entryType {
	case 0:
		return p.parseX509Entry(data[12:], ts)
	case 1:
		return p.parsePrecertEntry(data[12:], extraDataB64, ts)
	default:
		return nil, fmt.Errorf("unknown entry type: %d", entryType)
	}
}

func (p *Parser) parseX509Entry(data []byte, timestamp time.Time) (*ctlog.CertInfo, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("x509 entry data too short")
	}
	certLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	data = data[3:]
	if certLen <= 0 || len(data) < certLen {
		return nil, fmt.Errorf("certificate data truncated: need %d, have %d", certLen, len(data))
	}
	cert, err := x509.ParseCertificate(data[:certLen])
	if err != nil {
		return nil, &MalformedEntryError{Kind: "x509 certificate", Err: err}
	}
	return &ctlog.CertInfo{Cert: cert, IsPrecert: false, Timestamp: timestamp}, nil
}

func (p *Parser) parsePrecertEntry(data []byte, extraDataB64 string, timestamp time.Time) (*ctlog.CertInfo, error) {
	if len(data) < 35 {
		return nil, fmt.Errorf("precert entry data too short")
	}
	data = data[32:]
	tbsLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	if tbsLen <= 0 || len(data[3:]) < tbsLen {
		return nil, fmt.Errorf("TBS certificate data truncated: need %d, have %d", tbsLen, len(data[3:]))
	}

	extraData, err := base64.StdEncoding.DecodeString(extraDataB64)
	if err != nil {
		return nil, fmt.Errorf("decoding precert extra_data: %w", err)
	}
	if len(extraData) < 3 {
		return nil, fmt.Errorf("precert extra_data too short")
	}
	certLen := int(extraData[0])<<16 | int(extraData[1])<<8 | int(extraData[2])
	if certLen <= 0 || len(extraData[3:]) < certLen {
		return nil, fmt.Errorf("precertificate data truncated: need %d, have %d", certLen, len(extraData[3:]))
	}
	cert, err := x509.ParseCertificate(extraData[3 : 3+certLen])
	if err != nil {
		return nil, &MalformedEntryError{Kind: "precertificate", Err: err}
	}
	return &ctlog.CertInfo{Cert: cert, IsPrecert: true, Timestamp: timestamp}, nil
}

func (p *Parser) buildResult(info *ctlog.CertInfo, source ctlog.EntrySource) *ctlog.CertResult {
	cert := info.Cert
	domainSet := make(map[string]struct{})
	if cert.Subject.CommonName != "" {
		domainSet[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
	}
	for _, name := range cert.DNSNames {
		domainSet[strings.ToLower(name)] = struct{}{}
	}
	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	emails := append([]string(nil), cert.EmailAddresses...)
	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	serial := ""
	if cert.SerialNumber != nil {
		serial = fmt.Sprintf("%x", cert.SerialNumber)
	}
	certHash := sha256.Sum256(cert.Raw)
	return &ctlog.CertResult{
		Index:             info.Index,
		Timestamp:         info.Timestamp,
		Domains:           domains,
		IPs:               ips,
		Emails:            emails,
		CommonName:        cert.Subject.CommonName,
		Issuer:            issuer,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		IsPrecert:         info.IsPrecert,
		Protocol:          source.Protocol,
		LogID:             source.LogID,
		LogURL:            source.LogURL,
		Verified:          source.Verified,
		Serial:            serial,
		LeafHash:          info.LeafHash,
		CertificateSHA256: hex.EncodeToString(certHash[:]),
	}
}

func (p *Parser) resultMatchesDomain(result *ctlog.CertResult) bool {
	for _, domain := range result.Domains {
		for _, filter := range p.domainFilter {
			if matchesDomain(domain, filter) {
				return true
			}
		}
	}
	for _, ip := range result.IPs {
		for _, filter := range p.domainFilter {
			if ip == filter {
				return true
			}
		}
	}
	return false
}

func matchesDomain(domain, filter string) bool {
	if domain == filter {
		return true
	}
	if strings.HasSuffix(domain, "."+filter) {
		return true
	}
	if strings.HasPrefix(domain, "*.") {
		baseDomain := domain[2:]
		if baseDomain == filter || strings.HasSuffix(baseDomain, "."+filter) {
			return true
		}
	}
	return false
}
