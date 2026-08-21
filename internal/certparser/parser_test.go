package certparser

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		domain string
		filter string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", "example.com", true},
		{"deep.sub.example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"*.example.com", "example.com", true},
		{"*.sub.example.com", "example.com", true},
		{"*.other.com", "example.com", false},
		{"example.com.evil.com", "example.com", false},
		{"test.com", "example.com", false},
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.2", false},
	}
	for _, tt := range tests {
		if got := matchesDomain(tt.domain, tt.filter); got != tt.want {
			t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.domain, tt.filter, got, tt.want)
		}
	}
}

func TestNewParser_DomainNormalization(t *testing.T) {
	p := New([]string{" Example.COM ", ".sub.Example.COM"})
	if len(p.domainFilter) != 2 || p.domainFilter[0] != "example.com" || p.domainFilter[1] != "sub.example.com" {
		t.Fatalf("unexpected filters: %#v", p.domainFilter)
	}
	if string(p.domainFilterBytes[0]) != "example.com" || string(p.domainFilterBytes[1]) != "sub.example.com" {
		t.Fatalf("unexpected byte filters: %q %q", p.domainFilterBytes[0], p.domainFilterBytes[1])
	}
}

func TestRawBytesMatchDomain(t *testing.T) {
	p := New([]string{"example.com"})
	if !p.rawBytesMatchDomain([]byte("CN=test.example.com")) {
		t.Error("expected match")
	}
	if p.rawBytesMatchDomain([]byte("CN=test.other.com")) {
		t.Error("unexpected match")
	}
}

func TestContainsFoldASCII(t *testing.T) {
	tests := []struct {
		data, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"CN=test.EXAMPLE.COM", "example.com", true},
		{"CN=test.Example.Com", "Example.Com", true},
		{"CN=test.other.com", "example.com", false},
		{"short", "longerpattern", false},
		{"", "example.com", false},
		{"anything", "", true},
		{"exampl.example.com", "example.com", true},
		{"A", "a", true},
		{"B", "a", false},
	}
	for _, tt := range tests {
		if got := containsFoldASCII([]byte(tt.data), []byte(tt.pattern)); got != tt.want {
			t.Errorf("containsFoldASCII(%q, %q) = %v, want %v", tt.data, tt.pattern, got, tt.want)
		}
	}
}

func BenchmarkRawBytesMatchDomain(b *testing.B) {
	p := New([]string{"example.com", "test.org", "mysite.io"})
	data := []byte("some random DER data with CN=app.example.com embedded in it, plus extra padding bytes")
	for b.Loop() {
		p.rawBytesMatchDomain(data)
	}
}

func tlsUint24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

func makeLeaf(t *testing.T, entryType uint16, signedEntry []byte) string {
	t.Helper()
	buf := []byte{0, 0}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UnixMilli()))
	buf = append(buf, ts...)
	et := make([]byte, 2)
	binary.BigEndian.PutUint16(et, entryType)
	buf = append(buf, et...)
	buf = append(buf, signedEntry...)
	return base64.StdEncoding.EncodeToString(buf)
}

func makeX509RawEntry(t *testing.T, certDER []byte) ctlog.RawEntry {
	signed := append(tlsUint24(len(certDER)), certDER...)
	return ctlog.RawEntry{LeafInput: makeLeaf(t, 0, signed), ExtraData: base64.StdEncoding.EncodeToString([]byte{0, 0, 0})}
}

func makePrecertRawEntry(t *testing.T, certDER []byte) ctlog.RawEntry {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	signed := make([]byte, 32)
	signed = append(signed, tlsUint24(len(cert.RawTBSCertificate))...)
	signed = append(signed, cert.RawTBSCertificate...)
	extra := append(tlsUint24(len(certDER)), certDER...)
	extra = append(extra, 0, 0, 0)
	return ctlog.RawEntry{LeafInput: makeLeaf(t, 1, signed), ExtraData: base64.StdEncoding.EncodeToString(extra)}
}

func makeTestCert(t *testing.T, cn string, dnsNames []string, ips []net.IP, emails []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour).UTC(),
		NotAfter:       time.Now().Add(time.Hour).UTC(),
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		Issuer:         pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseMerkleTreeLeaf_TooShort(t *testing.T) {
	if _, err := New(nil).parseMerkleTreeLeaf([]byte{0, 0, 0}, ""); err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseMerkleTreeLeaf_UnknownEntryType(t *testing.T) {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[10:], 99)
	_, err := New(nil).parseMerkleTreeLeaf(data, "")
	if err == nil || !strings.Contains(err.Error(), "unknown entry type") {
		t.Fatalf("expected unknown entry type error, got %v", err)
	}
}

func TestParseX509Entry_TooShort(t *testing.T) {
	if _, err := New(nil).parseX509Entry([]byte{0, 0}, time.Now()); err == nil {
		t.Fatal("expected short-entry error")
	}
}

func TestParseX509Entry_Truncated(t *testing.T) {
	if _, err := New(nil).parseX509Entry([]byte{0, 3, 0xe8, 1, 2, 3, 4, 5}, time.Now()); err == nil {
		t.Fatal("expected truncated-entry error")
	}
}

func TestParseX509Entry_InvalidDERIsExplicitMalformedError(t *testing.T) {
	_, err := New(nil).parseX509Entry([]byte{0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0xff}, time.Now())
	if err == nil {
		t.Fatal("expected malformed certificate error")
	}
	var malformed *MalformedEntryError
	if !errors.As(err, &malformed) {
		t.Fatalf("error type = %T, want MalformedEntryError", err)
	}
}

func TestParsePrecertEntry_TooShort(t *testing.T) {
	if _, err := New(nil).parsePrecertEntry(make([]byte, 10), "", time.Now()); err == nil {
		t.Fatal("expected short precert error")
	}
}

func TestParseEntry_X509(t *testing.T) {
	der := makeTestCert(t, "test.example.com", []string{"www.example.com", "test.example.com"}, []net.IP{net.ParseIP("10.0.0.1")}, []string{"admin@example.com"})
	result, err := New(nil).ParseEntry(makeX509RawEntry(t, der), 42, "https://ct.example.com/")
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}
	if result == nil || result.Index != 42 || result.LogURL != "https://ct.example.com/" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Protocol != ctlog.ProtocolRFC6962 || result.Serial == "" || result.Issuer == "" || result.LeafHash == "" || result.CertificateSHA256 == "" {
		t.Fatalf("missing provenance fields: %#v", result)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "10.0.0.1" || len(result.Emails) != 1 {
		t.Fatalf("unexpected SANs: %#v", result)
	}
	wantDomains := []string{"test.example.com", "www.example.com"}
	if strings.Join(result.Domains, ",") != strings.Join(wantDomains, ",") {
		t.Fatalf("domains = %#v, want deterministic %#v", result.Domains, wantDomains)
	}
}

func TestParseEntry_PrecertUsesRFC6962ExtraData(t *testing.T) {
	der := makeTestCert(t, "precert.example.com", []string{"precert.example.com"}, nil, nil)
	result, err := New(nil).ParseEntry(makePrecertRawEntry(t, der), 7, "https://log.example.com/")
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}
	if result == nil || !result.IsPrecert || result.CommonName != "precert.example.com" {
		t.Fatalf("unexpected precert result: %#v", result)
	}
}

func TestParseEntry_PrecertRejectsMissingExtraData(t *testing.T) {
	der := makeTestCert(t, "precert.example.com", []string{"precert.example.com"}, nil, nil)
	entry := makePrecertRawEntry(t, der)
	entry.ExtraData = ""
	if _, err := New(nil).ParseEntry(entry, 7, ""); err == nil {
		t.Fatal("expected missing precert extra_data to fail")
	}
}

func TestParseEntry_InvalidBase64(t *testing.T) {
	if _, err := New(nil).ParseEntry(ctlog.RawEntry{LeafInput: "!!!invalid!!!"}, 0, ""); err == nil {
		t.Fatal("expected invalid base64 error")
	}
}

func TestParseEntry_DomainFilter_Match(t *testing.T) {
	der := makeTestCert(t, "app.example.com", []string{"app.example.com"}, nil, nil)
	result, err := New([]string{"example.com"}).ParseEntry(makeX509RawEntry(t, der), 0, "")
	if err != nil || result == nil {
		t.Fatalf("expected matching result, got result=%#v err=%v", result, err)
	}
}

func TestParseEntry_DomainFilter_NoMatch(t *testing.T) {
	der := makeTestCert(t, "app.other.com", []string{"app.other.com"}, nil, nil)
	result, err := New([]string{"example.com"}).ParseEntry(makeX509RawEntry(t, der), 0, "")
	if err != nil || result != nil {
		t.Fatalf("expected nil non-match, got result=%#v err=%v", result, err)
	}
}

func TestResultMatchesDomain(t *testing.T) {
	p := New([]string{"example.com"})
	tests := []struct {
		result *ctlog.CertResult
		want   bool
	}{
		{&ctlog.CertResult{Domains: []string{"sub.example.com"}}, true},
		{&ctlog.CertResult{Domains: []string{"other.com"}}, false},
		{&ctlog.CertResult{IPs: []string{"example.com"}}, true},
		{&ctlog.CertResult{}, false},
	}
	for _, tt := range tests {
		if got := p.resultMatchesDomain(tt.result); got != tt.want {
			t.Errorf("resultMatchesDomain() = %v, want %v", got, tt.want)
		}
	}
}

func TestBuildResult_IssuerFallback(t *testing.T) {
	der := makeTestCert(t, "test.com", nil, nil, nil)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	result := New(nil).buildResult(&ctlog.CertInfo{Cert: cert, Index: 1, Timestamp: time.Now(), LeafHash: "abc"}, ctlog.EntrySource{Protocol: ctlog.ProtocolRFC6962, LogURL: "https://log/"})
	if result.Issuer == "" || result.LogURL != "https://log/" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestContainsFoldASCII_WorstCase(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 1_000_000)
	pattern := []byte(strings.Repeat("a", 249) + "b")
	if got := containsFoldASCII(data, pattern); got {
		t.Errorf("expected false, got %v", got)
	}
}
