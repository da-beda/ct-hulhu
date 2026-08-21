package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
	"github.com/TheArqsz/ct-hulhu/internal/loglist"
	"github.com/TheArqsz/ct-hulhu/internal/staticct"
)

func staticDescriptorKey(t *testing.T) (string, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(digest[:])
}

func TestNewReaderRequiresStaticLogPublicKey(t *testing.T) {
	r := &Runner{opts: &Options{Timeout: 1}}
	_, err := r.newReader(loglist.Descriptor{
		Description:   "static",
		Protocol:      ctlog.ProtocolStaticCT,
		SubmissionURL: "https://submit.example/",
		MonitoringURL: "https://monitor.example/",
		LogID:         base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err == nil {
		t.Fatal("expected missing Static CT key to fail")
	}
}

func TestNewReaderBuildsSecureStaticClient(t *testing.T) {
	key, logID := staticDescriptorKey(t)
	r := &Runner{opts: &Options{Timeout: 1}}
	reader, err := r.newReader(loglist.Descriptor{
		Description:   "static",
		Protocol:      ctlog.ProtocolStaticCT,
		SubmissionURL: "https://submit.example/",
		MonitoringURL: "https://monitor.example/",
		LogID:         logID,
		Key:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, ok := reader.(*staticct.Client)
	if !ok {
		t.Fatalf("reader type = %T", reader)
	}
	if !client.Secure() {
		t.Fatal("auto-discovered Static CT reader must be secure")
	}
}
