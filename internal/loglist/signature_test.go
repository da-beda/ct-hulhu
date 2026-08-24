package loglist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmbeddedChromeLogListKeyFingerprint(t *testing.T) {
	key, der, err := embeddedChromeLogListPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("embedded key type = %T, want RSA", key)
	}
	sum := sha256.Sum256(der)
	const want = "f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("embedded key SHA-256 = %s, want %s", got, want)
	}
}

func TestVerifyLogListRSASignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":"test"}`)
	digest := sha256.Sum256(body)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	algorithm, err := verifyLogListSignatureWithKey(body, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != "sha256-rsa-pkcs1v15" {
		t.Fatalf("algorithm = %q", algorithm)
	}
	body[0] ^= 1
	if _, err := verifyLogListSignatureWithKey(body, signature, &privateKey.PublicKey); err == nil {
		t.Fatal("tampered JSON unexpectedly verified")
	}
}

func TestVerifyLogListECDSASignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":"test"}`)
	digest := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	algorithm, err := verifyLogListSignatureWithKey(body, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != "sha256-ecdsa-asn1" {
		t.Fatalf("algorithm = %q", algorithm)
	}
	signature[len(signature)-1] ^= 1
	if _, err := verifyLogListSignatureWithKey(body, signature, &privateKey.PublicKey); err == nil {
		t.Fatal("tampered ECDSA signature unexpectedly verified")
	}
}

func TestFetchDefaultRequiresSignatureBeforeParsingAndPersistsSidecars(t *testing.T) {
	body := []byte(`{"version":"3","operators":[]}`)
	signature := []byte("signature")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/log-list.json":
			_, _ = w.Write(body)
		case "/log-list.sig":
			_, _ = w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	output := filepath.Join(t.TempDir(), "log-list.json")
	SetEvidenceOutput(output)
	t.Cleanup(func() { SetEvidenceOutput("") })

	fetcher := NewFetcher(5 * time.Second)
	fetcher.defaultLogListURL = srv.URL + "/log-list.json"
	fetcher.defaultSignatureURL = srv.URL + "/log-list.sig"
	verified := false
	fetcher.verifyDefaultSignature = func(gotBody, gotSignature []byte) (*SignatureVerificationEvidence, error) {
		if string(gotBody) != string(body) || string(gotSignature) != string(signature) {
			return nil, fmt.Errorf("verifier received different bytes")
		}
		verified = true
		bodyDigest := sha256.Sum256(gotBody)
		signatureDigest := sha256.Sum256(gotSignature)
		return &SignatureVerificationEvidence{
			SchemaVersion:   verificationSchemaVersion,
			Kind:            verificationKind,
			Verified:        true,
			Algorithm:       "test",
			LogListURL:      fetcher.defaultLogListURL,
			SignatureURL:    fetcher.defaultSignatureURL,
			LogListSHA256:   hex.EncodeToString(bodyDigest[:]),
			SignatureSHA256: hex.EncodeToString(signatureDigest[:]),
			PublicKeySHA256: "f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85",
			PublicKeySource: "test",
			VerifiedAt:      "2026-08-24T00:00:00Z",
		}, nil
	}

	list, raw, err := fetcher.FetchDefaultRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("default response was parsed without invoking signature verification")
	}
	if list.Version != "3" || string(raw) != string(body) {
		t.Fatalf("unexpected default fetch result: version=%q raw=%q", list.Version, raw)
	}
	for _, path := range []string{output, output + ".sig", output + ".pubkey.pem", output + ".verification.json"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing signed evidence sidecar %s: %v", path, err)
		}
	}
}

func TestFetchDefaultVerificationFailureLeavesMainEvidenceAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/log-list.json" {
			_, _ = w.Write([]byte(`{"version":"3","operators":[]}`))
			return
		}
		_, _ = w.Write([]byte("bad-signature"))
	}))
	defer srv.Close()

	output := filepath.Join(t.TempDir(), "log-list.json")
	SetEvidenceOutput(output)
	t.Cleanup(func() { SetEvidenceOutput("") })
	fetcher := NewFetcher(5 * time.Second)
	fetcher.defaultLogListURL = srv.URL + "/log-list.json"
	fetcher.defaultSignatureURL = srv.URL + "/log-list.sig"
	fetcher.verifyDefaultSignature = func([]byte, []byte) (*SignatureVerificationEvidence, error) {
		return nil, fmt.Errorf("signature mismatch")
	}
	if _, _, err := fetcher.FetchDefaultRaw(context.Background()); err == nil {
		t.Fatal("invalid signature unexpectedly accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("main log-list evidence exists after verification failure: %v", err)
	}
}

func TestPersistSignedLogListEvidenceWritesBoundPrivateSidecars(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evidence", "log-list.json")
	body := []byte(`{"version":"test"}\n`)
	signature := []byte("detached-signature")
	bodyDigest := sha256.Sum256(body)
	signatureDigest := sha256.Sum256(signature)
	verification := &SignatureVerificationEvidence{
		SchemaVersion:   verificationSchemaVersion,
		Kind:            verificationKind,
		Verified:        true,
		Algorithm:       "sha256-rsa-pkcs1v15",
		LogListURL:      DefaultLogListURL,
		SignatureURL:    DefaultLogListSignatureURL,
		LogListSHA256:   hex.EncodeToString(bodyDigest[:]),
		SignatureSHA256: hex.EncodeToString(signatureDigest[:]),
		PublicKeySHA256: "f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85",
		PublicKeySource: "embedded-reviewed-key",
		VerifiedAt:      "2026-08-24T00:00:00Z",
	}
	if err := persistSignedLogListEvidence(path, body, signature, verification); err != nil {
		t.Fatal(err)
	}

	artifacts := map[string][]byte{
		path:                        body,
		path + ".sig":               signature,
		path + ".pubkey.pem":        []byte(embeddedChromeLogListPublicKeyPEM),
		path + ".verification.json": nil,
	}
	for artifact, want := range artifacts {
		got, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatal(err)
		}
		if want != nil && string(got) != string(want) {
			t.Fatalf("artifact %s bytes differ", artifact)
		}
		info, err := os.Stat(artifact)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode = %o, want 600", artifact, info.Mode().Perm())
		}
	}

	manifestRaw, err := os.ReadFile(path + ".verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest SignatureVerificationEvidence
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.Verified || manifest.LogListSHA256 != verification.LogListSHA256 || manifest.SignatureSHA256 != verification.SignatureSHA256 {
		t.Fatalf("unexpected verification manifest: %+v", manifest)
	}
}

func TestPersistSignedLogListEvidenceRequiresVerifiedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log-list.json")
	if err := persistSignedLogListEvidence(path, []byte("json"), []byte("sig"), nil); err == nil {
		t.Fatal("nil verification unexpectedly persisted")
	}
	if err := persistSignedLogListEvidence(path, []byte("json"), []byte("sig"), &SignatureVerificationEvidence{}); err == nil {
		t.Fatal("unverified manifest unexpectedly persisted")
	}
}
