package staticct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestParseLogPublicKeyAcceptsP256AndBoundLogID(t *testing.T) {
	key := newTestLogKey(t)
	pub, err := parseLogPublicKey(key.keyB64, key.logID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("public key type = %T", pub)
	}
}

func TestParseLogPublicKeyRejectsUnsupportedCurve(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(der)
	if _, err := parseLogPublicKey(base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(id[:])); err == nil {
		t.Fatal("expected P-384 key rejection")
	}
}

func TestVerifyCheckpointSignatureRejectsTampering(t *testing.T) {
	key := newTestLogKey(t)
	root := hashLeaf([]byte("one"))
	raw := buildSignedCheckpoint(t, key, "https://submit.example/log/", 1, root, 123)
	cp, err := ParseCheckpoint(raw, "https://submit.example/log/", key.logID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parseLogPublicKey(key.keyB64, key.logID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointSignature(pub, cp); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	cp.RootHash[0] ^= 0xff
	if err := verifyCheckpointSignature(pub, cp); err == nil {
		t.Fatal("expected tampered root to invalidate checkpoint signature")
	}
}

func TestVerifyDigitallySignedRSA(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("signed input")
	digest := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	ds := make([]byte, 4+len(sig))
	ds[0] = tlsHashSHA256
	ds[1] = tlsSignatureRSA
	binary.BigEndian.PutUint16(ds[2:4], uint16(len(sig)))
	copy(ds[4:], sig)
	if err := verifyDigitallySigned(&private.PublicKey, ds, input); err != nil {
		t.Fatalf("valid RSA DigitallySigned rejected: %v", err)
	}
	ds[len(ds)-1] ^= 1
	if err := verifyDigitallySigned(&private.PublicKey, ds, input); err == nil {
		t.Fatal("expected tampered RSA signature to fail")
	}
}
