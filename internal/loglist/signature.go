package loglist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

const (
	DefaultLogListSignatureURL = "https://www.gstatic.com/ct/log_list/v3/log_list.sig"
	maxLogListSignatureSize    = 16 << 10
	verificationSchemaVersion  = "1.0"
	verificationKind           = "ct-hulhu-chrome-log-list-signature-verification"
)

// Chrome publishes this key separately from the signed log list. Keeping the
// reviewed key in the binary makes signature verification independent of the
// same network response that supplies the JSON and signature. A Chrome key
// rotation therefore fails closed until this reviewed constant is updated.
const embeddedChromeLogListPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----
`

type SignatureVerificationEvidence struct {
	SchemaVersion   string `json:"schema_version"`
	Kind            string `json:"kind"`
	Verified        bool   `json:"verified"`
	Algorithm       string `json:"algorithm"`
	LogListURL      string `json:"log_list_url"`
	SignatureURL    string `json:"signature_url"`
	LogListSHA256   string `json:"log_list_sha256"`
	SignatureSHA256 string `json:"signature_sha256"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	PublicKeySource string `json:"public_key_source"`
	VerifiedAt      string `json:"verified_at"`
}

func embeddedChromeLogListPublicKey() (crypto.PublicKey, []byte, error) {
	block, rest := pem.Decode([]byte(embeddedChromeLogListPublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, nil, fmt.Errorf("embedded Chrome log-list key is not a PUBLIC KEY PEM block")
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("embedded Chrome log-list key has trailing data")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing embedded Chrome log-list public key: %w", err)
	}
	return key, append([]byte(nil), block.Bytes...), nil
}

func verifyLogListSignatureWithKey(logList, signature []byte, publicKey crypto.PublicKey) (string, error) {
	if len(logList) == 0 {
		return "", fmt.Errorf("Chrome log-list response is empty")
	}
	if len(signature) == 0 || len(signature) > maxLogListSignatureSize {
		return "", fmt.Errorf("Chrome log-list signature size %d is outside the accepted bound", len(signature))
	}
	digest := sha256.Sum256(logList)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return "", fmt.Errorf("verifying Chrome log-list RSA signature: %w", err)
		}
		return "sha256-rsa-pkcs1v15", nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return "", fmt.Errorf("verifying Chrome log-list ECDSA signature failed")
		}
		return "sha256-ecdsa-asn1", nil
	default:
		return "", fmt.Errorf("unsupported Chrome log-list public key type %T", publicKey)
	}
}

func verifyChromeLogListSignature(logList, signature []byte) (*SignatureVerificationEvidence, error) {
	publicKey, publicKeyDER, err := embeddedChromeLogListPublicKey()
	if err != nil {
		return nil, err
	}
	algorithm, err := verifyLogListSignatureWithKey(logList, signature, publicKey)
	if err != nil {
		return nil, err
	}
	logListDigest := sha256.Sum256(logList)
	signatureDigest := sha256.Sum256(signature)
	publicKeyDigest := sha256.Sum256(publicKeyDER)
	return &SignatureVerificationEvidence{
		SchemaVersion:   verificationSchemaVersion,
		Kind:            verificationKind,
		Verified:        true,
		Algorithm:       algorithm,
		LogListURL:      DefaultLogListURL,
		SignatureURL:    DefaultLogListSignatureURL,
		LogListSHA256:   hex.EncodeToString(logListDigest[:]),
		SignatureSHA256: hex.EncodeToString(signatureDigest[:]),
		PublicKeySHA256: hex.EncodeToString(publicKeyDigest[:]),
		PublicKeySource: "embedded-reviewed-key",
		VerifiedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func persistSignedLogListEvidence(path string, logList, signature []byte, verification *SignatureVerificationEvidence) error {
	if path == "" {
		return nil
	}
	if verification == nil || !verification.Verified {
		return fmt.Errorf("refusing to persist log-list evidence without successful signature verification")
	}
	manifest, err := json.Marshal(verification)
	if err != nil {
		return fmt.Errorf("marshalling log-list verification evidence: %w", err)
	}
	manifest = append(manifest, '\n')

	// The exact list is committed last. A caller that sees the requested main
	// artifact can therefore require the deterministic sidecars to be present.
	artifacts := []struct {
		path string
		data []byte
	}{
		{path: path + ".sig", data: signature},
		{path: path + ".pubkey.pem", data: []byte(embeddedChromeLogListPublicKeyPEM)},
		{path: path + ".verification.json", data: manifest},
		{path: path, data: logList},
	}
	for _, artifact := range artifacts {
		if _, err := persistEvidence(artifact.path, artifact.data); err != nil {
			return fmt.Errorf("persisting signed log-list artifact %s: %w", artifact.path, err)
		}
	}
	return nil
}
