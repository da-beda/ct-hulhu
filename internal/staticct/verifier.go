package staticct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

const (
	tlsHashSHA256       = 4
	tlsSignatureRSA     = 1
	tlsSignatureECDSA   = 3
	rfc6962VersionV1    = 0
	rfc6962TreeHashType = 1
)

func parseLogPublicKey(keyBase64, logIDBase64 string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding log public key: %w", err)
	}
	logID, err := base64.StdEncoding.DecodeString(logIDBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding log ID: %w", err)
	}
	if len(logID) != sha256.Size {
		return nil, fmt.Errorf("log ID has %d bytes, want %d", len(logID), sha256.Size)
	}
	digest := sha256.Sum256(der)
	if !cryptoBytesEqual(digest[:], logID) {
		return nil, fmt.Errorf("log ID does not equal SHA-256 of SubjectPublicKeyInfo")
	}

	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing log public key: %w", err)
	}
	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.Curve.Params() == nil {
			return nil, fmt.Errorf("ECDSA log key has no curve parameters")
		}
		if pub.Curve.Params().Name != elliptic.P256().Params().Name {
			return nil, fmt.Errorf("unsupported ECDSA curve %q; RFC6962 requires P-256", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if pub.N == nil {
			return nil, fmt.Errorf("RSA log key has no modulus")
		}
		if pub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA log key is %d bits; require at least 2048", pub.N.BitLen())
		}
	default:
		return nil, fmt.Errorf("unsupported log public key type %T", key)
	}
	return key, nil
}

func verifyCheckpointSignature(pub crypto.PublicKey, cp *Checkpoint) error {
	if cp == nil {
		return fmt.Errorf("nil checkpoint")
	}
	if cp.Timestamp < 0 || cp.TreeSize < 0 || len(cp.RootHash) != sha256.Size {
		return fmt.Errorf("checkpoint contains invalid signed tree-head fields")
	}
	return verifyDigitallySigned(pub, cp.DigitallySigned, treeHeadSignatureInput(cp))
}

func treeHeadSignatureInput(cp *Checkpoint) []byte {
	input := make([]byte, 2+8+8+sha256.Size)
	input[0] = rfc6962VersionV1
	input[1] = rfc6962TreeHashType
	binary.BigEndian.PutUint64(input[2:10], uint64(cp.Timestamp))
	binary.BigEndian.PutUint64(input[10:18], uint64(cp.TreeSize))
	copy(input[18:], cp.RootHash)
	return input
}

func verifyDigitallySigned(pub crypto.PublicKey, digitallySigned, signedInput []byte) error {
	if len(digitallySigned) < 4 {
		return fmt.Errorf("DigitallySigned is truncated")
	}
	hashAlgorithm := digitallySigned[0]
	signatureAlgorithm := digitallySigned[1]
	signatureLength := int(binary.BigEndian.Uint16(digitallySigned[2:4]))
	if hashAlgorithm != tlsHashSHA256 {
		return fmt.Errorf("unsupported TLS hash algorithm %d; want SHA-256", hashAlgorithm)
	}
	if signatureLength <= 0 || len(digitallySigned) != 4+signatureLength {
		return fmt.Errorf("DigitallySigned length says %d bytes, record has %d", signatureLength, len(digitallySigned)-4)
	}
	signature := digitallySigned[4:]
	digest := sha256.Sum256(signedInput)

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if signatureAlgorithm != tlsSignatureECDSA {
			return fmt.Errorf("ECDSA key paired with TLS signature algorithm %d", signatureAlgorithm)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return fmt.Errorf("invalid ECDSA checkpoint signature")
		}
		return nil
	case *rsa.PublicKey:
		if signatureAlgorithm != tlsSignatureRSA {
			return fmt.Errorf("RSA key paired with TLS signature algorithm %d", signatureAlgorithm)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("invalid RSA checkpoint signature: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

func cryptoBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
