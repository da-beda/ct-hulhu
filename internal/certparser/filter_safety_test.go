package certparser

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

func TestDomainFilterDoesNotHideMalformedEntry(t *testing.T) {
	leaf := make([]byte, 12)
	binary.BigEndian.PutUint16(leaf[10:12], 99)
	entry := ctlog.RawEntry{LeafInput: base64.StdEncoding.EncodeToString(leaf)}

	result, err := New([]string{"example.com"}).ParseEntry(entry, 42, "https://log.example/")
	if err == nil {
		t.Fatalf("malformed entry was silently filtered: result=%#v", result)
	}
	if result != nil {
		t.Fatalf("malformed entry returned result=%#v", result)
	}
}
