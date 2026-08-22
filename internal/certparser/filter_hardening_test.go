package certparser

import "testing"

func TestWildcardTargetFilterNormalizesToBaseDomain(t *testing.T) {
	parser := New([]string{" *.Example.COM. ", ".example.com", "example.com"})
	if len(parser.domainFilter) != 1 {
		t.Fatalf("normalized filters = %v, want one example.com filter", parser.domainFilter)
	}
	if parser.domainFilter[0] != "example.com" {
		t.Fatalf("normalized filter = %q, want example.com", parser.domainFilter[0])
	}
	if !matchesDomain("api.example.com", parser.domainFilter[0]) {
		t.Fatal("wildcard scope filter should match a concrete subdomain after normalization")
	}
}
