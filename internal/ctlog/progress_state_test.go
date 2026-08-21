package ctlog

import "testing"

func TestSafeResumeIndexV2RequiresCoveredRangeStart(t *testing.T) {
	p := &ScrapeProgress{Version: 2, RangeStart: 900, RangeEnd: 1000, NextIndex: 950}
	if got, ok := p.SafeResumeIndex(0, 1000); ok || got != 0 {
		t.Fatalf("historical request incorrectly reused from-end state: got=%d ok=%v", got, ok)
	}
	if got, ok := p.SafeResumeIndex(925, 1000); !ok || got != 950 {
		t.Fatalf("covered request did not resume: got=%d ok=%v", got, ok)
	}
}

func TestSafeResumeIndexV2RejectsCorruptBounds(t *testing.T) {
	p := &ScrapeProgress{Version: 2, RangeStart: 100, RangeEnd: 200, NextIndex: 250}
	if _, ok := p.SafeResumeIndex(100, 300); ok {
		t.Fatal("expected invalid saved bounds to be rejected")
	}
}

func TestSafeResumeIndexLegacyOnlyAtZero(t *testing.T) {
	p := &ScrapeProgress{LastIndex: 49}
	if got, ok := p.SafeResumeIndex(0, 100); !ok || got != 50 {
		t.Fatalf("legacy zero-based state: got=%d ok=%v", got, ok)
	}
	if _, ok := p.SafeResumeIndex(25, 100); ok {
		t.Fatal("legacy state must not be reused for nonzero range")
	}
}
