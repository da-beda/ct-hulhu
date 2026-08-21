package ctlog

import "testing"

func TestContiguousProgressInOrder(t *testing.T) {
	p := NewContiguousProgress(100)
	if got := p.Mark(100, 110); got != 110 {
		t.Fatalf("next = %d, want 110", got)
	}
	if got := p.Mark(110, 120); got != 120 {
		t.Fatalf("next = %d, want 120", got)
	}
	if got := p.LastIndex(); got != 119 {
		t.Fatalf("last = %d, want 119", got)
	}
}

func TestContiguousProgressDoesNotCrossGap(t *testing.T) {
	p := NewContiguousProgress(0)
	if got := p.Mark(10, 20); got != 0 {
		t.Fatalf("next = %d, want 0 while [0,10) is missing", got)
	}
	if got := p.Mark(0, 10); got != 20 {
		t.Fatalf("next = %d, want 20 after gap closes", got)
	}
}

func TestContiguousProgressMergesOverlaps(t *testing.T) {
	p := NewContiguousProgress(0)
	p.Mark(20, 30)
	p.Mark(10, 25)
	if got := p.Mark(0, 15); got != 30 {
		t.Fatalf("next = %d, want 30", got)
	}
}

func TestContiguousProgressIgnoresAlreadyProcessedRanges(t *testing.T) {
	p := NewContiguousProgress(5)
	p.Mark(5, 10)
	if got := p.Mark(0, 7); got != 10 {
		t.Fatalf("next = %d, want 10", got)
	}
}
