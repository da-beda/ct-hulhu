package ctlog

import "sync"

// ContiguousProgress tracks the largest fully processed prefix of a range.
// Batches may finish out of order; resume state must never advance across a gap.
type ContiguousProgress struct {
	mu      sync.Mutex
	next    int64
	pending map[int64]int64
}

func NewContiguousProgress(start int64) *ContiguousProgress {
	return &ContiguousProgress{
		next:    start,
		pending: make(map[int64]int64),
	}
}

// Mark records a processed half-open interval [start,end) and returns the first
// index that is not yet known to be processed.
func (p *ContiguousProgress) Mark(start, end int64) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	if end <= start || end <= p.next {
		return p.next
	}
	if start < p.next {
		start = p.next
	}
	if existing, ok := p.pending[start]; !ok || end > existing {
		p.pending[start] = end
	}

	for {
		advanced := false
		for segmentStart, segmentEnd := range p.pending {
			if segmentEnd <= p.next {
				delete(p.pending, segmentStart)
				continue
			}
			if segmentStart <= p.next {
				p.next = segmentEnd
				delete(p.pending, segmentStart)
				advanced = true
			}
		}
		if !advanced {
			break
		}
	}
	return p.next
}

func (p *ContiguousProgress) Next() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.next
}

func (p *ContiguousProgress) LastIndex() int64 {
	return p.Next() - 1
}
