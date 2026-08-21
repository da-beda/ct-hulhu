package ctlog

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type EntryBatch struct {
	StartIndex int64
	Entries    []RawEntry
}

type IncompleteRangeError struct {
	Start   int64
	End     int64
	Dropped int64
	Cause   error
}

func (e *IncompleteRangeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("incomplete CT range [%d-%d): dropped %d entries: %v", e.Start, e.End, e.Dropped, e.Cause)
	}
	return fmt.Sprintf("incomplete CT range [%d-%d): dropped %d entries", e.Start, e.End, e.Dropped)
}

func (e *IncompleteRangeError) Unwrap() error { return e.Cause }

type WorkerPool struct {
	client     EntryReader
	batchSize  int
	maxWorkers int
	rateLimit  int

	activeWorkers  atomic.Int32
	errCount       atomic.Int32
	successCount   atomic.Int32
	droppedEntries atomic.Int64
	debugLog       func(format string, args ...any)

	failureMu sync.Mutex
	failures  []error
}

func NewWorkerPool(client EntryReader, batchSize, maxWorkers, rateLimit int) *WorkerPool {
	return &WorkerPool{
		client:     client,
		batchSize:  batchSize,
		maxWorkers: maxWorkers,
		rateLimit:  rateLimit,
	}
}

func (wp *WorkerPool) SetDebugLog(fn func(format string, args ...any)) {
	wp.debugLog = fn
}

func (wp *WorkerPool) DroppedEntries() int64 {
	return wp.droppedEntries.Load()
}

func (wp *WorkerPool) debug(format string, args ...any) {
	if wp.debugLog != nil {
		wp.debugLog(format, args...)
	}
}

func (wp *WorkerPool) recordFailure(start, end int64, err error) {
	if end < start {
		return
	}
	wp.errCount.Add(1)
	wp.droppedEntries.Add(end - start + 1)
	wrapped := fmt.Errorf("range [%d-%d]: %w", start, end, err)
	wp.failureMu.Lock()
	wp.failures = append(wp.failures, wrapped)
	wp.failureMu.Unlock()
	wp.debug("batch [%d-%d] incomplete: %v", start, end, err)
}

func (wp *WorkerPool) joinedFailures() error {
	wp.failureMu.Lock()
	defer wp.failureMu.Unlock()
	return errors.Join(wp.failures...)
}

type workItem struct {
	start, end int64
}

func (wp *WorkerPool) FetchRange(ctx context.Context, start, end int64, results chan<- EntryBatch) error {
	defer close(results)

	if start >= end {
		return nil
	}
	if start < 0 {
		return fmt.Errorf("range start must be non-negative")
	}

	work := make(chan workItem, wp.maxWorkers*2)

	go func() {
		defer close(work)
		for pos := start; pos < end; pos += int64(wp.batchSize) {
			batchEnd := pos + int64(wp.batchSize) - 1
			if batchEnd >= end {
				batchEnd = end - 1
			}
			select {
			case work <- workItem{start: pos, end: batchEnd}:
			case <-ctx.Done():
				return
			}
		}
	}()

	var rateLimiter <-chan time.Time
	if wp.rateLimit > 0 {
		interval := time.Second / time.Duration(wp.rateLimit)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	var wg sync.WaitGroup
	workersDone := make(chan struct{})
	go func() {
		defer close(workersDone)

		wg.Add(1)
		go wp.worker(ctx, work, results, rateLimiter, &wg)
		wp.activeWorkers.Add(1)

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case <-ticker.C:
				current := int(wp.activeWorkers.Load())
				if current == 0 {
					wg.Wait()
					return
				}

				successes := wp.successCount.Load()
				errorsSeen := wp.errCount.Load()
				total := successes + errorsSeen
				if current < wp.maxWorkers && total > 0 {
					errorRate := float64(errorsSeen) / float64(total)
					if errorRate < 0.1 {
						wp.debug("ramping up: %d -> %d workers (error rate: %.1f%%)", current, current+1, errorRate*100)
						wg.Add(1)
						go wp.worker(ctx, work, results, rateLimiter, &wg)
						wp.activeWorkers.Add(1)
					}
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		<-workersDone
		return ctx.Err()
	case <-workersDone:
		wg.Wait()
	}

	if dropped := wp.DroppedEntries(); dropped > 0 {
		return &IncompleteRangeError{
			Start:   start,
			End:     end,
			Dropped: dropped,
			Cause:   wp.joinedFailures(),
		}
	}
	return nil
}

func (wp *WorkerPool) worker(
	ctx context.Context,
	work <-chan workItem,
	results chan<- EntryBatch,
	rateLimiter <-chan time.Time,
	wg *sync.WaitGroup,
) {
	defer func() {
		wp.activeWorkers.Add(-1)
		wg.Done()
	}()

	for item := range work {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if rateLimiter != nil {
			select {
			case <-rateLimiter:
			case <-ctx.Done():
				return
			}
		}

		wp.fetchItem(ctx, item, results)
	}
}

func (wp *WorkerPool) fetchItem(ctx context.Context, item workItem, results chan<- EntryBatch) {
	currentStart := item.start

	for currentStart <= item.end {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := wp.client.GetRawEntries(ctx, currentStart, item.end)
		if err != nil {
			wp.recordFailure(currentStart, item.end, err)
			return
		}
		if resp == nil {
			wp.recordFailure(currentStart, item.end, errors.New("reader returned nil response"))
			return
		}
		if len(resp.Entries) == 0 {
			wp.recordFailure(currentStart, item.end, errors.New("reader returned zero entries for non-empty range"))
			return
		}

		remaining := item.end - currentStart + 1
		if int64(len(resp.Entries)) > remaining {
			wp.recordFailure(currentStart, item.end, fmt.Errorf("reader returned %d entries for %d-entry remainder", len(resp.Entries), remaining))
			return
		}

		wp.successCount.Add(1)
		wp.debug("batch [%d-%d] fetched %d entries", currentStart, currentStart+int64(len(resp.Entries))-1, len(resp.Entries))
		select {
		case results <- EntryBatch{StartIndex: currentStart, Entries: resp.Entries}:
		case <-ctx.Done():
			return
		}

		currentStart += int64(len(resp.Entries))
	}
}

func (wp *WorkerPool) ErrorInfo() string {
	errorsSeen := wp.errCount.Load()
	successes := wp.successCount.Load()
	total := errorsSeen + successes
	if total == 0 {
		return "no requests made"
	}
	return fmt.Sprintf("%d errors / %d total requests (%.1f%% error rate)", errorsSeen, total, float64(errorsSeen)/float64(total)*100)
}
