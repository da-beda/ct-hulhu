package ctlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type entryReaderFunc func(context.Context, int64, int64) (*GetEntriesResponse, error)

func (f entryReaderFunc) GetRawEntries(ctx context.Context, start, end int64) (*GetEntriesResponse, error) {
	return f(ctx, start, end)
}

func TestNewWorkerPool(t *testing.T) {
	client := NewClient("https://example.com", 5*time.Second, 0)
	pool := NewWorkerPool(client, 256, 4, 0)

	if pool.client != client {
		t.Error("client not set")
	}
	if pool.batchSize != 256 {
		t.Errorf("batchSize = %d, want 256", pool.batchSize)
	}
	if pool.maxWorkers != 4 {
		t.Errorf("maxWorkers = %d, want 4", pool.maxWorkers)
	}
}

func TestDroppedEntries_Initial(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 4, 0)
	if pool.DroppedEntries() != 0 {
		t.Errorf("DroppedEntries() = %d, want 0", pool.DroppedEntries())
	}
}

func TestErrorInfo_NoRequests(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 4, 0)
	if got := pool.ErrorInfo(); got != "no requests made" {
		t.Errorf("ErrorInfo() = %q, want 'no requests made'", got)
	}
}

func TestFetchRange_EmptyRange(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 1, 0)
	results := make(chan EntryBatch, 1)
	if err := pool.FetchRange(context.Background(), 10, 10, results); err != nil {
		t.Fatalf("expected nil error for empty range, got: %v", err)
	}
	if _, ok := <-results; ok {
		t.Error("expected closed channel for empty range")
	}
}

func TestFetchRange_Basic(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = w.Write([]byte(`{"entries":[{"leaf_input":"dGVzdA==","extra_data":""}]}`))
	}))
	defer srv.Close()

	pool := NewWorkerPool(NewClient(srv.URL, 5*time.Second, 0), 10, 1, 0)
	results := make(chan EntryBatch, 10)
	errCh := make(chan error, 1)
	go func() { errCh <- pool.FetchRange(context.Background(), 0, 5, results) }()

	var count int
	for batch := range results {
		count += len(batch.Entries)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("FetchRange error: %v", err)
	}
	if count != 5 {
		t.Fatalf("received %d entries, want 5", count)
	}
	if callCount != 5 {
		t.Fatalf("server calls = %d, want 5", callCount)
	}
}

func TestFetchRange_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	defer srv.Close()

	pool := NewWorkerPool(NewClient(srv.URL, 5*time.Second, 0), 10, 1, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results := make(chan EntryBatch, 10)
	if err := pool.FetchRange(ctx, 0, 1000, results); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestFetchRange_ServerErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pool := NewWorkerPool(NewClient(srv.URL, 5*time.Second, 0), 10, 1, 0)
	results := make(chan EntryBatch, 10)
	err := pool.FetchRange(context.Background(), 0, 5, results)
	if err == nil {
		t.Fatal("expected incomplete-range error")
	}
	var incomplete *IncompleteRangeError
	if !errors.As(err, &incomplete) {
		t.Fatalf("error type = %T, want *IncompleteRangeError: %v", err, err)
	}
	if incomplete.Dropped != 5 || pool.DroppedEntries() != 5 {
		t.Fatalf("dropped = %d/%d, want 5", incomplete.Dropped, pool.DroppedEntries())
	}
}

func TestFetchRange_ZeroEntryResponseFailsClosed(t *testing.T) {
	reader := entryReaderFunc(func(context.Context, int64, int64) (*GetEntriesResponse, error) {
		return &GetEntriesResponse{}, nil
	})
	pool := NewWorkerPool(reader, 10, 1, 0)
	results := make(chan EntryBatch, 10)
	if err := pool.FetchRange(context.Background(), 7, 10, results); err == nil {
		t.Fatal("expected zero-entry response to make range incomplete")
	}
	if got := pool.DroppedEntries(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}

func TestFetchRange_OversizedResponseFailsClosed(t *testing.T) {
	reader := entryReaderFunc(func(context.Context, int64, int64) (*GetEntriesResponse, error) {
		return &GetEntriesResponse{Entries: make([]RawEntry, 4)}, nil
	})
	pool := NewWorkerPool(reader, 10, 1, 0)
	results := make(chan EntryBatch, 10)
	if err := pool.FetchRange(context.Background(), 0, 3, results); err == nil {
		t.Fatal("expected oversized response to fail")
	}
}

func TestSetDebugLog(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 4, 0)
	var called bool
	pool.SetDebugLog(func(format string, args ...any) { called = true })
	pool.debug("test %d", 1)
	if !called {
		t.Error("debug log function was not called")
	}
}

func TestDebug_NilHandler(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 4, 0)
	pool.debug("test %d", 1)
}

func TestErrorInfo_WithStats(t *testing.T) {
	pool := NewWorkerPool(NewClient("https://example.com", 5*time.Second, 0), 256, 4, 0)
	pool.errCount.Add(2)
	pool.successCount.Add(8)
	got := pool.ErrorInfo()
	want := fmt.Sprintf("2 errors / 10 total requests (20.0%% error rate)")
	if got != want {
		t.Errorf("ErrorInfo() = %q, want %q", got, want)
	}
}

func TestFetchRange_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"leaf_input":"dGVzdA==","extra_data":""}]}`))
	}))
	defer srv.Close()

	pool := NewWorkerPool(NewClient(srv.URL, 5*time.Second, 0), 10, 1, 100)
	results := make(chan EntryBatch, 10)
	errCh := make(chan error, 1)
	go func() { errCh <- pool.FetchRange(context.Background(), 0, 5, results) }()
	for range results {
	}
	if err := <-errCh; err != nil {
		t.Fatalf("FetchRange with rate limit error: %v", err)
	}
}
