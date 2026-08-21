package runner

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/certparser"
	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
	"github.com/TheArqsz/ct-hulhu/internal/loglist"
	"github.com/TheArqsz/ct-hulhu/internal/output"
	"github.com/TheArqsz/ct-hulhu/internal/staticct"
)

type Runner struct {
	opts *Options
}

func New(opts *Options) *Runner { return &Runner{opts: opts} }

func (r *Runner) Run() error {
	if !r.opts.Silent {
		showBanner()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if r.opts.Update {
		return fmt.Errorf("self-update is disabled in this fork build; update from da-beda/ct-hulhu releases or source")
	}
	if r.opts.ListLogs {
		return r.listLogs(ctx)
	}
	if r.opts.Monitor {
		return r.monitor(ctx)
	}
	return r.scrape(ctx)
}

func (r *Runner) listLogs(ctx context.Context) error {
	logList, err := loglist.NewFetcher(time.Duration(r.opts.Timeout) * time.Second).FetchDefault(ctx)
	if err != nil {
		return fmt.Errorf("fetching log list: %w", err)
	}
	logs := loglist.FilterDescriptors(logList, r.opts.LogState)
	if r.opts.JSON {
		for _, item := range logs {
			data, err := json.Marshal(map[string]any{
				"operator":       output.Sanitize(item.Operator),
				"description":    output.Sanitize(item.Description),
				"protocol":       item.Protocol,
				"log_id":         item.LogID,
				"url":            item.URL,
				"submission_url": item.SubmissionURL,
				"monitoring_url": item.MonitoringURL,
				"state":          item.State,
				"mmd":            item.MMD,
			})
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		}
		return nil
	}

	fmt.Printf("%-12s %-13s %-42s %-48s %s\n", "STATE", "PROTOCOL", "DESCRIPTION", "READ URL", "OPERATOR")
	fmt.Println(strings.Repeat("-", 150))
	for _, item := range logs {
		readURL := item.URL
		if item.Protocol == ctlog.ProtocolStaticCT {
			readURL = item.MonitoringURL
		}
		fmt.Printf("%-12s %-13s %-42s %-48s %s\n",
			item.State,
			item.Protocol,
			truncate(output.Sanitize(item.Description), 40),
			truncate(readURL, 46),
			output.Sanitize(item.Operator),
		)
	}
	fmt.Printf("\nTotal: %d logs\n", len(logs))
	return nil
}

func (r *Runner) newReader(d loglist.Descriptor) (ctlog.Reader, error) {
	timeout := time.Duration(r.opts.Timeout) * time.Second
	switch d.Protocol {
	case ctlog.ProtocolRFC6962:
		return ctlog.NewClientWithLogID(d.URL, d.LogID, timeout, r.opts.Retries), nil
	case ctlog.ProtocolStaticCT:
		if strings.TrimSpace(d.Key) == "" {
			return nil, fmt.Errorf("Static CT log %q has no public key in log-list descriptor", d.Description)
		}
		return staticct.NewClientWithKey(
			d.SubmissionURL,
			d.MonitoringURL,
			d.LogID,
			d.Key,
			timeout,
			r.opts.Retries,
		)
	default:
		return nil, fmt.Errorf("unsupported CT protocol %q", d.Protocol)
	}
}

func (r *Runner) scrape(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	logs, err := r.resolveLogs(ctx)
	if err != nil {
		return err
	}
	if len(logs) == 0 {
		return fmt.Errorf("no CT logs selected")
	}
	writer, err := output.NewWriterWithOptions(
		r.opts.Output,
		r.opts.JSON,
		r.opts.Fields,
		output.WriterOptions{Append: r.opts.Resume},
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := writer.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("closing output: %w", err))
		}
	}()

	parser := certparser.New(domains)
	if len(domains) > 0 {
		log.Info("filtering for domains: %s", strings.Join(domains, ", "))
	}

	var failures []error
	succeeded := 0
	for _, descriptor := range logs {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.Join(failures...))
		}
		if err := r.scrapeLog(ctx, descriptor, parser, writer); err != nil {
			wrapped := fmt.Errorf("%s %s: %w", descriptor.Protocol, descriptor.Description, err)
			failures = append(failures, wrapped)
			log.Warning("incomplete scrape: %v", wrapped)
			continue
		}
		succeeded++
	}
	if err := writer.Flush(); err != nil {
		failures = append(failures, fmt.Errorf("flushing output: %w", err))
	}
	if len(failures) > 0 {
		return fmt.Errorf("scrape incomplete: %d/%d logs completed: %w", succeeded, len(logs), errors.Join(failures...))
	}
	log.Success("done - %d unique results written in this process", writer.Stats())
	return nil
}

func (r *Runner) scrapeLog(
	ctx context.Context,
	descriptor loglist.Descriptor,
	parser *certparser.Parser,
	writer *output.Writer,
) error {
	reader, err := r.newReader(descriptor)
	if err != nil {
		return err
	}
	source := reader.Source()
	log.Info("connecting to %s (%s)", source.LogURL, source.Protocol)
	head, err := reader.GetTreeHead(ctx)
	if err != nil {
		return fmt.Errorf("getting tree head: %w", err)
	}
	treeSize := head.TreeSize
	rootHash := hex.EncodeToString(head.RootHash)
	log.Info("tree size: %d entries", treeSize)

	requestedStart, end := r.calculateRange(treeSize)
	if requestedStart >= end {
		log.Info("no entries to process")
		return nil
	}
	start := requestedStart
	proofStart := requestedStart
	if r.opts.Resume {
		progress, err := r.loadProgress(source.LogURL)
		if err != nil {
			return fmt.Errorf("loading resume state: %w", err)
		}
		if progress != nil {
			if progress.Protocol != "" && progress.Protocol != source.Protocol {
				return fmt.Errorf("resume state protocol %q does not match %q", progress.Protocol, source.Protocol)
			}
			if progress.LogID != "" && source.LogID != "" && progress.LogID != source.LogID {
				return fmt.Errorf("resume state log ID does not match selected log")
			}
			if next, ok := progress.SafeResumeIndex(requestedStart, end); ok {
				start = next
				if progress.Version >= 2 {
					proofStart = progress.RangeStart
				} else {
					proofStart = 0
				}
				if start >= end {
					return nil
				}
				log.Info("resuming from entry %d", start)
			} else {
				log.Info("saved state does not prove requested range prefix; starting at %d", requestedStart)
			}
		}
	}

	total := end - start
	pool := ctlog.NewWorkerPool(reader, r.opts.BatchSize, r.opts.Workers, r.opts.RateLimit)
	pool.SetDebugLog(log.Debug)
	results := make(chan ctlog.EntryBatch, r.opts.Workers*2)
	fetchErr := make(chan error, 1)
	go func() { fetchErr <- pool.FetchRange(ctx, start, end, results) }()

	tracker := ctlog.NewContiguousProgress(start)
	parseSem := r.newParseSem()
	var attempted atomic.Int64
	started := time.Now()
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go r.progressReporter(ctx, stopProgress, progressDone, &attempted, total, started, writer)

	var failures []error
	lastSaved := start
	for batch := range results {
		batchEnd := batch.StartIndex + int64(len(batch.Entries))
		parseErr := r.parseBatch(batch, parser, writer, source, parseSem, &attempted)
		flushErr := writer.Flush()
		if parseErr != nil || flushErr != nil {
			if parseErr != nil {
				failures = append(failures, parseErr)
				log.Warning("not checkpointing batch at %d: %v", batch.StartIndex, parseErr)
			}
			if flushErr != nil {
				failures = append(failures, fmt.Errorf("flushing output: %w", flushErr))
			}
			continue
		}
		next := tracker.Mark(batch.StartIndex, batchEnd)
		if r.opts.Resume && next-lastSaved >= 10000 {
			if err := r.saveProgress(source, treeSize, rootHash, proofStart, end, next); err != nil {
				failures = append(failures, fmt.Errorf("saving progress: %w", err))
			} else {
				lastSaved = next
			}
		}
	}
	close(stopProgress)
	<-progressDone
	if err := writer.Flush(); err != nil {
		failures = append(failures, fmt.Errorf("flushing output: %w", err))
	}
	if err := <-fetchErr; err != nil {
		failures = append(failures, err)
	}

	next := tracker.Next()
	if r.opts.Resume {
		if err := r.saveProgress(source, treeSize, rootHash, proofStart, end, next); err != nil {
			failures = append(failures, fmt.Errorf("saving final progress: %w", err))
		}
	}
	if next != end {
		failures = append(failures, fmt.Errorf("contiguous processed prefix ended at %d, requested end %d", next, end))
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	elapsed := time.Since(started)
	rate := float64(end-start) / max(elapsed.Seconds(), .000001)
	log.Success("completed %s %s: %d entries in %v (%.0f entries/sec)", source.Protocol, source.LogURL, end-start, elapsed.Round(time.Second), rate)
	return nil
}

func (r *Runner) progressReporter(
	ctx context.Context,
	stop <-chan struct{},
	done chan<- struct{},
	attempted *atomic.Int64,
	total int64,
	started time.Time,
	writer *output.Writer,
) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			count := attempted.Load()
			if count == 0 {
				continue
			}
			rate := float64(count) / max(time.Since(started).Seconds(), .000001)
			pct := float64(count) / float64(total) * 100
			log.Info("progress: %d/%d attempted (%.1f%%) - %.0f entries/sec - %d results", count, total, pct, rate, writer.Stats())
		}
	}
}

func (r *Runner) monitor(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	descriptors, err := r.resolveLogs(ctx)
	if err != nil {
		return err
	}
	if len(descriptors) == 0 {
		return fmt.Errorf("no CT logs selected")
	}
	writer, err := output.NewWriterWithOptions(
		r.opts.Output,
		r.opts.JSON,
		r.opts.Fields,
		output.WriterOptions{Append: r.opts.Resume},
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := writer.Close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	parser := certparser.New(domains)

	var mu sync.Mutex
	positions := map[string]int64{}
	readers := map[string]ctlog.Reader{}
	display := map[string]string{}
	var initGroup sync.WaitGroup
	for _, descriptor := range descriptors {
		descriptor := descriptor
		initGroup.Add(1)
		go func() {
			defer initGroup.Done()
			reader, err := r.newReader(descriptor)
			if err != nil {
				log.Warning("monitor init failed for %s: %v", descriptor.Description, err)
				return
			}
			head, err := reader.GetTreeHead(ctx)
			if err != nil {
				log.Warning("monitor init failed for %s: %v", descriptor.Description, err)
				return
			}
			id := reader.Source().Identity()
			mu.Lock()
			readers[id] = reader
			positions[id] = head.TreeSize
			display[id] = descriptor.Description
			mu.Unlock()
		}()
	}
	initGroup.Wait()
	if len(readers) == 0 {
		return fmt.Errorf("could not initialize any selected CT logs")
	}
	if len(readers) != len(descriptors) {
		log.Warning("monitor coverage incomplete at startup: %d/%d logs", len(readers), len(descriptors))
	}

	poll := func() {
		mu.Lock()
		snapshot := make(map[string]int64, len(positions))
		maps.Copy(snapshot, positions)
		mu.Unlock()
		sem := make(chan struct{}, r.opts.Workers)
		var group sync.WaitGroup
		for id, previous := range snapshot {
			id, previous := id, previous
			group.Add(1)
			sem <- struct{}{}
			go func() {
				defer group.Done()
				defer func() { <-sem }()
				reader := readers[id]
				head, err := reader.GetTreeHead(ctx)
				if err != nil {
					log.Warning("poll failed for %s; retaining %d: %v", display[id], previous, err)
					return
				}
				if head.TreeSize < previous {
					log.Warning("tree size decreased for %s; retaining %d", display[id], previous)
					return
				}
				if head.TreeSize == previous {
					return
				}
				if err := r.fetchAndProcess(ctx, reader, previous, head.TreeSize, parser, writer); err != nil {
					log.Warning("delta incomplete for %s; retaining %d: %v", display[id], previous, err)
					return
				}
				mu.Lock()
				positions[id] = head.TreeSize
				mu.Unlock()
			}()
		}
		group.Wait()
	}

	poll()
	ticker := time.NewTicker(time.Duration(r.opts.PollInterval) * time.Second)
	defer ticker.Stop()
	log.Info("monitoring %d log(s)", len(readers))
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			poll()
		}
	}
}

func (r *Runner) fetchAndProcess(
	ctx context.Context,
	reader ctlog.Reader,
	start, end int64,
	parser *certparser.Parser,
	writer *output.Writer,
) error {
	pool := ctlog.NewWorkerPool(reader, r.opts.BatchSize, r.opts.Workers, r.opts.RateLimit)
	results := make(chan ctlog.EntryBatch, r.opts.Workers*2)
	errCh := make(chan error, 1)
	go func() { errCh <- pool.FetchRange(ctx, start, end, results) }()
	tracker := ctlog.NewContiguousProgress(start)
	sem := r.newParseSem()
	var failures []error
	for batch := range results {
		if err := r.parseBatch(batch, parser, writer, reader.Source(), sem, nil); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := writer.Flush(); err != nil {
			failures = append(failures, err)
			continue
		}
		tracker.Mark(batch.StartIndex, batch.StartIndex+int64(len(batch.Entries)))
	}
	if err := <-errCh; err != nil {
		failures = append(failures, err)
	}
	if tracker.Next() != end {
		failures = append(failures, fmt.Errorf("contiguous processed prefix ended at %d, requested end %d", tracker.Next(), end))
	}
	return errors.Join(failures...)
}

func (r *Runner) newParseSem() chan struct{} {
	n := r.opts.ParseWorkers
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	if n < 1 {
		n = 1
	}
	return make(chan struct{}, n)
}

type batchParseError struct {
	Count int
	First []error
}

func (e *batchParseError) Error() string {
	return fmt.Sprintf("%d certificate entries failed to parse; first errors: %v", e.Count, e.First)
}

func (r *Runner) parseBatch(
	batch ctlog.EntryBatch,
	parser *certparser.Parser,
	writer *output.Writer,
	source ctlog.EntrySource,
	sem chan struct{},
	counter *atomic.Int64,
) error {
	var group sync.WaitGroup
	errs := make(chan error, len(batch.Entries))
	for i, entry := range batch.Entries {
		i, entry := i, entry
		group.Add(1)
		sem <- struct{}{}
		go func() {
			defer group.Done()
			defer func() { <-sem }()
			if counter != nil {
				defer counter.Add(1)
			}
			index := batch.StartIndex + int64(i)
			result, err := parser.ParseEntryFromSource(entry, index, source)
			if err != nil {
				errs <- fmt.Errorf("entry %d: %w", index, err)
				return
			}
			if result != nil {
				result.IssuerFingerprints = append([]string(nil), entry.IssuerFingerprints...)
				writer.WriteResult(result)
			}
		}()
	}
	group.Wait()
	close(errs)

	count := 0
	first := make([]error, 0, 5)
	for err := range errs {
		count++
		if len(first) < cap(first) {
			first = append(first, err)
		}
	}
	if count > 0 {
		return &batchParseError{Count: count, First: first}
	}
	return nil
}

func (r *Runner) collectDomains() []string {
	var domains []string
	domains = append(domains, r.opts.Domain...)
	if r.opts.DomainFile != "" {
		fileDomains, err := readLinesFromFile(r.opts.DomainFile)
		if err != nil {
			log.Warning("reading domain file: %v", err)
		} else {
			domains = append(domains, fileDomains...)
		}
	}
	if hasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if value := strings.TrimSpace(scanner.Text()); value != "" {
				domains = append(domains, value)
			}
		}
	}
	return domains
}

func (r *Runner) resolveLogs(ctx context.Context) ([]loglist.Descriptor, error) {
	if len(r.opts.LogURL) > 0 {
		out := make([]loglist.Descriptor, 0, len(r.opts.LogURL))
		for _, raw := range r.opts.LogURL {
			url := raw
			if strings.HasPrefix(url, "http://") {
				log.Warning("upgrading %s to HTTPS", url)
				url = "https://" + strings.TrimPrefix(url, "http://")
			} else if !strings.HasPrefix(url, "https://") {
				url = "https://" + url
			}
			out = append(out, loglist.Descriptor{
				Description: url,
				Protocol:    ctlog.ProtocolRFC6962,
				URL:         url,
				State:       "explicit",
			})
		}
		return out, nil
	}

	logList, err := loglist.NewFetcher(time.Duration(r.opts.Timeout) * time.Second).FetchDefault(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching log list: %w", err)
	}
	logs := loglist.FilterDescriptors(logList, r.opts.LogState)
	if len(logs) == 0 {
		return nil, fmt.Errorf("no logs match state %q", r.opts.LogState)
	}
	rfcCount, staticCount := 0, 0
	for _, descriptor := range logs {
		if descriptor.Protocol == ctlog.ProtocolStaticCT {
			staticCount++
		} else {
			rfcCount++
		}
	}
	log.Info("auto-discovered %d logs: %d RFC6962, %d Static CT", len(logs), rfcCount, staticCount)
	return logs, nil
}

func (r *Runner) calculateRange(treeSize int64) (start, end int64) {
	if r.opts.FromEnd {
		end = treeSize
		if r.opts.Count > 0 {
			start = max(end-r.opts.Count, 0)
		} else if r.opts.Start >= 0 {
			start = r.opts.Start
		} else {
			start = max(0, treeSize-10000)
		}
		return
	}
	if r.opts.Start >= 0 {
		start = r.opts.Start
	}
	if r.opts.Count > 0 {
		end = min(start+r.opts.Count, treeSize)
	} else {
		end = treeSize
	}
	return
}

func (r *Runner) loadProgress(logURL string) (*ctlog.ScrapeProgress, error) {
	path := r.stateFilePath(logURL)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var progress ctlog.ScrapeProgress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if progress.LogURL != logURL {
		return nil, fmt.Errorf("state log URL mismatch")
	}
	if progress.Version > 2 {
		return nil, fmt.Errorf("unsupported state version %d", progress.Version)
	}
	if progress.Version >= 2 && (
		progress.RangeStart < 0 ||
		progress.RangeEnd < progress.RangeStart ||
		progress.NextIndex < progress.RangeStart ||
		progress.NextIndex > progress.RangeEnd ||
		progress.RangeEnd > progress.TreeSize) {
		return nil, fmt.Errorf("invalid v2 state bounds")
	}
	return &progress, nil
}

func (r *Runner) saveProgress(
	source ctlog.EntrySource,
	treeSize int64,
	rootHash string,
	rangeStart, rangeEnd, next int64,
) error {
	if next < rangeStart || next > rangeEnd || rangeEnd > treeSize {
		return fmt.Errorf("invalid progress bounds")
	}
	progress := ctlog.ScrapeProgress{
		Version:     2,
		Protocol:    source.Protocol,
		LogID:       source.LogID,
		LogURL:      source.LogURL,
		TreeSize:    treeSize,
		RootHash:    rootHash,
		RangeStart:  rangeStart,
		RangeEnd:    rangeEnd,
		LastIndex:   next - 1,
		NextIndex:   next,
		EntriesDone: next - rangeStart,
		LastUpdated: time.Now().UTC(),
	}
	data, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.opts.StateDir, 0o700); err != nil {
		return err
	}
	path := r.stateFilePath(source.LogURL)
	tmp, err := os.CreateTemp(r.opts.StateDir, ".state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (r *Runner) stateFilePath(logURL string) string {
	safe := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
	).Replace(logURL)
	return filepath.Join(r.opts.StateDir, safe+".state.json")
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	return err == nil && (stat.Mode()&os.ModeCharDevice) == 0
}

func truncate(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	if maxLen < 3 {
		return value[:maxLen]
	}
	return value[:maxLen-2] + ".."
}
