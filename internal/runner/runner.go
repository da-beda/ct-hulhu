package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/certparser"
	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
	"github.com/TheArqsz/ct-hulhu/internal/evidence"
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
		client, err := staticct.NewClientWithKey(
			d.SubmissionURL,
			d.MonitoringURL,
			d.LogID,
			d.Key,
			timeout,
			r.opts.Retries,
		)
		if err != nil {
			return nil, err
		}
		client.SetRequestRateLimit(r.opts.RateLimit)
		return client, nil
	default:
		return nil, fmt.Errorf("unsupported CT protocol %q", d.Protocol)
	}
}

func (r *Runner) workerRate(reader ctlog.Reader) int {
	if reader.Protocol() == ctlog.ProtocolStaticCT {
		// Static CT performs several HTTP requests per logical entry range
		// (checkpoint/data/hash tiles), so the client itself owns the true
		// per-request rate limit.
		return 0
	}
	return r.opts.RateLimit
}

func (r *Runner) malformedPath() string {
	if r.opts.MalformedOutput != "" {
		return r.opts.MalformedOutput
	}
	if r.opts.Output != "" {
		return r.opts.Output + ".malformed.jsonl"
	}
	return filepath.Join(r.opts.StateDir, "malformed.jsonl")
}

func canonicalSelectionPath(path, emptyMarker string) (string, error) {
	if path == "" {
		return emptyMarker, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func normalizeSelectionDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
		if domain != "" {
			seen[domain] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func (r *Runner) selectionHash(kind string, domains []string) (string, error) {
	outputPath, err := canonicalSelectionPath(r.opts.Output, "<stdout>")
	if err != nil {
		return "", err
	}
	malformedPath, err := canonicalSelectionPath(r.malformedPath(), "<none>")
	if err != nil {
		return "", err
	}
	binding := struct {
		Kind          string   `json:"kind"`
		Domains       []string `json:"domains"`
		JSON          bool     `json:"json"`
		Fields        string   `json:"fields"`
		Output        string   `json:"output"`
		Malformed     string   `json:"malformed"`
		Start         int64    `json:"start"`
		Count         int64    `json:"count"`
		FromEnd       bool     `json:"from_end"`
	}{
		Kind:      kind,
		Domains:   normalizeSelectionDomains(domains),
		JSON:      r.opts.JSON,
		Fields:    r.opts.Fields,
		Output:    outputPath,
		Malformed: malformedPath,
		Start:     r.opts.Start,
		Count:     r.opts.Count,
		FromEnd:   r.opts.FromEnd,
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (r *Runner) openMalformedWriter() (*evidence.Writer, error) {
	malformedPath := r.malformedPath()
	if r.opts.Output != "" {
		out, err := canonicalSelectionPath(r.opts.Output, "")
		if err != nil {
			return nil, err
		}
		malformed, err := canonicalSelectionPath(malformedPath, "")
		if err != nil {
			return nil, err
		}
		if out == malformed {
			return nil, fmt.Errorf("output and malformed-evidence paths must be distinct")
		}
	}
	return evidence.NewWriter(malformedPath)
}

func (r *Runner) scrape(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	selectionHash, err := r.selectionHash("scrape", domains)
	if err != nil {
		return fmt.Errorf("binding scrape selection: %w", err)
	}
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

	malformed, err := r.openMalformedWriter()
	if err != nil {
		return err
	}
	defer func() {
		if err := malformed.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("closing malformed evidence: %w", err))
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
		if err := r.scrapeLog(ctx, descriptor, parser, writer, malformed, selectionHash); err != nil {
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
	if err := malformed.Flush(); err != nil {
		failures = append(failures, fmt.Errorf("flushing malformed evidence: %w", err))
	}
	if len(failures) > 0 {
		return fmt.Errorf("scrape incomplete: %d/%d logs completed: %w", succeeded, len(logs), errors.Join(failures...))
	}
	log.Success("done - %d unique results written in this process", writer.Stats())
	return nil
}

type consistencySeeder interface {
	SeedConsistencyAnchor(treeSize int64, rootHash []byte) error
}

func seedConsistency(reader ctlog.Reader, treeSize int64, rootHash string) error {
	if !reader.Source().Verified {
		return nil
	}
	seeder, ok := reader.(consistencySeeder)
	if !ok {
		return fmt.Errorf("verified reader %T cannot restore a consistency anchor", reader)
	}
	root, err := hex.DecodeString(rootHash)
	if err != nil {
		return fmt.Errorf("decoding saved root hash: %w", err)
	}
	if len(root) != sha256.Size {
		return fmt.Errorf("saved root hash has %d bytes, want %d", len(root), sha256.Size)
	}
	return seeder.SeedConsistencyAnchor(treeSize, root)
}

func (r *Runner) scrapeLog(
	ctx context.Context,
	descriptor loglist.Descriptor,
	parser *certparser.Parser,
	writer *output.Writer,
	malformed *evidence.Writer,
	selectionHash string,
) error {
	reader, err := r.newReader(descriptor)
	if err != nil {
		return err
	}
	source := reader.Source()
	log.Info("connecting to %s (%s, verified=%v)", source.LogURL, source.Protocol, source.Verified)

	var progress *ctlog.ScrapeProgress
	if r.opts.Resume {
		progress, err = r.loadScrapeProgress(source, selectionHash)
		if err != nil {
			return fmt.Errorf("loading resume state: %w", err)
		}
		if progress != nil && progress.Verified {
			if err := seedConsistency(reader, progress.TreeSize, progress.RootHash); err != nil {
				return fmt.Errorf("restoring consistency anchor: %w", err)
			}
		}
	}

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
	if progress != nil {
		if progress.TreeSize > treeSize {
			return fmt.Errorf("saved tree size %d exceeds current tree size %d", progress.TreeSize, treeSize)
		}
		if progress.TreeSize == treeSize && progress.RootHash != "" && progress.RootHash != rootHash {
			return fmt.Errorf("same-size current tree root disagrees with saved state")
		}
		if next, ok := progress.SafeResumeIndex(requestedStart, end); ok {
			start = next
			proofStart = progress.RangeStart
			if start >= end {
				return nil
			}
			log.Info("resuming from entry %d", start)
		} else {
			log.Info("saved state does not prove requested range prefix; starting at %d", requestedStart)
		}
	}

	total := end - start
	pool := ctlog.NewWorkerPool(reader, r.opts.BatchSize, r.opts.Workers, r.workerRate(reader))
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
		malformedWritten, parseErr := r.parseBatch(batch, parser, writer, malformed, source, parseSem, &attempted)
		outputErr := writer.Flush()
		var malformedErr error
		if malformedWritten {
			malformedErr = malformed.Flush()
		}
		if parseErr != nil || outputErr != nil || malformedErr != nil {
			if parseErr != nil {
				failures = append(failures, parseErr)
			}
			if outputErr != nil {
				failures = append(failures, fmt.Errorf("flushing output: %w", outputErr))
			}
			if malformedErr != nil {
				failures = append(failures, fmt.Errorf("flushing malformed evidence: %w", malformedErr))
			}
			continue
		}

		next := tracker.Mark(batch.StartIndex, batchEnd)
		if r.opts.Resume && next-lastSaved >= 10000 {
			if err := r.saveScrapeProgress(source, selectionHash, treeSize, rootHash, proofStart, end, next); err != nil {
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
		if err := r.saveScrapeProgress(source, selectionHash, treeSize, rootHash, proofStart, end, next); err != nil {
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

type monitorSession struct {
	reader  ctlog.Reader
	source  ctlog.EntrySource
	display string
	pos     int64
}

func (r *Runner) monitor(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	selectionHash, err := r.selectionHash("monitor", domains)
	if err != nil {
		return fmt.Errorf("binding monitor selection: %w", err)
	}
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
			retErr = errors.Join(retErr, fmt.Errorf("closing output: %w", err))
		}
	}()

	malformed, err := r.openMalformedWriter()
	if err != nil {
		return err
	}
	defer func() {
		if err := malformed.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("closing malformed evidence: %w", err))
		}
	}()

	parser := certparser.New(domains)
	if len(domains) > 0 {
		log.Info("monitoring for domains: %s", strings.Join(domains, ", "))
	}

	var initMu sync.Mutex
	var initFailures []error
	sessions := make(map[string]*monitorSession)
	var initGroup sync.WaitGroup
	for _, descriptor := range descriptors {
		descriptor := descriptor
		initGroup.Add(1)
		go func() {
			defer initGroup.Done()
			reader, err := r.newReader(descriptor)
			if err != nil {
				initMu.Lock()
				initFailures = append(initFailures, fmt.Errorf("%s: %w", descriptor.Description, err))
				initMu.Unlock()
				return
			}
			source := reader.Source()

			var saved *ctlog.MonitorProgress
			if r.opts.Resume {
				saved, err = r.loadMonitorProgress(source, selectionHash)
				if err != nil {
					initMu.Lock()
					initFailures = append(initFailures, fmt.Errorf("%s monitor state: %w", descriptor.Description, err))
					initMu.Unlock()
					return
				}
				if saved != nil && saved.Verified {
					if err := seedConsistency(reader, saved.TreeSize, saved.RootHash); err != nil {
						initMu.Lock()
						initFailures = append(initFailures, fmt.Errorf("%s consistency anchor: %w", descriptor.Description, err))
						initMu.Unlock()
						return
					}
				}
			}

			head, err := reader.GetTreeHead(ctx)
			if err != nil {
				initMu.Lock()
				initFailures = append(initFailures, fmt.Errorf("%s tree head: %w", descriptor.Description, err))
				initMu.Unlock()
				return
			}
			position := head.TreeSize
			if saved != nil {
				if saved.TreeSize > head.TreeSize {
					initMu.Lock()
					initFailures = append(initFailures, fmt.Errorf("%s saved tree size %d exceeds current %d", descriptor.Description, saved.TreeSize, head.TreeSize))
					initMu.Unlock()
					return
				}
				position = saved.TreeSize
			} else {
				if err := r.saveMonitorProgress(source, selectionHash, head); err != nil {
					initMu.Lock()
					initFailures = append(initFailures, fmt.Errorf("%s saving initial monitor state: %w", descriptor.Description, err))
					initMu.Unlock()
					return
				}
			}

			id := source.Identity()
			initMu.Lock()
			sessions[id] = &monitorSession{reader: reader, source: source, display: descriptor.Description, pos: position}
			initMu.Unlock()
		}()
	}
	initGroup.Wait()
	if len(initFailures) > 0 {
		return fmt.Errorf("monitor startup coverage incomplete: %w", errors.Join(initFailures...))
	}
	if len(sessions) != len(descriptors) {
		return fmt.Errorf("monitor startup coverage mismatch: initialized %d/%d logs", len(sessions), len(descriptors))
	}

	var sessionsMu sync.Mutex
	poll := func() {
		if ctx.Err() != nil {
			return
		}
		sessionsMu.Lock()
		snapshot := make(map[string]int64, len(sessions))
		for id, session := range sessions {
			snapshot[id] = session.pos
		}
		sessionsMu.Unlock()

		sem := make(chan struct{}, r.opts.Workers)
		var group sync.WaitGroup
		for id, previous := range snapshot {
			id, previous := id, previous
			group.Add(1)
			sem <- struct{}{}
			go func() {
				defer group.Done()
				defer func() { <-sem }()

				sessionsMu.Lock()
				session := sessions[id]
				sessionsMu.Unlock()
				head, err := session.reader.GetTreeHead(ctx)
				if err != nil {
					log.Warning("poll failed for %s; retaining %d: %v", session.display, previous, err)
					return
				}
				if head.TreeSize < previous {
					log.Warning("tree size decreased for %s; retaining %d", session.display, previous)
					return
				}
				if head.TreeSize == previous {
					return
				}

				if err := r.fetchAndProcess(ctx, session.reader, previous, head.TreeSize, parser, writer, malformed); err != nil {
					log.Warning("delta incomplete for %s; retaining %d: %v", session.display, previous, err)
					return
				}
				if err := r.saveMonitorProgress(session.source, selectionHash, head); err != nil {
					log.Warning("could not persist monitor checkpoint for %s; retaining %d: %v", session.display, previous, err)
					return
				}
				sessionsMu.Lock()
				session.pos = head.TreeSize
				sessionsMu.Unlock()
			}()
		}
		group.Wait()
	}

	// Immediately replay any downtime gap represented by persisted monitor
	// state before waiting for the first poll interval.
	poll()
	ticker := time.NewTicker(time.Duration(r.opts.PollInterval) * time.Second)
	defer ticker.Stop()
	log.Info("monitoring %d log(s)", len(sessions))
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
	malformed *evidence.Writer,
) error {
	pool := ctlog.NewWorkerPool(reader, r.opts.BatchSize, r.opts.Workers, r.workerRate(reader))
	results := make(chan ctlog.EntryBatch, r.opts.Workers*2)
	errCh := make(chan error, 1)
	go func() { errCh <- pool.FetchRange(ctx, start, end, results) }()
	tracker := ctlog.NewContiguousProgress(start)
	sem := r.newParseSem()
	var failures []error
	for batch := range results {
		malformedWritten, parseErr := r.parseBatch(batch, parser, writer, malformed, reader.Source(), sem, nil)
		outputErr := writer.Flush()
		var malformedErr error
		if malformedWritten {
			malformedErr = malformed.Flush()
		}
		if parseErr != nil || outputErr != nil || malformedErr != nil {
			if parseErr != nil {
				failures = append(failures, parseErr)
			}
			if outputErr != nil {
				failures = append(failures, outputErr)
			}
			if malformedErr != nil {
				failures = append(failures, malformedErr)
			}
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

type batchEvidenceError struct {
	Count int
	First []error
}

func (e *batchEvidenceError) Error() string {
	return fmt.Sprintf("%d malformed CT entries could not be preserved; first errors: %v", e.Count, e.First)
}

func (r *Runner) parseBatch(
	batch ctlog.EntryBatch,
	parser *certparser.Parser,
	writer *output.Writer,
	malformed *evidence.Writer,
	source ctlog.EntrySource,
	sem chan struct{},
	counter *atomic.Int64,
) (bool, error) {
	var group sync.WaitGroup
	errs := make(chan error, len(batch.Entries))
	var malformedWritten atomic.Bool
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
				if malformed == nil {
					errs <- fmt.Errorf("entry %d: %w", index, err)
					return
				}
				if evidenceErr := malformed.Append(source, index, entry, err); evidenceErr != nil {
					errs <- fmt.Errorf("entry %d malformed evidence: %w", index, evidenceErr)
					return
				}
				malformedWritten.Store(true)
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
		return malformedWritten.Load(), &batchEvidenceError{Count: count, First: first}
	}
	return malformedWritten.Load(), nil
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
		if err := scanner.Err(); err != nil {
			log.Warning("reading stdin: %v", err)
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

func (r *Runner) statePath(kind string, source ctlog.EntrySource) string {
	sum := sha256.Sum256([]byte(source.Identity()))
	return filepath.Join(r.opts.StateDir, fmt.Sprintf("%s-%x.json", kind, sum[:]))
}

func (r *Runner) scrapeStatePath(source ctlog.EntrySource) string {
	return r.statePath("scrape", source)
}

func (r *Runner) monitorStatePath(source ctlog.EntrySource) string {
	return r.statePath("monitor", source)
}

func (r *Runner) atomicWriteJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
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

func validateSourceState(source ctlog.EntrySource, protocol ctlog.Protocol, logID, logURL string, verified bool) error {
	if protocol != source.Protocol {
		return fmt.Errorf("state protocol %q does not match %q", protocol, source.Protocol)
	}
	if logID != source.LogID {
		return fmt.Errorf("state log ID does not match selected log")
	}
	if logURL != source.LogURL {
		return fmt.Errorf("state log URL does not match selected log")
	}
	if verified != source.Verified {
		return fmt.Errorf("state verification level does not match selected reader")
	}
	return nil
}

func (r *Runner) loadScrapeProgress(source ctlog.EntrySource, selectionHash string) (*ctlog.ScrapeProgress, error) {
	path := r.scrapeStatePath(source)
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
	if progress.Version != 3 {
		return nil, fmt.Errorf("state %s has unsupported safe-resume version %d; start fresh rather than reusing unbound state", path, progress.Version)
	}
	if err := validateSourceState(source, progress.Protocol, progress.LogID, progress.LogURL, progress.Verified); err != nil {
		return nil, err
	}
	if progress.SelectionHash != selectionHash {
		return nil, fmt.Errorf("saved scrape selection does not match the current domains/output/range semantics")
	}
	if progress.RangeStart < 0 || progress.RangeEnd < progress.RangeStart || progress.NextIndex < progress.RangeStart || progress.NextIndex > progress.RangeEnd || progress.RangeEnd > progress.TreeSize {
		return nil, fmt.Errorf("invalid v3 scrape-state bounds")
	}
	return &progress, nil
}

func (r *Runner) saveScrapeProgress(source ctlog.EntrySource, selectionHash string, treeSize int64, rootHash string, rangeStart, rangeEnd, next int64) error {
	if next < rangeStart || next > rangeEnd || rangeEnd > treeSize {
		return fmt.Errorf("invalid progress bounds")
	}
	progress := ctlog.ScrapeProgress{
		Version:       3,
		Protocol:      source.Protocol,
		LogID:         source.LogID,
		LogURL:        source.LogURL,
		Verified:      source.Verified,
		SelectionHash: selectionHash,
		TreeSize:      treeSize,
		RootHash:      rootHash,
		RangeStart:    rangeStart,
		RangeEnd:      rangeEnd,
		LastIndex:     next - 1,
		NextIndex:     next,
		EntriesDone:   next - rangeStart,
		LastUpdated:   time.Now().UTC(),
	}
	return r.atomicWriteJSON(r.scrapeStatePath(source), progress)
}

func (r *Runner) loadMonitorProgress(source ctlog.EntrySource, selectionHash string) (*ctlog.MonitorProgress, error) {
	path := r.monitorStatePath(source)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var progress ctlog.MonitorProgress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if progress.Version != 3 {
		return nil, fmt.Errorf("monitor state %s has unsupported version %d", path, progress.Version)
	}
	if err := validateSourceState(source, progress.Protocol, progress.LogID, progress.LogURL, progress.Verified); err != nil {
		return nil, err
	}
	if progress.SelectionHash != selectionHash {
		return nil, fmt.Errorf("saved monitor selection does not match current domains/output semantics")
	}
	if progress.TreeSize < 0 {
		return nil, fmt.Errorf("saved monitor tree size is negative")
	}
	if progress.Verified {
		root, err := hex.DecodeString(progress.RootHash)
		if err != nil || len(root) != sha256.Size {
			return nil, fmt.Errorf("saved verified monitor root is invalid")
		}
	}
	return &progress, nil
}

func (r *Runner) saveMonitorProgress(source ctlog.EntrySource, selectionHash string, head *ctlog.TreeHead) error {
	if head == nil || head.TreeSize < 0 || len(head.RootHash) != sha256.Size {
		return fmt.Errorf("refusing invalid monitor tree head")
	}
	progress := ctlog.MonitorProgress{
		Version:       3,
		Protocol:      source.Protocol,
		LogID:         source.LogID,
		LogURL:        source.LogURL,
		Verified:      source.Verified,
		SelectionHash: selectionHash,
		TreeSize:      head.TreeSize,
		RootHash:      hex.EncodeToString(head.RootHash),
		LastUpdated:   time.Now().UTC(),
	}
	return r.atomicWriteJSON(r.monitorStatePath(source), progress)
}

// Legacy v2 helpers are retained for migration/unit-test compatibility only.
// Runtime resume uses the selection-bound v3 hashed state paths above.
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
		return nil, fmt.Errorf("unsupported legacy state version %d", progress.Version)
	}
	if progress.Version >= 2 && (progress.RangeStart < 0 || progress.RangeEnd < progress.RangeStart || progress.NextIndex < progress.RangeStart || progress.NextIndex > progress.RangeEnd || progress.RangeEnd > progress.TreeSize) {
		return nil, fmt.Errorf("invalid v2 state bounds")
	}
	return &progress, nil
}

func (r *Runner) saveProgress(source ctlog.EntrySource, treeSize int64, rootHash string, rangeStart, rangeEnd, next int64) error {
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
	return r.atomicWriteJSON(r.stateFilePath(source.LogURL), progress)
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
