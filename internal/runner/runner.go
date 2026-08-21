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
)

type Runner struct { opts *Options }

func New(opts *Options) *Runner { return &Runner{opts: opts} }

func (r *Runner) Run() error {
	if !r.opts.Silent { showBanner() }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// The upstream self-updater is intentionally disabled on this fork branch:
	// its release owner and go-install fallback target TheArqsz/ct-hulhu and
	// would replace a fork build with upstream code.
	if r.opts.Update {
		return fmt.Errorf("self-update is disabled in this fork build; update from da-beda/ct-hulhu releases or source")
	}

	if r.opts.ListLogs { return r.listLogs(ctx) }
	if r.opts.Monitor { return r.monitor(ctx) }
	return r.scrape(ctx)
}

func (r *Runner) listLogs(ctx context.Context) error {
	timeout := time.Duration(r.opts.Timeout) * time.Second
	fetcher := loglist.NewFetcher(timeout)
	log.Info("fetching CT log list...")
	logList, err := fetcher.FetchDefault(ctx)
	if err != nil { return fmt.Errorf("fetching log list: %w", err) }
	logs := loglist.FilterLogs(logList, r.opts.LogState)
	if r.opts.JSON {
		for _, l := range logs {
			data, err := json.Marshal(map[string]any{
				"operator": output.Sanitize(l.Operator),
				"description": output.Sanitize(l.Log.Description),
				"url": l.Log.FullURL(),
				"state": l.Log.CurrentState(),
				"mmd": l.Log.MMD,
				"protocol": ctlog.ProtocolRFC6962,
				"log_id": l.Log.LogID,
			})
			if err != nil { log.Debug("json marshal error: %v", err); continue }
			fmt.Println(string(data))
		}
	} else {
		fmt.Printf("%-12s %-10s %-50s %-45s %s\n", "STATE", "PROTOCOL", "DESCRIPTION", "URL", "OPERATOR")
		fmt.Println(strings.Repeat("-", 152))
		for _, l := range logs {
			fmt.Printf("%-12s %-10s %-50s %-45s %s\n", l.Log.CurrentState(), ctlog.ProtocolRFC6962, truncate(output.Sanitize(l.Log.Description), 48), truncate(l.Log.FullURL(), 43), output.Sanitize(l.Operator))
		}
		fmt.Printf("\nTotal: %d logs\n", len(logs))
	}
	return nil
}

func (r *Runner) scrape(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	logURLs, err := r.resolveLogURLs(ctx)
	if err != nil { return err }
	if len(logURLs) == 0 { return fmt.Errorf("no CT logs to scrape - use -lu <url> to specify a log or omit to auto-discover") }

	writer, err := output.NewWriterWithOptions(r.opts.Output, r.opts.JSON, r.opts.Fields, output.WriterOptions{Append: r.opts.Resume})
	if err != nil { return err }
	defer func() { if err := writer.Close(); err != nil { retErr = errors.Join(retErr, fmt.Errorf("closing output: %w", err)) } }()

	parser := certparser.New(domains)
	if len(domains) > 0 { log.Info("filtering for domains: %s", strings.Join(domains, ", ")) }

	var failures []error
	succeeded := 0
	for _, logURL := range logURLs {
		if err := ctx.Err(); err != nil { return errors.Join(err, errors.Join(failures...)) }
		if err := r.scrapeLog(ctx, logURL, parser, writer); err != nil {
			wrapped := fmt.Errorf("%s: %w", logURL, err)
			failures = append(failures, wrapped)
			log.Warning("incomplete scrape: %v", wrapped)
			continue
		}
		succeeded++
	}

	if err := writer.Flush(); err != nil { failures = append(failures, fmt.Errorf("flushing output: %w", err)) }
	if len(failures) > 0 {
		return fmt.Errorf("scrape incomplete: %d/%d logs completed: %w", succeeded, len(logURLs), errors.Join(failures...))
	}
	log.Success("done - %d unique results written in this process", writer.Stats())
	return nil
}

func (r *Runner) scrapeLog(ctx context.Context, logURL string, parser *certparser.Parser, writer *output.Writer) error {
	timeout := time.Duration(r.opts.Timeout) * time.Second
	client := ctlog.NewClient(logURL, timeout, r.opts.Retries)
	source := client.Source()
	log.Info("connecting to %s", logURL)
	head, err := client.GetTreeHead(ctx)
	if err != nil { return fmt.Errorf("getting tree head: %w", err) }
	treeSize := head.TreeSize
	rootHash := hex.EncodeToString(head.RootHash)
	log.Info("tree size: %d entries", treeSize)

	requestedStart, end := r.calculateRange(treeSize)
	if requestedStart >= end { log.Info("no entries to process"); return nil }
	start := requestedStart
	proofStart := requestedStart

	if r.opts.Resume {
		progress, err := r.loadProgress(logURL)
		if err != nil { return fmt.Errorf("loading resume state: %w", err) }
		if progress != nil {
			if next, ok := progress.SafeResumeIndex(requestedStart, end); ok {
				start = next
				if progress.Version >= 2 { proofStart = progress.RangeStart } else { proofStart = 0 }
				if start >= end { log.Info("resume: requested range already processed"); return nil }
				log.Info("resuming from entry %d (%d entries remaining)", start, end-start)
			} else {
				log.Info("resume: saved state does not prove the requested range prefix; starting at %d", requestedStart)
			}
		} else { log.Info("resume: no saved state found, starting at %d", requestedStart) }
	}

	totalEntries := end - start
	log.Info("scraping entries %d to %d (%d entries) with %d workers", start, end-1, totalEntries, r.opts.Workers)
	pool := ctlog.NewWorkerPool(client, r.opts.BatchSize, r.opts.Workers, r.opts.RateLimit)
	pool.SetDebugLog(log.Debug)
	results := make(chan ctlog.EntryBatch, r.opts.Workers*2)
	fetchErr := make(chan error, 1)
	go func() { fetchErr <- pool.FetchRange(ctx, start, end, results) }()

	tracker := ctlog.NewContiguousProgress(start)
	parseSem := r.newParseSem()
	var attempted atomic.Int64
	startTime := time.Now()
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go r.progressReporter(ctx, stopProgress, progressDone, &attempted, totalEntries, startTime, writer)

	var stageFailures []error
	lastSavedNext := start
	for batch := range results {
		batchEnd := batch.StartIndex + int64(len(batch.Entries))
		parseErr := r.parseBatch(batch, parser, writer, source, parseSem, &attempted)
		flushErr := writer.Flush()
		if parseErr != nil || flushErr != nil {
			if parseErr != nil { stageFailures = append(stageFailures, parseErr); log.Warning("not checkpointing batch at %d: %v", batch.StartIndex, parseErr) }
			if flushErr != nil { stageFailures = append(stageFailures, fmt.Errorf("flushing output: %w", flushErr)) }
			continue
		}
		next := tracker.Mark(batch.StartIndex, batchEnd)
		if r.opts.Resume && next-lastSavedNext >= 10000 {
			if err := r.saveProgress(source, treeSize, rootHash, proofStart, end, next); err != nil {
				stageFailures = append(stageFailures, fmt.Errorf("saving progress: %w", err))
			} else { lastSavedNext = next }
		}
	}
	close(stopProgress); <-progressDone
	if err := writer.Flush(); err != nil { stageFailures = append(stageFailures, fmt.Errorf("flushing output: %w", err)) }
	if err := <-fetchErr; err != nil { stageFailures = append(stageFailures, err) }

	next := tracker.Next()
	if r.opts.Resume {
		if err := r.saveProgress(source, treeSize, rootHash, proofStart, end, next); err != nil { stageFailures = append(stageFailures, fmt.Errorf("saving final progress: %w", err)) } else { log.Info("resume state saved at next index %d to %s", next, r.stateFilePath(logURL)) }
	}
	if next != end { stageFailures = append(stageFailures, fmt.Errorf("contiguous processed prefix ended at %d, requested end is %d", next, end)) }
	if len(stageFailures) > 0 { return errors.Join(stageFailures...) }

	elapsed := time.Since(startTime)
	rate := float64(end-start) / max(elapsed.Seconds(), 0.000001)
	log.Success("completed %s: %d contiguous entries in %v (%.0f entries/sec)", logURL, end-start, elapsed.Round(time.Second), rate)
	log.Debug("fetch stats: %s", pool.ErrorInfo())
	return nil
}

func (r *Runner) progressReporter(ctx context.Context, stop <-chan struct{}, done chan<- struct{}, attempted *atomic.Int64, total int64, started time.Time, writer *output.Writer) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second); defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-stop: return
		case <-ticker.C:
			count := attempted.Load(); if count == 0 { continue }
			elapsed := time.Since(started); rate := float64(count) / max(elapsed.Seconds(), 0.000001); pct := float64(count) / float64(total) * 100
			log.Info("progress: %d/%d attempted (%.1f%%) - %.0f entries/sec - %d results", count, total, pct, rate, writer.Stats())
		}
	}
}

func (r *Runner) monitor(ctx context.Context) (retErr error) {
	domains := r.collectDomains()
	logURLs, err := r.resolveLogURLs(ctx)
	if err != nil { return err }
	if len(logURLs) == 0 { return fmt.Errorf("no CT logs to monitor") }
	writer, err := output.NewWriterWithOptions(r.opts.Output, r.opts.JSON, r.opts.Fields, output.WriterOptions{Append: r.opts.Resume})
	if err != nil { return err }
	defer func() { if err := writer.Close(); err != nil { retErr = errors.Join(retErr, fmt.Errorf("closing output: %w", err)) } }()
	parser := certparser.New(domains)
	if len(domains) > 0 { log.Info("monitoring for domains: %s", strings.Join(domains, ", ")) }

	pollInterval := time.Duration(r.opts.PollInterval) * time.Second
	var treeMu sync.Mutex
	lastTreeSize := make(map[string]int64)
	clients := make(map[string]*ctlog.Client)
	timeout := time.Duration(r.opts.Timeout) * time.Second
	var initWg sync.WaitGroup
	for _, logURL := range logURLs {
		initWg.Add(1)
		go func(logURL string) {
			defer initWg.Done()
			client := ctlog.NewClient(logURL, timeout, r.opts.Retries)
			head, err := client.GetTreeHead(ctx)
			if err != nil { log.Warning("monitor init failed for %s: %v", logURL, err); return }
			treeMu.Lock(); clients[logURL] = client; lastTreeSize[logURL] = head.TreeSize; treeMu.Unlock()
			log.Debug("[%s] starting at tree size %d", truncate(logURL, 50), head.TreeSize)
		}(logURL)
	}
	initWg.Wait()
	if len(lastTreeSize) == 0 { return fmt.Errorf("could not connect to any CT logs") }
	if len(lastTreeSize) != len(logURLs) { log.Warning("monitor coverage incomplete at startup: connected to %d/%d selected logs", len(lastTreeSize), len(logURLs)) }

	poll := func() {
		if ctx.Err() != nil { return }
		var wg sync.WaitGroup
		sem := make(chan struct{}, r.opts.Workers)
		treeMu.Lock(); snapshot := make(map[string]int64, len(lastTreeSize)); maps.Copy(snapshot, lastTreeSize); treeMu.Unlock()
		for logURL, prevSize := range snapshot {
			wg.Add(1); sem <- struct{}{}
			go func(logURL string, prevSize int64) {
				defer wg.Done(); defer func(){ <-sem }()
				client := clients[logURL]
				head, err := client.GetTreeHead(ctx)
				if err != nil { log.Warning("poll failed for %s; retaining checkpoint %d: %v", logURL, prevSize, err); return }
				newSize := head.TreeSize
				if newSize < prevSize { log.Warning("tree size decreased for %s: %d -> %d; retaining checkpoint", logURL, prevSize, newSize); return }
				if newSize == prevSize { return }
				log.Info("[%s] %d new entries (tree %d -> %d)", truncate(logURL, 40), newSize-prevSize, prevSize, newSize)
				if err := r.fetchAndProcess(ctx, client, prevSize, newSize, parser, writer); err != nil { log.Warning("delta incomplete for %s; retaining checkpoint %d: %v", logURL, prevSize, err); return }
				treeMu.Lock(); lastTreeSize[logURL] = newSize; treeMu.Unlock()
			}(logURL, prevSize)
		}
		wg.Wait()
	}

	poll()
	ticker := time.NewTicker(pollInterval); defer ticker.Stop()
	log.Info("connected to %d log(s), polling every %vs (Ctrl+C to stop)", len(lastTreeSize), r.opts.PollInterval)
	for {
		select {
		case <-ctx.Done(): log.Success("monitor stopped - %d unique results written in this process", writer.Stats()); return nil
		case <-ticker.C: poll()
		}
	}
}

func (r *Runner) fetchAndProcess(ctx context.Context, reader ctlog.Reader, start, end int64, parser *certparser.Parser, writer *output.Writer) error {
	pool := ctlog.NewWorkerPool(reader, r.opts.BatchSize, r.opts.Workers, r.opts.RateLimit)
	pool.SetDebugLog(log.Debug)
	results := make(chan ctlog.EntryBatch, r.opts.Workers*2)
	fetchErr := make(chan error, 1)
	go func(){ fetchErr <- pool.FetchRange(ctx, start, end, results) }()
	tracker := ctlog.NewContiguousProgress(start)
	parseSem := r.newParseSem()
	var failures []error
	for batch := range results {
		if err := r.parseBatch(batch, parser, writer, reader.Source(), parseSem, nil); err != nil { failures = append(failures, err); continue }
		if err := writer.Flush(); err != nil { failures = append(failures, fmt.Errorf("flushing output: %w", err)); continue }
		tracker.Mark(batch.StartIndex, batch.StartIndex+int64(len(batch.Entries)))
	}
	if err := <-fetchErr; err != nil { failures = append(failures, err) }
	if tracker.Next() != end { failures = append(failures, fmt.Errorf("contiguous processed prefix ended at %d, requested end is %d", tracker.Next(), end)) }
	return errors.Join(failures...)
}

func (r *Runner) newParseSem() chan struct{} {
	n := r.opts.ParseWorkers; if n <= 0 { n = runtime.GOMAXPROCS(0) }; if n < 1 { n = 1 }; return make(chan struct{}, n)
}

type batchParseError struct { Count int; First []error }
func (e *batchParseError) Error() string { return fmt.Sprintf("%d certificate entries failed to parse; first errors: %v", e.Count, e.First) }

func (r *Runner) parseBatch(batch ctlog.EntryBatch, parser *certparser.Parser, writer *output.Writer, source ctlog.EntrySource, parseSem chan struct{}, counter *atomic.Int64) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(batch.Entries))
	for i, entry := range batch.Entries {
		wg.Add(1); parseSem <- struct{}{}
		go func(e ctlog.RawEntry, idx int64) {
			defer wg.Done(); defer func(){ <-parseSem }(); if counter != nil { defer counter.Add(1) }
			result, err := parser.ParseEntryFromSource(e, idx, source)
			if err != nil { errCh <- fmt.Errorf("entry %d: %w", idx, err); return }
			if result != nil { writer.WriteResult(result) }
		}(entry, batch.StartIndex+int64(i))
	}
	wg.Wait(); close(errCh)
	count := 0; first := make([]error, 0, 5)
	for err := range errCh { count++; if len(first) < cap(first) { first = append(first, err) } }
	if count > 0 { return &batchParseError{Count: count, First: first} }
	return nil
}

func (r *Runner) collectDomains() []string {
	var domains []string; domains = append(domains, r.opts.Domain...)
	if r.opts.DomainFile != "" { if fileDomains, err := readLinesFromFile(r.opts.DomainFile); err != nil { log.Warning("reading domain file: %v", err) } else { domains = append(domains, fileDomains...) } }
	if hasStdin() { scanner := bufio.NewScanner(os.Stdin); for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" { domains = append(domains, line) } }; if err := scanner.Err(); err != nil { log.Warning("reading stdin: %v", err) } }
	return domains
}

func (r *Runner) resolveLogURLs(ctx context.Context) ([]string, error) {
	if len(r.opts.LogURL) > 0 {
		urls := make([]string, len(r.opts.LogURL))
		for i, u := range r.opts.LogURL {
			switch { case strings.HasPrefix(u, "https://"): case strings.HasPrefix(u, "http://"): log.Warning("upgrading %s to HTTPS", u); u = "https://"+strings.TrimPrefix(u,"http://"); default: u = "https://"+u }
			urls[i] = u
		}
		return urls, nil
	}
	log.Info("auto-discovering CT logs...")
	fetcher := loglist.NewFetcher(time.Duration(r.opts.Timeout)*time.Second)
	logList, err := fetcher.FetchDefault(ctx); if err != nil { return nil, fmt.Errorf("fetching log list: %w", err) }
	logs := loglist.FilterLogs(logList, r.opts.LogState); if len(logs)==0 { return nil, fmt.Errorf("no logs found matching state filter %q", r.opts.LogState) }
	log.Info("found %d %s RFC6962 CT logs", len(logs), r.opts.LogState)
	urls := make([]string,len(logs)); for i,l := range logs { urls[i]=l.Log.FullURL() }; return urls,nil
}

func (r *Runner) calculateRange(treeSize int64) (start,end int64) {
	if r.opts.FromEnd { end=treeSize; if r.opts.Count>0 { start=max(end-r.opts.Count,0) } else if r.opts.Start>=0 { start=r.opts.Start } else { start=max(0,treeSize-10000) } } else { if r.opts.Start>=0 { start=r.opts.Start }; if r.opts.Count>0 { end=min(start+r.opts.Count,treeSize) } else { end=treeSize } }; return
}

func (r *Runner) loadProgress(logURL string) (*ctlog.ScrapeProgress,error) {
	path := r.stateFilePath(logURL); data,err := os.ReadFile(path); if errors.Is(err,os.ErrNotExist){return nil,nil}; if err!=nil{return nil,err}
	var p ctlog.ScrapeProgress; if err:=json.Unmarshal(data,&p);err!=nil{return nil,fmt.Errorf("parsing %s: %w",path,err)}
	if p.LogURL!=logURL{return nil,fmt.Errorf("state log URL %q does not match %q",p.LogURL,logURL)}
	if p.Version>2{return nil,fmt.Errorf("unsupported state version %d",p.Version)}
	if p.Version>=2 { if p.RangeStart<0 || p.RangeEnd<p.RangeStart || p.NextIndex<p.RangeStart || p.NextIndex>p.RangeEnd || p.RangeEnd>p.TreeSize { return nil,fmt.Errorf("invalid v2 state bounds") } }
	return &p,nil
}

func (r *Runner) saveProgress(source ctlog.EntrySource, treeSize int64, rootHash string, rangeStart, rangeEnd, nextIndex int64) error {
	if nextIndex<rangeStart || nextIndex>rangeEnd || rangeEnd>treeSize{return fmt.Errorf("refusing invalid progress bounds start=%d next=%d end=%d tree=%d",rangeStart,nextIndex,rangeEnd,treeSize)}
	p:=ctlog.ScrapeProgress{Version:2,Protocol:source.Protocol,LogID:source.LogID,LogURL:source.LogURL,TreeSize:treeSize,RootHash:rootHash,RangeStart:rangeStart,RangeEnd:rangeEnd,LastIndex:nextIndex-1,NextIndex:nextIndex,EntriesDone:nextIndex-rangeStart,LastUpdated:time.Now().UTC()}
	data,err:=json.Marshal(p);if err!=nil{return err}
	if err:=os.MkdirAll(r.opts.StateDir,0o700);err!=nil{return err}
	path:=r.stateFilePath(source.LogURL);tmp,err:=os.CreateTemp(r.opts.StateDir,".state-*");if err!=nil{return err};tmpPath:=tmp.Name();defer os.Remove(tmpPath)
	if err:=tmp.Chmod(0o600);err!=nil{tmp.Close();return err};if _,err:=tmp.Write(data);err!=nil{tmp.Close();return err};if err:=tmp.Sync();err!=nil{tmp.Close();return err};if err:=tmp.Close();err!=nil{return err}
	if err:=os.Rename(tmpPath,path);err!=nil{return err};return os.Chmod(path,0o600)
}

func (r *Runner) stateFilePath(logURL string) string { safe:=strings.NewReplacer("https://","","http://","","/","_",":","_").Replace(logURL);return filepath.Join(r.opts.StateDir,safe+".state.json") }
func readLinesFromFile(path string)([]string,error){f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close();var lines []string;scanner:=bufio.NewScanner(f);for scanner.Scan(){line:=strings.TrimSpace(scanner.Text());if line!=""&&!strings.HasPrefix(line,"#"){lines=append(lines,line)}};return lines,scanner.Err()}
func hasStdin()bool{stat,err:=os.Stdin.Stat();if err!=nil{return false};return(stat.Mode()&os.ModeCharDevice)==0}
func truncate(s string,maxLen int)string{if len(s)<=maxLen{return s};if maxLen<3{return s[:maxLen]};return s[:maxLen-2]+".."}
