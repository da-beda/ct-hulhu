package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/certparser"
	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
	"github.com/TheArqsz/ct-hulhu/internal/evidence"
	"github.com/TheArqsz/ct-hulhu/internal/output"
)

// RunWithBaseline preserves the existing runner behavior while routing monitor
// sessions that request startup-baseline evidence through the pre-poll monitor
// implementation below.
func (r *Runner) RunWithBaseline() error {
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
		if r.opts.MonitorBaselineOutput != "" {
			return r.monitorWithBaseline(ctx)
		}
		return r.monitor(ctx)
	}
	return r.scrape(ctx)
}

// monitorWithBaseline is the normal monitor lifecycle with one additional
// durability boundary: after every selected log has either loaded existing
// state or persisted its first checkpoint, but before any delta poll can run,
// it writes the newly initialized state files to MonitorBaselineOutput.
func (r *Runner) monitorWithBaseline(ctx context.Context) (retErr error) {
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
	initializedStatePaths := make([]string, 0)
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
			initializedStatePath := ""

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
				initializedStatePath = r.monitorStatePath(source)
			}

			id := source.Identity()
			initMu.Lock()
			sessions[id] = &monitorSession{reader: reader, source: source, display: descriptor.Description, pos: position}
			if initializedStatePath != "" {
				initializedStatePaths = append(initializedStatePaths, initializedStatePath)
			}
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
	if err := writeMonitorBaseline(
		r.opts.MonitorBaselineOutput,
		r.opts.StateDir,
		selectionHash,
		initializedStatePaths,
	); err != nil {
		return fmt.Errorf("writing monitor startup baseline: %w", err)
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

// Compile-time anchors for the duplicated monitor collaborators. They also make
// accidental import removal visible to gofmt/go vet during review.
var (
	_ *evidence.Writer
	_ ctlog.Reader
)
