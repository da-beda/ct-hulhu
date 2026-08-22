package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TheArqsz/ct-hulhu/internal/ctlog"
)

type MalformedEvent struct {
	RecordedAt         time.Time         `json:"recorded_at"`
	Protocol           ctlog.Protocol    `json:"protocol"`
	LogID              string            `json:"log_id,omitempty"`
	LogURL             string            `json:"log_url"`
	Verified           bool              `json:"verified"`
	Index              int64             `json:"index"`
	Error              string            `json:"error"`
	LeafInput          string            `json:"leaf_input"`
	ExtraData          string            `json:"extra_data"`
	IssuerFingerprints []string          `json:"issuer_fingerprints,omitempty"`
}

type Writer struct {
	mu       sync.Mutex
	file     *os.File
	buffered *bufio.Writer
	writeErr error
}

func NewWriter(path string) (*Writer, error) {
	parent := filepath.Dir(path)
	if parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("creating malformed-evidence directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening malformed-evidence file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("restricting malformed-evidence permissions: %w", err)
	}
	return &Writer{file: file, buffered: bufio.NewWriter(file)}, nil
}

func (w *Writer) recordErr(err error) {
	if err != nil && w.writeErr == nil {
		w.writeErr = err
	}
}

func (w *Writer) Append(source ctlog.EntrySource, index int64, entry ctlog.RawEntry, parseErr error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	event := MalformedEvent{
		RecordedAt:         time.Now().UTC(),
		Protocol:           source.Protocol,
		LogID:              source.LogID,
		LogURL:             source.LogURL,
		Verified:           source.Verified,
		Index:              index,
		Error:              parseErr.Error(),
		LeafInput:          entry.LeafInput,
		ExtraData:          entry.ExtraData,
		IssuerFingerprints: append([]string(nil), entry.IssuerFingerprints...),
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encoding malformed event: %w", err)
	}
	if _, err := w.buffered.Write(data); err != nil {
		w.recordErr(err)
		return w.writeErr
	}
	w.recordErr(w.buffered.WriteByte('\n'))
	return w.writeErr
}

// Flush is a durability boundary. A caller must not advance its CT checkpoint
// until this returns nil for every malformed observation in the batch.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	w.recordErr(w.buffered.Flush())
	if w.writeErr == nil {
		w.recordErr(w.file.Sync())
	}
	return w.writeErr
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buffered != nil {
		w.recordErr(w.buffered.Flush())
	}
	if w.writeErr == nil && w.file != nil {
		w.recordErr(w.file.Sync())
	}
	if w.file != nil {
		w.recordErr(w.file.Close())
	}
	return w.writeErr
}
