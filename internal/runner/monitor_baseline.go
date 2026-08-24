package runner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	monitorBaselineSchema   = "1.0"
	maxMonitorBaselineFiles = 4096
	maxMonitorBaselineBytes = 16 << 20
)

type monitorBaselineFile struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
}

type monitorBaseline struct {
	SchemaVersion string                `json:"schema_version"`
	Kind          string                `json:"kind"`
	CreatedAt     time.Time             `json:"created_at"`
	StateDir      string                `json:"state_dir"`
	SelectionHash string                `json:"selection_hash"`
	Files         []monitorBaselineFile `json:"files"`
}

func privateFreshJSON(path string, value any) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	if filepath.Clean(resolvedParent) != parent {
		return fmt.Errorf("monitor-baseline parent contains a symlink: %s", parent)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return fmt.Errorf("monitor-baseline destination already exists: %s", absolute)
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".monitor-baseline-*")
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
	if err := os.Rename(tmpPath, absolute); err != nil {
		return err
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return err
	}
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func writeMonitorBaseline(path, stateDir, selectionHash string, initializedPaths []string) error {
	if path == "" {
		return nil
	}
	if len(selectionHash) != sha256.Size*2 {
		return fmt.Errorf("monitor-baseline selection hash has invalid length")
	}
	if _, err := hex.DecodeString(selectionHash); err != nil {
		return fmt.Errorf("monitor-baseline selection hash is not hexadecimal: %w", err)
	}
	stateRoot, err := filepath.Abs(stateDir)
	if err != nil {
		return err
	}
	stateRoot = filepath.Clean(stateRoot)

	paths := append([]string(nil), initializedPaths...)
	sort.Strings(paths)
	if len(paths) > maxMonitorBaselineFiles {
		return fmt.Errorf("monitor-baseline contains %d files, limit is %d", len(paths), maxMonitorBaselineFiles)
	}
	files := make([]monitorBaselineFile, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	total := int64(0)
	for _, raw := range paths {
		absolute, err := filepath.Abs(raw)
		if err != nil {
			return err
		}
		absolute = filepath.Clean(absolute)
		relative, err := filepath.Rel(stateRoot, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("monitor-baseline state file escapes state directory: %s", raw)
		}
		if filepath.Base(relative) != relative || !strings.HasPrefix(relative, "monitor-") || !strings.HasSuffix(relative, ".json") {
			return fmt.Errorf("unexpected monitor-baseline state filename: %s", relative)
		}
		if _, exists := seen[relative]; exists {
			return fmt.Errorf("duplicate monitor-baseline state filename: %s", relative)
		}
		seen[relative] = struct{}{}
		info, err := os.Lstat(absolute)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("monitor-baseline state path is not a regular file: %s", absolute)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("monitor-baseline state file is not private: %s", absolute)
		}
		if info.Size() < 0 || total+info.Size() > maxMonitorBaselineBytes {
			return fmt.Errorf("monitor-baseline state exceeds %d bytes", maxMonitorBaselineBytes)
		}
		data, err := os.ReadFile(absolute)
		if err != nil {
			return err
		}
		if int64(len(data)) != info.Size() {
			return fmt.Errorf("monitor-baseline state changed while reading: %s", absolute)
		}
		total += int64(len(data))
		sum := sha256.Sum256(data)
		files = append(files, monitorBaselineFile{
			Path:       filepath.ToSlash(relative),
			Size:       int64(len(data)),
			SHA256:     hex.EncodeToString(sum[:]),
			DataBase64: base64.StdEncoding.EncodeToString(data),
		})
	}

	return privateFreshJSON(path, monitorBaseline{
		SchemaVersion: monitorBaselineSchema,
		Kind:          "ct-hulhu-monitor-startup-baseline",
		CreatedAt:     time.Now().UTC(),
		StateDir:      stateRoot,
		SelectionHash: selectionHash,
		Files:         files,
	})
}
