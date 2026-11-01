package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const maxSpoolPending = 100000

type FileSpoolSink struct {
	mu         sync.Mutex
	target     Sink
	directory  string
	maxPending int
}

func NewFileSpoolSink(target Sink, directory string, maxPending int) (*FileSpoolSink, error) {
	if target == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || maxPending < 1 || maxPending > maxSpoolPending {
		return nil, fmt.Errorf("valid audit spool target, absolute directory, and pending bound are required")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect audit spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("audit spool directory must be a private non-symlink directory")
	}
	return &FileSpoolSink{target: target, directory: directory, maxPending: maxPending}, nil
}

func (sink *FileSpoolSink) Record(ctx context.Context, event Event) error {
	if sink == nil || sink.target == nil {
		return fmt.Errorf("audit spool sink is not initialized")
	}
	if err := ValidateEvent(event); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	path, err := sink.persist(event)
	if err != nil {
		return err
	}
	if err := sink.target.Record(ctx, cloneEvent(event)); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("acknowledge durable audit event: %w", err)
	}
	return nil
}

func (sink *FileSpoolSink) Replay(ctx context.Context) error {
	if sink == nil || sink.target == nil {
		return fmt.Errorf("audit spool sink is not initialized")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	entries, err := sink.pendingEntries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		path := filepath.Join(sink.directory, entry.Name())
		event, err := readSpooledEvent(path, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		if err := sink.target.Record(ctx, event); err != nil {
			return fmt.Errorf("replay durable audit event: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("acknowledge replayed audit event: %w", err)
		}
	}
	return nil
}

func (sink *FileSpoolSink) persist(event Event) (string, error) {
	path := filepath.Join(sink.directory, event.EventID+".json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("audit spool entry is not a regular file")
		}
		if _, err := readSpooledEvent(path, event.EventID); err != nil {
			return "", err
		}
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect audit spool entry: %w", err)
	}
	entries, err := sink.pendingEntries()
	if err != nil {
		return "", err
	}
	if len(entries) >= sink.maxPending {
		return "", fmt.Errorf("audit spool pending limit reached")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("encode audit spool event: %w", err)
	}
	temporary, err := os.CreateTemp(sink.directory, ".audit-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create audit spool entry: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure audit spool entry: %w", err)
	}
	if _, err := temporary.Write(append(payload, '\n')); err != nil {
		return "", fmt.Errorf("write audit spool entry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync audit spool entry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close audit spool entry: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("publish audit spool entry: %w", err)
	}
	removeTemporary = false
	return path, nil
}

func (sink *FileSpoolSink) pendingEntries() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(sink.directory)
	if err != nil {
		return nil, fmt.Errorf("read audit spool directory: %w", err)
	}
	pending := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".audit-") && strings.HasSuffix(entry.Name(), ".tmp") {
			if err := os.Remove(filepath.Join(sink.directory, entry.Name())); err != nil {
				return nil, fmt.Errorf("remove incomplete audit spool entry: %w", err)
			}
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !eventIDPattern.MatchString(strings.TrimSuffix(entry.Name(), ".json")) {
			return nil, fmt.Errorf("audit spool contains an unexpected entry")
		}
		pending = append(pending, entry)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Name() < pending[j].Name() })
	return pending, nil
}

func readSpooledEvent(path, expectedID string) (Event, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Event{}, fmt.Errorf("audit spool entry is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Event{}, fmt.Errorf("open audit spool entry: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxEventBytes+2))
	if err != nil || len(payload) > maxEventBytes+1 {
		return Event{}, fmt.Errorf("read bounded audit spool entry")
	}
	var event Event
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil || event.EventID != expectedID || ValidateEvent(event) != nil {
		return Event{}, fmt.Errorf("audit spool entry contract is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Event{}, fmt.Errorf("audit spool entry contains trailing data")
	}
	return event, nil
}
