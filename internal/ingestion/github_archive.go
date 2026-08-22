package ingestion

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultMaximumArchiveBytes   int64 = 100 << 20
	defaultMaximumExtractedBytes int64 = 500 << 20
	defaultMaximumArchiveEntries       = 100000
)

type GitHubArchiveLimits struct {
	MaximumArchiveBytes   int64
	MaximumExtractedBytes int64
	MaximumEntries        int
}

type GitHubArchiveOptions struct {
	TemporaryDirectory string
	Limits             GitHubArchiveLimits
}

type MaterializedCheckout struct {
	Root string

	cleanupOnce sync.Once
	cleanupErr  error
	cleanup     func() error
}

func (checkout *MaterializedCheckout) Close() error {
	if checkout == nil {
		return nil
	}
	checkout.cleanupOnce.Do(func() {
		if checkout.cleanup != nil {
			checkout.cleanupErr = checkout.cleanup()
		}
	})
	return checkout.cleanupErr
}

// MaterializeGitHubZIP copies a bounded archive stream to an isolated temporary
// directory and safely extracts the single top-level directory emitted by
// GitHub. The caller owns the returned checkout and must close it.
func MaterializeGitHubZIP(ctx context.Context, content io.Reader, options GitHubArchiveOptions) (_ *MaterializedCheckout, resultErr error) {
	if ctx == nil || content == nil {
		return nil, fmt.Errorf("GitHub archive context and content are required")
	}
	limits, err := normalizeGitHubArchiveLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	if options.TemporaryDirectory != "" {
		if !filepath.IsAbs(options.TemporaryDirectory) || filepath.Clean(options.TemporaryDirectory) != options.TemporaryDirectory {
			return nil, fmt.Errorf("GitHub archive temporary directory must be a clean absolute path")
		}
		info, err := os.Stat(options.TemporaryDirectory)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("GitHub archive temporary directory is unavailable")
		}
	}
	session, err := os.MkdirTemp(options.TemporaryDirectory, "opscustodian-github-")
	if err != nil {
		return nil, fmt.Errorf("create GitHub archive workspace: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			resultErr = joinMaterializationError(resultErr, os.RemoveAll(session))
		}
	}()

	archivePath := filepath.Join(session, "archive.zip")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create bounded GitHub archive: %w", err)
	}
	written, copyErr := io.Copy(archive, io.LimitReader(contextReader{ctx: ctx, reader: content}, limits.MaximumArchiveBytes+1))
	closeErr := archive.Close()
	if copyErr != nil {
		return nil, fmt.Errorf("copy GitHub archive: %w", copyErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close GitHub archive: %w", closeErr)
	}
	if written > limits.MaximumArchiveBytes {
		return nil, fmt.Errorf("GitHub archive exceeds %d compressed bytes", limits.MaximumArchiveBytes)
	}

	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open GitHub ZIP archive: %w", err)
	}
	defer reader.Close()
	checkoutRoot := filepath.Join(session, "checkout")
	if err := os.Mkdir(checkoutRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create GitHub checkout root: %w", err)
	}
	if err := extractGitHubZIP(ctx, reader.File, checkoutRoot, limits); err != nil {
		return nil, err
	}

	checkout := &MaterializedCheckout{Root: checkoutRoot, cleanup: func() error { return os.RemoveAll(session) }}
	cleanup = false
	return checkout, nil
}

func normalizeGitHubArchiveLimits(limits GitHubArchiveLimits) (GitHubArchiveLimits, error) {
	if limits.MaximumArchiveBytes == 0 {
		limits.MaximumArchiveBytes = defaultMaximumArchiveBytes
	}
	if limits.MaximumExtractedBytes == 0 {
		limits.MaximumExtractedBytes = defaultMaximumExtractedBytes
	}
	if limits.MaximumEntries == 0 {
		limits.MaximumEntries = defaultMaximumArchiveEntries
	}
	if limits.MaximumArchiveBytes < 1 || limits.MaximumArchiveBytes > defaultMaximumArchiveBytes ||
		limits.MaximumExtractedBytes < 1 || limits.MaximumExtractedBytes > defaultMaximumExtractedBytes ||
		limits.MaximumEntries < 1 || limits.MaximumEntries > defaultMaximumArchiveEntries {
		return GitHubArchiveLimits{}, fmt.Errorf("GitHub archive limits must be positive and within supported maxima")
	}
	return limits, nil
}

func extractGitHubZIP(ctx context.Context, entries []*zip.File, root string, limits GitHubArchiveLimits) error {
	if len(entries) == 0 || len(entries) > limits.MaximumEntries+1 {
		return fmt.Errorf("GitHub archive has invalid or excessive entry count")
	}
	prefix := ""
	seen := make(map[string]struct{}, len(entries))
	var extracted int64
	entryCount := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, top, relative, err := safeGitHubArchivePath(entry.Name)
		if err != nil {
			return err
		}
		if prefix == "" {
			prefix = top
		} else if top != prefix {
			return fmt.Errorf("GitHub archive contains multiple top-level roots")
		}
		if relative == "" {
			if !entry.FileInfo().IsDir() {
				return fmt.Errorf("GitHub archive root entry must be a directory")
			}
			continue
		}
		entryCount++
		if entryCount > limits.MaximumEntries {
			return fmt.Errorf("GitHub archive exceeds %d entries", limits.MaximumEntries)
		}
		key := strings.ToLower(relative)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("GitHub archive contains duplicate path %q", name)
		}
		seen[key] = struct{}{}
		destination := filepath.Join(root, filepath.FromSlash(relative))
		inside, err := filepath.Rel(root, destination)
		if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			return fmt.Errorf("GitHub archive path escapes checkout root")
		}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || (!entry.FileInfo().IsDir() && !mode.IsRegular()) {
			return fmt.Errorf("GitHub archive entry %q has unsupported file type", name)
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return fmt.Errorf("create GitHub archive directory: %w", err)
			}
			continue
		}
		if entry.UncompressedSize64 > uint64(limits.MaximumExtractedBytes-extracted) {
			return fmt.Errorf("GitHub archive exceeds %d extracted bytes", limits.MaximumExtractedBytes)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fmt.Errorf("create GitHub archive parent: %w", err)
		}
		if err := extractGitHubZIPFile(ctx, entry, destination, limits.MaximumExtractedBytes-extracted, &extracted); err != nil {
			return err
		}
	}
	if prefix == "" || entryCount == 0 {
		return fmt.Errorf("GitHub archive contains no checkout files")
	}
	return nil
}

func safeGitHubArchivePath(name string) (cleaned, top, relative string, err error) {
	if name == "" || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") {
		return "", "", "", fmt.Errorf("GitHub archive contains unsafe path")
	}
	cleaned = path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != strings.TrimSuffix(name, "/") {
		return "", "", "", fmt.Errorf("GitHub archive contains unsafe path")
	}
	parts := strings.Split(cleaned, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", "", "", fmt.Errorf("GitHub archive contains unsafe path")
	}
	for _, segment := range parts {
		if !safePortableArchiveSegment(segment) {
			return "", "", "", fmt.Errorf("GitHub archive contains non-portable path")
		}
	}
	top = parts[0]
	if len(parts) > 1 {
		relative = strings.Join(parts[1:], "/")
	}
	return cleaned, top, relative, nil
}

func safePortableArchiveSegment(segment string) bool {
	if segment == "" || strings.Contains(segment, ":") || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
		return false
	}
	upper := strings.ToUpper(strings.TrimSuffix(segment, filepath.Ext(segment)))
	if upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" {
		return false
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' {
		return false
	}
	for _, character := range segment {
		if character < 32 || character == 127 {
			return false
		}
	}
	return true
}

func extractGitHubZIPFile(ctx context.Context, entry *zip.File, destination string, remaining int64, extracted *int64) error {
	input, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open GitHub archive entry: %w", err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create GitHub checkout file: %w", err)
	}
	written, copyErr := io.Copy(output, io.LimitReader(contextReader{ctx: ctx, reader: input}, remaining+1))
	closeErr := output.Close()
	if copyErr != nil {
		return fmt.Errorf("extract GitHub checkout file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close GitHub checkout file: %w", closeErr)
	}
	if written > remaining {
		return fmt.Errorf("GitHub archive exceeds extracted byte limit")
	}
	*extracted += written
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func joinMaterializationError(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	if primary == nil {
		return cleanup
	}
	return fmt.Errorf("%v; cleanup GitHub archive workspace: %w", primary, cleanup)
}
