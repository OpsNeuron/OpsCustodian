package releaseartifact

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maximumMetadataBytes = 16 << 20
	maximumBinaryBytes   = 200 << 20
)

var (
	releaseTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?$`)
	sensitivePatterns = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"private key", regexp.MustCompile("-----BEGIN " + `[A-Z0-9 ]*PRIVATE KEY-----`)},
		{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
		{"AWS signed URL", regexp.MustCompile(`(?i)[?&]X-Amz-Signature=[0-9a-f]{32,}`)},
		{"Google signed URL", regexp.MustCompile(`(?i)[?&]X-Goog-Signature=[0-9a-f]{32,}`)},
		{"Windows user path", regexp.MustCompile(`(?i)[A-Z]:\\Users\\[^\\\s]+\\`)},
		{"Unix home path", regexp.MustCompile(`(?:/home|/Users)/[^/\s]+/`)},
	}
)

// VerifyDirectory validates the complete release-asset set before publication.
func VerifyDirectory(directory, tag string) error {
	if !releaseTagPattern.MatchString(tag) {
		return fmt.Errorf("release tag is invalid")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("release directory is unavailable")
	}

	assets := expectedAssets(strings.TrimPrefix(tag, "v"))
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	if len(entries) != len(assets)+1 {
		return fmt.Errorf("release directory contains %d entries; expected %d", len(entries), len(assets)+1)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("release directory contains unexpected directory %q", entry.Name())
		}
		if entry.Name() != "SHA256SUMS" {
			if _, ok := assets[entry.Name()]; !ok {
				return fmt.Errorf("release directory contains unexpected asset %q", entry.Name())
			}
		}
	}

	checksums, err := readChecksums(filepath.Join(absolute, "SHA256SUMS"))
	if err != nil {
		return err
	}
	if len(checksums) != len(assets) {
		return fmt.Errorf("checksum manifest contains %d entries; expected %d", len(checksums), len(assets))
	}
	for name, kind := range assets {
		expected, ok := checksums[name]
		if !ok {
			return fmt.Errorf("checksum manifest is missing %q", name)
		}
		assetPath := filepath.Join(absolute, name)
		actual, err := fileSHA256(assetPath)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
		switch kind {
		case "archive":
			if err := verifyArchive(assetPath, name); err != nil {
				return err
			}
		case "sbom":
			if err := verifySBOM(assetPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func expectedAssets(version string) map[string]string {
	assets := map[string]string{"opscustodian.cdx.json": "sbom"}
	for _, target := range []struct{ os, arch, extension string }{
		{"linux", "amd64", ".tar.gz"},
		{"linux", "arm64", ".tar.gz"},
		{"darwin", "amd64", ".tar.gz"},
		{"darwin", "arm64", ".tar.gz"},
		{"windows", "amd64", ".zip"},
	} {
		name := fmt.Sprintf("opscustodian_%s_%s_%s%s", version, target.os, target.arch, target.extension)
		assets[name] = "archive"
	}
	return assets
}

func readChecksums(filename string) (map[string]string, error) {
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumMetadataBytes {
		return nil, fmt.Errorf("checksum manifest is unavailable, empty, or oversized")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open checksum manifest: %w", err)
	}
	defer file.Close()
	checksums := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(file, maximumMetadataBytes+1))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, fmt.Errorf("checksum manifest contains an invalid line")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if path.Base(name) != name || name == "SHA256SUMS" {
			return nil, fmt.Errorf("checksum manifest contains an unsafe asset name")
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("checksum manifest contains an invalid digest")
		}
		if _, exists := checksums[name]; exists {
			return nil, fmt.Errorf("checksum manifest contains duplicate asset %q", name)
		}
		checksums[name] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksum manifest: %w", err)
	}
	return checksums, nil
}

func fileSHA256(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("open release asset: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash release asset: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func verifyArchive(filename, assetName string) error {
	root := strings.TrimSuffix(strings.TrimSuffix(assetName, ".zip"), ".tar.gz")
	required := map[string]bool{
		root + "/README.md":   false,
		root + "/SECURITY.md": false,
		root + "/LICENSE":     false,
	}
	binary := root + "/opscustodian"
	if strings.Contains(assetName, "_windows_") {
		binary += ".exe"
	}
	required[binary] = false

	visit := func(name string, mode os.FileMode, size int64, reader io.Reader) error {
		trimmed := strings.TrimSuffix(name, "/")
		clean := path.Clean(trimmed)
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || clean != trimmed || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("archive %q contains an unsafe path", assetName)
		}
		if mode.IsDir() {
			if clean != root {
				return fmt.Errorf("archive %q contains unexpected directory %q", assetName, name)
			}
			return nil
		}
		if !mode.IsRegular() {
			return fmt.Errorf("archive %q contains unsupported file type %q", assetName, name)
		}
		if strings.HasSuffix(name, "/") {
			return fmt.Errorf("archive %q contains a file with a directory path %q", assetName, name)
		}
		found, ok := required[clean]
		if !ok {
			return fmt.Errorf("archive %q contains unexpected file %q", assetName, name)
		}
		if found {
			return fmt.Errorf("archive %q contains duplicate file %q", assetName, name)
		}
		required[clean] = true
		if clean == binary {
			if size < 1 || size > maximumBinaryBytes {
				return fmt.Errorf("archive %q contains invalid binary size", assetName)
			}
			return nil
		}
		content, err := io.ReadAll(io.LimitReader(reader, maximumMetadataBytes+1))
		if err != nil || len(content) > maximumMetadataBytes {
			return fmt.Errorf("archive %q contains unreadable or oversized metadata", assetName)
		}
		return rejectSensitiveContent(assetName+":"+clean, content)
	}

	if strings.HasSuffix(assetName, ".zip") {
		reader, err := zip.OpenReader(filename)
		if err != nil {
			return fmt.Errorf("open release ZIP %q: %w", assetName, err)
		}
		defer reader.Close()
		for _, entry := range reader.File {
			input, err := entry.Open()
			if err != nil {
				return fmt.Errorf("open archive entry: %w", err)
			}
			err = visit(entry.Name, entry.Mode(), int64(entry.UncompressedSize64), input)
			input.Close()
			if err != nil {
				return err
			}
		}
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("open release archive: %w", err)
		}
		defer file.Close()
		compressed, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open release gzip %q: %w", assetName, err)
		}
		defer compressed.Close()
		archive := tar.NewReader(compressed)
		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("read release tar %q: %w", assetName, err)
			}
			if err := visit(header.Name, header.FileInfo().Mode(), header.Size, archive); err != nil {
				return err
			}
		}
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("archive %q is missing %q", assetName, name)
		}
	}
	return nil
}

func verifySBOM(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil || len(content) == 0 || len(content) > maximumMetadataBytes {
		return fmt.Errorf("SBOM is unreadable, empty, or oversized")
	}
	if err := rejectSensitiveContent("SBOM", content); err != nil {
		return err
	}
	var document struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("decode CycloneDX SBOM: %w", err)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion == "" || len(document.Components) == 0 {
		return fmt.Errorf("SBOM does not contain a populated CycloneDX contract")
	}
	return nil
}

func rejectSensitiveContent(source string, content []byte) error {
	for _, candidate := range sensitivePatterns {
		if candidate.pattern.Match(content) {
			return fmt.Errorf("%s contains a possible %s", source, candidate.name)
		}
	}
	return nil
}

// ExpectedAssetNames exposes a sorted, secret-free list for tests and tooling.
func ExpectedAssetNames(tag string) ([]string, error) {
	if !releaseTagPattern.MatchString(tag) {
		return nil, fmt.Errorf("release tag is invalid")
	}
	names := make([]string, 0, 6)
	for name := range expectedAssets(strings.TrimPrefix(tag, "v")) {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
