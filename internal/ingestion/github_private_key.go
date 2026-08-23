package ingestion

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

const MaximumGitHubAppPrivateKeyBytes int64 = 64 << 10

func LoadGitHubAppPrivateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("GitHub App private key path is required")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect GitHub App private key file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("GitHub App private key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && linkInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("GitHub App private key permissions must not grant group or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open GitHub App private key file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened GitHub App private key file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return nil, fmt.Errorf("GitHub App private key file changed while opening")
	}
	if openedInfo.Size() > MaximumGitHubAppPrivateKeyBytes {
		return nil, fmt.Errorf("GitHub App private key file exceeds %d bytes", MaximumGitHubAppPrivateKeyBytes)
	}
	content, err := io.ReadAll(io.LimitReader(file, MaximumGitHubAppPrivateKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub App private key file: %w", err)
	}
	if int64(len(content)) > MaximumGitHubAppPrivateKeyBytes {
		return nil, fmt.Errorf("GitHub App private key file exceeds %d bytes", MaximumGitHubAppPrivateKeyBytes)
	}
	return content, nil
}
