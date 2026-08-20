package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

const MaximumCredentialFileBytes int64 = 1 << 20

func ParseBearerCredentialsJSON(content []byte) ([]BearerCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var credentials []BearerCredential
	if err := decoder.Decode(&credentials); err != nil {
		return nil, fmt.Errorf("parse credential JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("credential source must contain exactly one JSON value")
	}
	return credentials, nil
}

// ReloadCredentialFile validates the source before atomically publishing it.
// Invalid reads leave the registry's last-known-good snapshot unchanged.
func ReloadCredentialFile(registry *CredentialRegistry, path string) error {
	if registry == nil {
		return fmt.Errorf("configured credential registry is required")
	}
	if path == "" {
		return fmt.Errorf("credential file path is required")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect credential file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return fmt.Errorf("credential source must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && linkInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credential file permissions must not grant group or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened credential file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return fmt.Errorf("credential file changed while opening")
	}
	if openedInfo.Size() > MaximumCredentialFileBytes {
		return fmt.Errorf("credential file exceeds %d bytes", MaximumCredentialFileBytes)
	}
	content, err := io.ReadAll(io.LimitReader(file, MaximumCredentialFileBytes+1))
	if err != nil {
		return fmt.Errorf("read credential file: %w", err)
	}
	if int64(len(content)) > MaximumCredentialFileBytes {
		return fmt.Errorf("credential file exceeds %d bytes", MaximumCredentialFileBytes)
	}
	credentials, err := ParseBearerCredentialsJSON(content)
	if err != nil {
		return err
	}
	if err := registry.Reload(credentials); err != nil {
		return fmt.Errorf("validate credential file: %w", err)
	}
	return nil
}
