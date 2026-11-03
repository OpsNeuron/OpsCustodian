package releasenotes

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maximumReleaseNotesBytes = 1 << 20

var releaseTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?$`)

// Verify checks the reviewed release-note contract for one exact tag.
func Verify(root, tag string) error {
	if !releaseTagPattern.MatchString(tag) {
		return fmt.Errorf("release tag is invalid")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	filename := filepath.Join(absolute, "docs", "releases", tag+".md")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumReleaseNotesBytes {
		return fmt.Errorf("reviewed release notes for %s are missing or invalid", tag)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read release notes: %w", err)
	}
	text := string(content)
	if !strings.HasPrefix(text, "# OpsCustodian "+tag+"\n") && !strings.HasPrefix(text, "# OpsCustodian "+tag+"\r\n") {
		return fmt.Errorf("release notes heading does not match %s", tag)
	}

	required := []string{"## Installation and verification"}
	if strings.Contains(strings.ToLower(tag), "beta") {
		required = append(required,
			"## Supported beta contract",
			"## Upgrade and rollback",
			"## Known limitations",
			"BETA_SUPPORT_MATRIX.md",
			"THREAT_MODEL.md",
			"UPGRADES.md",
			"BACKUP_RESTORE.md",
			"single-replica",
			"consecutive",
			"not supported",
		)
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			return fmt.Errorf("release notes for %s are missing required boundary %q", tag, value)
		}
	}
	for _, placeholder := range []string{"<tag>", "<previous-release>", "TODO", "TBD"} {
		if strings.Contains(text, placeholder) {
			return fmt.Errorf("release notes for %s contain unresolved placeholder %q", tag, placeholder)
		}
	}
	return nil
}
