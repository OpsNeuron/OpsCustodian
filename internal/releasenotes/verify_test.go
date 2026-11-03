package releasenotes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyAcceptsReviewedBetaNotes(t *testing.T) {
	root := t.TempDir()
	writeReleaseNotesFixture(t, root, "v0.6.0-beta.1", reviewedBetaNotes("v0.6.0-beta.1"))
	if err := Verify(root, "v0.6.0-beta.1"); err != nil {
		t.Fatal(err)
	}
}

func TestFirstBetaCandidateNotesPassReviewedContract(t *testing.T) {
	if err := Verify(filepath.Join("..", ".."), "v0.6.0-beta.1"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsMissingBoundaryAndPlaceholder(t *testing.T) {
	tests := []struct {
		name, content, contains string
	}{
		{"missing non HA boundary", strings.Replace(reviewedBetaNotes("v0.6.0-beta.1"), "single-replica", "one process", 1), "single-replica"},
		{"placeholder", reviewedBetaNotes("v0.6.0-beta.1") + "\nTODO\n", "placeholder"},
		{"wrong heading", strings.Replace(reviewedBetaNotes("v0.6.0-beta.1"), "# OpsCustodian v0.6.0-beta.1", "# OpsCustodian latest", 1), "heading"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeReleaseNotesFixture(t, root, "v0.6.0-beta.1", test.content)
			err := Verify(root, "v0.6.0-beta.1")
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("release notes result = %v", err)
			}
		})
	}
}

func reviewedBetaNotes(tag string) string {
	return "# OpsCustodian " + tag + `

## Supported beta contract

The supported single-replica contract and features that are not supported are
in BETA_SUPPORT_MATRIX.md and THREAT_MODEL.md.

## Upgrade and rollback

Use the consecutive upgrade in UPGRADES.md and restore through
BACKUP_RESTORE.md.

## Known limitations

High availability is not supported.

## Installation and verification

Verify checksums and provenance.
`
}

func writeReleaseNotesFixture(t *testing.T, root, tag, content string) {
	t.Helper()
	directory := filepath.Join(root, "docs", "releases")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, tag+".md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
