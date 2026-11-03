package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/opscustodian/opscustodian/internal/repositoryhygiene"
)

func main() {
	root := flag.String("root", ".", "Git repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: opscustodian-repocheck --root <repository>")
		os.Exit(2)
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "repository hygiene failed: invalid root")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "-C", absolute, "ls-files", "-z")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = ioDiscard{}
	if err := command.Run(); err != nil || ctx.Err() != nil || output.Len() > 16<<20 {
		fmt.Fprintln(os.Stderr, "repository hygiene failed: tracked-file manifest unavailable")
		os.Exit(1)
	}
	manifest := strings.Split(strings.TrimSuffix(output.String(), "\x00"), "\x00")
	if err := repositoryhygiene.VerifyTrackedFiles(absolute, manifest); err != nil {
		fmt.Fprintln(os.Stderr, "repository hygiene failed:", err)
		os.Exit(1)
	}
	fmt.Printf("repository hygiene verified: %d tracked files\n", len(manifest))
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }
