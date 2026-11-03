package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/opscustodian/opscustodian/internal/releasenotes"
)

func main() {
	root := flag.String("root", ".", "repository root")
	tag := flag.String("tag", "", "release tag")
	flag.Parse()
	if flag.NArg() != 0 || *tag == "" {
		fmt.Fprintln(os.Stderr, "usage: opscustodian-release-notescheck --root <repository> --tag <tag>")
		os.Exit(2)
	}
	if err := releasenotes.Verify(*root, *tag); err != nil {
		fmt.Fprintln(os.Stderr, "release notes verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("release notes verified")
}
