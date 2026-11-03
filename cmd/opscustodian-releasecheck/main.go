package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/opscustodian/opscustodian/internal/releaseartifact"
)

func main() {
	directory := flag.String("dist", "dist", "directory containing release assets")
	tag := flag.String("tag", "", "release tag such as v0.6.0-beta.1")
	flag.Parse()
	if flag.NArg() != 0 || *tag == "" {
		fmt.Fprintln(os.Stderr, "usage: opscustodian-releasecheck --dist <directory> --tag <tag>")
		os.Exit(2)
	}
	if err := releaseartifact.VerifyDirectory(*directory, *tag); err != nil {
		fmt.Fprintln(os.Stderr, "release verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("release assets verified")
}
