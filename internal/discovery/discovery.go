package discovery

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Artifact struct {
	Path    string
	RelPath string
	Content []byte
}

type Options struct {
	MaxFileSize int64
}

var ignoredDirectories = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, "node_modules": {}, "vendor": {},
	"dist": {}, "build": {}, ".opscustodian-cache": {},
}

func Discover(ctx context.Context, root string, opts Options) ([]Artifact, error) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 2 << 20
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect scan root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan root is not a directory: %s", root)
	}

	var artifacts []Artifact
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if entry.IsDir() {
			if path != absRoot {
				if _, ignored := ignoredDirectories[entry.Name()]; ignored {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !isCandidate(path, absRoot) {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if fileInfo.Size() > opts.MaxFileSize {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return fmt.Errorf("make relative path for %s: %w", path, err)
		}
		artifacts = append(artifacts, Artifact{
			Path: path, RelPath: filepath.ToSlash(rel), Content: content,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover artifacts: %w", err)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].RelPath < artifacts[j].RelPath })
	return artifacts, nil
}

func isCandidate(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	lowerRel := strings.ToLower(rel)
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	if strings.HasPrefix(lowerRel, ".github/workflows/") && (ext == ".yml" || ext == ".yaml") {
		return true
	}
	if strings.HasPrefix(lowerRel, ".github/workflows/") && ext == ".md" {
		return true
	}
	if base == "mcp.json" || base == ".mcp.json" || base == "mcp.yaml" || base == "mcp.yml" {
		return true
	}
	if rel == ".github/CODEOWNERS" || rel == "CODEOWNERS" || rel == "docs/CODEOWNERS" {
		return true
	}
	if base == "catalog-info.yaml" || base == "catalog-info.yml" {
		return true
	}
	if ext == ".yaml" || ext == ".yml" {
		segments := strings.Split(lowerRel, "/")
		for _, segment := range segments[:len(segments)-1] {
			switch segment {
			case "k8s", "kubernetes", "manifests", "deploy", "deployments":
				return true
			}
		}
	}
	if base == "agents.md" || base == "claude.md" {
		return true
	}
	if strings.HasPrefix(lowerRel, ".github/agents/") && (ext == ".md" || ext == ".mdc") {
		return true
	}
	if strings.HasPrefix(lowerRel, ".cursor/rules/") && (ext == ".md" || ext == ".mdc") {
		return true
	}
	if (strings.Contains(lowerRel, "/skills/") || strings.HasPrefix(lowerRel, "skills/")) && base == "skill.md" {
		return strings.Contains(lowerRel, ".claude/") || strings.Contains(lowerRel, ".codex/") || strings.Contains(lowerRel, ".agents/")
	}
	return false
}
