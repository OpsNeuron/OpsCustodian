package boundary

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/model"
)

type Definition struct{ Path, Name string }

func Parse(values []string) ([]Definition, error) {
	seen := map[string]struct{}{}
	result := make([]Definition, 0, len(values))
	for _, raw := range values {
		parts := strings.SplitN(raw, "=", 2)
		boundaryPath := strings.Trim(strings.ReplaceAll(parts[0], "\\", "/"), "/ ")
		if boundaryPath == "" || boundaryPath == "." || path.IsAbs(boundaryPath) || strings.Contains(strings.SplitN(boundaryPath, "/", 2)[0], ":") || boundaryPath == ".." || strings.HasPrefix(boundaryPath, "../") {
			return nil, fmt.Errorf("invalid boundary path %q", parts[0])
		}
		clean := path.Clean(boundaryPath)
		if clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("boundary path escapes repository: %q", parts[0])
		}
		name := path.Base(clean)
		if len(parts) == 2 {
			name = strings.TrimSpace(parts[1])
		}
		if name == "" {
			return nil, fmt.Errorf("boundary %q has an empty component name", raw)
		}
		if _, exists := seen[strings.ToLower(clean)]; exists {
			return nil, fmt.Errorf("duplicate boundary path %q", clean)
		}
		seen[strings.ToLower(clean)] = struct{}{}
		result = append(result, Definition{Path: clean, Name: name})
	}
	sort.Slice(result, func(i, j int) bool {
		if len(result[i].Path) != len(result[j].Path) {
			return len(result[i].Path) > len(result[j].Path)
		}
		return result[i].Path < result[j].Path
	})
	return result, nil
}

func Apply(bom *model.AgentBOM, definitions []Definition) {
	for index := range bom.Assets {
		assetPath := strings.Trim(strings.ReplaceAll(bom.Assets[index].Source.Path, "\\", "/"), "/")
		for _, definition := range definitions {
			if assetPath == definition.Path || strings.HasPrefix(assetPath, definition.Path+"/") {
				bom.Assets[index].Component = definition.Name
				break
			}
		}
	}
}
