package ownership

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

type rule struct {
	pattern string
	owners  []string
	line    int
	matcher *regexp.Regexp
}

func ApplyCODEOWNERS(bom *model.AgentBOM, artifacts []discovery.Artifact) []model.Diagnostic {
	artifact, exists := selectCODEOWNERS(artifacts)
	if !exists {
		return nil
	}
	rules, diagnostics := parseRules(artifact)
	for assetIndex := range bom.Assets {
		asset := &bom.Assets[assetIndex]
		if len(asset.Owners) > 0 {
			continue
		}
		var matched *rule
		for ruleIndex := range rules {
			if rules[ruleIndex].matcher.MatchString(asset.Source.Path) {
				matched = &rules[ruleIndex]
			}
		}
		if matched == nil {
			continue
		}
		asset.Owners = append([]string(nil), matched.owners...)
		evidenceID := ownershipEvidenceID(artifact.RelPath, matched.line, asset.ID)
		observation := "ownership resolved by CODEOWNERS pattern " + matched.pattern
		if len(matched.owners) == 0 {
			observation = "ownership explicitly cleared by CODEOWNERS pattern " + matched.pattern
		}
		asset.Evidence = append(asset.Evidence, model.Evidence{
			ID: evidenceID, Path: artifact.RelPath, Line: matched.line, Parser: "codeowners",
			Confidence: "high", Observation: observation,
		})
	}
	return diagnostics
}

func selectCODEOWNERS(artifacts []discovery.Artifact) (discovery.Artifact, bool) {
	for _, candidate := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		for _, artifact := range artifacts {
			if artifact.RelPath == candidate {
				return artifact, true
			}
		}
	}
	return discovery.Artifact{}, false
}

func parseRules(artifact discovery.Artifact) ([]rule, []model.Diagnostic) {
	lines := strings.Split(strings.ReplaceAll(string(artifact.Content), "\r\n", "\n"), "\n")
	var rules []rule
	var diagnostics []model.Diagnostic
	for index, rawLine := range lines {
		lineNumber := index + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pattern := fields[0]
		if strings.HasPrefix(pattern, "!") || strings.ContainsAny(pattern, "[]") || strings.HasPrefix(pattern, `\#`) {
			diagnostics = append(diagnostics, codeownersDiagnostic(artifact.RelPath, lineNumber, "unsupported-codeowners-pattern", "unsupported CODEOWNERS syntax: "+pattern))
			continue
		}
		matcher, err := compilePattern(pattern)
		if err != nil {
			diagnostics = append(diagnostics, codeownersDiagnostic(artifact.RelPath, lineNumber, "invalid-codeowners-pattern", err.Error()))
			continue
		}
		var owners []string
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "#") {
				break
			}
			owners = append(owners, field)
		}
		rules = append(rules, rule{pattern: pattern, owners: unique(owners), line: lineNumber, matcher: matcher})
	}
	return rules, diagnostics
}

func compilePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty CODEOWNERS pattern")
	}
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	directory := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return nil, fmt.Errorf("CODEOWNERS pattern resolves to an empty path")
	}
	hasSlash := strings.Contains(pattern, "/")
	prefix := "^"
	if !anchored && (!hasSlash || directory) {
		prefix = `(?:^|.*/)`
	}
	var expression strings.Builder
	expression.WriteString(prefix)
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				expression.WriteString(`.*`)
				index++
			} else {
				expression.WriteString(`[^/]*`)
			}
		case '?':
			expression.WriteString(`[^/]`)
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	lastSegment := pattern
	if slash := strings.LastIndex(pattern, "/"); slash >= 0 {
		lastSegment = pattern[slash+1:]
	}
	if directory || !strings.ContainsAny(lastSegment, "*?") {
		expression.WriteString(`(?:/.*)?`)
	}
	expression.WriteString("$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return nil, fmt.Errorf("compile CODEOWNERS pattern %q: %w", pattern, err)
	}
	return compiled, nil
}

func ownershipEvidenceID(path string, line int, assetID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", path, line, assetID)))
	return fmt.Sprintf("codeowners-%x", sum[:6])
}

func codeownersDiagnostic(path string, line int, code, message string) model.Diagnostic {
	return model.Diagnostic{Severity: "warning", Code: code, Path: path, Parser: "codeowners", Message: fmt.Sprintf("line %d: %s", line, message)}
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, value := range values {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}
