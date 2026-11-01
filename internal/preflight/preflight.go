package preflight

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/opscustodian/opscustodian/internal/controlplane"
	"github.com/opscustodian/opscustodian/internal/ingestion"
)

const (
	APIVersion = "opscustodian.dev/preflight/v1alpha1"
	Kind       = "PreflightReport"

	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

type Check struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
}

type Report struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Profile    string  `json:"profile"`
	Ready      bool    `json:"ready"`
	Checks     []Check `json:"checks"`
}

type Options struct {
	Profile    string
	Root       string
	OPAPath    string
	PolicyPath string
	LookupEnv  controlplane.LookupEnv
	LookPath   func(string) (string, error)
	Stat       func(string) (os.FileInfo, error)
}

func Evaluate(options Options) Report {
	report := Report{APIVersion: APIVersion, Kind: Kind, Profile: options.Profile, Ready: true}
	if options.LookupEnv == nil {
		options.LookupEnv = os.LookupEnv
	}
	if options.LookPath == nil {
		options.LookPath = exec.LookPath
	}
	if options.Stat == nil {
		options.Stat = os.Stat
	}
	if options.Root == "" {
		options.Root = "."
	}
	switch options.Profile {
	case "server":
		report.Checks = append(report.Checks, serverChecks(options)...)
	case "policy":
		report.Checks = append(report.Checks, policyChecks(options)...)
	case "release":
		report.Checks = append(report.Checks, serverChecks(options)...)
		report.Checks = append(report.Checks, policyChecks(options)...)
		report.Checks = append(report.Checks, fileCheck("license", filepath.Join(options.Root, "LICENSE"), true, options.Stat))
	case "beta":
		report.Checks = append(report.Checks, serverChecks(options)...)
		report.Checks = append(report.Checks, policyChecks(options)...)
		report.Checks = append(report.Checks,
			fileCheck("license", filepath.Join(options.Root, "LICENSE"), true, options.Stat),
			fileCheck("beta-checklist", filepath.Join(options.Root, "docs", "BETA_RELEASE_CHECKLIST.md"), true, options.Stat),
			fileCheck("integration-runbook", filepath.Join(options.Root, "docs", "INTEGRATION_TESTING.md"), true, options.Stat),
			fileCheck("release-runbook", filepath.Join(options.Root, "docs", "RELEASE.md"), true, options.Stat),
			fileCheck("extended-fuzz-workflow", filepath.Join(options.Root, ".github", "workflows", "fuzz-extended.yml"), true, options.Stat),
			fileCheck("codeql-workflow", filepath.Join(options.Root, ".github", "workflows", "codeql.yml"), true, options.Stat),
		)
	default:
		report.Profile = options.Profile
		report.Checks = []Check{{ID: "profile", Status: StatusFailed, Required: true}}
	}
	for _, check := range report.Checks {
		if check.Required && check.Status != StatusPassed {
			report.Ready = false
		}
	}
	return report
}

func serverChecks(options Options) []Check {
	checks := []Check{}
	config, err := controlplane.ConfigFromEnvironment(options.LookupEnv)
	if err != nil {
		return []Check{
			{ID: "server-config", Status: StatusFailed, Required: true},
			{ID: "repository-set", Status: StatusSkipped},
			{ID: "github-app-key", Status: StatusSkipped},
		}
	}
	checks = append(checks, Check{ID: "server-config", Status: StatusPassed, Required: true})
	githubAppRequired := false
	if config.RepositorySetFile == "" {
		checks = append(checks, Check{ID: "repository-set", Status: StatusSkipped})
	} else {
		repositorySet, err := ingestion.LoadRepositorySet(config.RepositorySetFile)
		if err != nil {
			checks = append(checks, Check{ID: "repository-set", Status: StatusFailed, Required: true})
		} else {
			checks = append(checks, Check{ID: "repository-set", Status: StatusPassed, Required: true})
			for _, repository := range repositorySet.Repositories {
				if _, err := ingestion.ParseGitHubAppCredentialReference(repository.CredentialReference); err == nil {
					githubAppRequired = true
					break
				}
			}
		}
	}
	if config.GitHubAppID == 0 {
		status := StatusSkipped
		if githubAppRequired {
			status = StatusFailed
		}
		checks = append(checks, Check{ID: "github-app-key", Status: status, Required: githubAppRequired})
		return checks
	}
	content, err := ingestion.LoadGitHubAppPrivateKey(config.GitHubAppPrivateKeyFile)
	if err == nil {
		_, err = ingestion.NewGitHubAppProvider(ingestion.GitHubAppProviderOptions{AppID: config.GitHubAppID, PrivateKeyPEM: content})
	}
	clear(content)
	status := StatusPassed
	if err != nil {
		status = StatusFailed
	}
	checks = append(checks, Check{ID: "github-app-key", Status: status, Required: true})
	return checks
}

func policyChecks(options Options) []Check {
	opaStatus := StatusPassed
	if _, err := options.LookPath(options.OPAPath); err != nil {
		opaStatus = StatusFailed
	}
	return []Check{
		{ID: "opa-binary", Status: opaStatus, Required: true},
		fileCheck("policy-bundle", options.PolicyPath, true, options.Stat),
	}
}

func fileCheck(id, path string, required bool, stat func(string) (os.FileInfo, error)) Check {
	status := StatusPassed
	info, err := stat(path)
	if err != nil || info == nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		status = StatusFailed
	}
	return Check{ID: id, Status: status, Required: required}
}

func Write(writer io.Writer, report Report, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "terminal":
		fmt.Fprintf(writer, "OpsCustodian preflight (%s): ready=%t\n", report.Profile, report.Ready)
		for _, check := range report.Checks {
			fmt.Fprintf(writer, "%-18s %s\n", check.ID, check.Status)
		}
		return nil
	default:
		return fmt.Errorf("unsupported preflight format %q; expected terminal or json", format)
	}
}
