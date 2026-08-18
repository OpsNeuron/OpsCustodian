package githubactions

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

type githubEnvironmentControl struct {
	Job              string `json:"job" yaml:"job"`
	Name             string `json:"name" yaml:"name"`
	URL              string `json:"url,omitempty" yaml:"url,omitempty"`
	ProtectionStatus string `json:"protectionStatus" yaml:"protectionStatus"`
}

type githubTriggerExposure struct {
	Event         string `json:"event" yaml:"event"`
	TrustBoundary string `json:"trustBoundary" yaml:"trustBoundary"`
	Reason        string `json:"reason" yaml:"reason"`
}

type githubUntrustedDataFlow struct {
	Job         string   `json:"job" yaml:"job"`
	Trigger     string   `json:"trigger" yaml:"trigger"`
	Source      string   `json:"source" yaml:"source"`
	Sink        string   `json:"sink" yaml:"sink"`
	Action      string   `json:"action" yaml:"action"`
	Reason      string   `json:"reason" yaml:"reason"`
	EvidenceIDs []string `json:"evidenceIds" yaml:"evidenceIds"`
}

type githubRunnerSelection struct {
	Job         string   `json:"job" yaml:"job"`
	Kind        string   `json:"kind" yaml:"kind"`
	Labels      []string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Group       string   `json:"group,omitempty" yaml:"group,omitempty"`
	Dynamic     bool     `json:"dynamic,omitempty" yaml:"dynamic,omitempty"`
	Reason      string   `json:"reason" yaml:"reason"`
	EvidenceIDs []string `json:"evidenceIds" yaml:"evidenceIds"`
}

type githubDependencyIntegrity struct {
	Job         string   `json:"job" yaml:"job"`
	Kind        string   `json:"kind" yaml:"kind"`
	Reference   string   `json:"reference" yaml:"reference"`
	Locator     string   `json:"locator,omitempty" yaml:"locator,omitempty"`
	PinType     string   `json:"pinType" yaml:"pinType"`
	Immutable   bool     `json:"immutable" yaml:"immutable"`
	Reason      string   `json:"reason" yaml:"reason"`
	EvidenceIDs []string `json:"evidenceIds" yaml:"evidenceIds"`
}

type githubReusableWorkflowCall struct {
	Job              string   `json:"job" yaml:"job"`
	Reference        string   `json:"reference" yaml:"reference"`
	Locator          string   `json:"locator,omitempty" yaml:"locator,omitempty"`
	Local            bool     `json:"local" yaml:"local"`
	PermissionSource string   `json:"permissionSource" yaml:"permissionSource"`
	SecretMode       string   `json:"secretMode" yaml:"secretMode"`
	SecretNames      []string `json:"secretNames,omitempty" yaml:"secretNames,omitempty"`
	Resolution       string   `json:"resolution" yaml:"resolution"`
	EvidenceIDs      []string `json:"evidenceIds" yaml:"evidenceIds"`
}

var secretPattern = regexp.MustCompile(`(?i)secrets\.([A-Z0-9_]+)`)
var githubExpressionPattern = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)
var fullCommitSHAPattern = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)
var containerDigestPattern = regexp.MustCompile(`(?i)@sha256:[0-9a-f]{64}$`)

var untrustedRunContexts = []string{
	"github.event.comment.body",
	"github.event.discussion.body",
	"github.event.discussion.title",
	"github.event.discussion_comment.body",
	"github.event.issue.body",
	"github.event.issue.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.title",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.head_ref",
}

func (Parser) Name() string { return "github-actions" }

func (Parser) Supports(a discovery.Artifact) bool {
	return strings.HasPrefix(a.RelPath, ".github/workflows/") &&
		(filepath.Ext(a.RelPath) == ".yml" || filepath.Ext(a.RelPath) == ".yaml")
}

func (Parser) Parse(_ context.Context, a discovery.Artifact) ([]model.Agent, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(a.Content, &root); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions workflow %s: %w", a.RelPath, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow %s must be a mapping", a.RelPath)
	}
	doc := root.Content[0]
	name := scalarValue(mappingValue(doc, "name"))
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(a.RelPath), filepath.Ext(a.RelPath))
	}
	evidenceID := stableID("gha", a.RelPath)
	agent := model.Agent{
		ID:      "github-actions:" + a.RelPath,
		Type:    "workflow",
		Name:    name,
		Source:  model.Source{Path: a.RelPath},
		Runtime: &model.Runtime{Type: "github-actions", Reference: a.RelPath},
		Evidence: []model.Evidence{{
			ID: evidenceID, Path: a.RelPath, Line: doc.Line, Column: doc.Column,
			Parser: "github-actions", Confidence: "high", Observation: "workflow definition",
		}},
	}
	triggers := workflowTriggers(mappingValue(doc, "on"))
	if len(triggers) > 0 {
		agent.Controls = append(agent.Controls, model.Control{Type: "githubWorkflowTriggers", Value: triggers})
	}
	if exposures := privilegedTriggerExposures(triggers); len(exposures) > 0 {
		agent.Controls = append(agent.Controls, model.Control{Type: "githubPrivilegedTriggerExposure", Value: exposures})
	}

	workflowPermissions := mappingValue(doc, "permissions")
	workflowPermissionEvidence := ""
	if workflowPermissions != nil {
		workflowPermissionEvidence = stableID("gha-permissions", a.RelPath+":workflow")
		agent.Evidence = append(agent.Evidence, permissionEvidence(a.RelPath, workflowPermissions, workflowPermissionEvidence, "workflow token permissions"))
	}
	jobs := mappingValue(doc, "jobs")
	if jobs != nil && jobs.Kind == yaml.MappingNode {
		var unspecifiedJobs, disabledJobs []string
		var untrustedDataFlows []githubUntrustedDataFlow
		var runnerSelections, selfHostedRunners, unknownRunners []githubRunnerSelection
		var dependencies, mutableDependencies []githubDependencyIntegrity
		var reusableCalls, inheritedSecretCalls, externalReusableCalls []githubReusableWorkflowCall
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
			environmentName, environmentURL, environmentNode := jobEnvironment(mappingValue(job, "environment"))
			jobEvidence := stableID("gha-job", a.RelPath+":"+jobName)
			agent.Evidence = append(agent.Evidence, model.Evidence{
				ID: jobEvidence, Path: a.RelPath, Line: job.Line, Column: job.Column,
				Parser: "github-actions", Confidence: "high", Observation: "job " + jobName,
			})
			if runsOn := mappingValue(job, "runs-on"); runsOn != nil {
				runnerEvidenceID := stableID("gha-runner", a.RelPath+":"+jobName)
				agent.Evidence = append(agent.Evidence, permissionEvidence(a.RelPath, runsOn, runnerEvidenceID, "runner selection for job "+jobName))
				selection := parseRunnerSelection(jobName, runsOn, []string{jobEvidence, runnerEvidenceID})
				runnerSelections = append(runnerSelections, selection)
				switch selection.Kind {
				case "self-hosted":
					selfHostedRunners = append(selfHostedRunners, selection)
				case "unknown":
					unknownRunners = append(unknownRunners, selection)
				}
			}
			effectivePermissions := workflowPermissions
			permissionEvidenceID := workflowPermissionEvidence
			jobPermissions := mappingValue(job, "permissions")
			if jobPermissions != nil {
				effectivePermissions = jobPermissions
				permissionEvidenceID = stableID("gha-permissions", a.RelPath+":"+jobName)
				agent.Evidence = append(agent.Evidence, permissionEvidence(a.RelPath, jobPermissions, permissionEvidenceID, "job "+jobName+" token permissions"))
			}
			if effectivePermissions == nil {
				unspecifiedJobs = append(unspecifiedJobs, jobName)
			} else if permissionsDisabled(effectivePermissions) {
				disabledJobs = append(disabledJobs, jobName)
			}
			evidenceIDs := []string{jobEvidence}
			if permissionEvidenceID != "" {
				evidenceIDs = append(evidenceIDs, permissionEvidenceID)
			}
			if reusableNode := mappingValue(job, "uses"); reusableNode != nil {
				permissionSource := "repository-default-unknown"
				if jobPermissions != nil {
					permissionSource = "job"
				} else if workflowPermissions != nil {
					permissionSource = "workflow"
				}
				call, callEvidence := parseReusableWorkflowCall(a.RelPath, jobName, job, reusableNode, permissionSource, jobEvidence)
				reusableCalls = append(reusableCalls, call)
				agent.Evidence = append(agent.Evidence, callEvidence)
				agent.Capabilities = append(agent.Capabilities, model.Capability{
					Action: "github.reusable_workflow.invoke", Resource: "github:workflow:" + call.Reference,
					Effect: "execute", Environment: environmentName, EvidenceIDs: call.EvidenceIDs,
					Scope: githubJobScope(jobName),
				})
				if call.SecretMode == "inherit" {
					inheritedSecretCalls = append(inheritedSecretCalls, call)
					agent.Credentials = append(agent.Credentials, model.CredentialReference{
						Type: "github-actions-secret-set", Reference: "caller-visible:" + call.Reference, ValueCaptured: false,
					})
				}
				if !call.Local {
					externalReusableCalls = append(externalReusableCalls, call)
				}
			}
			agent.Capabilities = append(agent.Capabilities,
				permissionCapabilities(effectivePermissions, evidenceIDs, jobName, environmentName)...)
			if environmentName != "" {
				environmentEvidence := stableID("gha-environment", a.RelPath+":"+jobName+":"+environmentName)
				agent.Evidence = append(agent.Evidence, permissionEvidence(a.RelPath, environmentNode, environmentEvidence, "job "+jobName+" deployment environment "+environmentName))
				environmentEvidenceIDs := []string{jobEvidence, environmentEvidence}
				agent.Capabilities = append(agent.Capabilities, model.Capability{
					Action: "github.environment.deploy", Resource: "github:environment:" + environmentName,
					Effect: "execute", Environment: environmentName, EvidenceIDs: environmentEvidenceIDs,
					Scope: githubJobScope(jobName),
				})
				agent.Controls = append(agent.Controls, model.Control{Type: "githubDeploymentEnvironment", Value: githubEnvironmentControl{
					Job: jobName, Name: environmentName, URL: environmentURL, ProtectionStatus: "unknown",
				}})
			}
			flows, flowEvidence := analyzeJobDataFlows(a.RelPath, jobName, job, triggers, jobEvidence)
			untrustedDataFlows = append(untrustedDataFlows, flows...)
			agent.Evidence = append(agent.Evidence, flowEvidence...)
			jobDependencies, dependencyEvidence := analyzeJobDependencies(a.RelPath, jobName, job, jobEvidence)
			dependencies = append(dependencies, jobDependencies...)
			agent.Evidence = append(agent.Evidence, dependencyEvidence...)
			for _, dependency := range jobDependencies {
				agent.Dependencies = append(agent.Dependencies, model.Reference{
					Type: dependency.Kind, Reference: dependency.Reference, Locator: dependency.Locator,
				})
				if !dependency.Immutable && dependency.PinType != "same-commit" {
					mutableDependencies = append(mutableDependencies, dependency)
				}
			}
		}
		if len(unspecifiedJobs) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubTokenPermissionsUnspecified", Value: unspecifiedJobs})
		}
		if len(disabledJobs) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubTokenPermissionsDisabled", Value: disabledJobs})
		}
		if len(untrustedDataFlows) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubUntrustedDataFlow", Value: untrustedDataFlows})
		}
		if len(runnerSelections) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubRunnerSelections", Value: runnerSelections})
		}
		if len(selfHostedRunners) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubSelfHostedRunnerExposure", Value: selfHostedRunners})
		}
		if len(unknownRunners) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubRunnerSelectionUnknown", Value: unknownRunners})
		}
		if len(dependencies) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubDependencyIntegrity", Value: dependencies})
		}
		if len(mutableDependencies) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubMutableDependencyExposure", Value: mutableDependencies})
		}
		if len(reusableCalls) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubReusableWorkflowCalls", Value: reusableCalls})
		}
		if len(inheritedSecretCalls) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubReusableWorkflowSecretInheritance", Value: inheritedSecretCalls})
		}
		if len(externalReusableCalls) > 0 {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubReusableWorkflowExternalBoundary", Value: externalReusableCalls})
		}
	} else {
		agent.Capabilities = append(agent.Capabilities,
			permissionCapabilities(workflowPermissions, []string{workflowPermissionEvidence}, "workflow", "")...)
		if workflowPermissions == nil {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubTokenPermissionsUnspecified", Value: []string{"workflow"}})
		} else if permissionsDisabled(workflowPermissions) {
			agent.Controls = append(agent.Controls, model.Control{Type: "githubTokenPermissionsDisabled", Value: []string{"workflow"}})
		}
	}

	seenSecrets := map[string]struct{}{}
	for _, match := range secretPattern.FindAllStringSubmatch(string(a.Content), -1) {
		if len(match) != 2 {
			continue
		}
		name := strings.ToUpper(match[1])
		if _, exists := seenSecrets[name]; exists {
			continue
		}
		seenSecrets[name] = struct{}{}
		agent.Credentials = append(agent.Credentials, model.CredentialReference{
			Type: "github-actions-secret", Reference: name, ValueCaptured: false,
		})
	}
	sort.Slice(agent.Credentials, func(i, j int) bool {
		return agent.Credentials[i].Reference < agent.Credentials[j].Reference
	})
	agent.Capabilities = uniqueCapabilities(agent.Capabilities)
	return []model.Agent{agent}, nil
}

func permissionCapabilities(node *yaml.Node, evidenceIDs []string, jobScope, environment string) []model.Capability {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		switch strings.ToLower(node.Value) {
		case "read-all":
			return []model.Capability{{Action: "github.repository.*", Resource: "github:repository", Effect: "read", Environment: environment, EvidenceIDs: evidenceIDs, Scope: githubJobScope(jobScope)}}
		case "write-all":
			return []model.Capability{
				{Action: "github.repository.*", Resource: "github:repository", Effect: "write", Environment: environment, EvidenceIDs: evidenceIDs, Scope: githubJobScope(jobScope)},
				{Action: "github.oidc_token.issue", Resource: "github:oidc-token", Effect: "execute", Environment: environment, EvidenceIDs: append([]string(nil), evidenceIDs...), Scope: githubJobScope(jobScope)},
			}
		case "{}", "none":
			return nil
		}
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var result []model.Capability
	for i := 0; i+1 < len(node.Content); i += 2 {
		permissionScope := strings.ToLower(node.Content[i].Value)
		level := strings.ToLower(node.Content[i+1].Value)
		if level == "none" || level == "" {
			continue
		}
		action := "github." + strings.ReplaceAll(permissionScope, "-", ".") + ".*"
		resource, effect := "github:repository", level
		if permissionScope == "id-token" && level == "write" {
			action, resource, effect = "github.oidc_token.issue", "github:oidc-token", "execute"
		}
		result = append(result, model.Capability{
			Action: action, Resource: resource, Effect: effect, Environment: environment,
			EvidenceIDs: append([]string(nil), evidenceIDs...), Scope: githubJobScope(jobScope),
		})
	}
	return result
}

func jobEnvironment(node *yaml.Node) (string, string, *yaml.Node) {
	if node == nil {
		return "", "", nil
	}
	if node.Kind == yaml.ScalarNode {
		return strings.TrimSpace(node.Value), "", node
	}
	if node.Kind != yaml.MappingNode {
		return "", "", node
	}
	return strings.TrimSpace(scalarValue(mappingValue(node, "name"))), strings.TrimSpace(scalarValue(mappingValue(node, "url"))), node
}

func workflowTriggers(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	switch node.Kind {
	case yaml.ScalarNode:
		add(node.Value)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind == yaml.ScalarNode {
				add(child.Value)
			}
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			add(node.Content[index].Value)
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func parseRunnerSelection(job string, node *yaml.Node, evidenceIDs []string) githubRunnerSelection {
	selection := githubRunnerSelection{Job: job, Kind: "unknown", EvidenceIDs: evidenceIDs}
	if node == nil {
		selection.Reason = "runner selection is absent"
		return selection
	}
	switch node.Kind {
	case yaml.ScalarNode:
		selection.Labels = []string{strings.TrimSpace(node.Value)}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind == yaml.ScalarNode && strings.TrimSpace(child.Value) != "" {
				selection.Labels = append(selection.Labels, strings.TrimSpace(child.Value))
			}
		}
	case yaml.MappingNode:
		selection.Group = strings.TrimSpace(scalarValue(mappingValue(node, "group")))
		labels := mappingValue(node, "labels")
		if labels != nil && labels.Kind == yaml.SequenceNode {
			for _, child := range labels.Content {
				if child.Kind == yaml.ScalarNode && strings.TrimSpace(child.Value) != "" {
					selection.Labels = append(selection.Labels, strings.TrimSpace(child.Value))
				}
			}
		} else if value := strings.TrimSpace(scalarValue(labels)); value != "" {
			selection.Labels = append(selection.Labels, value)
		}
	}
	for _, label := range selection.Labels {
		lower := strings.ToLower(label)
		if strings.Contains(lower, "${{") {
			selection.Dynamic = true
		}
		if lower == "self-hosted" {
			selection.Kind = "self-hosted"
			selection.Reason = "job explicitly targets a self-hosted runner label"
			return selection
		}
	}
	if selection.Dynamic {
		selection.Reason = "runner label is selected dynamically and cannot be classified offline"
		return selection
	}
	if selection.Group != "" {
		selection.Reason = "runner group may contain a larger or self-hosted runner and requires GitHub API enrichment"
		return selection
	}
	if len(selection.Labels) == 1 && githubHostedRunnerLabel(strings.ToLower(selection.Labels[0])) {
		selection.Kind = "github-hosted"
		selection.Reason = "job targets a standard GitHub-hosted runner label"
		return selection
	}
	selection.Reason = "custom runner labels cannot prove hosting or isolation without repository configuration"
	return selection
}

func githubHostedRunnerLabel(label string) bool {
	return strings.HasPrefix(label, "ubuntu-") || strings.HasPrefix(label, "windows-") || strings.HasPrefix(label, "macos-")
}

func privilegedTriggerExposures(triggers []string) []githubTriggerExposure {
	var result []githubTriggerExposure
	for _, event := range triggers {
		switch event {
		case "pull_request_target":
			result = append(result, githubTriggerExposure{
				Event: event, TrustBoundary: "base-repository-privileged",
				Reason: "runs in the base branch context and must not execute untrusted pull request code",
			})
		case "workflow_run":
			result = append(result, githubTriggerExposure{
				Event: event, TrustBoundary: "privileged-follow-up",
				Reason: "can access secrets and write tokens even when the triggering workflow could not",
			})
		}
	}
	return result
}

func analyzeJobDataFlows(path, jobName string, job *yaml.Node, triggers []string, jobEvidenceID string) ([]githubUntrustedDataFlow, []model.Evidence) {
	steps := mappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil, nil
	}
	triggerSet := map[string]struct{}{}
	for _, trigger := range triggers {
		triggerSet[trigger] = struct{}{}
	}
	var flows []githubUntrustedDataFlow
	var evidence []model.Evidence
	for index, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		uses := strings.ToLower(strings.TrimSpace(scalarValue(mappingValue(step, "uses"))))
		with := mappingValue(step, "with")
		if strings.HasPrefix(uses, "actions/checkout@") {
			ref := strings.ToLower(scalarValue(mappingValue(with, "ref")))
			trigger, source := untrustedCheckoutSource(ref, triggerSet)
			if source != "" {
				flowEvidenceID := stableID("gha-data-flow", fmt.Sprintf("%s:%s:%d:checkout", path, jobName, index))
				evidence = append(evidence, model.Evidence{
					ID: flowEvidenceID, Path: path, Line: step.Line, Column: step.Column,
					Parser: "github-actions", Confidence: "high", Observation: "untrusted checkout ref in job " + jobName,
				})
				flows = append(flows, githubUntrustedDataFlow{
					Job: jobName, Trigger: trigger, Source: source, Sink: "runner-workspace", Action: uses,
					Reason:      "privileged workflow checks out a ref selected by lower-trust event data",
					EvidenceIDs: []string{jobEvidenceID, flowEvidenceID},
				})
			}
		}
		if strings.HasPrefix(uses, "actions/download-artifact@") {
			runID := strings.ToLower(scalarValue(mappingValue(with, "run-id")))
			if _, enabled := triggerSet["workflow_run"]; enabled && strings.Contains(runID, "github.event.workflow_run.id") {
				flowEvidenceID := stableID("gha-data-flow", fmt.Sprintf("%s:%s:%d:artifact", path, jobName, index))
				evidence = append(evidence, model.Evidence{
					ID: flowEvidenceID, Path: path, Line: step.Line, Column: step.Column,
					Parser: "github-actions", Confidence: "high", Observation: "workflow_run artifact download in job " + jobName,
				})
				flows = append(flows, githubUntrustedDataFlow{
					Job: jobName, Trigger: "workflow_run", Source: "triggering-workflow-artifact", Sink: "runner-workspace", Action: uses,
					Reason:      "privileged follow-up downloads an artifact selected from the triggering workflow run",
					EvidenceIDs: []string{jobEvidenceID, flowEvidenceID},
				})
			}
		}
		run := scalarValue(mappingValue(step, "run"))
		for _, source := range directUntrustedRunSources(run) {
			flowEvidenceID := stableID("gha-data-flow", fmt.Sprintf("%s:%s:%d:run:%s", path, jobName, index, source))
			evidence = append(evidence, model.Evidence{
				ID: flowEvidenceID, Path: path, Line: step.Line, Column: step.Column,
				Parser: "github-actions", Confidence: "high", Observation: "direct untrusted expression interpolation in run step for job " + jobName,
			})
			shell := strings.TrimSpace(scalarValue(mappingValue(step, "shell")))
			if shell == "" {
				shell = "default"
			}
			flows = append(flows, githubUntrustedDataFlow{
				Job: jobName, Trigger: triggerForContext(source, triggerSet), Source: source,
				Sink: "runner-shell", Action: "run:" + shell,
				Reason:      "event-controlled expression is interpolated directly into a generated runner script",
				EvidenceIDs: []string{jobEvidenceID, flowEvidenceID},
			})
		}
	}
	return flows, evidence
}

func analyzeJobDependencies(path, jobName string, job *yaml.Node, jobEvidenceID string) ([]githubDependencyIntegrity, []model.Evidence) {
	var dependencies []githubDependencyIntegrity
	var evidence []model.Evidence
	if reusable := mappingValue(job, "uses"); reusable != nil {
		dependency, itemEvidence := classifyDependency(path, jobName, "reusable-workflow", scalarValue(reusable), reusable, "job", jobEvidenceID)
		if dependency.Reference != "" {
			dependencies = append(dependencies, dependency)
			evidence = append(evidence, itemEvidence)
		}
	}
	steps := mappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return dependencies, evidence
	}
	for index, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		usesNode := mappingValue(step, "uses")
		uses := strings.TrimSpace(scalarValue(usesNode))
		if uses == "" {
			continue
		}
		kind := "github-action"
		if strings.HasPrefix(strings.ToLower(uses), "docker://") {
			kind = "container-action"
		} else if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "$/") {
			kind = "local-action"
		}
		dependency, itemEvidence := classifyDependency(path, jobName, kind, uses, usesNode, fmt.Sprintf("step-%d", index), jobEvidenceID)
		dependencies = append(dependencies, dependency)
		evidence = append(evidence, itemEvidence)
	}
	return dependencies, evidence
}

func parseReusableWorkflowCall(path, jobName string, job, usesNode *yaml.Node, permissionSource, jobEvidenceID string) (githubReusableWorkflowCall, model.Evidence) {
	uses := strings.TrimSpace(scalarValue(usesNode))
	reference, locator := splitDependencyReference(uses)
	local := strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "$/")
	call := githubReusableWorkflowCall{
		Job: jobName, Reference: reference, Locator: locator, Local: local,
		PermissionSource: permissionSource, SecretMode: "none", Resolution: "external-unresolved",
	}
	if local {
		call.Resolution = "local-candidate"
	}
	secretsNode := mappingValue(job, "secrets")
	if secretsNode != nil && secretsNode.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(secretsNode.Value), "inherit") {
		call.SecretMode = "inherit"
	} else if secretsNode != nil && secretsNode.Kind == yaml.MappingNode {
		call.SecretMode = "explicit"
		for index := 0; index+1 < len(secretsNode.Content); index += 2 {
			name := strings.TrimSpace(secretsNode.Content[index].Value)
			if name != "" {
				call.SecretNames = append(call.SecretNames, name)
			}
		}
		sort.Strings(call.SecretNames)
	}
	evidenceID := stableID("gha-reusable-call", path+":"+jobName+":"+uses)
	call.EvidenceIDs = []string{jobEvidenceID, evidenceID}
	evidence := model.Evidence{
		ID: evidenceID, Path: path, Line: usesNode.Line, Column: usesNode.Column,
		Parser: "github-actions", Confidence: "high", Observation: "reusable workflow call " + uses + " in job " + jobName,
	}
	return call, evidence
}

func classifyDependency(path, jobName, kind, uses string, node *yaml.Node, discriminator, jobEvidenceID string) (githubDependencyIntegrity, model.Evidence) {
	uses = strings.TrimSpace(uses)
	reference, locator := splitDependencyReference(uses)
	dependency := githubDependencyIntegrity{
		Job: jobName, Kind: kind, Reference: reference, Locator: locator,
		EvidenceIDs: []string{jobEvidenceID},
	}
	switch {
	case kind == "local-action" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "$/"):
		dependency.PinType, dependency.Immutable = "same-commit", true
		dependency.Reason = "local dependency is loaded from the caller workflow commit"
	case strings.Contains(uses, "${{"):
		dependency.PinType = "dynamic"
		dependency.Reason = "dependency reference is expression-selected and cannot be resolved offline"
	case kind == "container-action" && containerDigestPattern.MatchString(uses):
		dependency.PinType, dependency.Immutable = "container-digest", true
		dependency.Reason = "container action is pinned to a SHA-256 digest"
	case kind == "container-action":
		dependency.PinType = "container-tag"
		dependency.Reason = "container action tag or implicit latest reference is mutable"
	case fullCommitSHAPattern.MatchString(locator):
		dependency.PinType, dependency.Immutable = "full-commit-sha", true
		dependency.Reason = "GitHub dependency is pinned to a full commit SHA"
	case locator == "":
		dependency.PinType = "unversioned"
		dependency.Reason = "external GitHub dependency has no explicit ref"
	default:
		dependency.PinType = "tag-or-branch"
		dependency.Reason = "GitHub tag or branch reference can move to different code"
	}
	evidenceID := stableID("gha-dependency", path+":"+jobName+":"+discriminator+":"+uses)
	dependency.EvidenceIDs = append(dependency.EvidenceIDs, evidenceID)
	itemEvidence := model.Evidence{
		ID: evidenceID, Path: path, Line: node.Line, Column: node.Column,
		Parser: "github-actions", Confidence: "high", Observation: "dependency " + uses + " in job " + jobName,
	}
	return dependency, itemEvidence
}

func splitDependencyReference(uses string) (string, string) {
	if strings.HasPrefix(strings.ToLower(uses), "docker://") {
		value := strings.TrimPrefix(uses, "docker://")
		if index := strings.LastIndex(value, "@sha256:"); index >= 0 {
			return value[:index], value[index+1:]
		}
		if index := strings.LastIndex(value, ":"); index > strings.LastIndex(value, "/") {
			return value[:index], value[index+1:]
		}
		return value, "latest"
	}
	if index := strings.LastIndex(uses, "@"); index > 0 {
		return uses[:index], uses[index+1:]
	}
	return uses, ""
}

func directUntrustedRunSources(run string) []string {
	if run == "" {
		return nil
	}
	seen := map[string]struct{}{}
	for _, expression := range githubExpressionPattern.FindAllString(strings.ToLower(run), -1) {
		for _, source := range untrustedRunContexts {
			if strings.Contains(expression, source) {
				seen[source] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for source := range seen {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}

func triggerForContext(source string, triggers map[string]struct{}) string {
	candidates := []string{}
	switch {
	case strings.Contains(source, "pull_request") || source == "github.head_ref":
		candidates = []string{"pull_request_target", "pull_request"}
	case strings.Contains(source, "comment"):
		candidates = []string{"issue_comment", "pull_request_review_comment", "discussion_comment"}
	case strings.Contains(source, "discussion"):
		candidates = []string{"discussion", "discussion_comment"}
	case strings.Contains(source, "issue"):
		candidates = []string{"issues", "issue_comment"}
	case strings.Contains(source, "review"):
		candidates = []string{"pull_request_review", "pull_request_review_comment"}
	}
	for _, candidate := range candidates {
		if _, exists := triggers[candidate]; exists {
			return candidate
		}
	}
	return "event-context"
}

func untrustedCheckoutSource(ref string, triggers map[string]struct{}) (string, string) {
	if _, enabled := triggers["pull_request_target"]; enabled {
		for _, value := range []string{"github.event.pull_request.head.sha", "github.event.pull_request.head.ref", "github.head_ref"} {
			if strings.Contains(ref, value) {
				return "pull_request_target", "pull-request-head-ref"
			}
		}
	}
	if _, enabled := triggers["workflow_run"]; enabled {
		for _, value := range []string{"github.event.workflow_run.head_sha", "github.event.workflow_run.head_branch"} {
			if strings.Contains(ref, value) {
				return "workflow_run", "triggering-workflow-head-ref"
			}
		}
	}
	return "", ""
}

func githubJobScope(job string) *model.Scope {
	return &model.Scope{Kind: "github-actions-job", Values: []string{job}}
}

func permissionsDisabled(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content) == 0 {
			return true
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if strings.ToLower(node.Content[i+1].Value) != "none" {
				return false
			}
		}
		return true
	}
	value := strings.ToLower(strings.TrimSpace(node.Value))
	return value == "none" || value == "{}"
}

func permissionEvidence(path string, node *yaml.Node, id, observation string) model.Evidence {
	return model.Evidence{
		ID: id, Path: path, Line: node.Line, Column: node.Column,
		Parser: "github-actions", Confidence: "high", Observation: observation,
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func stableID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s-%x", prefix, sum[:6])
}

func uniqueCapabilities(values []model.Capability) []model.Capability {
	seen := map[string]model.Capability{}
	for _, value := range values {
		scope := ""
		if value.Scope != nil {
			scope = value.Scope.Kind + "\x00" + strings.Join(value.Scope.Values, "\x00") + fmt.Sprintf("\x00%t", value.Scope.Wildcard)
		}
		key := value.Action + "\x00" + value.Resource + "\x00" + value.Effect + "\x00" + value.Environment + "\x00" + scope
		seen[key] = value
	}
	result := make([]model.Capability, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].Action+result[i].Effect, result[j].Action+result[j].Effect
		if result[i].Scope != nil {
			left += strings.Join(result[i].Scope.Values, "/")
		}
		if result[j].Scope != nil {
			right += strings.Join(result[j].Scope.Values, "/")
		}
		return left < right
	})
	return result
}
