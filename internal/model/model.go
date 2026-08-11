package model

const (
	APIVersion = "opscustodian.dev/v1alpha1"
	Kind       = "AgentBOM"
)

type AgentBOM struct {
	APIVersion    string           `json:"apiVersion" yaml:"apiVersion"`
	Kind          string           `json:"kind" yaml:"kind"`
	Metadata      DocumentMetadata `json:"metadata" yaml:"metadata"`
	Assets        []Asset          `json:"assets" yaml:"assets"`
	Relationships []Relationship   `json:"relationships,omitempty" yaml:"relationships,omitempty"`
	AccessPaths   []AccessPath     `json:"accessPaths,omitempty" yaml:"accessPaths,omitempty"`
	LegacyAgents  []Asset          `json:"agents,omitempty" yaml:"agents,omitempty"`
	Diagnostics   []Diagnostic     `json:"diagnostics,omitempty" yaml:"diagnostics,omitempty"`
}

type AccessPath struct {
	ID          string           `json:"id" yaml:"id"`
	Origin      string           `json:"origin" yaml:"origin"`
	Steps       []AccessPathStep `json:"steps" yaml:"steps"`
	Capability  Capability       `json:"capability" yaml:"capability"`
	Confidence  string           `json:"confidence" yaml:"confidence"`
	EvidenceIDs []string         `json:"evidenceIds,omitempty" yaml:"evidenceIds,omitempty"`
}

type AccessPathStep struct {
	Kind    string `json:"kind" yaml:"kind"`
	AssetID string `json:"assetId" yaml:"assetId"`
}

type Diagnostic struct {
	Severity string `json:"severity" yaml:"severity"`
	Code     string `json:"code" yaml:"code"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Parser   string `json:"parser,omitempty" yaml:"parser,omitempty"`
	Message  string `json:"message" yaml:"message"`
}

type DocumentMetadata struct {
	Source               string `json:"source" yaml:"source"`
	Revision             string `json:"revision" yaml:"revision"`
	GeneratedAt          string `json:"generatedAt,omitempty" yaml:"generatedAt,omitempty"`
	Generator            string `json:"generator,omitempty" yaml:"generator,omitempty"`
	NormalizationVersion string `json:"normalizationVersion,omitempty" yaml:"normalizationVersion,omitempty"`
}

type Asset struct {
	ID           string                `json:"id" yaml:"id"`
	Type         string                `json:"type" yaml:"type"`
	Name         string                `json:"name" yaml:"name"`
	Component    string                `json:"component,omitempty" yaml:"component,omitempty"`
	Owners       []string              `json:"owners,omitempty" yaml:"owners,omitempty"`
	LegacyOwner  string                `json:"owner,omitempty" yaml:"owner,omitempty"`
	Source       Source                `json:"source" yaml:"source"`
	Runtime      *Runtime              `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Identities   []Reference           `json:"identities,omitempty" yaml:"identities,omitempty"`
	Credentials  []CredentialReference `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	Tools        []Reference           `json:"tools,omitempty" yaml:"tools,omitempty"`
	Dependencies []Reference           `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Capabilities []Capability          `json:"capabilities" yaml:"capabilities"`
	Controls     []Control             `json:"controls,omitempty" yaml:"controls,omitempty"`
	Evidence     []Evidence            `json:"evidence" yaml:"evidence"`
}

// Agent is an internal compatibility alias while parser APIs migrate to the
// generic asset terminology before the first public release.
type Agent = Asset

type Source struct {
	Repository string `json:"repository,omitempty" yaml:"repository,omitempty"`
	Path       string `json:"path" yaml:"path"`
}

type Runtime struct {
	Type      string `json:"type" yaml:"type"`
	Reference string `json:"reference,omitempty" yaml:"reference,omitempty"`
}

type Reference struct {
	Type       string         `json:"type" yaml:"type"`
	Reference  string         `json:"reference" yaml:"reference"`
	Locator    string         `json:"locator,omitempty" yaml:"locator,omitempty"`
	Optional   bool           `json:"optional,omitempty" yaml:"optional,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Order      int            `json:"order,omitempty" yaml:"order,omitempty"`
}

type Relationship struct {
	ID          string   `json:"id" yaml:"id"`
	From        string   `json:"from" yaml:"from"`
	Type        string   `json:"type" yaml:"type"`
	To          string   `json:"to" yaml:"to"`
	TargetType  string   `json:"targetType" yaml:"targetType"`
	Confidence  string   `json:"confidence" yaml:"confidence"`
	EvidenceIDs []string `json:"evidenceIds,omitempty" yaml:"evidenceIds,omitempty"`
}

type CredentialReference struct {
	Type          string `json:"type" yaml:"type"`
	Reference     string `json:"reference" yaml:"reference"`
	ValueCaptured bool   `json:"valueCaptured" yaml:"valueCaptured"`
}

type Capability struct {
	Action      string   `json:"action" yaml:"action"`
	Resource    string   `json:"resource" yaml:"resource"`
	Effect      string   `json:"effect" yaml:"effect"`
	Environment string   `json:"environment,omitempty" yaml:"environment,omitempty"`
	EvidenceIDs []string `json:"evidenceIds,omitempty" yaml:"evidenceIds,omitempty"`
	Scope       *Scope   `json:"scope,omitempty" yaml:"scope,omitempty"`
}

type Scope struct {
	Kind     string   `json:"kind" yaml:"kind"`
	Values   []string `json:"values,omitempty" yaml:"values,omitempty"`
	Wildcard bool     `json:"wildcard,omitempty" yaml:"wildcard,omitempty"`
}

type Control struct {
	Type  string `json:"type" yaml:"type"`
	Value any    `json:"value" yaml:"value"`
}

type Evidence struct {
	ID          string `json:"id" yaml:"id"`
	Path        string `json:"path" yaml:"path"`
	Line        int    `json:"line,omitempty" yaml:"line,omitempty"`
	Column      int    `json:"column,omitempty" yaml:"column,omitempty"`
	Parser      string `json:"parser" yaml:"parser"`
	Confidence  string `json:"confidence" yaml:"confidence"`
	Observation string `json:"observation,omitempty" yaml:"observation,omitempty"`
}
