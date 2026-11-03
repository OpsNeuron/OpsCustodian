package contracts

const (
	AgentBOMAPIVersion      = "opscustodian.dev/v1alpha1"
	AgentBOMKind            = "AgentBOM"
	NormalizationVersion    = "v1alpha1"
	FindingsAPIVersion      = "opscustodian.dev/findings/v1alpha1"
	PolicyInputAPIVersion   = "opscustodian.dev/policy-input/v1alpha1"
	PolicyDecisionVersion   = "v1alpha1"
	AuditEventAPIVersion    = "opscustodian.dev/audit-event/v1alpha1"
	ControlPlaneAPIVersion  = "opscustodian.dev/control-plane/v1alpha1"
	RepositorySetAPIVersion = "opscustodian.dev/ingestion/v1alpha1"
	PreflightAPIVersion     = "opscustodian.dev/preflight/v1alpha1"
	SARIFVersion            = "2.1.0"
	SARIFSchema             = "https://json.schemastore.org/sarif-2.1.0.json"
)

type Info struct {
	Version   string      `json:"version"`
	Contracts ContractSet `json:"contracts"`
}

type ContractSet struct {
	AgentBOM       string `json:"agentBOM"`
	Normalization  string `json:"normalization"`
	Findings       string `json:"findings"`
	PolicyInput    string `json:"policyInput"`
	PolicyDecision string `json:"policyDecision"`
	AuditEvent     string `json:"auditEvent"`
	ControlPlane   string `json:"controlPlane"`
	RepositorySet  string `json:"repositorySet"`
	Preflight      string `json:"preflight"`
	SARIF          string `json:"sarif"`
}

func BuildInfo(version string) Info {
	return Info{Version: version, Contracts: ContractSet{
		AgentBOM: AgentBOMAPIVersion, Normalization: NormalizationVersion,
		Findings: FindingsAPIVersion, PolicyInput: PolicyInputAPIVersion,
		PolicyDecision: PolicyDecisionVersion, AuditEvent: AuditEventAPIVersion,
		ControlPlane: ControlPlaneAPIVersion, RepositorySet: RepositorySetAPIVersion,
		Preflight: PreflightAPIVersion, SARIF: SARIFVersion,
	}}
}
