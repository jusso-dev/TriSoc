package aws

import "time"

type Architecture string

const (
	SecurityLakeOnly             Architecture = "security_lake_only"
	SecurityLakeWithOpenSearch   Architecture = "security_lake_with_opensearch"
	SecurityHubFindingsCentric   Architecture = "security_hub_findings_centric"
	ExistingThirdPartySIEMExport Architecture = "existing_third_party_siem_export"
	FullAWSNativeSOC             Architecture = "full_aws_native_soc"
)

type Target struct {
	Profile                        string       `json:"profile,omitempty" yaml:"profile,omitempty"`
	RoleARN                        string       `json:"roleArn,omitempty" yaml:"roleArn,omitempty"`
	ExternalID                     string       `json:"-" yaml:"-"`
	HomeRegion                     string       `json:"homeRegion" yaml:"homeRegion"`
	GovernedRegions                []string     `json:"governedRegions" yaml:"governedRegions"`
	Architecture                   Architecture `json:"architecture" yaml:"architecture"`
	RequireDelegatedAdministrators bool         `json:"requireDelegatedAdministrators" yaml:"requireDelegatedAdministrators"`
	RequireSecurityLake            bool         `json:"requireSecurityLake" yaml:"requireSecurityLake"`
	RequiredSecurityHubStandards   []string     `json:"requiredSecurityHubStandards" yaml:"requiredSecurityHubStandards"`
}

type Snapshot struct {
	Provider                               string             `json:"provider" yaml:"provider"`
	CallerAccountID                        string             `json:"callerAccountId" yaml:"callerAccountId"`
	CollectorIdentity                      string             `json:"collectorIdentity" yaml:"collectorIdentity"`
	Organization                           Organization       `json:"organization" yaml:"organization"`
	HomeRegion                             string             `json:"homeRegion" yaml:"homeRegion"`
	GovernedRegions                        []string           `json:"governedRegions" yaml:"governedRegions"`
	Architecture                           Architecture       `json:"architecture" yaml:"architecture"`
	DelegatedAdministratorsRequired        bool               `json:"delegatedAdministratorsRequired" yaml:"delegatedAdministratorsRequired"`
	GuardDuty                              []RegionalService  `json:"guardDuty" yaml:"guardDuty"`
	GuardDutyAllRegions                    bool               `json:"guardDutyAllRegions" yaml:"guardDutyAllRegions"`
	GuardDutyDelegatedAdministrator        bool               `json:"guardDutyDelegatedAdministrator" yaml:"guardDutyDelegatedAdministrator"`
	SecurityHub                            []RegionalService  `json:"securityHub" yaml:"securityHub"`
	SecurityHubAllRegions                  bool               `json:"securityHubAllRegions" yaml:"securityHubAllRegions"`
	SecurityHubDelegatedAdministrator      bool               `json:"securityHubDelegatedAdministrator" yaml:"securityHubDelegatedAdministrator"`
	EnabledSecurityHubStandards            []string           `json:"enabledSecurityHubStandards" yaml:"enabledSecurityHubStandards"`
	RequiredSecurityHubStandards           []string           `json:"requiredSecurityHubStandards" yaml:"requiredSecurityHubStandards"`
	RequiredSecurityHubStandardsConfigured bool               `json:"requiredSecurityHubStandardsConfigured" yaml:"requiredSecurityHubStandardsConfigured"`
	RequiredSecurityHubStandardsPresent    bool               `json:"requiredSecurityHubStandardsPresent" yaml:"requiredSecurityHubStandardsPresent"`
	Trails                                 []Trail            `json:"trails" yaml:"trails"`
	ConfigRecorders                        []ConfigRecorder   `json:"configRecorders" yaml:"configRecorders"`
	ConfigRecordersAllRegions              bool               `json:"configRecordersAllRegions" yaml:"configRecordersAllRegions"`
	SecurityLakes                          []SecurityLake     `json:"securityLakes" yaml:"securityLakes"`
	SecurityLakeRequired                   bool               `json:"securityLakeRequired" yaml:"securityLakeRequired"`
	SecurityLakeAllRegions                 bool               `json:"securityLakeAllRegions" yaml:"securityLakeAllRegions"`
	OpenSearchDomains                      []OpenSearchDomain `json:"openSearchDomains,omitempty" yaml:"openSearchDomains,omitempty"`
	ObservedAt                             time.Time          `json:"observedAt" yaml:"observedAt"`
}

type Organization struct {
	ID                  string `json:"id" yaml:"id"`
	ManagementAccountID string `json:"managementAccountId" yaml:"managementAccountId"`
	AccountCount        int    `json:"accountCount" yaml:"accountCount"`
	Enabled             bool   `json:"enabled" yaml:"enabled"`
}
type RegionalService struct {
	Region  string `json:"region" yaml:"region"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Status  string `json:"status,omitempty" yaml:"status,omitempty"`
	ID      string `json:"id,omitempty" yaml:"id,omitempty"`
}
type Trail struct {
	ARN               string `json:"arn" yaml:"arn"`
	Name              string `json:"name" yaml:"name"`
	HomeRegion        string `json:"homeRegion" yaml:"homeRegion"`
	OrganizationTrail bool   `json:"organizationTrail" yaml:"organizationTrail"`
	MultiRegion       bool   `json:"multiRegion" yaml:"multiRegion"`
	Logging           bool   `json:"logging" yaml:"logging"`
	ManagementRead    bool   `json:"managementRead" yaml:"managementRead"`
	ManagementWrite   bool   `json:"managementWrite" yaml:"managementWrite"`
	LogFileValidation bool   `json:"logFileValidation" yaml:"logFileValidation"`
	KMSEncrypted      bool   `json:"kmsEncrypted" yaml:"kmsEncrypted"`
}
type ConfigRecorder struct {
	Region     string `json:"region" yaml:"region"`
	Name       string `json:"name" yaml:"name"`
	Recording  bool   `json:"recording" yaml:"recording"`
	LastStatus string `json:"lastStatus,omitempty" yaml:"lastStatus,omitempty"`
}
type SecurityLake struct {
	Region              string `json:"region" yaml:"region"`
	Enabled             bool   `json:"enabled" yaml:"enabled"`
	Encryption          string `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	LifecycleConfigured bool   `json:"lifecycleConfigured" yaml:"lifecycleConfigured"`
}
type OpenSearchDomain struct {
	Region               string `json:"region" yaml:"region"`
	Name                 string `json:"name" yaml:"name"`
	ARN                  string `json:"arn,omitempty" yaml:"arn,omitempty"`
	EncryptionAtRest     bool   `json:"encryptionAtRest" yaml:"encryptionAtRest"`
	NodeToNodeEncryption bool   `json:"nodeToNodeEncryption" yaml:"nodeToNodeEncryption"`
	HTTPSRequired        bool   `json:"httpsRequired" yaml:"httpsRequired"`
}
