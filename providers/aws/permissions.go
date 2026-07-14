package aws

import "encoding/json"

var ReadPermissions = []string{"sts:GetCallerIdentity", "organizations:DescribeOrganization", "organizations:ListAccounts", "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListOrganizationAdminAccounts", "securityhub:DescribeHub", "securityhub:GetEnabledStandards", "securityhub:ListOrganizationAdminAccounts", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors", "config:DescribeConfigurationRecorderStatus", "securitylake:ListDataLakes", "es:ListDomainNames", "es:DescribeDomainConfig"}

func ReadOnlyPolicyJSON() ([]byte, error) {
	return json.MarshalIndent(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "TriSOCAttestorReadOnlyAssessment", "Effect": "Allow", "Action": ReadPermissions, "Resource": "*"}}}, "", "  ")
}
