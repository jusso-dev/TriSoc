package azure

import "encoding/json"

var ReadPermissions = []string{
	"Microsoft.OperationalInsights/workspaces/read",
	"Microsoft.OperationalInsights/workspaces/query/read",
	"Microsoft.SecurityInsights/onboardingStates/read",
	"Microsoft.SecurityInsights/dataConnectors/read",
	"Microsoft.SecurityInsights/alertRules/read",
	"Microsoft.SecurityInsights/automationRules/read",
}

func ReadOnlyRoleJSON() ([]byte, error) {
	return json.MarshalIndent(map[string]any{"Name": "TriSOC Attestor Microsoft Sentinel Reader", "IsCustom": true, "Description": "Read-only Microsoft Sentinel assessment permissions generated from collector operations.", "Actions": ReadPermissions, "NotActions": []string{}, "AssignableScopes": []string{"/subscriptions/<subscription-id>"}}, "", "  ")
}
