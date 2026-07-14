// Reviewable example generated for controls microsoft.sentinel.enabled and
// microsoft.sentinel.workspace_retention. This template does not apply itself.
targetScope = 'resourceGroup'

param workspaceName string
param workspaceLocation string = resourceGroup().location
@minValue(30)
@maxValue(730)
param minimumRetentionDays int = 90

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource workspaceRetention 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: workspace.name
  location: workspaceLocation
  properties: {
    retentionInDays: minimumRetentionDays
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-09-01' = {
  scope: workspace
  name: 'default'
  properties: {
    customerManagedKey: false
  }
}
