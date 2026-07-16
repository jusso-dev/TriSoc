// Deploy from subscription scope. Creates the resource group, Log Analytics
// workspace, Microsoft Sentinel, Sentinel health/audit diagnostics, and the
// subscription Activity Log route used by the baseline SIEM.
targetScope = 'subscription'

@description('Resource group that owns the Microsoft Sentinel workspace.')
param resourceGroupName string = 'security-operations'

@description('Azure region for the resource group and workspace.')
param location string = deployment().location

@description('Globally unique Log Analytics workspace name within the tenant.')
@minLength(4)
@maxLength(63)
param workspaceName string

@description('Workspace retention. Ninety days is the security baseline.')
@minValue(30)
@maxValue(730)
param retentionDays int = 90

@description('Daily ingestion cap in GB. -1 avoids silently dropping security telemetry; use budgets and alerts for cost control.')
@minValue(-1)
param dailyQuotaGb int = -1

@description('Disable shared-key local authentication and require Microsoft Entra authorization.')
param disableLocalAuth bool = true

@allowed([
  'Enabled'
  'Disabled'
  'SecuredByPerimeter'
])
@description('Workspace public ingestion access. Disable only after a private ingestion path exists.')
param publicNetworkAccessForIngestion string = 'Enabled'

@allowed([
  'Enabled'
  'Disabled'
  'SecuredByPerimeter'
])
@description('Workspace public query access. Disable only after a private query path exists.')
param publicNetworkAccessForQuery string = 'Enabled'

@description('Tags applied to baseline resources.')
param tags object = {
  managedBy: 'TriSOC'
  workload: 'security-operations'
  dataClassification: 'security-telemetry'
}

resource securityOperationsResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module sentinel './workspace.bicep' = {
  name: 'microsoft-sentinel-baseline'
  scope: securityOperationsResourceGroup
  params: {
    workspaceName: workspaceName
    location: location
    retentionDays: retentionDays
    dailyQuotaGb: dailyQuotaGb
    disableLocalAuth: disableLocalAuth
    publicNetworkAccessForIngestion: publicNetworkAccessForIngestion
    publicNetworkAccessForQuery: publicNetworkAccessForQuery
    tags: tags
  }
}

resource subscriptionActivityLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'trisoc-subscription-activity-to-sentinel'
  properties: {
    workspaceId: sentinel.outputs.workspaceResourceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'Administrative', enabled: true }
      { category: 'Security', enabled: true }
      { category: 'ServiceHealth', enabled: true }
      { category: 'Alert', enabled: true }
      { category: 'Recommendation', enabled: true }
      { category: 'Policy', enabled: true }
      { category: 'Autoscale', enabled: true }
      { category: 'ResourceHealth', enabled: true }
    ]
  }
}

output workspaceResourceId string = sentinel.outputs.workspaceResourceId
output workspaceCustomerId string = sentinel.outputs.workspaceCustomerId
output sentinelOnboardingStateId string = sentinel.outputs.sentinelOnboardingStateId
