targetScope = 'resourceGroup'

param workspaceName string
param location string
@minValue(30)
@maxValue(730)
param retentionDays int
@minValue(-1)
param dailyQuotaGb int
param disableLocalAuth bool
param publicNetworkAccessForIngestion string
param publicNetworkAccessForQuery string
param tags object

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: workspaceName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  tags: tags
  properties: {
    features: {
      disableLocalAuth: disableLocalAuth
      enableLogAccessUsingOnlyResourcePermissions: true
      enableDataExport: false
      immediatePurgeDataOn30Days: false
    }
    publicNetworkAccessForIngestion: publicNetworkAccessForIngestion
    publicNetworkAccessForQuery: publicNetworkAccessForQuery
    retentionInDays: retentionDays
    sku: {
      name: 'PerGB2018'
    }
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2025-06-01' = {
  scope: workspace
  name: 'default'
  properties: {
    customerManagedKey: false
  }
}

// Sentinel exposes health/audit diagnostic categories on this settings scope.
resource sentinelHealthSettings 'Microsoft.SecurityInsights/settings@2025-07-01-preview' existing = {
  scope: workspace
  name: 'SentinelHealth'
}

resource sentinelHealthAndAudit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'trisoc-sentinel-health-and-audit'
  scope: sentinelHealthSettings
  properties: {
    workspaceId: workspace.id
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
  dependsOn: [
    sentinel
  ]
}

output workspaceResourceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
output sentinelOnboardingStateId string = sentinel.id
