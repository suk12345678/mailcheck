targetScope = 'resourceGroup'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Name of the Log Analytics Workspace')
param logAnalyticsName string = 'log-mailcheck'

@description('Name of the Container Apps Environment')
param environmentName string = 'cae-mailcheck'

@description('Name of the scheduled Container Apps Job')
param jobName string = 'job-mailcheck'

@description('Full container image path (from GitHub Container Registry or Docker Hub)')
param containerImage string = 'ghcr.io/suk12345678/mailcheck:latest'

@description('Cron schedule for mailcheck (default: every 5 minutes)')
param cronSchedule string = '*/5 * * * *'

@description('Target Hotmail / Outlook account email address')
param accountEmail string = 'sukhpal_sandhu@hotmail.com'

@secure()
@description('Hotmail OAuth 2.0 refresh token')
param refreshToken string

// 1. Log Analytics Workspace (Required for Container Apps logs; 5 GB/mo free ingestion)
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// 2. Container Apps Managed Environment (Consumption plan = 100% Free tier eligible)
resource appEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

// 3. Container Apps Scheduled Job
resource mailcheckJob 'Microsoft.App/jobs@2024-03-01' = {
  name: jobName
  location: location
  properties: {
    environmentId: appEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: cronSchedule
        parallelism: 1
        replicaCompletionCount: 1
      }
      replicaTimeout: 120
      replicaRetryLimit: 1
      secrets: [
        {
          name: 'refresh-token'
          value: refreshToken
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'mailcheck'
          image: containerImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'MAILCHECK_REFRESH_TOKEN'
              secretRef: 'refresh-token'
            }
            {
              name: 'MAILCHECK_ACCOUNT_EMAIL'
              value: accountEmail
            }
          ]
        }
      ]
    }
  }
}

output jobName string = mailcheckJob.name
output environmentName string = appEnv.name

