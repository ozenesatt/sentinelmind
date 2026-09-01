targetScope = 'resourceGroup'

@description('Demo NSG adi')
param nsgName string = 'sentinelmind-soc-nsg'

@description('Demo insecure SSH rule adi')
param ruleName string = 'DEMO-Insecure-SSH-Any'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' existing = {
  name: nsgName
}

resource insecureSshRule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: nsg
  name: ruleName
  properties: {
    priority: 100
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourceAddressPrefix: '*'
    sourcePortRange: '*'
    destinationAddressPrefix: '*'
    destinationPortRange: '22'
  }
}

output restoredRuleId string = insecureSshRule.id
