@description('Azure region for the isolated SentinelMind holdout environment.')
param location string = resourceGroup().location

@description('Prefix used for holdout resource names.')
param prefix string = 'sentinelmind-holdout'

resource holdoutNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-nsg'
  location: location

  properties: {
    securityRules: [
      {
        name: 'HOLDOUT-Allow-HTTP-Internet'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'

          sourcePortRange: '*'
          destinationPortRange: '80'

          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'HOLDOUT-Allow-RDP-Internet'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'

          sourcePortRange: '*'
          destinationPortRange: '3389'

          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'HOLDOUT-Allow-UDP-Internet'
        properties: {
          priority: 120
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Udp'

          sourcePortRange: '*'
          destinationPortRange: '53'

          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource holdoutVnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: '${prefix}-vnet'
  location: location

  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }

    subnets: [
      {
        name: 'exposed-subnet'
        properties: {
          addressPrefix: '10.20.1.0/24'

          networkSecurityGroup: {
            id: holdoutNsg.id
          }
        }
      }

      {
        name: 'unprotected-subnet'
        properties: {
          addressPrefix: '10.20.2.0/24'
        }
      }
    ]
  }
}

output nsgName string = holdoutNsg.name
output vnetName string = holdoutVnet.name
output exposedSubnet string = 'exposed-subnet'
output unprotectedSubnet string = 'unprotected-subnet'