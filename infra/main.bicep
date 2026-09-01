targetScope = 'resourceGroup'

@description('Kaynakların bölgesi')
param location string = resourceGroup().location

@description('Ortam adı, kaynak isimlerinde önek')
param envName string = 'sentinelmind'

@description('Benzersiz son ek (storage account global isim çakışmasını önler)')
param uniqueSuffix string = uniqueString(resourceGroup().id)

// ============================================================
// AĞ KATMANI
// Prowler tarama hedefi + ileride VM eklenirse hazır altyapı
// ============================================================

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${envName}-soc-nsg'
  location: location
  properties: {
    securityRules: [
      {
        // KASITLI ZAYIF YAPILANDIRMA — demo amaçlı
        // Prowler bunu FAIL olarak raporlamalı.
        // NSG soc-subnet'e baglidir; demo ortaminda aktif NIC/VM olmadigi icin gercek endpoint maruziyeti yok.
        name: 'DEMO-Insecure-SSH-Any'
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
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${envName}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.10.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'soc-subnet'
        properties: {
          addressPrefix: '10.10.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

// ============================================================
// DEMO LAB
// Prowler'in gercek bulgu uretmesi icin kasitli yapilandirmalar
// ============================================================

// ZAYIF: public blob erisimi acik, eski TLS, HTTP'ye izin veriyor
resource storageWeak 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'smweak${uniqueSuffix}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}

// GUVENLI: karsilastirma icin, Prowler PASS vermeli
resource storageSecure 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'smsecure${uniqueSuffix}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// Key Vault: purge protection kapali -> Prowler bulgusu
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'sm-kv-${uniqueSuffix}'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    enableRbacAuthorization: true
  }
}

output nsgId string = nsg.id
output weakStorageName string = storageWeak.name
output secureStorageName string = storageSecure.name
output keyVaultName string = kv.name
