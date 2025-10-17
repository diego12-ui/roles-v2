param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('Assign','Remove')]
  [string]$Action,

  [Parameter(Mandatory=$true)]
  [ValidateSet('Grupo de Red','Service Principal','Managed Identity')]
  [string]$PrincipalType,
  [Parameter(Mandatory=$true)]
  [string]$PrincipalName,

  [Parameter(Mandatory=$true)]
  [ValidateSet('ManagementGroup','Subscription','ResourceGroup','Resource')]
  [string]$ScopeType,
  [string]$ManagementGroupName,
  [string]$SubscriptionName,
  [string]$ResourceGroupName,
  [string]$ResourceType, 
  [string]$ResourceName,
  [string]$SubresourceId,

  # Rol
  [Parameter(Mandatory=$true)]
  [string]$RoleName,

  # (Sin uso de negocio) CodApp / Ambiente ya no se validan
  [string]$CodApp,
  [ValidateSet('Producción','Certificación','Desarrollo')]
  [string]$Ambiente,

  # Duración
  [ValidateSet('Permanente','Temporal')]
  [string]$DuracionTipo = 'Permanente',
  [string]$FechaInicioPeru,  # "MM/dd/yyyy HH:mm:ss"
  [string]$FechaFinPeru      # "MM/dd/yyyy HH:mm:ss"
)

# --- Mapa simple de tipos (opcional)
$global:AzureResourceTypeMap = @{
  "API Management"               = "Microsoft.ApiManagement/service"
  "App Service plan"             = "Microsoft.Web/serverfarms"
  "Application gateway"          = "Microsoft.Network/applicationGateways"
  "Application Insights"         = "Microsoft.Insights/components"
  "Azure Function"               = "Microsoft.Web/sites"
  "Automation Account"           = "Microsoft.Automation/automationAccounts"
  "Container registry"           = "Microsoft.ContainerRegistry/registries"
  "Databricks"                   = "Microsoft.Databricks/workspaces"
  "DNS zone"                     = "Microsoft.Network/dnszones"
  "Event Hub"                    = "Microsoft.EventHub/namespaces"
  "Event Grid Topic"             = "Microsoft.EventGrid/topics"
  "Event Grid System Topic"      = "Microsoft.EventGrid/systemTopics"
  "Front Door and CDN profile"   = "Microsoft.Cdn/profiles"
  "Kubernetes service"           = "Microsoft.ContainerService/managedClusters"
  "Key vault"                    = "Microsoft.KeyVault/vaults"
  "Storage account"              = "Microsoft.Storage/storageAccounts"
  "SQL server"                   = "Microsoft.Sql/servers"
  "Cosmos DB"                    = "Microsoft.DocumentDB/databaseAccounts"
  "Cache for Redis"              = "Microsoft.Cache/Redis"
  "Web App"                      = "Microsoft.Web/sites"
  "Virtual network"              = "Microsoft.Network/virtualNetworks"
  "Data factory"                 = "Microsoft.DataFactory/factories"
  "Log Analytics"                = "Microsoft.OperationalInsights/workspaces"
  "Logic app"                    = "Microsoft.Logic/workflows"
  "Virtual machine"              = "Microsoft.Compute/virtualMachines"
  "Azure Bot"                    = "Microsoft.BotService/botServices"
}

function Resolve-ResourceType {
  param([string]$InputType)
  if ([string]::IsNullOrWhiteSpace($InputType)) { return $null }
  if ($global:AzureResourceTypeMap.ContainsKey($InputType)) { return $global:AzureResourceTypeMap[$InputType] }
  return $InputType
}

function Convert-PeruTextToUtcWindow {
  param(
    [Parameter(Mandatory=$true)][string]$StartPeruText,
    [Parameter(Mandatory=$true)][string]$EndPeruText
  )
  $startTrim = $StartPeruText -replace '\.\d{3}-\d{4}$',''
  $endTrim   = $EndPeruText   -replace '\.\d{3}-\d{4}$',''
  $fmt = "MM/dd/yyyy HH:mm:ss"
  $startLocal = [datetime]::ParseExact($startTrim, $fmt, $null)
  $endLocal   = [datetime]::ParseExact($endTrim,   $fmt, $null)
  $tzPeru = [System.TimeZoneInfo]::FindSystemTimeZoneById("SA Pacific Standard Time")
  $startUtc = [System.TimeZoneInfo]::ConvertTimeToUtc($startLocal, $tzPeru)
  $endUtc   = [System.TimeZoneInfo]::ConvertTimeToUtc($endLocal,   $tzPeru)
  [pscustomobject]@{
    StartUtc     = $startUtc
    EndUtc       = $endUtc
    StartIso8601 = (Get-Date $startUtc -Format o)
    EndIso8601   = (Get-Date $endUtc   -Format o)
    StartPeru    = $startLocal
    EndPeru      = $endLocal
  }
}

function Get-PrincipalId {
  param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Grupo de Red','Service Principal','Managed Identity')]
    [string]$PrincipalType,
    [Parameter(Mandatory=$true)][string]$PrincipalName
  )
  switch ($PrincipalType) {
    'Grupo de Red' {
      (Get-AzADGroup -DisplayName $PrincipalName -ErrorAction Stop).Id
    }
    'Service Principal' { 
      (Get-AzADServicePrincipal -DisplayName $PrincipalName -ErrorAction Stop).Id
    }
    'Managed Identity' {
      # Las MIs aparecen como Service Principals en Entra ID
      (Get-AzADServicePrincipal -DisplayName $PrincipalName -ErrorAction Stop).Id
    }
  }
}

Write-Host "== Iniciando Role Assignment (simple) ==" -ForegroundColor Cyan

# Contexto opcional si se indica suscripción
if ($SubscriptionName) {
  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if ($sub) { Set-AzContext -Subscription $sub.Id -Force | Out-Null }
}

# Construir scope path según ScopeType
function Get-ScopePath {
  param()
  switch ($ScopeType) {
    'ManagementGroup' {
      if (-not $ManagementGroupName) { throw "Para ManagementGroup indica ManagementGroupName." }
      "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
    }
    'Subscription' {
      if (-not $SubscriptionName) { throw "Para Subscription indica SubscriptionName." }
      $s = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop
      "/subscriptions/$($s.Id)"
    }
    'ResourceGroup' {
      if (-not $SubscriptionName -or -not $ResourceGroupName) { throw "Para ResourceGroup indica SubscriptionName y ResourceGroupName." }
      $s = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop
      "/subscriptions/$($s.Id)/resourceGroups/$ResourceGroupName"
    }
    'Resource' {
      if (-not $SubscriptionName -or -not $ResourceGroupName -or (-not $SubresourceId -and (-not $ResourceType -or -not $ResourceName))) {
        throw "Para Resource indica SubscriptionName, ResourceGroupName y (ResourceType+ResourceName) o SubresourceId."
      }
      if ($SubresourceId) { 
        $SubresourceId 
      } else {
        $rt = Resolve-ResourceType -InputType $ResourceType
        $s  = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop
        "/subscriptions/$($s.Id)/resourceGroups/$ResourceGroupName/providers/$rt/$ResourceName"
      }
    }
  }
}

# Obtener principal y role definition
$principalId = Get-PrincipalId -PrincipalType $PrincipalType -PrincipalName $PrincipalName
$roleDef     = Get-AzRoleDefinition -Name $RoleName -ErrorAction Stop
$roleDefId   = $roleDef.Id

if ($Action -eq 'Assign') {
  $scopePath = Get-ScopePath

  if ($DuracionTipo -eq 'Permanente') {
    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName $RoleName -Scope $scopePath -ErrorAction Stop | Out-Null
    Write-Host "✅ Asignado (permanente) -> $RoleName @ $scopePath" -ForegroundColor Green
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) {
      throw "Para asignación Temporal especifica FechaInicioPeru y FechaFinPeru (formato 'MM/dd/yyyy HH:mm:ss')."
    }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $reqId = [guid]::NewGuid().ToString()
    $rdPath = "/providers/Microsoft.Authorization/roleDefinitions/$roleDefId"
    New-AzRoleAssignmentScheduleRequest `
      -Name $reqId `
      -Scope $scopePath `
      -ExpirationType AfterDateTime `
      -PrincipalId $principalId `
      -RequestType AdminAssign `
      -RoleDefinitionId $rdPath `
      -ScheduleInfoStartDateTime $($win.StartIso8601) `
      -ExpirationEndDateTime $($win.EndIso8601) `
      -Justification "Asignación temporal automática (sin validaciones)" | Out-Null
    Write-Host "✅ Asignado (temporal) -> $RoleName @ $scopePath" -ForegroundColor Green
  }

} elseif ($Action -eq 'Remove') {
  $scopePath = Get-ScopePath
  try {
    # Intento directo (sin chequear existencia previa)
    Remove-AzRoleAssignment -RoleDefinitionName $RoleName -ObjectId $principalId -Scope $scopePath -ErrorAction Stop
    Write-Host "🗑️  Eliminado -> $RoleName @ $scopePath" -ForegroundColor Green
  } catch {
    Write-Host "ℹ️ No se pudo eliminar (quizá no existía): $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

Write-Host "== Finalizado ==" -ForegroundColor Cyan
