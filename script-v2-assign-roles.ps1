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

  # Validaciones de negocio
  [string]$CodApp,
  [ValidateSet('Producción','Certificación','Desarrollo')]
  [string]$Ambiente,

  # Duración
  [ValidateSet('Permanente','Temporal')]
  [string]$DuracionTipo = 'Permanente',
  [string]$FechaInicioPeru,  # "MM/dd/yyyy HH:mm:ss"
  [string]$FechaFinPeru,     # "MM/dd/yyyy HH:mm:ss"

  # Opcional: desactivar chequeo de AssignableScopes
  [switch]$SkipAssignableScopesCheck
)

$global:rolesRestringidos = @(
   "Owner","Contributor","User Access Administrator",
   "Azure File Sync Administrator",
   "Custom_Rol_BotServices_Automation_CDAI_PROD",
   "Custom_Rol_Databricks_Workspace_Automation_CDAI_PROD",
   "Orca Security - Dedicated Resource Group Creator Role v13.00.00 / nc5srtx3f35n4",
   "Orca Security - Key Vault Updater Role v13.00.00 / nc5srtx3f35n4",
   "Reservations Administrator","Access Review Operator Service Role",
   "Role Based Access Control Administrator","Service Group Contributor",
   "Administrador IBM Cloud","Environment Automation","Environment Automation II",
   "Rol Administrador de Accesos","Rol Administrador de Accesos PIM",
   "Administrador Modelo Soporte","Environment Operator APIM",
   "Rol Modificar NSG SOAR","Rol Networking Whitelist - Ambientes Previos",
   "Developer Environment Operator","Environment Operator",
   "Reader Environment Certi","Reader Certi QA"
)
$global:SuscripcionesNoPermitidas = @(
    "DTI - INF - INFR - Servicios Compartidos",
    "Azure EA - Credicorp"
)

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

$script:EnforceAssignableScopes = -not $SkipAssignableScopesCheck

# --------------- Utilitarios ---------------
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

function Test-RoleAssignableToScope {
  param([Parameter(Mandatory=$true)]$RoleDef,[Parameter(Mandatory=$true)][string]$Scope)
  if (-not $script:EnforceAssignableScopes) { return $true }
  if (-not $RoleDef.AssignableScopes -or $RoleDef.AssignableScopes.Count -eq 0) { return $true }
  if ($RoleDef.AssignableScopes -contains "/") { return $true }
  foreach ($a in $RoleDef.AssignableScopes) {
    if ($Scope.StartsWith($a, $true, [Globalization.CultureInfo]::InvariantCulture)) { return $true }
  }
  return $false
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
      $g = Get-AzADGroup -DisplayName $PrincipalName -ErrorAction SilentlyContinue
      if ($g) { return $g.Id }
    }
    'Service Principal' {
      $sp = Get-AzADServicePrincipal -DisplayName $PrincipalName -ErrorAction SilentlyContinue
      if ($sp) { return $sp.Id }
    }
    'Managed Identity' {
      $mi = Get-AzADServicePrincipal -DisplayName $PrincipalName -ErrorAction SilentlyContinue
      if ($mi) { return $mi.Id }
    }
  }
  throw "No se pudo resolver el principal '$PrincipalName' de tipo '$PrincipalType'."
}

function Get-AmbienteFromName {
  param([Parameter(Mandatory=$true)][string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -lt 3) {
    throw "No se puede inferir ambiente desde el nombre '$Name' (muy corto)."
  }
  $ch = $Name.Substring($Name.Length-3,1).ToLower()
  switch ($ch) {
    'd' { return 'Desarrollo' }
    'c' { return 'Certificación' }
    'p' { return 'Producción' }
    default { throw "No se puede inferir ambiente desde '$Name' (carácter '$ch' no válido; use d/c/p)." }
  }
}

function Assert-SameEnvByName {
  param(
    [string]$NameA,[string]$DescA,
    [string]$NameB,[string]$DescB
  )
  $envA = Get-AmbienteFromName -Name $NameA
  $envB = Get-AmbienteFromName -Name $NameB
  if ($envA -ne $envB) {
    throw "$DescA '$NameA' es de '$envA' y $DescB '$NameB' es de '$envB'. La asignación solo procede cuando AMBOS pertenecen al MISMO ambiente."
  }
  return $envA
}

function Assert-ProdEnvByName {
  param([string]$Name,[string]$Desc)
  $env = Get-AmbienteFromName -Name $Name
  if ($env -ne 'Producción') {
    throw "$Desc '$Name' es de '$env'. A nivel de Management Group SOLO se permiten recursos/identidades de PRODUCCIÓN."
  }
  return $true
}

# Prefijos válidos para el NOMBRE de la Managed Identity
$global:AllowedMIPrefixes = @("wapp","wapc","fnct","lapp","azau","dafa","ehub","apim")

function Convert-EnvLetterToName {
  param([char]$ch)
  switch ($ch.ToString().ToLower()) {
    'd' { return 'Desarrollo' }
    'c' { return 'Certificación' }
    'p' { return 'Producción' }
    default { return $null }
  }
}


function Parse-NameParts {
  param([Parameter(Mandatory=$true)][string]$Name)

  $out = [ordered]@{
    Prefix = $null
    Region = $null
    App    = $null
    Env    = $null
    EnvCh  = $null
    Seq    = $null
  }

  if ([string]::IsNullOrWhiteSpace($Name)) { return $out }

  # (d|c|p)\d{2}$ al final
  $mEnv = [regex]::Match($Name, '([dcpDCP])(\d{2})$')
  if (-not $mEnv.Success) { return $out }
  $out.EnvCh = $mEnv.Groups[1].Value.ToLower()
  $out.Env   = Convert-EnvLetterToName -ch $out.EnvCh
  $out.Seq   = $mEnv.Groups[2].Value

  $endIndexBeforeEnv = $mEnv.Index


  $mReg = [regex]::Matches($Name.Substring(0,$endIndexBeforeEnv), '(eu2|cu1)', 'IgnoreCase')
  if ($mReg.Count -gt 0) {
    $last = $mReg[$mReg.Count-1]
    $out.Region = $last.Value.ToLower()


    $out.Prefix = $Name.Substring(0, $last.Index).ToLower()


    $appStart = $last.Index + $last.Length
    $appLen   = $endIndexBeforeEnv - $appStart
    if ($appLen -gt 0) {
      $out.App = $Name.Substring($appStart, $appLen).ToLower()
    }
  }

  return $out
}


function Validate-MI-Resource-Against-RG {
  param(
    [Parameter(Mandatory=$true)][string]$ManagedIdentityName,
    [Parameter(Mandatory=$true)][string]$ResourceName,
    [Parameter(Mandatory=$true)][string]$ResourceType,   
    [Parameter(Mandatory=$true)][string]$ResourceGroupName
  )

  $mi  = Parse-NameParts -Name $ManagedIdentityName
  $rg  = Parse-NameParts -Name $ResourceGroupName
  $res = Parse-NameParts -Name $ResourceName


  $miPrefixOk = $false
  foreach ($p in $global:AllowedMIPrefixes) { if ($mi.Prefix -like "$p*") { $miPrefixOk = $true; break } }
  if (-not $miPrefixOk) {
    throw "La Managed Identity '$ManagedIdentityName' no cumple prefijos permitidos: $($global:AllowedMIPrefixes -join ', ')."
  }

  # Región coherente y solo eu2/cu1
  if ($mi.Region -notin @('eu2','cu1'))                   { throw "Región de MI '$($mi.Region)' no permitida (solo eu2/cu1)." }
  if ($res.Region -and $res.Region -ne $mi.Region)        { throw "La región del recurso '$($res.Region)' difiere de la MI '$($mi.Region)'." }
  if ($rg.Region -and $rg.Region -ne $mi.Region)          { throw "La región del RG '$($rg.Region)' difiere de la MI '$($mi.Region)'." }

  # App coherente
  if ($mi.App -and $rg.App -and ($mi.App -ne $rg.App))    { throw "La app de la MI ('$($mi.App)') no coincide con la del RG ('$($rg.App)')." }
  if ($res.App -and $mi.App -and ($res.App -ne $mi.App))  { throw "La app del recurso ('$($res.App)') no coincide con la de la MI ('$($mi.App)')." }

  # Ambiente coherente
  if ($mi.EnvCh -and $rg.EnvCh -and ($mi.EnvCh -ne $rg.EnvCh))   { throw "El ambiente de la MI ('$($mi.Env)') no coincide con el del RG ('$($rg.Env)')." }
  if ($res.EnvCh -and $mi.EnvCh -and ($res.EnvCh -ne $mi.EnvCh)) { throw "El ambiente del recurso ('$($res.Env)') no coincide con el de la MI ('$($mi.Env)')." }

  # Correlativo (solo aviso si difiere)
  if ($mi.Seq -and $res.Seq -and ($mi.Seq -ne $res.Seq)) {
    Write-Host "⚠️  Aviso: Correlativos distintos entre MI ($($mi.Seq)) y recurso ($($res.Seq))." -ForegroundColor Yellow
  }

  return $true
}


function Invoke-ValidatedRoleAssignment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$CodApp,
    [Parameter(Mandatory=$true)][string]$SubscriptionName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$ServicePrincipalName, 
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  if ($ServicePrincipalName -notmatch 'PRO') { throw "El SP '$ServicePrincipalName' no es de producción (debe contener 'PRO')." }
  $spObj = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction SilentlyContinue
  if (-not $spObj) { throw "El SP '$ServicePrincipalName' no existe." }
  $spId = $spObj.Id
  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
  if ($global:SuscripcionesNoPermitidas -contains $SubscriptionName) { throw "Suscripción '$SubscriptionName' no permitida." }
  Set-AzContext -Subscription $sub.Id -Force | Out-Null
  if ($SubscriptionName -notlike "*$CodApp*") { throw "CodApp '$CodApp' no corresponde a la suscripción '$SubscriptionName'." }
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' restringido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no existe." }
  $scope = "/subscriptions/$($sub.Id)"
  $already = Get-AzRoleAssignment -ObjectId $spId -Scope $scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($already) { return "Ya asignado" }
  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $spId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $scope -ExpirationType AfterDateTime -PrincipalId $spId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}

function Invoke-ValidatedGroupAssignment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$CodApp,
    [Parameter(Mandatory=$true)][string]$SubscriptionName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)][ValidateSet("Cost Management Reader","Dashboard Reader")][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
  if ($global:SuscripcionesNoPermitidas -contains $SubscriptionName) { throw "Suscripción '$SubscriptionName' no permitida." }
  Set-AzContext -Subscription $sub.Id -Force | Out-Null
  if ($SubscriptionName -notlike "*$CodApp*") { throw "CodApp '$CodApp' no corresponde a la suscripción '$SubscriptionName'." }
  $expectedCost  = "POAZ_COSTMANAGEMENT_$CodApp"
  $expectedDash  = "POAZ_DASHBOARD_$CodApp"
  if (($GroupName -ne $expectedCost) -and ($GroupName -ne $expectedDash)) {
    throw "Grupo '$GroupName' inválido. Debe ser '$expectedCost' o '$expectedDash'."
  }
  if ($GroupName -eq $expectedCost  -and $RoleName -ne "Cost Management Reader") { throw "Grupo requiere rol 'Cost Management Reader'." }
  if ($GroupName -eq $expectedDash  -and $RoleName -ne "Dashboard Reader")       { throw "Grupo requiere rol 'Dashboard Reader'." }
  $grp = Get-AzADGroup -DisplayName $GroupName -ErrorAction SilentlyContinue
  if (-not $grp) { throw "Grupo '$GroupName' no existe." }
  $groupId = $grp.Id
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' restringido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no disponible." }
  $scope = "/subscriptions/$($sub.Id)"
  $assigned = Get-AzRoleAssignment -ObjectId $groupId -Scope $scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }
  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $groupId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $scope -ExpirationType AfterDateTime -PrincipalId $groupId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}

function Invoke-ValidatedGroupAssignmentRG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$CodApp,[Parameter(Mandatory=$true)][string]$SubscriptionName,
    [Parameter(Mandatory=$true)][string]$ResourceGroupName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción","Certificación","Desarrollo")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
  Set-AzContext -Subscription $sub.Id -Force | Out-Null
  if ($ResourceGroupName -notlike "*$CodApp*") { throw "CodApp '$CodApp' no corresponde al RG '$ResourceGroupName'." }
  $rgObj = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
  if (-not $rgObj) { throw "El RG '$ResourceGroupName' no existe." }
  if (-not $rgObj.Tags.ContainsKey("environment")) { throw "El RG no tiene tag 'environment'." }
  $tagValue = "$($rgObj.Tags["environment"])".ToLower()
  switch ($tagValue) { "prod" { $ambEsperado="Producción" } "desa" { $ambEsperado="Desarrollo" } "cert" { $ambEsperado="Certificación" } default { throw "Tag 'environment' inválido." } }
  if ($ambEsperado -ne $Ambiente) { throw "RG '$ResourceGroupName' no corresponde al ambiente '$Ambiente' (tag: '$ambEsperado')." }
  if ($GroupName -notmatch "POAZ") { throw "Grupo '$GroupName' debe contener 'POAZ'." }
  if ($GroupName -notmatch [regex]::Escape($CodApp)) { throw "Grupo '$GroupName' no corresponde a '$CodApp'." }

  $grupoDev    = "POAZ_DEV_${CodApp}_DESA"
  $grupoLTDev  = "POAZ_LT_${CodApp}_DESA"
  $grupoLTcert = "POAZ_LT_${CodApp}_CERT"
  $grupoQAcert = "POAZ_QA_${CodApp}_CERT"
  $rolDev      = "Developer Environment Operator"
  $rolDevLT    = "Environment Operator"
  $rolCertLT   = "Reader Environment Certi"
  $rolCertQA   = "Reader Certi QA"

  if ($Ambiente -eq "Desarrollo") {
    if ($RoleName -notin @($rolDev,$rolDevLT)) { throw "Rol inválido para Desarrollo." }
    if ($RoleName -eq $rolDev   -and $GroupName -ne $grupoDev)   { throw "Rol '$rolDev' solo para '$grupoDev'." }
    if ($RoleName -eq $rolDevLT -and $GroupName -ne $grupoLTDev) { throw "Rol '$rolDevLT' solo para '$grupoLTDev'." }
  }
  if ($Ambiente -eq "Certificación") {
    if ($RoleName -notin @($rolCertLT,$rolCertQA)) { throw "Rol inválido para Certificación." }
    if ($RoleName -eq $rolCertQA -and $GroupName -ne $grupoQAcert) { throw "Rol '$rolCertQA' solo para '$grupoQAcert'." }
    if ($RoleName -eq $rolCertLT -and $GroupName -ne $grupoLTcert) { throw "Rol '$rolCertLT' solo para '$grupoLTcert'." }
  }

  $okSuffix =
    ($GroupName -like '*_prod_poaz' -and $Ambiente -eq 'Producción') -or
    ($GroupName -like '*_cert_poaz' -and $Ambiente -eq 'Certificación') -or
    ($GroupName -like '*_desa_poaz' -and $Ambiente -eq 'Desarrollo')
  if (-not $okSuffix) { throw "Sufijo del grupo no coincide con el ambiente." }

  $grp = Get-AzADGroup -DisplayName $GroupName -ErrorAction SilentlyContinue
  if (-not $grp) { throw "Grupo '$GroupName' no existe." }
  $groupId = $grp.Id
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' no permitido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no disponible." }

  $assigned = Get-AzRoleAssignment -ObjectId $groupId -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }

  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $groupId -RoleDefinitionName $RoleName -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope "/subscriptions/$($sub.Id)/resourceGroups/$ResourceGroupName" -ExpirationType AfterDateTime -PrincipalId $groupId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}

function Invoke-ValidatedGroupAssignmentMG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$ManagementGroupName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  if ($GroupName -notlike 'POAZ_*') { throw "Grupo '$GroupName' debe ser 'POAZ_*'." }
  if ($GroupName -notlike 'POAZ_SOPORTE_*' -and $GroupName -notlike 'POAZ_OPERATOR_*' -and $GroupName -notlike 'POAZ_READER_*' -and $GroupName -notlike 'POAZ_NET_*') {
    throw "Grupo '$GroupName' no es POAZ cross válido."
  }
  if ($GroupName -notlike '*_PROD') { throw "Grupo '$GroupName' debe terminar en '_PROD'." }
  $grp = Get-AzADGroup -DisplayName $GroupName -ErrorAction SilentlyContinue
  if (-not $grp) { throw "Grupo '$GroupName' no existe." }
  $groupId = $grp.Id
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' restringido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no existe." }

  $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
  $assigned = Get-AzRoleAssignment -ObjectId $groupId -Scope $scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }

  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $groupId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $scope -ExpirationType AfterDateTime -PrincipalId $groupId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}

function Invoke-ValidatedSPAssignmentMG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$ManagementGroupName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$ServicePrincipalName,
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  $spObj = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction SilentlyContinue
  if (-not $spObj) { throw "SP '$ServicePrincipalName' no existe." }
  if ($ServicePrincipalName -notmatch "PRO") { throw "SP '$ServicePrincipalName' debe contener 'PRO'." }
  $spId = $spObj.Id
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' restringido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no existe." }
  $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
  $assigned = Get-AzRoleAssignment -ObjectId $spId -Scope $scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }
  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $spId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $scope -ExpirationType AfterDateTime -PrincipalId $spId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}

function Invoke-ValidatedSPAssignmentRG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$CodApp,[Parameter(Mandatory=$true)][string]$SubscriptionName,
    [Parameter(Mandatory=$true)][string]$ResourceGroupName,
    [Parameter(Mandatory=$true)][ValidateSet("Producción","Certificación","Desarrollo")][string]$Ambiente,
    [Parameter(Mandatory=$true)][string]$ServicePrincipalName,
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][ValidateSet("Permanente","Temporal")][string]$DuracionTipo,
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )
  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
  Set-AzContext -Subscription $sub.Id -Force | Out-Null
  if ($ResourceGroupName -notlike "*$CodApp*") { throw "CodApp '$CodApp' no corresponde al RG '$ResourceGroupName'." }
  $rgObj = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
  if (-not $rgObj) { throw "El RG '$ResourceGroupName' no existe." }
  if (-not $rgObj.Tags.ContainsKey("environment")) { throw "El RG no tiene tag 'environment'." }
  $tagValue = "$($rgObj.Tags["environment"])".ToLower()
  switch ($tagValue) { "prod" { $ambEsperado="Producción" } "desa" { $ambEsperado="Desarrollo" } "cert" { $ambEsperado="Certificación" } default { throw "Tag 'environment' inválido." } }
  if ($ambEsperado -ne $Ambiente) { throw "RG '$ResourceGroupName' no corresponde al ambiente '$Ambiente' (tag: '$ambEsperado')." }
  switch ($Ambiente) {
    "Desarrollo"    { if ($ServicePrincipalName -notmatch "des") { throw "SP '$ServicePrincipalName' no corresponde a Desarrollo." } }
    "Certificación" { if ($ServicePrincipalName -notmatch "cer") { throw "SP '$ServicePrincipalName' no corresponde a Certificación." } }
    "Producción"    { if ($ServicePrincipalName -notmatch "pro") { throw "SP '$ServicePrincipalName' no corresponde a Producción." } }
  }
  $spObj = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction SilentlyContinue
  if (-not $spObj) { throw "SP '$ServicePrincipalName' no existe en Entra ID." }
  $spId = $spObj.Id
  if ($global:rolesRestringidos -contains $RoleName) { throw "Rol '$RoleName' no permitido." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "Rol '$RoleName' no disponible." }
  $assigned = Get-AzRoleAssignment -ObjectId $spId -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }
  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $spId -RoleDefinitionName $RoleName -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Out-Null
    return "Asignado permanente"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, provee fechas Perú." }
    $win = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolGuid = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope "/subscriptions/$($sub.Id)/resourceGroups/$ResourceGroupName" -ExpirationType AfterDateTime -PrincipalId $spId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolGuid" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal"
  }
}


function Invoke-ValidatedMIAssignmentResource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$SubscriptionName,
    [Parameter(Mandatory=$true)][string]$ResourceGroupName,
    [Parameter(Mandatory=$true)][string]$ManagedIdentityName,   
    [Parameter(Mandatory=$true)][string]$RoleName,
    [Parameter(Mandatory=$true)][string]$ResourceName,          
    [Parameter(Mandatory=$true)][string]$ResourceType,          
    [string]$SubresourceId,
    [ValidateSet("Permanente","Temporal")][string]$DuracionTipo = "Permanente",
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )

  $ResourceType = Resolve-ResourceType -InputType $ResourceType


  $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
  if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
  Set-AzContext -Subscription $sub.Id -Force | Out-Null

  # 2) Validaciones (solo región/app/ambiente)
  Validate-MI-Resource-Against-RG -ManagedIdentityName $ManagedIdentityName `
                                  -ResourceName        $ResourceName `
                                  -ResourceType        $ResourceType `
                                  -ResourceGroupName   $ResourceGroupName | Out-Null

  # 3) Misma letra de ambiente por estándar (extra)
  $ambEfectivo = Assert-SameEnvByName -NameA $ManagedIdentityName -DescA "La Managed Identity" `
                                      -NameB $ResourceName        -DescB "el recurso destino"

  # 4) Resolver MI en Entra ID
  $miSp = Get-AzADServicePrincipal -DisplayName $ManagedIdentityName -ErrorAction SilentlyContinue
  if (-not $miSp) { throw "La Managed Identity '$ManagedIdentityName' no existe en Entra ID." }
  $miId = $miSp.Id

  # 5) Rol permitido + disponible
  if ($global:rolesRestringidos -contains $RoleName) { throw "El rol '$RoleName' no está permitido por este medio." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "El rol '$RoleName' no existe / no está disponible." }

  # 6) ResourceId
  $resourceId = if ($SubresourceId) {
    $SubresourceId
  } else {
    "/subscriptions/$($sub.Id)/resourceGroups/$ResourceGroupName/providers/$ResourceType/$ResourceName"
  }
  $resource = Get-AzResource -ResourceId $resourceId -ErrorAction SilentlyContinue
  if (-not $resource) { throw "Recurso no existe: $resourceId" }

  # 7) Assignable scopes
  if (-not (Test-RoleAssignableToScope -RoleDef $roleDef -Scope $resourceId)) {
    throw "El rol '$RoleName' no es asignable al scope del recurso."
  }

  # 8) Evitar duplicados
  $assigned = Get-AzRoleAssignment -ObjectId $miId -Scope $resourceId -ErrorAction SilentlyContinue `
              | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado ($ambEfectivo)" }

  # 9) Asignar
  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $miId -RoleDefinitionName $RoleName -Scope $resourceId -ErrorAction Stop | Out-Null
    return "Asignado permanente ($ambEfectivo)"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) {
      throw "Para Temporal, especifica FechaInicioPeru/FechaFinPeru (Perú)."
    }
    $win   = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolId = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal (MI) automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $resourceId -ExpirationType AfterDateTime `
      -PrincipalId $miId -RequestType AdminAssign `
      -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolId" `
      -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) `
      -Justification $just | Out-Null
    return "Asignado temporal ($ambEfectivo)"
  }
}

function Invoke-ValidatedMIAssignmentMG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$ManagementGroupName,
    [Parameter(Mandatory=$true)][string]$ManagedIdentityName, 
    [Parameter(Mandatory=$true)][string]$RoleName,
    [ValidateSet("Permanente","Temporal")][string]$DuracionTipo = "Permanente",
    [string]$FechaInicioPeru,[string]$FechaFinPeru
  )

  Assert-ProdEnvByName -Name $ManagedIdentityName -Desc "La Managed Identity"

  $miSp = Get-AzADServicePrincipal -DisplayName $ManagedIdentityName -ErrorAction SilentlyContinue
  if (-not $miSp) { throw "La Managed Identity '$ManagedIdentityName' no existe en Entra ID." }
  $miId = $miSp.Id

  if ($global:rolesRestringidos -contains $RoleName) { throw "El rol '$RoleName' no está permitido por este medio." }
  $roleDef = Get-AzRoleDefinition | Where-Object { $_.Name -eq $RoleName }
  if (-not $roleDef) { throw "El rol '$RoleName' no existe a nivel MG/tenant." }

  $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"

  $assigned = Get-AzRoleAssignment -ObjectId $miId -Scope $scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if ($assigned) { return "Ya asignado" }

  if ($DuracionTipo -eq "Permanente") {
    New-AzRoleAssignment -ObjectId $miId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop | Out-Null
    return "Asignado permanente (Producción)"
  } else {
    if (-not $FechaInicioPeru -or -not $FechaFinPeru) { throw "Para Temporal, especifica FechaInicioPeru/FechaFinPeru (Perú)." }
    $win   = Convert-PeruTextToUtcWindow -StartPeruText $FechaInicioPeru -EndPeruText $FechaFinPeru
    $rolId = (Get-AzRoleDefinition -Name $RoleName).Id
    $guid  = [guid]::NewGuid().ToString()
    $just  = "Asignación de rol temporal (MI) en MG automatizada"
    New-AzRoleAssignmentScheduleRequest -Name $guid -Scope $scope -ExpirationType AfterDateTime -PrincipalId $miId -RequestType AdminAssign -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$rolId" -ScheduleInfoStartDateTime $($win.StartIso8601) -ExpirationEndDateTime $($win.EndIso8601) -Justification $just | Out-Null
    return "Asignado temporal (Producción)"
  }
}


Write-Host "== Iniciando Role Assignment CI ==" -ForegroundColor Cyan


try {
  $ctx = Get-AzContext
  if (-not $ctx) { throw "No hay contexto de Azure. Ejecuta 'azure/login@v2' con enable-AzPSSession:true antes de llamar este script." }
  Write-Host "Azure Context OK - Tenant: $($ctx.Tenant.Id)" -ForegroundColor Green
} catch {
  throw $_
}

# Dispatcher
if ($Action -eq 'Assign') {

  switch ($ScopeType) {

    'Resource' {
      if ([string]::IsNullOrWhiteSpace($SubscriptionName) -or
          [string]::IsNullOrWhiteSpace($ResourceGroupName) -or
          [string]::IsNullOrWhiteSpace($ResourceType) -or
          [string]::IsNullOrWhiteSpace($ResourceName)) {
        throw "Para ScopeType=Resource debes indicar SubscriptionName, ResourceGroupName, ResourceType y ResourceName."
      }

      if ($PrincipalType -eq 'Grupo de Red') {
        if (-not $CodApp -or -not $Ambiente) { throw "Para Grupo de Red a nivel Recurso indica CodApp y Ambiente." }
        $null = Invoke-ValidatedGroupAssignmentResource -CodApp $CodApp -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -Ambiente $Ambiente -GroupName $PrincipalName -RoleName $RoleName -ResourceName $ResourceName -ResourceType $ResourceType -SubresourceId $SubresourceId -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (Recurso – Grupo de Red)."

      } elseif ($PrincipalType -eq 'Service Principal') {
        if (-not $CodApp -or -not $Ambiente) { throw "Para Service Principal a nivel Recurso indica CodApp y Ambiente." }
        $null = Invoke-ValidatedSPAssignmentResource -CodApp $CodApp -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -Ambiente $Ambiente -ServicePrincipalName $PrincipalName -RoleName $RoleName -ResourceName $ResourceName -ResourceType $ResourceType -SubresourceId $SubresourceId -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (Recurso – Service Principal)."

      } elseif ($PrincipalType -eq 'Managed Identity') {
        $null = Invoke-ValidatedMIAssignmentResource -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -ManagedIdentityName $PrincipalName -RoleName $RoleName -ResourceName $ResourceName -ResourceType $ResourceType -SubresourceId $SubresourceId -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (Recurso – Managed Identity)."

      } else {
        throw "Validación avanzada no implementada para PrincipalType '$PrincipalType' en Resource."
      }
    }

    'ResourceGroup' {
      # Managed Identity NO permitido a nivel RG
      if ($PrincipalType -eq 'Managed Identity') {
        throw "Managed Identity NO está permitido a nivel de Resource Group. Usa scope Resource o ManagementGroup."
      }

      if ([string]::IsNullOrWhiteSpace($SubscriptionName) -or [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw "Para ScopeType=ResourceGroup debes indicar SubscriptionName y ResourceGroupName."
      }
      if ($PrincipalType -eq 'Grupo de Red') {
        if (-not $CodApp -or -not $Ambiente) { throw "Para Grupo de Red en RG indica CodApp y Ambiente." }
        $null = Invoke-ValidatedGroupAssignmentRG -CodApp $CodApp -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -Ambiente $Ambiente -GroupName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (RG – Grupo de Red)."
      } elseif ($PrincipalType -eq 'Service Principal') {
        if (-not $CodApp -or -not $Ambiente) { throw "Para Service Principal en RG indica CodApp y Ambiente." }
        $null = Invoke-ValidatedSPAssignmentRG -CodApp $CodApp -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -Ambiente $Ambiente -ServicePrincipalName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (RG – Service Principal)."
      } else {
        throw "Validación avanzada no implementada para PrincipalType '$PrincipalType' en ResourceGroup."
      }
    }

    'Subscription' {
      # Managed Identity NO permitido a nivel de Subscription
      if ($PrincipalType -eq 'Managed Identity') {
        throw "Managed Identity NO está permitido a nivel de Suscripción. Usa scope Resource o ManagementGroup."
      }

      if ([string]::IsNullOrWhiteSpace($SubscriptionName)) {
        throw "Para ScopeType=Subscription debes indicar SubscriptionName."
      }
      if ($PrincipalType -eq 'Service Principal') {
        if (-not $CodApp) { throw "Para SP en Subscription indica CodApp." }
        $null = Invoke-ValidatedRoleAssignment -CodApp $CodApp -SubscriptionName $SubscriptionName -Ambiente 'Producción' -ServicePrincipalName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (Subscription – SP)."
      } elseif ($PrincipalType -eq 'Grupo de Red') {
        $null = Invoke-ValidatedGroupAssignment -CodApp $CodApp -SubscriptionName $SubscriptionName -Ambiente 'Producción' -GroupName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (Subscription – Grupo de Red)."
      } else {
        throw "Validación avanzada no implementada para PrincipalType '$PrincipalType' en Subscription."
      }
    }

    'ManagementGroup' {
      if ([string]::IsNullOrWhiteSpace($ManagementGroupName)) {
        throw "Para ScopeType=ManagementGroup debes indicar ManagementGroupName."
      }
      if ($PrincipalType -eq 'Grupo de Red') {
        $null = Invoke-ValidatedGroupAssignmentMG -ManagementGroupName $ManagementGroupName -Ambiente 'Producción' -GroupName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (MG – Grupo de Red)."
      } elseif ($PrincipalType -eq 'Service Principal') {
        $null = Invoke-ValidatedSPAssignmentMG -ManagementGroupName $ManagementGroupName -Ambiente 'Producción' -ServicePrincipalName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (MG – Service Principal)."
      } elseif ($PrincipalType -eq 'Managed Identity') {
        $null = Invoke-ValidatedMIAssignmentMG -ManagementGroupName $ManagementGroupName -ManagedIdentityName $PrincipalName -RoleName $RoleName -DuracionTipo $DuracionTipo -FechaInicioPeru $FechaInicioPeru -FechaFinPeru $FechaFinPeru
        Write-Host "✅ Asignación completada (MG – Managed Identity: SOLO Producción)."
      } else {
        throw "Validación avanzada no implementada para PrincipalType '$PrincipalType' en ManagementGroup."
      }
    }
  }

} elseif ($Action -eq 'Remove') {
  # Eliminación genérica (sin validaciones de negocio)
  $principalId = Get-PrincipalId -PrincipalType $PrincipalType -PrincipalName $PrincipalName

  switch ($ScopeType) {
    'ManagementGroup' {
      if (-not $ManagementGroupName) { throw "Falta ManagementGroupName." }
      $scopePath = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
    }
    'Subscription' {
      if (-not $SubscriptionName) { throw "Falta SubscriptionName." }
      if ($PrincipalType -eq 'Managed Identity') {
        throw "Managed Identity NO está permitido a nivel de Suscripción (Remove)."
      }
      $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
      if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
      $scopePath = "/subscriptions/$($sub.Id)"
    }
    'ResourceGroup' {
      if (-not $SubscriptionName -or -not $ResourceGroupName) { throw "Faltan SubscriptionName/ResourceGroupName." }
      if ($PrincipalType -eq 'Managed Identity') {
        throw "Managed Identity NO está permitido a nivel de Resource Group (Remove)."
      }
      $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
      if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
      $scopePath = "/subscriptions/$($sub.Id)/resourceGroups/$ResourceGroupName"
    }
    'Resource' {
      if (-not $SubscriptionName -or -not $ResourceGroupName -or -not $ResourceName -or -not $ResourceType) {
        throw "Para eliminar en Resource indica SubscriptionName, ResourceGroupName, ResourceType, ResourceName (o SubresourceId)."
      }
      $ResourceType = Resolve-ResourceType -InputType $ResourceType
      $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction SilentlyContinue
      if (-not $sub) { throw "La suscripción '$SubscriptionName' no existe." }
      $scopePath = if ($SubresourceId) { $SubresourceId } else { "/subscriptions/$($sub.Id)/resourceGroups/$ResourceGroupName/providers/$ResourceType/$ResourceName" }
    }
  }

  $existing = Get-AzRoleAssignment -Scope $scopePath -ObjectId $principalId -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $RoleName }
  if (-not $existing) {
    Write-Host "No existe asignación de '$RoleName' para el principal en el scope." -ForegroundColor Yellow
  } else {
    Remove-AzRoleAssignment -RoleDefinitionName $RoleName -ObjectId $principalId -Scope $scopePath -ErrorAction Stop
    Write-Host "🗑️  Asignación eliminada correctamente." -ForegroundColor Green
  }
}

Write-Host "== Finalizado ==" -ForegroundColor Cyan
