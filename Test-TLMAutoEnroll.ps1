<#
.SYNOPSIS
  Remotely validates DigiCert Trust Lifecycle Manager Auto‑Enrollment server configuration
  for Device, Server, User Authentication templates in an ADCS‐managed environment.

.DESCRIPTION
  Checks the TLM (AutoEnrollment Server) service, log files, event logs, registry settings,
  group memberships, certificate template publication/permissions, and subject mapping (AD attributes).
  Ideal for troubleshooting failures like "malformed template" or corrupted attribute mappings.

.PARAMETER ComputerName
  Fully qualified hostname(s) of the AutoEnrollment (TLM) server(s) to test, can be piped.

.PARAMETER TemplateDeviceAuth
  Name of the certificate template used for Device Authentication (machine cert autoenrollment).

.PARAMETER TemplateServerAuth
  Name of the certificate template used for Domain Controller / Server Authentication.

.PARAMETER TemplateUserAuth
  Name of the certificate template used for User Client Authentication.

.PARAMETER Username
  The user principal to test for user certificate mapping.

.PARAMETER LogPath
  Full path to write a named log with timestamp prefix.

.PARAMETER Credential
  Credentials for remote server access. If not provided, uses current user context.

.PARAMETER TimeoutSeconds
  Timeout for remote operations in seconds. Default is 60.

.INPUTS
  [string] computer name(s). Accepts pipeline input.

.OUTPUTS
  PSCustomObject per ComputerName with comprehensive diagnostic results.

.EXAMPLE
  'aesrv1','aesrv2' | Test‑TLM‑AutoEnroll `
    -TemplateDeviceAuth DeviceAuth_TLM `
    -TemplateServerAuth ServerAuth_TLM `
    -TemplateUserAuth UserAuth_TLM `
    -Username jdohler `
    -LogPath C:\Logs\AES‐AutoEnroll‐2025_08_04.log

#>

[CmdletBinding(DefaultParameterSetName='HostName')]
param(
  [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
  [ValidateNotNullOrEmpty()]
  [string[]]$ComputerName,

  [Parameter(Mandatory=$true)] [string]$TemplateDeviceAuth,
  [Parameter(Mandatory=$true)] [string]$TemplateServerAuth,
  [Parameter(Mandatory=$true)] [string]$TemplateUserAuth,
  [Parameter(Mandatory=$true)] [string]$Username,
  
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$LogPath = "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_TLM-AutoEnroll.log",
  
  [Parameter()]
  [System.Management.Automation.PSCredential]$Credential,
  
  [Parameter()]
  [ValidateRange(10,300)]
  [int]$TimeoutSeconds = 60
)

begin {
  # Ensure Output Encoding supports Unicode
  $PSDefaultParameterValues['*:Encoding'] = 'utf8'
  
  # Initialize global log file
  $script:LogFile = Join-Path (Get-Location) $LogPath
  "" | Out-File -FilePath $script:LogFile -Force
  
  # Enhanced logging helper with error handling
  function Write-Log {
    param(
      [Parameter(Mandatory)][string]$Message,
      [Parameter()][ValidateSet('INFO','WARN','ERROR','DEBUG')] [string]$Level = 'INFO',
      [Parameter()][string]$LogFile = $script:LogFile
    )
    
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"
    
    $color = switch ($Level) {
      'INFO' { 'White' }
      'WARN' { 'Yellow' }
      'ERROR' { 'Red' }
      'DEBUG' { 'Gray' }
    }
    
    Write-Host $line -ForegroundColor $color
    
    try {
      Add-Content -Path $LogFile -Value $line -ErrorAction Stop
    } catch {
      Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
  }

  # Network connectivity test
  function Test-RemoteConnectivity {
    param(
      [Parameter(Mandatory)][string]$ComputerName,
      [Parameter()][int]$TimeoutSeconds = 10
    )
    
    try {
      $result = Test-Connection -ComputerName $ComputerName -Count 1 -TimeoutSeconds $TimeoutSeconds -Quiet
      if ($result) {
        Write-Log "Network connectivity to ${ComputerName}: OK" DEBUG
        return $true
      } else {
        Write-Log "Network connectivity to ${ComputerName}: FAILED" ERROR
        return $false
      }
    } catch {
      Write-Log "Network connectivity test failed: $($_.Exception.Message)" ERROR
      return $false
    }
  }

  # Enhanced remote command execution with proper error handling
  function Invoke-RemoteCommand {
    param(
      [Parameter(Mandatory)][string]$ComputerName,
      [Parameter(Mandatory)][scriptblock]$ScriptBlock,
      [Parameter()][object[]]$ArgumentList = @(),
      [Parameter()][System.Management.Automation.PSCredential]$Credential,
      [Parameter()][int]$TimeoutSeconds = 60,
      [Parameter()][string]$Description = "Remote command"
    )
    
    $invokeParams = @{
      ComputerName = $ComputerName
      ScriptBlock = $ScriptBlock
      ErrorAction = 'Stop'
      ConnectionTimeout = $TimeoutSeconds
      OperationTimeout = $TimeoutSeconds
    }
    
    if ($ArgumentList.Count -gt 0) {
      $invokeParams.ArgumentList = $ArgumentList
    }
    
    if ($Credential) {
      $invokeParams.Credential = $Credential
    }
    
    try {
      Write-Log "$Description on $ComputerName" DEBUG
      return Invoke-Command @invokeParams
    } catch {
      Write-Log "$Description failed on $ComputerName`: $($_.Exception.Message)" ERROR
      throw
    }
  }

  Write-Log "Starting TLM auto-enrollment diagnostic check" INFO
  Write-Log "Target templates: Device=$TemplateDeviceAuth, Server=$TemplateServerAuth, User=$TemplateUserAuth" INFO
  Write-Log "Test user: $Username" INFO
}

process {
  foreach ($cn in $ComputerName) {
    # Enhanced result object with error categorization
    $res = [pscustomobject]@{
      ComputerName              = $cn
      ConnectivityStatus        = $null
      ServiceStatus             = $null
      ServiceDependencies       = @()
      AEConfigLogExists         = $false
      AEConfigLogLastModified   = $null
      AEConfigLogErrors         = 0
      AEServerLogExists         = $false
      AEServerLogLastModified   = $null
      AEServerLogErrors         = 0
      RequestQueueSizeKB        = 0
      RegistryPostfix           = $null
      EventAutoEnrollErrorCount = 0
      CAStatus                  = $null
      CertPublishMember         = $null
      AuthAccessMember          = $null
      TemplateDeviceAuthStatus  = $null
      DeviceAuthPermissions     = $null
      DeviceAuthVersion         = $null
      DeviceAuthValidation      = @()
      TemplateServerAuthStatus  = $null
      ServerAuthPermissions     = $null
      ServerAuthVersion         = $null
      ServerAuthValidation      = @()
      TemplateUserAuthStatus    = $null
      UserAuthPermissions       = $null
      UserAuthVersion           = $null
      UserAuthValidation        = @()
      UserMappingStatus         = $null
      NetworkErrors             = @()
      ServiceErrors             = @()
      LogErrors                 = @()
      PermissionErrors          = @()
      TemplateErrors            = @()
      ConfigurationWarnings     = @()
      OverallStatus             = 'Unknown'
      ErrorMessage              = $null
    }

    try {
      Write-Log "=== Testing Autoenrollment Server on '$cn' ===" INFO
      
      # Test connectivity first
      if (-not (Test-RemoteConnectivity -ComputerName $cn -TimeoutSeconds 10)) {
        $res.ConnectivityStatus = 'Failed'
        $res.NetworkErrors += "Unable to reach $cn"
        $res.OverallStatus = 'NetworkFailure'
        $res.ErrorMessage = "Network connectivity failed"
        Write-Log "Skipping $cn due to connectivity failure" WARN
        $res
        continue
      }
      $res.ConnectivityStatus = 'Success'

      # Service status and dependencies
      try {
        $serviceInfo = Invoke-RemoteCommand -ComputerName $cn -Description "Service status check" -Credential $Credential -TimeoutSeconds $TimeoutSeconds -ScriptBlock {
          $svc = Get-Service -Name 'AutoEnrollmentDCOMSrv' -ErrorAction Stop
          $deps = $svc.ServicesDependedOn | Where-Object Status -ne 'Running' | ForEach-Object { "$($_.Name): $($_.Status)" }
          
          @{
            Status = $svc.Status.ToString()
            Dependencies = $deps
          }
        }
        
        $res.ServiceStatus = $serviceInfo.Status
        $res.ServiceDependencies = $serviceInfo.Dependencies
        
        Write-Log "AutoEnrollmentDCOMSrv service status: $($res.ServiceStatus)" INFO
        if ($res.ServiceDependencies.Count -gt 0) {
          Write-Log "Service dependencies not running: $($res.ServiceDependencies -join ', ')" WARN
          $res.ServiceErrors += "Dependencies not running: $($res.ServiceDependencies -join ', ')"
        }
      } catch {
        $res.ServiceErrors += $_.Exception.Message
        Write-Log "Service check failed: $($_.Exception.Message)" ERROR
      }

      # Certificate Authority status
      try {
        $caInfo = Invoke-RemoteCommand -ComputerName $cn -Description "CA status check" -Credential $Credential -TimeoutSeconds $TimeoutSeconds -ScriptBlock {
          try {
            Import-Module ADCSAdministration -ErrorAction Stop
            $ca = Get-CertificationAuthority -ErrorAction Stop
            @{
              Available = $true
              Name = $ca.Name
              Status = $ca.ServiceStatus
            }
          } catch {
            @{
              Available = $false
              Error = $_.Exception.Message
            }
          }
        }
        
        if ($caInfo.Available) {
          $res.CAStatus = "$($caInfo.Name): $($caInfo.Status)"
          Write-Log "Certificate Authority: $($res.CAStatus)" INFO
        } else {
          $res.CAStatus = "Unavailable: $($caInfo.Error)"
          $res.ServiceErrors += "CA unavailable: $($caInfo.Error)"
          Write-Log "Certificate Authority check failed: $($caInfo.Error)" ERROR
        }
      } catch {
        $res.ServiceErrors += "CA check failed: $($_.Exception.Message)"
        Write-Log "CA status check failed: $($_.Exception.Message)" ERROR
      }

      # Log file analysis
      try {
        $logInfo = Invoke-RemoteCommand -ComputerName $cn -Description "Log file analysis" -Credential $Credential -TimeoutSeconds $TimeoutSeconds -ScriptBlock {
          $result = @{
            AEConfig = @{ Exists = $false; LastModified = $null; Errors = 0 }
            AEServer = @{ Exists = $false; LastModified = $null; Errors = 0 }
            RequestQueue = 0
          }
          
          # AEConfig.log
          $aeCfg = Get-ChildItem C:\Users\*\AEConfig.log -ErrorAction SilentlyContinue | Select-Object -First 1
          if ($aeCfg) {
            $result.AEConfig.Exists = $true
            $result.AEConfig.LastModified = $aeCfg.LastWriteTime
            $errorLines = Get-Content -Path $aeCfg.FullName -ErrorAction SilentlyContinue | Select-String -Pattern 'ERROR|FATAL'
            $result.AEConfig.Errors = ($errorLines | Measure-Object).Count
          }
          
          # AEServer.log
          $aesPath = 'C:\Program Files\DigiCert\AEServer\logs\AEServer.log'
          if (Test-Path $aesPath) {
            $aesFile = Get-Item $aesPath
            $result.AEServer.Exists = $true
            $result.AEServer.LastModified = $aesFile.LastWriteTime
            $errorLines = Get-Content -Path $aesPath -ErrorAction SilentlyContinue | Select-String -Pattern 'ERROR|WARN'
            $result.AEServer.Errors = ($errorLines | Measure-Object).Count
          }
          
          # Request queue size
          $reqBuffer = Get-ChildItem 'C:\Program Files\DigiCert\AEServer\RequestBufferFile.dat' -ErrorAction SilentlyContinue
          if ($reqBuffer) {
            $result.RequestQueue = [math]::Round($reqBuffer.Length / 1KB, 1)
          }
          
          return $result
        }
        
        $res.AEConfigLogExists = $logInfo.AEConfig.Exists
        $res.AEConfigLogLastModified = $logInfo.AEConfig.LastModified
        $res.AEConfigLogErrors = $logInfo.AEConfig.Errors
        $res.AEServerLogExists = $logInfo.AEServer.Exists
        $res.AEServerLogLastModified = $logInfo.AEServer.LastModified
        $res.AEServerLogErrors = $logInfo.AEServer.Errors
        $res.RequestQueueSizeKB = $logInfo.RequestQueue
        
        Write-Log "AEConfig.log: Exists=$($res.AEConfigLogExists), Errors=$($res.AEConfigLogErrors)" INFO
        Write-Log "AEServer.log: Exists=$($res.AEServerLogExists), Errors=$($res.AEServerLogErrors)" INFO
        Write-Log "Request queue size: $($res.RequestQueueSizeKB) KB" INFO
        
        if ($res.AEConfigLogErrors -gt 0) {
          $res.LogErrors += "AEConfig.log contains $($res.AEConfigLogErrors) errors"
        }
        if ($res.AEServerLogErrors -gt 0) {
          $res.LogErrors += "AEServer.log contains $($res.AEServerLogErrors) errors"
        }
        
      } catch {
        $res.LogErrors += $_.Exception.Message
        Write-Log "Log analysis failed: $($_.Exception.Message)" ERROR
      }

      # Event log and registry
      try {
        $systemInfo = Invoke-RemoteCommand -ComputerName $cn -Description "System info check" -Credential $Credential -TimeoutSeconds $TimeoutSeconds -ScriptBlock {
          $result = @{
            EventCount = 0
            RegistryPostfix = $null
          }
          
          # Event log count
          try {
            $events = Get-WinEvent -FilterHashtable @{
              LogName = 'Application'
              ProviderName = 'Autoenrollment'
              StartTime = (Get-Date).AddHours(-1)
            } -ErrorAction SilentlyContinue
            $result.EventCount = ($events | Measure-Object).Count
          } catch {
            $result.EventCount = 0
          }
          
          # Registry
          $regPath = 'HKLM:\SOFTWARE\DigiCert\Autoenrollment'
          if (Test-Path $regPath) {
            try {
              $result.RegistryPostfix = Get-ItemProperty -Path $regPath -Name 'ServiceCN-Postfix' -ErrorAction SilentlyContinue | 
                Select-Object -ExpandProperty 'ServiceCN-Postfix'
            } catch {}
          }
          
          return $result
        }
        
        $res.EventAutoEnrollErrorCount = $systemInfo.EventCount
        $res.RegistryPostfix = $systemInfo.RegistryPostfix
        
        Write-Log "Autoenrollment events (last hour): $($res.EventAutoEnrollErrorCount)" INFO
        Write-Log "Registry ServiceCN-Postfix: $($res.RegistryPostfix)" INFO
        
      } catch {
        $res.ConfigurationWarnings += "System info check failed: $($_.Exception.Message)"
        Write-Log "System info check failed: $($_.Exception.Message)" WARN
      }

      # AD group membership checks
      try {
        $adInfo = & {
          param($computerName, $userName)
          try {
            $compObj = Get-ADComputer -Identity $computerName -ErrorAction Stop
            $certPubMembers = Get-ADGroupMember -Identity 'Cert Publishers' -Recursive -ErrorAction Stop | 
              Select-Object -ExpandProperty DistinguishedName
            $authAccessMembers = Get-ADGroupMember -Identity 'Authorization Access' -Recursive -ErrorAction Stop | 
              Select-Object -ExpandProperty DistinguishedName
            
            [PSCustomObject]@{
              IsCertPublisher = $compObj.DistinguishedName -in $certPubMembers
              IsAuthAccessMember = $compObj.DistinguishedName -in $authAccessMembers
              Error = $null
            }
          } catch {
            [PSCustomObject]@{
              IsCertPublisher = $null
              IsAuthAccessMember = $null
              Error = $_.Exception.Message
            }
          }
        } -ArgumentList $cn, $Username
        
        if ($adInfo.Error) {
          $res.PermissionErrors += "AD group check failed: $($adInfo.Error)"
          Write-Log "AD group membership check failed: $($adInfo.Error)" ERROR
        } else {
          $res.CertPublishMember = $adInfo.IsCertPublisher
          $res.AuthAccessMember = $adInfo.IsAuthAccessMember
          Write-Log "Computer in Cert Publishers: $($res.CertPublishMember); in Authorization Access: $($res.AuthAccessMember)" INFO
        }
      } catch {
        $res.PermissionErrors += "AD group check failed: $($_.Exception.Message)"
        Write-Log "AD group membership check failed: $($_.Exception.Message)" ERROR
      }

      # Certificate template validation
      try {
        $templateResults = Invoke-RemoteCommand -ComputerName $cn -Description "Template validation" -Credential $Credential -TimeoutSeconds $TimeoutSeconds -ScriptBlock {
          param($devTemplate, $srvTemplate, $usrTemplate, $testUser)
          
          try {
            Import-Module ADCSAdministration -ErrorAction Stop
            $templates = Get-CATemplate -ErrorAction Stop
          } catch {
            throw "ADCSAdministration module unavailable or CA not accessible: $($_.Exception.Message)"
          }
          
          function Test-Template {
            param([string]$TemplateName)
            
            $template = $templates | Where-Object Name -EQ $TemplateName
            if (-not $template) {
              return @{
                Exists = $false
                Permissions = $null
                Version = $null
                ValidationErrors = @("Template '$TemplateName' not found")
                IsValidForAutoEnroll = $false
              }
            }
            
            $validationErrors = @()
            
            # Get template version
            try {
              $version = $template.GetType().GetProperty('Version').GetValue($template, $null)
              if ($version -notin @(2, 4)) {
                $validationErrors += "Invalid template version: $version (must be 2 or 4 for auto-enrollment)"
              }
            } catch {
              $version = "Unknown"
              $validationErrors += "Could not determine template version: $($_.Exception.Message)"
            }
            
            # Check permissions
            $permissionResult = @{}
            try {
              $templateDN = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADDomain).DistinguishedName)"
              $acl = Get-ACL "AD:$templateDN" -ErrorAction Stop
              
              $requiredGroups = @('Domain Computers', 'Domain Users')
              foreach ($group in $requiredGroups) {
                $hasEnrollPermission = $acl.Access | Where-Object {
                  $_.IdentityReference -like "*$group" -and 
                  ($_.ActiveDirectoryRights -match 'ExtendedRight' -or $_.ActiveDirectoryRights -match 'GenericAll')
                }
                
                if ($hasEnrollPermission) {
                  $permissionResult[$group] = $hasEnrollPermission.ActiveDirectoryRights -join ','
                } else {
                  $permissionResult[$group] = "No enrollment permissions"
                  $validationErrors += "Missing enrollment permissions for $group on template $TemplateName"
                }
              }
            } catch {
              $permissionResult['Error'] = $_.Exception.Message
              $validationErrors += "ACL read failed: $($_.Exception.Message)"
            }
            
            return @{
              Exists = $true
              Permissions = ($permissionResult | ConvertTo-Json -Compress)
              Version = $version
              ValidationErrors = $validationErrors
              IsValidForAutoEnroll = ($validationErrors.Count -eq 0)
            }
          }
          
          # Test all templates
          $results = @{
            Device = Test-Template $devTemplate
            Server = Test-Template $srvTemplate
            User = Test-Template $usrTemplate
          }
          
          # User mapping test
          $userMappingStatus = "OK"
          try {
            $userObj = Get-ADUser -Identity $testUser -Properties tokenGroupsGlobalAndUniversal -ErrorAction Stop
            if ($userObj.tokenGroupsGlobalAndUniversal.Count -gt 50) {
              $userMappingStatus = "WARN: User has many group memberships ($($userObj.tokenGroupsGlobalAndUniversal.Count)) - potential subject mapping issues"
            }
          } catch {
            $userMappingStatus = "FAILED: Could not retrieve user information - $($_.Exception.Message)"
          }
          
          return @{
            DeviceTemplate = $results.Device
            ServerTemplate = $results.Server
            UserTemplate = $results.User
            UserMappingStatus = $userMappingStatus
          }
        } -ArgumentList $TemplateDeviceAuth, $TemplateServerAuth, $TemplateUserAuth, $Username
        
        # Process device template results
        $res.TemplateDeviceAuthStatus = $templateResults.DeviceTemplate.Exists
        $res.DeviceAuthPermissions = $templateResults.DeviceTemplate.Permissions
        $res.DeviceAuthVersion = $templateResults.DeviceTemplate.Version
        $res.DeviceAuthValidation = $templateResults.DeviceTemplate.ValidationErrors
        if ($templateResults.DeviceTemplate.ValidationErrors.Count -gt 0) {
          $res.TemplateErrors += $templateResults.DeviceTemplate.ValidationErrors
        }
        
        # Process server template results
        $res.TemplateServerAuthStatus = $templateResults.ServerTemplate.Exists
        $res.ServerAuthPermissions = $templateResults.ServerTemplate.Permissions
        $res.ServerAuthVersion = $templateResults.ServerTemplate.Version
        $res.ServerAuthValidation = $templateResults.ServerTemplate.ValidationErrors
        if ($templateResults.ServerTemplate.ValidationErrors.Count -gt 0) {
          $res.TemplateErrors += $templateResults.ServerTemplate.ValidationErrors
        }
        
        # Process user template results
        $res.TemplateUserAuthStatus = $templateResults.UserTemplate.Exists
        $res.UserAuthPermissions = $templateResults.UserTemplate.Permissions
        $res.UserAuthVersion = $templateResults.UserTemplate.Version
        $res.UserAuthValidation = $templateResults.UserTemplate.ValidationErrors
        if ($templateResults.UserTemplate.ValidationErrors.Count -gt 0) {
          $res.TemplateErrors += $templateResults.UserTemplate.ValidationErrors
        }
        
        # User mapping status
        $res.UserMappingStatus = $templateResults.UserMappingStatus
        if ($templateResults.UserMappingStatus -notlike "OK*") {
          $res.ConfigurationWarnings += $templateResults.UserMappingStatus
        }
        
        Write-Log "Template validation complete - Device: $($res.TemplateDeviceAuthStatus), Server: $($res.TemplateServerAuthStatus), User: $($res.TemplateUserAuthStatus)" INFO
        Write-Log "User mapping status: $($res.UserMappingStatus)" INFO
        
      } catch {
        $res.TemplateErrors += $_.Exception.Message
        Write-Log "Template validation failed: $($_.Exception.Message)" ERROR
      }

      # Determine overall status
      $criticalErrors = $res.NetworkErrors.Count + $res.ServiceErrors.Count + $res.TemplateErrors.Count
      $warnings = $res.LogErrors.Count + $res.PermissionErrors.Count + $res.ConfigurationWarnings.Count
      
      if ($criticalErrors -eq 0 -and $warnings -eq 0) {
        $res.OverallStatus = 'Healthy'
      } elseif ($criticalErrors -eq 0) {
        $res.OverallStatus = 'Warning'
      } else {
        $res.OverallStatus = 'Critical'
      }
      
      Write-Log "Overall status for $cn`: $($res.OverallStatus)" INFO

    } catch {
      $res.ErrorMessage = $_.Exception.Message
      $res.OverallStatus = 'Error'
      Write-Log "Critical error testing $cn`: $($_.Exception.Message)" ERROR
    }

    # Output result
    $res
  }
}

end {
  Write-Log "=== TLM Auto-Enrollment Diagnostic Complete ===" INFO
  Write-Log "Detailed results logged to: $script:LogFile" INFO
}