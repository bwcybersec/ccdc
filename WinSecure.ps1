<#
.SYNOPSIS
Baseline hardening for Windows Server hosting: IIS (HTTP/HTTPS), IIS FTP (FTPS), DNS Server, and MySQL.

.NOTES
- Requires elevation (Run as Administrator).
- Designed for Windows Server (2016+ recommended).
- Safe-to-rerun (idempotent-ish): firewall rules and IIS settings are set/updated, not duplicated.

Optional env var:
  MYSQL_ROOT_PWD  -> if set AND mysql.exe is in PATH, script will attempt basic SQL cleanup.

#>

Set-ExecutionPolicy Unrestricted

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [switch]$DryRun,

  # Firewall toggles
  [switch]$AllowHTTP  = $true,
  [switch]$AllowHTTPS = $true,
  [switch]$AllowFTP   = $true,
  [switch]$AllowDNS   = $true,
  [switch]$AllowMySQLRemote = $false,

  # Scoping
  [string]$MySQLRemoteCIDR = "127.0.0.1/32",  # only used if AllowMySQLRemote

  # FTP Passive Ports (match firewall + IIS FTP config)
  [int]$FtpPasvMin = 30000,
  [int]$FtpPasvMax = 31000,

  # DNS role: Authoritative disables recursion; Resolver enables recursion
  [ValidateSet("Authoritative","Resolver")]
  [string]$DnsRole = "Authoritative",

  # IIS response headers
  [switch]$ReduceIisHeaders = $true
)

# ---------------- Helpers ----------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
  }
}

function Invoke-Step($Message, [scriptblock]$Block) {
  Write-Host "`n[+] $Message" -ForegroundColor Cyan
  if ($DryRun) {
    Write-Host "    (DryRun) Would execute step." -ForegroundColor Yellow
  } else {
    & $Block
  }
}

function Ensure-FirewallRule {
  param(
    [Parameter(Mandatory)] [string]$DisplayName,
    [Parameter(Mandatory)] [string]$Protocol,
    [Parameter(Mandatory)] [string]$LocalPort,
    [string]$RemoteAddress = "Any",
    [ValidateSet("Allow","Block")] [string]$Action = "Allow",
    [ValidateSet("Inbound","Outbound")] [string]$Direction = "Inbound",
    [ValidateSet("Any","Domain","Private","Public")] [string]$Profile = "Any"
  )

  $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  if (-not $existing) {
    if ($PSCmdlet.ShouldProcess("Firewall", "Create rule: $DisplayName")) {
      New-NetFirewallRule `
        -DisplayName $DisplayName `
        -Direction $Direction `
        -Action $Action `
        -Protocol $Protocol `
        -LocalPort $LocalPort `
        -Profile $Profile `
        -RemoteAddress $RemoteAddress | Out-Null
    }
  } else {
    # Update the existing rule to match desired settings
    if ($PSCmdlet.ShouldProcess("Firewall", "Update rule: $DisplayName")) {
      Set-NetFirewallRule -DisplayName $DisplayName -Direction $Direction -Action $Action -Profile $Profile | Out-Null
      Set-NetFirewallPortFilter -AssociatedNetFirewallRule $existing -Protocol $Protocol -LocalPort $LocalPort | Out-Null
      Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $existing -RemoteAddress $RemoteAddress | Out-Null
    }
  }
}

function Try-InstallWindowsFeature {
  param([string[]]$FeatureNames)

  # Server-only cmdlet. If not found, we skip installation and just configure what exists.
  if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
    foreach ($f in $FeatureNames) {
      $feat = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
      if ($feat -and -not $feat.Installed) {
        if ($PSCmdlet.ShouldProcess("WindowsFeature", "Install $f")) {
          Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
        }
      }
    }
  } else {
    Write-Warning "Install-WindowsFeature not available (not a Windows Server / missing ServerManager). Skipping feature installation."
  }
}

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Warning "Module '$Name' not found; related configuration steps may be skipped."
    return $false
  }
  Import-Module $Name -ErrorAction SilentlyContinue | Out-Null
  return $true
}

# ---------------- Main ----------------
Assert-Admin

Invoke-Step "Enable Windows Firewall profiles (Domain/Private/Public) and default posture" {
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
}

Invoke-Step "Open required inbound ports with scoped rules (HTTP/HTTPS/FTP/DNS/MySQL)" {
  if ($AllowHTTP)  { Ensure-FirewallRule -DisplayName "Hardening - Allow HTTP 80"  -Protocol TCP -LocalPort "80"  }
  if ($AllowHTTPS) { Ensure-FirewallRule -DisplayName "Hardening - Allow HTTPS 443" -Protocol TCP -LocalPort "443" }

  if ($AllowFTP) {
    Ensure-FirewallRule -DisplayName "Hardening - Allow FTP Control 21" -Protocol TCP -LocalPort "21"
    Ensure-FirewallRule -DisplayName "Hardening - Allow FTP Passive $FtpPasvMin-$FtpPasvMax" -Protocol TCP -LocalPort "$FtpPasvMin-$FtpPasvMax"
  }

  if ($AllowDNS) {
    Ensure-FirewallRule -DisplayName "Hardening - Allow DNS TCP 53" -Protocol TCP -LocalPort "53"
    Ensure-FirewallRule -DisplayName "Hardening - Allow DNS UDP 53" -Protocol UDP -LocalPort "53"
  }

  if ($AllowMySQLRemote) {
    # Restrict source IP/CIDR
    Ensure-FirewallRule -DisplayName "Hardening - Allow MySQL 3306 (Scoped)" -Protocol TCP -LocalPort "3306" -RemoteAddress $MySQLRemoteCIDR
  } else {
    # Best-effort explicit block (optional): comment out if you rely on other rule sets
    Ensure-FirewallRule -DisplayName "Hardening - Block MySQL 3306" -Protocol TCP -LocalPort "3306" -Action Block
  }
}

Invoke-Step "Install Windows roles/features (IIS + FTP + DNS) if available" {
  Try-InstallWindowsFeature -FeatureNames @(
    "Web-Server",          # IIS
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Default-Doc",
    "Web-Http-Errors",
    "Web-Static-Content",
    "Web-Http-Redirect",
    "Web-Filtering",
    "Web-Performance",
    "Web-Security",
    "Web-Mgmt-Tools",
    "Web-FTP-Server",
    "Web-FTP-Service",
    "DNS"
  )
}

# ---------------- IIS Hardening ----------------
Invoke-Step "Harden IIS (HTTP) settings if WebAdministration is available" {
  if (-not (Ensure-Module -Name "WebAdministration")) { return }

  # Disable directory browsing
  Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false

  # Add minimal security headers (global)
  # Ensure customHeaders exists then add/set
  $headersPath = "MACHINE/WEBROOT/APPHOST"
  $filter = "system.webServer/httpProtocol/customHeaders"


