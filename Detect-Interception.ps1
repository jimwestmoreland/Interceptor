<#
.SYNOPSIS
    Detects SSL/TLS interception by comparing certificate thumbprints and issuers against known endpoints.

.DESCRIPTION
    This script tests various endpoints commonly used by Azure Virtual Desktop (AVD) sessions and 
    applications running within them. It compares the certificate thumbprint and issuer chain 
    against expected values to detect if traffic is being intercepted by a proxy performing 
    SSL/TLS inspection.
    
    Runs the graphical user interface by default. Use -NoGUI with other switches for command-line mode.

.PARAMETER NoGUI
    Suppresses the graphical user interface and runs in command-line mode

.PARAMETER TestAVD
    Tests Azure Virtual Desktop specific endpoints (RDP Gateway, Broker, Diagnostics)

.PARAMETER TestMicrosoft365
    Tests Microsoft 365 endpoints (Outlook, Teams, SharePoint, OneDrive)

.PARAMETER TestAzure
    Tests Azure management and authentication endpoints (Azure AD, Graph API, Management)

.PARAMETER TestTRv2
    Tests Tenant Restriction v2 and Global Secure Access endpoints

.PARAMETER TestAppleSSO
    Tests Apple SSO Extension endpoints (required for Enterprise SSO on macOS/iOS)

.PARAMETER TestHairpin
    Tests for hairpin NAT (NAT loopback) by comparing internal vs external routing paths

.PARAMETER TestAll
    Tests all endpoint categories

.PARAMETER FetchM365Endpoints
    Fetches the current Microsoft 365 endpoint list from the official Microsoft JSON feed

.PARAMETER FetchAzureEndpoints
    Fetches the current Azure endpoint list from the official Microsoft JSON feed

.PARAMETER DiscoverRootCAs
    Scans all known Microsoft endpoints to discover root CAs currently in use.
    Optionally saves them to a config file for future use.

.PARAMETER RootCAConfigPath
    Path to a JSON file containing additional trusted root CAs.
    If not specified, looks for 'TrustedRootCAs.json' in the script directory.
    Use with -DiscoverRootCAs to save discovered CAs to this file.

.PARAMETER CustomEndpoints
    Array of custom endpoints to test (e.g., @("contoso.com:443", "api.example.com:443"))

.PARAMETER OutputPath
    Path to save the results file. Default is current directory.

.EXAMPLE
    .\Detect-Interception.ps1
    Launches the graphical user interface (default behavior)

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -TestAVD
    Tests only AVD-related endpoints via command line without GUI

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -TestAll -OutputPath "C:\Logs"
    Tests all endpoints and saves results to C:\Logs

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -CustomEndpoints @("myapp.contoso.com:443")
    Tests custom endpoints via command line

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -DiscoverRootCAs
    Scans endpoints to discover current Microsoft root CAs and saves to TrustedRootCAs.json

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -DiscoverRootCAs -RootCAConfigPath "C:\Config\MyRootCAs.json"
    Discovers root CAs and saves to a custom config file path

.NOTES
    Author: AVD Diagnostics Team
    Version: 1.0
    Date: 2026-02-06
#>

[CmdletBinding()]
param(
    [switch]$NoGUI,
    [switch]$TestAVD,
    [switch]$TestMicrosoft365,
    [switch]$TestAzure,
    [switch]$TestTRv2,
    [switch]$TestAppleSSO,
    [switch]$TestHairpin,
    [switch]$TestAll,
    [switch]$FetchM365Endpoints,
    [switch]$FetchAzureEndpoints,
    [switch]$DiscoverRootCAs,
    [string]$RootCAConfigPath,
    [string[]]$CustomEndpoints,
    [string]$OutputPath = $PWD.Path
)

#region Shared Configuration

# Known Microsoft Root CA Thumbprints (these are legitimate Microsoft/DigiCert/Baltimore roots)
$script:KnownMicrosoftRootCAs = @{
    # Microsoft Root CAs
    "Microsoft Root Certificate Authority 2011" = "8F43288AD272F3103B6FB1428485EA3014C0BCFE"
    "Microsoft ECC Root Certificate Authority 2017" = "999A64C37FF47D9FAB95F14769891460EEC4C3C5"
    "Microsoft RSA Root Certificate Authority 2017" = "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74"
    
    # DigiCert (used by Microsoft)
    "DigiCert Global Root CA" = "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436"
    "DigiCert Global Root G2" = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
    "DigiCert Global Root G3" = "7E04DE896A3E666D00E687D33FFAD93BE83D349E"
    
    # Baltimore (Azure/Microsoft legacy)
    "Baltimore CyberTrust Root" = "D4DE20D05E66FC53FE1A50882C78DB2852CAE474"
    
    # GlobalSign (Microsoft partner)
    "GlobalSign Root CA" = "B1BC968BD4F49D622AA89A81F2150152A41D829C"
    "GlobalSign Root CA - R3" = "D69B561148F01C77C54578C10926DF5B856976AD"
}

# Known Microsoft Intermediate CA Issuers (partial matches)
$script:KnownMicrosoftIssuers = @(
    "Microsoft Corporation",
    "Microsoft Azure",
    "DigiCert",
    "Baltimore",
    "GlobalSign",
    "Microsoft IT"
)

# Endpoint categories
$script:AVDEndpoints = @(
    @{ Host = "rdweb.wvd.microsoft.com"; Port = 443; Description = "AVD Web Client" }
    @{ Host = "rdbroker.wvd.microsoft.com"; Port = 443; Description = "AVD Broker" }
    @{ Host = "client.wvd.microsoft.com"; Port = 443; Description = "AVD Client Service" }
    @{ Host = "gateway.wvd.microsoft.com"; Port = 443; Description = "AVD Gateway" }
    @{ Host = "rdgateway.wvd.microsoft.com"; Port = 443; Description = "AVD RD Gateway" }
    @{ Host = "gcs.prod.monitoring.core.windows.net"; Port = 443; Description = "AVD Diagnostics" }
    @{ Host = "production.diagnostics.monitoring.core.windows.net"; Port = 443; Description = "AVD Monitoring" }
    @{ Host = "catalogartifact.azureedge.net"; Port = 443; Description = "AVD Artifacts" }
    @{ Host = "kms.core.windows.net"; Port = 1688; Description = "Windows Activation (KMS)" }
    @{ Host = "azkms.core.windows.net"; Port = 1688; Description = "Azure KMS" }
)

$script:Microsoft365Endpoints = @(
    @{ Host = "outlook.office365.com"; Port = 443; Description = "Outlook Online" }
    @{ Host = "outlook.office.com"; Port = 443; Description = "Outlook Web" }
    @{ Host = "teams.microsoft.com"; Port = 443; Description = "Microsoft Teams" }
    @{ Host = "graph.microsoft.com"; Port = 443; Description = "Microsoft Graph API" }
    @{ Host = "sharepoint.com"; Port = 443; Description = "SharePoint" }
    @{ Host = "onedrive.live.com"; Port = 443; Description = "OneDrive" }
    @{ Host = "officeapps.live.com"; Port = 443; Description = "Office Online Apps" }
    @{ Host = "onenote.com"; Port = 443; Description = "OneNote" }
    @{ Host = "cdn.office.net"; Port = 443; Description = "Office CDN" }
)

$script:AzureEndpoints = @(
    @{ Host = "login.microsoftonline.com"; Port = 443; Description = "Azure AD / Entra ID" }
    @{ Host = "login.windows.net"; Port = 443; Description = "Azure AD (Legacy)" }
    @{ Host = "login.microsoft.com"; Port = 443; Description = "Microsoft Login" }
    @{ Host = "aadcdn.msftauth.net"; Port = 443; Description = "Azure AD CDN" }
    @{ Host = "management.azure.com"; Port = 443; Description = "Azure Management API" }
    @{ Host = "management.core.windows.net"; Port = 443; Description = "Azure Classic Management" }
    @{ Host = "blob.core.windows.net"; Port = 443; Description = "Azure Blob Storage" }
    @{ Host = "vault.azure.net"; Port = 443; Description = "Azure Key Vault" }
    @{ Host = "servicebus.windows.net"; Port = 443; Description = "Azure Service Bus" }
    @{ Host = "database.windows.net"; Port = 1433; Description = "Azure SQL" }
)

$script:TRv2Endpoints = @(
    @{ Host = "device.login.microsoftonline.com"; Port = 443; Description = "Device Code Flow" }
    @{ Host = "autologon.microsoftazuread-sso.com"; Port = 443; Description = "Seamless SSO" }
    @{ Host = "enterpriseregistration.windows.net"; Port = 443; Description = "Device Registration" }
    @{ Host = "pas.windows.net"; Port = 443; Description = "Azure AD Password Protection" }
    @{ Host = "passwordreset.microsoftonline.com"; Port = 443; Description = "Self-Service Password Reset" }
    @{ Host = "*.globalsecureaccess.microsoft.com"; Port = 443; Description = "Global Secure Access" }
    @{ Host = "tunnel.globalsecureaccess.microsoft.com"; Port = 443; Description = "GSA Tunnel" }
    @{ Host = "edge.microsoft.com"; Port = 443; Description = "Edge Updates (TRv2)" }
    @{ Host = "config.edge.skype.com"; Port = 443; Description = "Edge Config" }
)

$script:AppleSSOEndpoints = @(
    @{ Host = "app-site-association.cdn-apple.com"; Port = 443; Description = "Apple Associated Domains CDN" }
    @{ Host = "app-site-association.networking.apple"; Port = 443; Description = "Apple Associated Domains" }
    @{ Host = "login.microsoftonline.com"; Port = 443; Description = "Entra ID (SSO Extension)" }
    @{ Host = "login.microsoft.com"; Port = 443; Description = "Microsoft Login (SSO Extension)" }
    @{ Host = "login.windows.net"; Port = 443; Description = "Azure AD Legacy (SSO Extension)" }
    @{ Host = "sts.windows.net"; Port = 443; Description = "Security Token Service" }
    @{ Host = "login.partner.microsoftonline.cn"; Port = 443; Description = "China Cloud Login" }
    @{ Host = "login.chinacloudapi.cn"; Port = 443; Description = "China Cloud API" }
    @{ Host = "login.microsoftonline.us"; Port = 443; Description = "US Gov Cloud Login" }
    @{ Host = "login.usgovcloudapi.net"; Port = 443; Description = "US Gov Cloud API" }
    @{ Host = "login-us.microsoftonline.com"; Port = 443; Description = "US Region Login" }
)

# Initialize config path and load additional root CAs if config exists
$script:RootCAConfigFile = if ($RootCAConfigPath) { 
    $RootCAConfigPath 
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($scriptDir) { Join-Path $scriptDir "TrustedRootCAs.json" } else { "TrustedRootCAs.json" }
}

# Load additional root CAs from config file if it exists (will be merged after functions are defined)
$script:AdditionalRootCAs = @{}

#endregion

#region Endpoint Fetch Functions

function Get-M365EndpointsFromMicrosoft {
    <#
    .SYNOPSIS
        Fetches the current Microsoft 365 endpoint list from the official Microsoft JSON feed
    .DESCRIPTION
        Uses the Office 365 IP Address and URL web service to get the current list of endpoints
        https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
    #>
    param(
        [string]$Instance = "Worldwide",  # Worldwide, USGovDoD, USGovGCCHigh, China, Germany
        [switch]$RequiredOnly  # Only return endpoints marked as required
    )
    
    $endpoints = @()
    
    try {
        # Generate a client request ID
        $clientRequestId = [Guid]::NewGuid().ToString()
        
        # Microsoft 365 endpoints API
        $uri = "https://endpoints.office.com/endpoints/$Instance`?clientrequestid=$clientRequestId"
        
        Write-Host "Fetching M365 endpoints from: $uri" -ForegroundColor Cyan
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        
        foreach ($item in $response) {
            # Skip if RequiredOnly and this isn't required
            if ($RequiredOnly -and $item.required -ne $true) {
                continue
            }
            
            # Process URLs (these are the HTTPS endpoints we want to test)
            if ($item.urls) {
                foreach ($url in $item.urls) {
                    # Skip wildcards that start with *. as we can't test those directly
                    if ($url -match '^\*\.') {
                        # Try to extract a testable subdomain
                        $baseDomain = $url -replace '^\*\.', ''
                        # Add common subdomains for testing
                        $testUrls = @($baseDomain)
                    }
                    else {
                        $testUrls = @($url)
                    }
                    
                    foreach ($testUrl in $testUrls) {
                        # Clean the URL
                        $cleanUrl = $testUrl -replace '/$', ''
                        
                        # Skip if already in list
                        if ($endpoints | Where-Object { $_.Host -eq $cleanUrl }) {
                            continue
                        }
                        
                        $endpoints += @{
                            Host = $cleanUrl
                            Port = 443
                            Description = "M365: $($item.serviceAreaDisplayName)"
                            Category = "M365-Live"
                            ServiceArea = $item.serviceArea
                            Required = $item.required
                        }
                    }
                }
            }
        }
        
        Write-Host "Retrieved $($endpoints.Count) M365 endpoints" -ForegroundColor Green
    }
    catch {
        Write-Host "Error fetching M365 endpoints: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $endpoints
}

function Get-AzureEndpointsFromMicrosoft {
    <#
    .SYNOPSIS
        Fetches common Azure service endpoints
    .DESCRIPTION
        Returns a curated list of Azure service endpoints based on Azure documentation.
        Note: Azure Service Tags JSON contains IP ranges, not hostnames, so we use known Azure endpoints.
    #>
    param(
        [switch]$IncludeRegional  # Include regional endpoints (can be many)
    )
    
    $endpoints = @()
    
    try {
        Write-Host "Fetching Azure endpoints..." -ForegroundColor Cyan
        
        # Core Azure endpoints (these are global/common endpoints)
        $azureEndpoints = @(
            # Identity & Access
            @{ Host = "login.microsoftonline.com"; Description = "Azure AD / Entra ID"; ServiceArea = "Identity" }
            @{ Host = "login.microsoft.com"; Description = "Microsoft Login"; ServiceArea = "Identity" }
            @{ Host = "login.windows.net"; Description = "Azure AD (Legacy)"; ServiceArea = "Identity" }
            @{ Host = "graph.microsoft.com"; Description = "Microsoft Graph"; ServiceArea = "Identity" }
            @{ Host = "graph.windows.net"; Description = "Azure AD Graph (Legacy)"; ServiceArea = "Identity" }
            @{ Host = "aadcdn.msftauth.net"; Description = "Azure AD CDN"; ServiceArea = "Identity" }
            @{ Host = "aadcdn.msauth.net"; Description = "Azure AD Auth CDN"; ServiceArea = "Identity" }
            @{ Host = "autologon.microsoftazuread-sso.com"; Description = "Azure AD SSO"; ServiceArea = "Identity" }
            
            # Management
            @{ Host = "management.azure.com"; Description = "Azure Resource Manager"; ServiceArea = "Management" }
            @{ Host = "management.core.windows.net"; Description = "Azure Service Management"; ServiceArea = "Management" }
            @{ Host = "portal.azure.com"; Description = "Azure Portal"; ServiceArea = "Management" }
            @{ Host = "azure.microsoft.com"; Description = "Azure Website"; ServiceArea = "Management" }
            
            # Storage
            @{ Host = "blob.core.windows.net"; Description = "Azure Blob Storage"; ServiceArea = "Storage" }
            @{ Host = "table.core.windows.net"; Description = "Azure Table Storage"; ServiceArea = "Storage" }
            @{ Host = "queue.core.windows.net"; Description = "Azure Queue Storage"; ServiceArea = "Storage" }
            @{ Host = "file.core.windows.net"; Description = "Azure File Storage"; ServiceArea = "Storage" }
            
            # Databases
            @{ Host = "database.windows.net"; Port = 1433; Description = "Azure SQL"; ServiceArea = "Database" }
            @{ Host = "documents.azure.com"; Description = "Azure Cosmos DB"; ServiceArea = "Database" }
            
            # Messaging
            @{ Host = "servicebus.windows.net"; Description = "Azure Service Bus"; ServiceArea = "Messaging" }
            @{ Host = "eventhub.azure.net"; Description = "Azure Event Hub"; ServiceArea = "Messaging" }
            
            # Security
            @{ Host = "vault.azure.net"; Description = "Azure Key Vault"; ServiceArea = "Security" }
            @{ Host = "managedhsm.azure.net"; Description = "Azure Managed HSM"; ServiceArea = "Security" }
            
            # Compute
            @{ Host = "azurewebsites.net"; Description = "Azure App Service"; ServiceArea = "Compute" }
            @{ Host = "cloudapp.azure.com"; Description = "Azure Cloud Services"; ServiceArea = "Compute" }
            @{ Host = "azurecr.io"; Description = "Azure Container Registry"; ServiceArea = "Compute" }
            
            # Monitoring
            @{ Host = "monitor.azure.com"; Description = "Azure Monitor"; ServiceArea = "Monitoring" }
            @{ Host = "applicationinsights.azure.com"; Description = "Application Insights"; ServiceArea = "Monitoring" }
            @{ Host = "loganalytics.io"; Description = "Log Analytics"; ServiceArea = "Monitoring" }
            
            # CDN & Networking
            @{ Host = "azureedge.net"; Description = "Azure CDN"; ServiceArea = "CDN" }
            @{ Host = "trafficmanager.net"; Description = "Azure Traffic Manager"; ServiceArea = "Networking" }
            @{ Host = "azurefd.net"; Description = "Azure Front Door"; ServiceArea = "Networking" }
            
            # DevOps
            @{ Host = "dev.azure.com"; Description = "Azure DevOps"; ServiceArea = "DevOps" }
            @{ Host = "visualstudio.com"; Description = "Visual Studio Online"; ServiceArea = "DevOps" }
            @{ Host = "vsassets.io"; Description = "VS Assets"; ServiceArea = "DevOps" }
        )
        
        foreach ($ep in $azureEndpoints) {
            $port = if ($ep.Port) { $ep.Port } else { 443 }
            $endpoints += @{
                Host = $ep.Host
                Port = $port
                Description = "Azure: $($ep.Description)"
                Category = "Azure-Live"
                ServiceArea = $ep.ServiceArea
                Required = $true
            }
        }
        
        Write-Host "Retrieved $($endpoints.Count) Azure endpoints" -ForegroundColor Green
    }
    catch {
        Write-Host "Error fetching Azure endpoints: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $endpoints
}

function Get-RootCAConfigPath {
    <#
    .SYNOPSIS
        Gets the path to the root CA config file
    #>
    param([string]$CustomPath)
    
    if ($CustomPath) {
        return $CustomPath
    }
    
    # Default to script directory
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $scriptDir) {
        $scriptDir = $PWD.Path
    }
    return Join-Path $scriptDir "TrustedRootCAs.json"
}

function Import-RootCAConfig {
    <#
    .SYNOPSIS
        Loads additional trusted root CAs from a JSON config file
    #>
    param([string]$ConfigPath)
    
    if (-not (Test-Path $ConfigPath)) {
        return @{}
    }
    
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $rootCAs = @{}
        
        foreach ($prop in $config.PSObject.Properties) {
            $rootCAs[$prop.Name] = $prop.Value
        }
        
        Write-Host "Loaded $($rootCAs.Count) additional root CAs from config" -ForegroundColor Green
        return $rootCAs
    }
    catch {
        Write-Host "Warning: Failed to load root CA config: $($_.Exception.Message)" -ForegroundColor Yellow
        return @{}
    }
}

function Export-RootCAConfig {
    <#
    .SYNOPSIS
        Saves discovered root CAs to a JSON config file
    #>
    param(
        [hashtable]$RootCAs,
        [string]$ConfigPath
    )
    
    try {
        $RootCAs | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath -Encoding UTF8
        Write-Host "Saved $($RootCAs.Count) root CAs to: $ConfigPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error saving root CA config: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Invoke-RootCADiscovery {
    <#
    .SYNOPSIS
        Scans known Microsoft endpoints to discover root CAs currently in use
    .DESCRIPTION
        Connects to a sample of known Microsoft/Azure/M365 endpoints, retrieves their
        certificate chains, and extracts the unique root CAs.
    #>
    param(
        [string]$ConfigPath,
        [switch]$SaveToConfig
    )
    
    Write-Host ""
    Write-Host "Root CA Discovery" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Scanning Microsoft endpoints to discover current root CAs..." -ForegroundColor Yellow
    Write-Host ""
    
    # Combine all endpoint lists for scanning
    $allEndpoints = @()
    $allEndpoints += $script:AVDEndpoints | Where-Object { $_.Port -eq 443 }
    $allEndpoints += $script:Microsoft365Endpoints
    $allEndpoints += $script:AzureEndpoints | Where-Object { $_.Port -eq 443 }
    
    # Limit to a reasonable sample to avoid too many connections
    $sampleEndpoints = $allEndpoints | Select-Object -First 20
    
    $discoveredRootCAs = @{}
    $scannedCount = 0
    $successCount = 0
    
    foreach ($endpoint in $sampleEndpoints) {
        $scannedCount++
        Write-Host "  [$scannedCount/$($sampleEndpoints.Count)] Checking $($endpoint.Host)..." -NoNewline
        
        try {
            $result = Get-CertificateChain -Hostname $endpoint.Host -Port $endpoint.Port -TimeoutMs 5000
            
            if ($result.Success -and $result.RootThumbprint) {
                $successCount++
                $rootName = $result.RootCA -replace '^CN=', '' -replace ',.*$', ''
                
                if (-not $discoveredRootCAs.ContainsKey($rootName)) {
                    $discoveredRootCAs[$rootName] = $result.RootThumbprint
                    Write-Host " Found: $rootName" -ForegroundColor Green
                }
                else {
                    Write-Host " OK (already discovered)" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host " Failed: $($result.Error)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Discovery Complete" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host "Scanned: $scannedCount endpoints"
    Write-Host "Successful: $successCount endpoints"
    Write-Host "Unique Root CAs Found: $($discoveredRootCAs.Count)"
    Write-Host ""
    
    # Display discovered CAs
    Write-Host "Discovered Root CAs:" -ForegroundColor Yellow
    foreach ($ca in $discoveredRootCAs.GetEnumerator() | Sort-Object Name) {
        $isKnown = $script:KnownMicrosoftRootCAs.Values -contains $ca.Value
        $status = if ($isKnown) { "[Already in built-in list]" } else { "[NEW]" }
        $color = if ($isKnown) { "DarkGray" } else { "Green" }
        Write-Host "  $($ca.Name)" -ForegroundColor $color
        Write-Host "    Thumbprint: $($ca.Value) $status" -ForegroundColor $color
    }
    
    # Find new CAs not in current list
    $newCAs = @{}
    foreach ($ca in $discoveredRootCAs.GetEnumerator()) {
        if ($script:KnownMicrosoftRootCAs.Values -notcontains $ca.Value) {
            $newCAs[$ca.Name] = $ca.Value
        }
    }
    
    if ($newCAs.Count -gt 0) {
        Write-Host ""
        Write-Host "Found $($newCAs.Count) NEW root CA(s) not in the built-in list!" -ForegroundColor Yellow
        
        if ($SaveToConfig -or $ConfigPath) {
            # Merge with existing config if present
            $existingConfig = @{}
            if ($ConfigPath -and (Test-Path $ConfigPath)) {
                $existingConfig = Import-RootCAConfig -ConfigPath $ConfigPath
            }
            
            # Merge discovered CAs with existing
            foreach ($ca in $discoveredRootCAs.GetEnumerator()) {
                $existingConfig[$ca.Name] = $ca.Value
            }
            
            $savePath = if ($ConfigPath) { $ConfigPath } else { Get-RootCAConfigPath }
            Export-RootCAConfig -RootCAs $existingConfig -ConfigPath $savePath
        }
        else {
            Write-Host ""
            Write-Host "To save these root CAs to a config file, run with -DiscoverRootCAs" -ForegroundColor Cyan
            Write-Host "The config file will be created at: $(Get-RootCAConfigPath)" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host ""
        Write-Host "All discovered root CAs are already in the built-in list." -ForegroundColor Green
    }
    
    Write-Host ""
    
    return $discoveredRootCAs
}

#endregion

#region Hairpin NAT Detection

function Test-HairpinNAT {
    <#
    .SYNOPSIS
        Tests for hairpin NAT (NAT loopback) by comparing internal vs external routing paths
    .DESCRIPTION
        Hairpin NAT occurs when traffic from an internal host destined for a public IP
        is routed back to an internal destination. This is detected by:
        1. Comparing TTL differences between internal and external paths
        2. Measuring latency differences
        3. Performing traceroute analysis
    .PARAMETER TargetIP
        The public IP address to test (typically your organization's public IP)
    .PARAMETER TargetPort
        The port to test connectivity on (default: 443)
    .PARAMETER InternalHost
        Optional internal hostname to compare against
    .PARAMETER TimeoutMs
        Connection timeout in milliseconds (default: 5000)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        [int]$TargetPort = 443,
        [string]$InternalHost,
        [int]$TimeoutMs = 5000,
        [int]$PingCount = 4
    )
    
    $result = [PSCustomObject]@{
        TargetIP = $TargetIP
        TargetPort = $TargetPort
        InternalHost = $InternalHost
        IsHairpin = $false
        HairpinConfidence = "Unknown"
        HairpinIndicators = @()
        ExternalLatencyMs = $null
        InternalLatencyMs = $null
        TTLToTarget = $null
        HopCount = $null
        TracerouteHops = @()
        LocalIPAddresses = @()
        RoutingDetails = ""
        Error = $null
        Success = $false
    }
    
    try {
        # Get local IP addresses for comparison
        $localIPs = Get-NetIPAddress -AddressFamily IPv4 | 
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
            Select-Object -ExpandProperty IPAddress
        $result.LocalIPAddresses = $localIPs
        
        # Check if target IP is one of our local IPs (definite hairpin)
        if ($localIPs -contains $TargetIP) {
            $result.IsHairpin = $true
            $result.HairpinConfidence = "Confirmed"
            $result.HairpinIndicators += "Target IP matches local interface IP"
            $result.Success = $true
            return $result
        }
        
        # Test 1: Ping-based TTL and latency analysis
        Write-Host "  Testing connectivity to $TargetIP..." -ForegroundColor Gray
        
        $pingResults = @()
        for ($i = 0; $i -lt $PingCount; $i++) {
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $pingReply = $ping.Send($TargetIP, $TimeoutMs)
                if ($pingReply.Status -eq 'Success') {
                    $pingResults += [PSCustomObject]@{
                        RTT = $pingReply.RoundtripTime
                        TTL = $pingReply.Options.Ttl
                    }
                }
                $ping.Dispose()
            }
            catch { }
            Start-Sleep -Milliseconds 100
        }
        
        if ($pingResults.Count -gt 0) {
            $avgLatency = ($pingResults | Measure-Object -Property RTT -Average).Average
            $result.ExternalLatencyMs = [math]::Round($avgLatency, 2)
            $result.TTLToTarget = $pingResults[0].TTL
            
            # Estimate hop count (common initial TTL values are 64, 128, 255)
            $initialTTL = 64
            if ($pingResults[0].TTL -gt 64) { $initialTTL = 128 }
            if ($pingResults[0].TTL -gt 128) { $initialTTL = 255 }
            $result.HopCount = $initialTTL - $pingResults[0].TTL
            
            # Hairpin indicators based on TTL/latency
            if ($result.HopCount -le 2 -and $avgLatency -lt 5) {
                $result.HairpinIndicators += "Very low hop count ($($result.HopCount)) with sub-5ms latency suggests local routing"
            }
            if ($avgLatency -lt 1) {
                $result.HairpinIndicators += "Sub-millisecond latency ($($result.ExternalLatencyMs)ms) indicates local network"
            }
        }
        
        # Test 2: Traceroute analysis (limited hops)
        Write-Host "  Performing traceroute analysis..." -ForegroundColor Gray
        
        $traceHops = @()
        for ($ttl = 1; $ttl -le 10; $ttl++) {
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $options = New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)
                $buffer = [byte[]]::new(32)
                $reply = $ping.Send($TargetIP, 1000, $buffer, $options)
                
                $hopInfo = [PSCustomObject]@{
                    Hop = $ttl
                    Address = if ($reply.Address) { $reply.Address.ToString() } else { "*" }
                    RTT = if ($reply.Status -eq 'Success' -or $reply.Status -eq 'TtlExpired') { $reply.RoundtripTime } else { $null }
                    Status = $reply.Status.ToString()
                }
                $traceHops += $hopInfo
                $ping.Dispose()
                
                # If we reached the target, stop
                if ($reply.Status -eq 'Success') {
                    break
                }
            }
            catch {
                $traceHops += [PSCustomObject]@{
                    Hop = $ttl
                    Address = "*"
                    RTT = $null
                    Status = "Error"
                }
            }
        }
        $result.TracerouteHops = $traceHops
        
        # Analyze traceroute for hairpin patterns
        if ($traceHops.Count -gt 0) {
            $reachableHops = $traceHops | Where-Object { $_.Address -ne "*" }
            
            # Check if target is reached in 1-2 hops
            $targetReached = $traceHops | Where-Object { $_.Address -eq $TargetIP }
            if ($targetReached -and $targetReached.Hop -le 2) {
                $result.HairpinIndicators += "Target reached in only $($targetReached.Hop) hop(s)"
            }
            
            # Check for RFC1918 addresses in the path to a public IP
            $privatePattern = '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            $privateHops = $reachableHops | Where-Object { $_.Address -match $privatePattern }
            $allHopsPrivate = ($reachableHops | Where-Object { $_.Address -ne $TargetIP }) | 
                Where-Object { $_.Address -notmatch $privatePattern }
            
            if ($privateHops.Count -gt 0 -and $allHopsPrivate.Count -eq 0) {
                $result.HairpinIndicators += "All intermediate hops are private IPs (hairpin through NAT device)"
            }
            
            # Build routing details
            $routeDetails = "Route: "
            foreach ($hop in $traceHops | Select-Object -First 5) {
                $rtt = if ($hop.RTT) { "$($hop.RTT)ms" } else { "?" }
                $routeDetails += "[$($hop.Hop)] $($hop.Address) ($rtt) -> "
            }
            $result.RoutingDetails = $routeDetails.TrimEnd(" -> ")
        }
        
        # Test 3: TCP connection test to verify port accessibility
        Write-Host "  Testing TCP connection on port $TargetPort..." -ForegroundColor Gray
        
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcpClient.ConnectAsync($TargetIP, $TargetPort)
            $connected = $connectTask.Wait($TimeoutMs)
            
            if ($connected -and $tcpClient.Connected) {
                # Connection successful - measure actual TCP latency
                $tcpClient.Close()
                
                # Quick TCP latency test
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $tcpClient2 = New-Object System.Net.Sockets.TcpClient
                $connectTask2 = $tcpClient2.ConnectAsync($TargetIP, $TargetPort)
                if ($connectTask2.Wait($TimeoutMs)) {
                    $sw.Stop()
                    $tcpLatency = $sw.ElapsedMilliseconds
                    
                    if ($tcpLatency -lt 3) {
                        $result.HairpinIndicators += "TCP connection established in ${tcpLatency}ms (very fast - likely local)"
                    }
                }
                $tcpClient2.Close()
            }
        }
        catch {
            # Connection failed - this is informational only
        }
        
        # Test 4: Compare with internal host if provided
        if ($InternalHost) {
            Write-Host "  Comparing with internal host $InternalHost..." -ForegroundColor Gray
            
            try {
                $internalPings = @()
                for ($i = 0; $i -lt $PingCount; $i++) {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($InternalHost, $TimeoutMs)
                    if ($reply.Status -eq 'Success') {
                        $internalPings += $reply.RoundtripTime
                    }
                    $ping.Dispose()
                }
                
                if ($internalPings.Count -gt 0) {
                    $result.InternalLatencyMs = [math]::Round(($internalPings | Measure-Object -Average).Average, 2)
                    
                    # Compare latencies - if they're similar, likely hairpin
                    if ($result.ExternalLatencyMs -and $result.InternalLatencyMs) {
                        $latencyDiff = [math]::Abs($result.ExternalLatencyMs - $result.InternalLatencyMs)
                        if ($latencyDiff -lt 2) {
                            $result.HairpinIndicators += "Latency to public IP ($($result.ExternalLatencyMs)ms) similar to internal host ($($result.InternalLatencyMs)ms)"
                        }
                    }
                }
            }
            catch { }
        }
        
        # Determine overall hairpin status
        $indicatorCount = $result.HairpinIndicators.Count
        if ($indicatorCount -ge 3) {
            $result.IsHairpin = $true
            $result.HairpinConfidence = "High"
        }
        elseif ($indicatorCount -eq 2) {
            $result.IsHairpin = $true
            $result.HairpinConfidence = "Medium"
        }
        elseif ($indicatorCount -eq 1) {
            $result.IsHairpin = $false
            $result.HairpinConfidence = "Low (possible)"
        }
        else {
            $result.IsHairpin = $false
            $result.HairpinConfidence = "No hairpin detected"
        }
        
        $result.Success = $true
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Success = $false
    }
    
    return $result
}

function Get-PublicIPAddress {
    <#
    .SYNOPSIS
        Gets the current public IP address using external services
    #>
    $services = @(
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    )
    
    foreach ($service in $services) {
        try {
            $response = Invoke-RestMethod -Uri $service -TimeoutSec 5 -ErrorAction Stop
            $ip = $response.Trim()
            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                return $ip
            }
        }
        catch {
            continue
        }
    }
    return $null
}

function Invoke-HairpinTest {
    <#
    .SYNOPSIS
        Interactive hairpin NAT test with automatic public IP detection
    #>
    param(
        [string]$TargetIP,
        [int]$TargetPort = 443,
        [string]$InternalHost,
        [switch]$AutoDetectPublicIP
    )
    
    Write-Host ""
    Write-Host "Hairpin NAT Detection" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    # Auto-detect public IP if requested or no target provided
    if ($AutoDetectPublicIP -or -not $TargetIP) {
        Write-Host "Detecting public IP address..." -ForegroundColor Yellow
        $detectedIP = Get-PublicIPAddress
        if ($detectedIP) {
            Write-Host "Detected public IP: $detectedIP" -ForegroundColor Green
            if (-not $TargetIP) {
                $TargetIP = $detectedIP
            }
        }
        else {
            Write-Host "Could not auto-detect public IP" -ForegroundColor Red
            if (-not $TargetIP) {
                Write-Host "Please specify a target IP with -TargetIP parameter" -ForegroundColor Yellow
                return
            }
        }
    }
    
    Write-Host "Testing hairpin NAT for: $TargetIP`:$TargetPort" -ForegroundColor Yellow
    Write-Host ""
    
    $result = Test-HairpinNAT -TargetIP $TargetIP -TargetPort $TargetPort -InternalHost $InternalHost
    
    # Display results
    Write-Host ""
    Write-Host "Results" -ForegroundColor Cyan
    Write-Host "=======" -ForegroundColor Cyan
    
    if ($result.Success) {
        $statusColor = if ($result.IsHairpin) { "Yellow" } else { "Green" }
        $statusIcon = if ($result.IsHairpin) { "[!]" } else { "[OK]" }
        
        Write-Host ""
        Write-Host "$statusIcon Hairpin NAT: $(if($result.IsHairpin){'DETECTED'}else{'Not Detected'})" -ForegroundColor $statusColor
        Write-Host "    Confidence: $($result.HairpinConfidence)" -ForegroundColor $statusColor
        Write-Host ""
        
        Write-Host "Network Metrics:" -ForegroundColor White
        if ($result.ExternalLatencyMs) {
            Write-Host "  Latency to target: $($result.ExternalLatencyMs)ms" -ForegroundColor Gray
        }
        if ($result.InternalLatencyMs) {
            Write-Host "  Latency to internal: $($result.InternalLatencyMs)ms" -ForegroundColor Gray
        }
        if ($result.HopCount) {
            Write-Host "  Estimated hops: $($result.HopCount)" -ForegroundColor Gray
        }
        if ($result.TTLToTarget) {
            Write-Host "  TTL received: $($result.TTLToTarget)" -ForegroundColor Gray
        }
        
        if ($result.RoutingDetails) {
            Write-Host ""
            Write-Host "Routing Path:" -ForegroundColor White
            Write-Host "  $($result.RoutingDetails)" -ForegroundColor Gray
        }
        
        if ($result.HairpinIndicators.Count -gt 0) {
            Write-Host ""
            Write-Host "Indicators:" -ForegroundColor White
            foreach ($indicator in $result.HairpinIndicators) {
                Write-Host "  - $indicator" -ForegroundColor Yellow
            }
        }
        
        Write-Host ""
        Write-Host "Local IP Addresses:" -ForegroundColor White
        foreach ($ip in $result.LocalIPAddresses) {
            Write-Host "  - $ip" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[X] Test failed: $($result.Error)" -ForegroundColor Red
    }
    
    Write-Host ""
    return $result
}

#endregion

#region Teams Jitter Testing

# Microsoft Teams media relay endpoints for jitter testing
$script:TeamsMediaEndpoints = @(
    @{ Host = "13.107.64.0"; Description = "Teams Media Relay (Global)"; Region = "Global" }
    @{ Host = "52.120.0.0"; Description = "Teams Media Relay (Americas)"; Region = "Americas" }
    @{ Host = "52.112.0.0"; Description = "Teams Media Relay (EMEA)"; Region = "EMEA" }
    @{ Host = "52.122.0.0"; Description = "Teams Media Relay (APAC)"; Region = "APAC" }
    @{ Host = "worldaz.tr.teams.microsoft.com"; Description = "Teams Transport Relay"; Region = "Global" }
    @{ Host = "teams.microsoft.com"; Description = "Teams Web Service"; Region = "Global" }
    @{ Host = "statics.teams.cdn.office.net"; Description = "Teams CDN"; Region = "Global" }
)

function Test-NetworkJitter {
    <#
    .SYNOPSIS
        Tests network jitter (latency variation) to a target host
    .DESCRIPTION
        Sends multiple ICMP ping requests and calculates jitter metrics including:
        - Average latency
        - Min/Max latency
        - Jitter (standard deviation of latency)
        - Packet loss percentage
        - ICMP blocked detection
    .PARAMETER Target
        The hostname or IP to test
    .PARAMETER PingCount
        Number of ping requests to send (default: 50)
    .PARAMETER IntervalMs
        Interval between pings in milliseconds (default: 50)
    .PARAMETER TimeoutMs
        Timeout for each ping in milliseconds (default: 1000)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        [string]$Description = "",
        [int]$PingCount = 50,
        [int]$IntervalMs = 50,
        [int]$TimeoutMs = 1000
    )
    
    $result = [PSCustomObject]@{
        Target = $Target
        Description = $Description
        Success = $false
        PingsSent = $PingCount
        PingsReceived = 0
        PacketLoss = 100.0
        MinLatency = $null
        MaxLatency = $null
        AvgLatency = $null
        Jitter = $null
        JitterRating = "Unknown"
        Latencies = @()
        ICMPBlocked = $false
        ICMPBlockedReason = $null
        HostReachable = $null
        PingStatuses = @{}
        Error = $null
    }
    
    try {
        $latencies = @()
        $pingStatuses = @{}
        $ping = New-Object System.Net.NetworkInformation.Ping
        
        for ($i = 0; $i -lt $PingCount; $i++) {
            try {
                $reply = $ping.Send($Target, $TimeoutMs)
                
                # Track status counts
                $statusKey = $reply.Status.ToString()
                if ($pingStatuses.ContainsKey($statusKey)) {
                    $pingStatuses[$statusKey]++
                } else {
                    $pingStatuses[$statusKey] = 1
                }
                
                if ($reply.Status -eq 'Success') {
                    $latencies += $reply.RoundtripTime
                }
            }
            catch {
                # Track exceptions as a status
                if ($pingStatuses.ContainsKey("Exception")) {
                    $pingStatuses["Exception"]++
                } else {
                    $pingStatuses["Exception"] = 1
                }
            }
            
            if ($IntervalMs -gt 0 -and $i -lt ($PingCount - 1)) {
                Start-Sleep -Milliseconds $IntervalMs
            }
        }
        
        $ping.Dispose()
        $result.Latencies = $latencies
        $result.PingsReceived = $latencies.Count
        $result.PacketLoss = [math]::Round((($PingCount - $latencies.Count) / $PingCount) * 100, 2)
        $result.PingStatuses = $pingStatuses
        
        if ($latencies.Count -gt 1) {
            $result.MinLatency = ($latencies | Measure-Object -Minimum).Minimum
            $result.MaxLatency = ($latencies | Measure-Object -Maximum).Maximum
            $result.AvgLatency = [math]::Round(($latencies | Measure-Object -Average).Average, 2)
            
            # Calculate jitter (standard deviation)
            $avg = $result.AvgLatency
            $sumSquares = 0
            foreach ($lat in $latencies) {
                $sumSquares += [math]::Pow(($lat - $avg), 2)
            }
            $result.Jitter = [math]::Round([math]::Sqrt($sumSquares / $latencies.Count), 2)
            
            # Rate jitter quality for Teams
            # Microsoft recommends: Jitter < 30ms for good quality
            if ($result.Jitter -lt 10) {
                $result.JitterRating = "Excellent"
            }
            elseif ($result.Jitter -lt 20) {
                $result.JitterRating = "Good"
            }
            elseif ($result.Jitter -lt 30) {
                $result.JitterRating = "Acceptable"
            }
            elseif ($result.Jitter -lt 50) {
                $result.JitterRating = "Poor"
            }
            else {
                $result.JitterRating = "Very Poor"
            }
            
            $result.Success = $true
        }
        elseif ($latencies.Count -eq 1) {
            $result.MinLatency = $latencies[0]
            $result.MaxLatency = $latencies[0]
            $result.AvgLatency = $latencies[0]
            $result.Jitter = 0
            $result.JitterRating = "Insufficient data"
            $result.Success = $true
        }
        else {
            # No successful pings - check if ICMP might be blocked
            $result.Error = "No successful ping responses received"
            
            # Analyze ping statuses to determine likely cause
            $timeoutCount = if ($pingStatuses.ContainsKey("TimedOut")) { $pingStatuses["TimedOut"] } else { 0 }
            $destUnreachable = if ($pingStatuses.ContainsKey("DestinationHostUnreachable")) { $pingStatuses["DestinationHostUnreachable"] } else { 0 }
            $destNetUnreachable = if ($pingStatuses.ContainsKey("DestinationNetworkUnreachable")) { $pingStatuses["DestinationNetworkUnreachable"] } else { 0 }
            
            # If all pings timed out, ICMP might be blocked - verify with TCP
            if ($timeoutCount -eq $PingCount -or ($timeoutCount + $destUnreachable) -eq $PingCount) {
                # Try TCP connection to common ports to verify host is reachable
                $tcpReachable = $false
                $testPorts = @(443, 80, 3478, 3479, 3480)  # HTTPS, HTTP, and Teams media ports
                
                foreach ($port in $testPorts) {
                    try {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $connectTask = $tcpClient.ConnectAsync($Target, $port)
                        if ($connectTask.Wait(2000)) {
                            if ($tcpClient.Connected) {
                                $tcpReachable = $true
                                $tcpClient.Close()
                                break
                            }
                        }
                        $tcpClient.Close()
                    }
                    catch {
                        # Port not open, try next
                    }
                }
                
                $result.HostReachable = $tcpReachable
                
                if ($tcpReachable) {
                    $result.ICMPBlocked = $true
                    $result.ICMPBlockedReason = "Host is reachable via TCP but all ICMP pings failed. ICMP/ping is likely blocked by firewall."
                    $result.Error = "ICMP BLOCKED - Host reachable via TCP but not responding to ping"
                }
                else {
                    $result.ICMPBlockedReason = "Host not reachable via ICMP or TCP. May be offline, blocked, or network issue."
                }
            }
            elseif ($destNetUnreachable -gt 0) {
                $result.ICMPBlockedReason = "Destination network unreachable - routing issue or network blocked"
            }
            
            # Add status breakdown to error
            if ($pingStatuses.Count -gt 0) {
                $statusSummary = ($pingStatuses.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
                $result.Error += " [Statuses: $statusSummary]"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Test-TeamsJitter {
    <#
    .SYNOPSIS
        Tests jitter to multiple Microsoft Teams media endpoints
    .PARAMETER PingCount
        Number of pings per endpoint (default: 50)
    .PARAMETER TestAllRegions
        Test all regional endpoints, not just global
    #>
    param(
        [int]$PingCount = 50,
        [switch]$TestAllRegions
    )
    
    $results = @()
    $endpointsToTest = if ($TestAllRegions) {
        $script:TeamsMediaEndpoints
    } else {
        $script:TeamsMediaEndpoints | Where-Object { $_.Region -eq "Global" }
    }
    
    Write-Host ""
    Write-Host "Microsoft Teams Jitter Test" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Testing $($endpointsToTest.Count) endpoints with $PingCount pings each..." -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($endpoint in $endpointsToTest) {
        Write-Host "Testing $($endpoint.Host) ($($endpoint.Description))..." -ForegroundColor Gray
        
        $result = Test-NetworkJitter -Target $endpoint.Host -Description $endpoint.Description -PingCount $PingCount
        $results += $result
        
        if ($result.Success) {
            $color = switch ($result.JitterRating) {
                "Excellent" { "Green" }
                "Good" { "Green" }
                "Acceptable" { "Yellow" }
                "Poor" { "Red" }
                "Very Poor" { "Red" }
                default { "Gray" }
            }
            Write-Host "  Latency: $($result.AvgLatency)ms (min: $($result.MinLatency)ms, max: $($result.MaxLatency)ms)" -ForegroundColor Gray
            Write-Host "  Jitter: $($result.Jitter)ms - $($result.JitterRating)" -ForegroundColor $color
            Write-Host "  Packet Loss: $($result.PacketLoss)%" -ForegroundColor $(if ($result.PacketLoss -eq 0) { "Green" } else { "Yellow" })
        }
        else {
            if ($result.ICMPBlocked) {
                Write-Host "  [ICMP BLOCKED] Host reachable via TCP but not responding to ping" -ForegroundColor Yellow
                Write-Host "  $($result.ICMPBlockedReason)" -ForegroundColor Gray
            }
            else {
                Write-Host "  Failed: $($result.Error)" -ForegroundColor Red
                if ($result.ICMPBlockedReason) {
                    Write-Host "  $($result.ICMPBlockedReason)" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    # Summary
    $successResults = $results | Where-Object { $_.Success }
    if ($successResults.Count -gt 0) {
        $overallJitter = [math]::Round(($successResults | Measure-Object -Property Jitter -Average).Average, 2)
        $overallLatency = [math]::Round(($successResults | Measure-Object -Property AvgLatency -Average).Average, 2)
        $maxPacketLoss = ($successResults | Measure-Object -Property PacketLoss -Maximum).Maximum
        
        Write-Host "Summary" -ForegroundColor Cyan
        Write-Host "=======" -ForegroundColor Cyan
        Write-Host "  Average Jitter: ${overallJitter}ms" -ForegroundColor White
        Write-Host "  Average Latency: ${overallLatency}ms" -ForegroundColor White
        Write-Host "  Max Packet Loss: ${maxPacketLoss}%" -ForegroundColor White
        
        # Check for ICMP blocked endpoints
        $icmpBlockedResults = $results | Where-Object { $_.ICMPBlocked }
        if ($icmpBlockedResults.Count -gt 0) {
            Write-Host "  ICMP Blocked: $($icmpBlockedResults.Count) endpoint(s)" -ForegroundColor Yellow
        }
        
        # Teams quality assessment
        Write-Host ""
        if ($overallJitter -lt 30 -and $overallLatency -lt 100 -and $maxPacketLoss -lt 1) {
            Write-Host "[OK] Network quality is suitable for Microsoft Teams calls" -ForegroundColor Green
        }
        elseif ($overallJitter -lt 50 -and $overallLatency -lt 150 -and $maxPacketLoss -lt 5) {
            Write-Host "[!] Network quality may cause minor Teams call issues" -ForegroundColor Yellow
        }
        else {
            Write-Host "[!!] Network quality may cause significant Teams call issues" -ForegroundColor Red
        }
        
        # Note about ICMP blocking
        if ($icmpBlockedResults.Count -gt 0) {
            Write-Host ""
            Write-Host "Note: $($icmpBlockedResults.Count) endpoint(s) block ICMP/ping." -ForegroundColor Gray
            Write-Host "This prevents jitter measurement but doesn't affect Teams calls (uses UDP/TCP)." -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    return $results
}

#endregion

#region Shared Functions

function Get-CertificateChain {
    param(
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutMs = 10000
    )
    
    $result = [PSCustomObject]@{
        Hostname = $Hostname
        Port = $Port
        Success = $false
        Certificate = $null
        Chain = @()
        RootCA = $null
        RootThumbprint = $null
        IsIntercepted = $false
        InterceptionDetails = ""
        Error = $null
    }
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)
        
        if (-not $connectTask.Wait($TimeoutMs)) {
            throw "Connection timed out after $($TimeoutMs/1000) seconds"
        }
        
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { param($sslSender, $cert, $chain, $sslErrors) return $true }  # Accept all certs for inspection
        )
        
        try {
            $sslStream.AuthenticateAsClient($Hostname)
            
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
            $result.Certificate = $cert
            $result.Success = $true
            
            # Build and validate the certificate chain
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags
            $chain.Build($cert) | Out-Null
            
            $chainElements = @()
            foreach ($element in $chain.ChainElements) {
                $chainElements += [PSCustomObject]@{
                    Subject = $element.Certificate.Subject
                    Issuer = $element.Certificate.Issuer
                    Thumbprint = $element.Certificate.Thumbprint
                    NotBefore = $element.Certificate.NotBefore
                    NotAfter = $element.Certificate.NotAfter
                }
            }
            $result.Chain = $chainElements
            
            # Get the root CA (last in chain)
            if ($chain.ChainElements.Count -gt 0) {
                $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
                $result.RootCA = $rootCert.Subject
                $result.RootThumbprint = $rootCert.Thumbprint
                
                # Check for interception
                $isKnownRoot = $false
                $isKnownIssuer = $false
                
                # Check thumbprint
                foreach ($knownRoot in $script:KnownMicrosoftRootCAs.GetEnumerator()) {
                    if ($rootCert.Thumbprint -eq $knownRoot.Value) {
                        $isKnownRoot = $true
                        break
                    }
                }
                
                # Check issuer name contains known issuers
                foreach ($issuer in $script:KnownMicrosoftIssuers) {
                    if ($rootCert.Subject -match $issuer -or $rootCert.Issuer -match $issuer) {
                        $isKnownIssuer = $true
                        break
                    }
                }
                
                # Determine if intercepted
                if (-not $isKnownRoot -and -not $isKnownIssuer) {
                    $result.IsIntercepted = $true
                    $result.InterceptionDetails = "Unknown Root CA detected. This certificate was likely issued by an intercepting proxy."
                }
            }
            
            $chain.Dispose()
        }
        finally {
            $sslStream.Close()
        }
        
        $tcpClient.Close()
    }
    catch {
        # Extract the actual error message from AggregateException if present
        $errorMsg = $_.Exception.Message
        if ($_.Exception.InnerException) {
            $innerEx = $_.Exception.InnerException
            # Handle AggregateException which wraps multiple exceptions
            if ($innerEx -is [System.AggregateException]) {
                $errorMsg = ($innerEx.InnerExceptions | ForEach-Object { $_.Message }) -join "; "
            }
            elseif ($innerEx.InnerException) {
                # Go deeper if there's another level
                $errorMsg = $innerEx.InnerException.Message
            }
            else {
                $errorMsg = $innerEx.Message
            }
        }
        
        # Add helpful context for common expected failures
        $ignoreNote = ""
        if ($errorMsg -match "No such host is known|did not receive a response from an authoritative server") {
            # This is likely a domain suffix, not a real host
            $ignoreNote = " [This is a domain suffix for firewall rules, not a directly testable host. Can be ignored.]"
        }
        elseif ($errorMsg -match "remote party has closed the transport stream|forcibly closed by the remote host") {
            # Endpoint requires specific protocol or SNI
            $ignoreNote = " [Endpoint requires specific resource name or protocol. Can be ignored for interception testing.]"
        }
        elseif ($errorMsg -match "SSPI failed") {
            # TLS/protocol negotiation issue
            $ignoreNote = " [TLS negotiation issue - endpoint may use non-standard configuration. Can be ignored.]"
        }
        
        $result.Error = $errorMsg + $ignoreNote
    }
    
    return $result
}

#endregion

#region GUI Mode

function Start-GUIMode {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms

    #region XAML Definition
    [xml]$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SSL/TLS Interception Detector" 
        Height="950" Width="1150"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E">
    <Window.Resources>
        <!-- Dark Theme Colors -->
        <SolidColorBrush x:Key="BackgroundBrush" Color="#1E1E1E"/>
        <SolidColorBrush x:Key="SecondaryBackgroundBrush" Color="#252526"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#3C3C3C"/>
        <SolidColorBrush x:Key="ForegroundBrush" Color="#CCCCCC"/>
        <SolidColorBrush x:Key="AccentBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="SuccessBrush" Color="#4EC9B0"/>
        <SolidColorBrush x:Key="WarningBrush" Color="#FFCC00"/>
        <SolidColorBrush x:Key="ErrorBrush" Color="#F14C4C"/>
        
        <!-- Button Style -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="15,8"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="4" 
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#1084D8"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#006CBD"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#555555"/>
                                <Setter Property="Foreground" Value="#888888"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- CheckBox Style -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>
        
        <!-- TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="5,3"/>
            <Setter Property="CaretBrush" Value="#CCCCCC"/>
        </Style>
        
        <!-- DataGrid Style -->
        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="#252526"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
            <Setter Property="RowBackground" Value="#252526"/>
            <Setter Property="AlternatingRowBackground" Value="#2D2D30"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#3C3C3C"/>
        </Style>
        
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="Padding" Value="8,5"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
        
        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="5,3"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#094771"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        
        <Style TargetType="DataGridRow">
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#094771"/>
                </Trigger>
                <DataTrigger Binding="{Binding StatusIcon}" Value="[WARN]">
                    <Setter Property="Background" Value="#4D3D00"/>
                    <Setter Property="Foreground" Value="#FFCC00"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding StatusIcon}" Value="[FAIL]">
                    <Setter Property="Background" Value="#4D1A1A"/>
                    <Setter Property="Foreground" Value="#F14C4C"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>
        
        <!-- GroupBox Style -->
        <Style TargetType="GroupBox">
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="Padding" Value="10"/>
            <Setter Property="Margin" Value="5"/>
        </Style>
        
        <!-- TabControl Style -->
        <Style TargetType="TabControl">
            <Setter Property="Background" Value="#252526"/>
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
        </Style>
        
        <Style TargetType="TabItem">
            <Setter Property="Background" Value="#2D2D30"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="Padding" Value="15,8"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border Name="Border" Background="#2D2D30" BorderThickness="1,1,1,0" BorderBrush="#3C3C3C" Margin="0,0,2,0">
                            <ContentPresenter x:Name="ContentSite" VerticalAlignment="Center" HorizontalAlignment="Center" 
                                              ContentSource="Header" Margin="15,8"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#252526"/>
                                <Setter Property="Foreground" Value="#0078D4"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#3C3C3C"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,15">
            <TextBlock Text="SSL/TLS Interception Detector" FontSize="24" FontWeight="Bold" Foreground="#0078D4"/>
            <TextBlock Text="Detect proxy SSL inspection that may affect application connectivity" 
                       FontSize="13" Foreground="#888888" Margin="0,5,0,0"/>
        </StackPanel>
        
        <!-- Main Content -->
        <TabControl Grid.Row="1">
            <!-- Endpoints Tab -->
            <TabItem Header="Endpoints">
                <Grid Margin="10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="250"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    
                    <!-- Left Panel - Categories -->
                    <ScrollViewer Grid.Column="0" Margin="0,0,10,0" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <GroupBox Header="Endpoint Categories">
                            <StackPanel>
                                <CheckBox x:Name="chkAVD" Content="Azure Virtual Desktop" IsChecked="True" Margin="0,5"/>
                                <CheckBox x:Name="chkM365" Content="Microsoft 365" IsChecked="True" Margin="0,5"/>
                                <CheckBox x:Name="chkAzure" Content="Azure Services" IsChecked="True" Margin="0,5"/>
                                <CheckBox x:Name="chkTRv2" Content="TRv2 / Global Secure Access" IsChecked="True" Margin="0,5"/>
                                <CheckBox x:Name="chkAppleSSO" Content="Apple SSO Extension" IsChecked="True" Margin="0,5"/>
                                <Separator Margin="0,10" Background="#3C3C3C"/>
                                <Button x:Name="btnSelectAll" Content="Select All" Margin="0,5"/>
                                <Button x:Name="btnDeselectAll" Content="Deselect All" Margin="0,5" Background="#555555"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Fetch Live Endpoints" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="Import from Microsoft:" Foreground="#CCCCCC" Margin="0,0,0,5"/>
                                <Button x:Name="btnFetchM365" Content="Fetch M365 Endpoints" Margin="0,3" Background="#107C10"/>
                                <Button x:Name="btnFetchAzure" Content="Fetch Azure Endpoints" Margin="0,3" Background="#107C10"/>
                                <TextBlock x:Name="txtFetchStatus" Text="" Foreground="#888888" FontSize="11" Margin="0,5,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Add Custom Endpoint" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="Hostname:" Foreground="#CCCCCC" Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomHost" Margin="0,0,0,8"/>
                                <TextBlock Text="Port:" Foreground="#CCCCCC" Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomPort" Text="443" Margin="0,0,0,8"/>
                                <TextBlock Text="Description:" Foreground="#CCCCCC" Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomDesc" Margin="0,0,0,8"/>
                                <Button x:Name="btnAddEndpoint" Content="Add Endpoint" Margin="0,5"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Import Endpoints from File" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="File format (CSV or TXT):" Foreground="#CCCCCC" Margin="0,0,0,3" FontWeight="Bold"/>
                                <TextBlock Text="hostname,port,description" Foreground="#888888" FontSize="11" Margin="0,0,0,2"/>
                                <TextBlock Text="Example:" Foreground="#888888" FontSize="10" Margin="0,3,0,0"/>
                                <TextBlock Text="myapp.contoso.com,443,My App" Foreground="#6A9955" FontSize="10" FontFamily="Consolas"/>
                                <TextBlock Text="api.example.com,8443,API" Foreground="#6A9955" FontSize="10" FontFamily="Consolas" Margin="0,0,0,8"/>
                                <Button x:Name="btnImportFile" Content="Import from File..." Margin="0,5" Background="#0E639C"/>
                                <TextBlock x:Name="txtImportStatus" Text="" Foreground="#888888" FontSize="11" Margin="0,5,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <Button x:Name="btnRemoveSelected" Content="Remove Selected" Margin="5,10" Background="#C42B1C"/>
                    </StackPanel>
                    </ScrollViewer>
                    
                    <!-- Right Panel - Endpoints Grid -->
                    <GroupBox Grid.Column="1" Header="Endpoints to Test">
                        <DataGrid x:Name="dgEndpoints" 
                                  AutoGenerateColumns="False" 
                                  CanUserAddRows="False"
                                  SelectionMode="Extended"
                                  HeadersVisibility="Column"
                                  VerticalScrollBarVisibility="Auto">
                            <DataGrid.Columns>
                                <DataGridCheckBoxColumn Header="On" Binding="{Binding Enabled, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" Width="40"/>
                                <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="100" IsReadOnly="True"/>
                                <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="180" IsReadOnly="True"/>
                                <DataGridTextColumn Header="Hostname" Binding="{Binding Host}" Width="*" IsReadOnly="True"/>
                                <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="60" IsReadOnly="True"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </GroupBox>
                </Grid>
            </TabItem>
            
            <!-- Results Tab -->
            <TabItem Header="Results">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Summary Cards -->
                    <Grid Grid.Row="0" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <Border Grid.Column="0" Background="#252526" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Total Tested" Foreground="#888888" FontSize="12"/>
                                <TextBlock x:Name="txtTotalCount" Text="0" Foreground="#CCCCCC" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="1" Background="#252526" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Trusted" Foreground="#888888" FontSize="12"/>
                                <TextBlock x:Name="txtTrustedCount" Text="0" Foreground="#4EC9B0" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="2" Background="#252526" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Intercepted" Foreground="#888888" FontSize="12"/>
                                <TextBlock x:Name="txtInterceptedCount" Text="0" Foreground="#FFCC00" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="3" Background="#252526" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Failed" Foreground="#888888" FontSize="12"/>
                                <TextBlock x:Name="txtFailedCount" Text="0" Foreground="#F14C4C" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                    </Grid>
                    
                    <!-- Results Grid -->
                    <DataGrid x:Name="dgResults" Grid.Row="1"
                              AutoGenerateColumns="False" 
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              SelectionMode="Single"
                              HeadersVisibility="Column"
                              VerticalScrollBarVisibility="Auto"
                              HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Status" Binding="{Binding StatusIcon}" Width="60"/>
                            <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="180"/>
                            <DataGridTextColumn Header="Hostname" Binding="{Binding Hostname}" Width="200"/>
                            <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="50"/>
                            <DataGridTextColumn Header="Root CA" Binding="{Binding RootCA}" Width="200"/>
                            <DataGridTextColumn Header="Expected CA" Binding="{Binding ExpectedCA}" Width="150"/>
                            <DataGridTextColumn Header="Thumbprint" Binding="{Binding RootThumbprint}" Width="120"/>
                            <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="350"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            
            <!-- Certificate Details Tab -->
            <TabItem Header="Certificate Details">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="Select a result to view certificate chain details" 
                               Foreground="#888888" Margin="0,0,0,10"/>
                    
                    <Border Grid.Row="1" Background="#252526" CornerRadius="4" Padding="15">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="txtCertDetails" 
                                       Foreground="#CCCCCC" 
                                       FontFamily="Consolas" 
                                       FontSize="12"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </Grid>
            </TabItem>
            
            <!-- Known CAs Tab -->
            <TabItem Header="Known Root CAs">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="These are the trusted Microsoft root CAs used to detect SSL/TLS interception:" 
                               Foreground="#AAAAAA" Margin="0,0,0,10"/>
                    
                    <DataGrid x:Name="dgKnownCAs" Grid.Row="1"
                              AutoGenerateColumns="False" 
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              HeadersVisibility="Column"
                              VerticalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Root CA Name" Binding="{Binding Name}" Width="350"/>
                            <DataGridTextColumn Header="Thumbprint" Binding="{Binding Thumbprint}" Width="300"/>
                            <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                    
                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Left" Margin="0,10,0,0">
                        <Button x:Name="btnDiscoverCAs" Content="Discover &amp; Update Root CAs" Padding="15,8" Margin="0,0,10,0"/>
                        <TextBlock x:Name="txtCAStatus" VerticalAlignment="Center" Foreground="#888888" Text=""/>
                    </StackPanel>
                </Grid>
            </TabItem>
            
            <!-- Hairpin NAT Detection Tab -->
            <TabItem Header="Hairpin NAT">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Description -->
                    <StackPanel Grid.Row="0" Margin="0,0,0,15">
                        <TextBlock Text="Hairpin NAT Detection" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                        <TextBlock Text="Detect NAT loopback where traffic to your public IP is routed back internally" 
                                   Foreground="#888888" Margin="0,5,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    
                    <!-- Configuration -->
                    <Grid Grid.Row="1" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="350"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <GroupBox Grid.Column="0" Header="Test Configuration">
                            <StackPanel Margin="5">
                                <TextBlock Text="Target Public IP:" Foreground="#CCCCCC" Margin="0,0,0,3"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="txtHairpinIP" Grid.Column="0" Margin="0,0,5,0"/>
                                    <Button x:Name="btnDetectIP" Grid.Column="1" Content="Auto-Detect" Padding="10,3" Background="#107C10"/>
                                </Grid>
                                
                                <TextBlock Text="Port (optional):" Foreground="#CCCCCC" Margin="0,10,0,3"/>
                                <TextBox x:Name="txtHairpinPort" Text="443" Width="80" HorizontalAlignment="Left"/>
                                
                                <TextBlock Text="Internal Host (optional, for comparison):" Foreground="#CCCCCC" Margin="0,10,0,3"/>
                                <TextBox x:Name="txtHairpinInternal"/>
                                
                                <Button x:Name="btnRunHairpin" Content="Run Hairpin Test" Margin="0,15,0,0" Padding="15,8"/>
                                <TextBlock x:Name="txtHairpinStatus" Text="" Foreground="#888888" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Grid.Column="1" Header="What is Hairpin NAT?" Margin="10,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock Foreground="#AAAAAA" TextWrapping="Wrap" Margin="5">
                                    <Run FontWeight="Bold">Hairpin NAT</Run> (also called NAT loopback) occurs when:
                                    <LineBreak/><LineBreak/>
                                    1. An internal client sends traffic to a public IP
                                    <LineBreak/>
                                    2. The NAT device recognizes it's destined for an internal server
                                    <LineBreak/>
                                    3. Traffic is "hairpinned" back to the internal network
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Detection Methods:</Run>
                                    <LineBreak/>
                                    • TTL analysis (low hop count to public IP)
                                    <LineBreak/>
                                    • Latency comparison (sub-millisecond to public IP)
                                    <LineBreak/>
                                    • Traceroute showing only private hops
                                    <LineBreak/>
                                    • TCP connection timing analysis
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Why it matters:</Run>
                                    <LineBreak/>
                                    Hairpin NAT can cause unexpected routing, bypass security controls, 
                                    or indicate network misconfiguration.
                                </TextBlock>
                            </ScrollViewer>
                        </GroupBox>
                    </Grid>
                    
                    <!-- Results -->
                    <GroupBox Grid.Row="2" Header="Test Results">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <!-- Summary -->
                            <Grid Grid.Row="0" Margin="0,5,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                
                                <Border Grid.Column="0" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Status" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinResult" Text="-" Foreground="#CCCCCC" FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="1" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Latency" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinLatency" Text="-" Foreground="#CCCCCC" FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="2" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Hops" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinHops" Text="-" Foreground="#CCCCCC" FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="3" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Confidence" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinConfidence" Text="-" Foreground="#CCCCCC" FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <!-- Details -->
                            <Border Grid.Row="1" Background="#1E1E1E" CornerRadius="4" Padding="10">
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <TextBlock x:Name="txtHairpinDetails" 
                                               Foreground="#CCCCCC" 
                                               FontFamily="Consolas" 
                                               FontSize="12"
                                               TextWrapping="Wrap"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </GroupBox>
                </Grid>
            </TabItem>
            
            <!-- Teams Jitter Test Tab -->
            <TabItem Header="Teams Jitter">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Description -->
                    <StackPanel Grid.Row="0" Margin="0,0,0,15">
                        <TextBlock Text="Microsoft Teams Jitter Test" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                        <TextBlock Text="Test network jitter and latency to Microsoft Teams media endpoints for call quality assessment" 
                                   Foreground="#888888" Margin="0,5,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    
                    <!-- Configuration -->
                    <Grid Grid.Row="1" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="350"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <GroupBox Grid.Column="0" Header="Test Configuration">
                            <StackPanel Margin="5">
                                <TextBlock Text="Number of Pings per Endpoint:" Foreground="#CCCCCC" Margin="0,0,0,3"/>
                                <ComboBox x:Name="cmbJitterPingCount" SelectedIndex="1" Width="100" HorizontalAlignment="Left">
                                    <ComboBoxItem Content="25 (Quick)"/>
                                    <ComboBoxItem Content="50 (Standard)"/>
                                    <ComboBoxItem Content="100 (Thorough)"/>
                                </ComboBox>
                                
                                <CheckBox x:Name="chkTestAllRegions" Content="Test All Regional Endpoints" Margin="0,15,0,0" Foreground="#CCCCCC"/>
                                <TextBlock Text="(Uncheck to test only global endpoints)" Foreground="#666666" FontSize="10" Margin="20,2,0,0"/>
                                
                                <Button x:Name="btnRunJitter" Content="Run Jitter Test" Margin="0,20,0,0" Padding="15,8"/>
                                <TextBlock x:Name="txtJitterStatus" Text="" Foreground="#888888" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Grid.Column="1" Header="Teams Call Quality Requirements" Margin="10,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock Foreground="#AAAAAA" TextWrapping="Wrap" Margin="5">
                                    <Run FontWeight="Bold">Microsoft Teams Network Requirements:</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#4EC9B0">Jitter:</Run> &lt; 30ms recommended
                                    <LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#4EC9B0">Latency:</Run> &lt; 100ms recommended
                                    <LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#4EC9B0">Packet Loss:</Run> &lt; 1% recommended
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">What is Jitter?</Run>
                                    <LineBreak/>
                                    Jitter is the variation in packet arrival times. High jitter 
                                    causes choppy audio/video in Teams calls even when average 
                                    latency is acceptable.
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Rating Scale:</Run>
                                    <LineBreak/>
                                    • Excellent: &lt; 10ms
                                    <LineBreak/>
                                    • Good: 10-20ms
                                    <LineBreak/>
                                    • Acceptable: 20-30ms
                                    <LineBreak/>
                                    • Poor: 30-50ms
                                    <LineBreak/>
                                    • Very Poor: &gt; 50ms
                                </TextBlock>
                            </ScrollViewer>
                        </GroupBox>
                    </Grid>
                    
                    <!-- Results -->
                    <GroupBox Grid.Row="2" Header="Test Results">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <!-- Summary -->
                            <Grid Grid.Row="0" Margin="0,5,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                
                                <Border Grid.Column="0" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Overall Quality" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterQuality" Text="-" Foreground="#CCCCCC" FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="1" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Avg Jitter" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterAvg" Text="-" Foreground="#CCCCCC" FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="2" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Avg Latency" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterLatency" Text="-" Foreground="#CCCCCC" FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="3" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Packet Loss" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterLoss" Text="-" Foreground="#CCCCCC" FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="4" Background="#252526" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Endpoints" Foreground="#888888" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterEndpoints" Text="-" Foreground="#CCCCCC" FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <!-- Details -->
                            <Border Grid.Row="1" Background="#1E1E1E" CornerRadius="4" Padding="10">
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <TextBlock x:Name="txtJitterDetails" 
                                               Foreground="#CCCCCC" 
                                               FontFamily="Consolas" 
                                               FontSize="12"
                                               TextWrapping="Wrap"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </GroupBox>
                </Grid>
            </TabItem>
        </TabControl>
        
        <!-- Progress Bar -->
        <Grid Grid.Row="2" Margin="0,15,0,10">
            <ProgressBar x:Name="progressBar" Height="6" Background="#3C3C3C" Foreground="#0078D4" BorderThickness="0"/>
        </Grid>
        
        <!-- Bottom Controls -->
        <Grid Grid.Row="3">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            
            <TextBlock x:Name="txtStatus" Grid.Column="0" VerticalAlignment="Center" Foreground="#888888" Text="Ready to scan"/>
            
            <Button x:Name="btnExport" Grid.Column="1" Content="Export Results" Margin="10,0" IsEnabled="False"/>
            <Button x:Name="btnStop" Grid.Column="2" Content="Stop" Margin="0,0,10,0" Background="#C42B1C" IsEnabled="False"/>
            <Button x:Name="btnStart" Grid.Column="3" Content="Start Scan" Padding="25,8"/>
        </Grid>
    </Grid>
</Window>
"@
    #endregion

    #region Initialize Window

    $reader = New-Object System.Xml.XmlNodeReader $XAML
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Get all named controls
    $XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object {
        Set-Variable -Name ($_.Name) -Value $window.FindName($_.Name) -Scope Local
    }

    #endregion

    #region Data Collections

    # Create observable collection for endpoints
    $guiEndpointsList = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $guiResultsList = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $guiKnownCAsList = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $guiCertificateDetails = @{}
    $guiScanCancelled = $false

    # Default Endpoints for GUI
    $defaultGuiEndpoints = @(
        # AVD Endpoints
        @{ Category = "AVD"; Host = "rdweb.wvd.microsoft.com"; Port = 443; Description = "AVD Web Client"; Enabled = $true }
        @{ Category = "AVD"; Host = "rdbroker.wvd.microsoft.com"; Port = 443; Description = "AVD Broker"; Enabled = $true }
        @{ Category = "AVD"; Host = "client.wvd.microsoft.com"; Port = 443; Description = "AVD Client Service"; Enabled = $true }
        @{ Category = "AVD"; Host = "gateway.wvd.microsoft.com"; Port = 443; Description = "AVD Gateway"; Enabled = $true }
        @{ Category = "AVD"; Host = "rdgateway.wvd.microsoft.com"; Port = 443; Description = "AVD RD Gateway"; Enabled = $true }
        @{ Category = "AVD"; Host = "gcs.prod.monitoring.core.windows.net"; Port = 443; Description = "AVD Diagnostics"; Enabled = $true }
        @{ Category = "AVD"; Host = "catalogartifact.azureedge.net"; Port = 443; Description = "AVD Artifacts"; Enabled = $true }
        
        # Microsoft 365 Endpoints
        @{ Category = "M365"; Host = "outlook.office365.com"; Port = 443; Description = "Outlook Online"; Enabled = $true }
        @{ Category = "M365"; Host = "outlook.office.com"; Port = 443; Description = "Outlook Web"; Enabled = $true }
        @{ Category = "M365"; Host = "teams.microsoft.com"; Port = 443; Description = "Microsoft Teams"; Enabled = $true }
        @{ Category = "M365"; Host = "graph.microsoft.com"; Port = 443; Description = "Microsoft Graph API"; Enabled = $true }
        @{ Category = "M365"; Host = "sharepoint.com"; Port = 443; Description = "SharePoint"; Enabled = $true }
        @{ Category = "M365"; Host = "onedrive.live.com"; Port = 443; Description = "OneDrive"; Enabled = $true }
        @{ Category = "M365"; Host = "officeapps.live.com"; Port = 443; Description = "Office Online Apps"; Enabled = $true }
        
        # Azure Endpoints
        @{ Category = "Azure"; Host = "login.microsoftonline.com"; Port = 443; Description = "Azure AD / Entra ID"; Enabled = $true }
        @{ Category = "Azure"; Host = "login.windows.net"; Port = 443; Description = "Azure AD (Legacy)"; Enabled = $true }
        @{ Category = "Azure"; Host = "login.microsoft.com"; Port = 443; Description = "Microsoft Login"; Enabled = $true }
        @{ Category = "Azure"; Host = "aadcdn.msftauth.net"; Port = 443; Description = "Azure AD CDN"; Enabled = $true }
        @{ Category = "Azure"; Host = "management.azure.com"; Port = 443; Description = "Azure Management API"; Enabled = $true }
        @{ Category = "Azure"; Host = "management.core.windows.net"; Port = 443; Description = "Azure Classic Management"; Enabled = $true }
        
        # TRv2 / Global Secure Access Endpoints
        @{ Category = "TRv2"; Host = "device.login.microsoftonline.com"; Port = 443; Description = "Device Code Flow"; Enabled = $true }
        @{ Category = "TRv2"; Host = "autologon.microsoftazuread-sso.com"; Port = 443; Description = "Seamless SSO"; Enabled = $true }
        @{ Category = "TRv2"; Host = "enterpriseregistration.windows.net"; Port = 443; Description = "Device Registration"; Enabled = $true }
        @{ Category = "TRv2"; Host = "pas.windows.net"; Port = 443; Description = "Azure AD Password Protection"; Enabled = $true }
        @{ Category = "TRv2"; Host = "passwordreset.microsoftonline.com"; Port = 443; Description = "Self-Service Password Reset"; Enabled = $true }
        @{ Category = "TRv2"; Host = "tunnel.globalsecureaccess.microsoft.com"; Port = 443; Description = "GSA Tunnel"; Enabled = $true }
        @{ Category = "TRv2"; Host = "edge.microsoft.com"; Port = 443; Description = "Edge Updates (TRv2)"; Enabled = $true }
        
        # Apple SSO Extension Endpoints
        @{ Category = "AppleSSO"; Host = "app-site-association.cdn-apple.com"; Port = 443; Description = "Apple Associated Domains CDN"; Enabled = $true }
        @{ Category = "AppleSSO"; Host = "app-site-association.networking.apple"; Port = 443; Description = "Apple Associated Domains"; Enabled = $true }
        @{ Category = "AppleSSO"; Host = "sts.windows.net"; Port = 443; Description = "Security Token Service"; Enabled = $true }
        @{ Category = "AppleSSO"; Host = "login.partner.microsoftonline.cn"; Port = 443; Description = "China Cloud Login"; Enabled = $true }
        @{ Category = "AppleSSO"; Host = "login.microsoftonline.us"; Port = 443; Description = "US Gov Cloud Login"; Enabled = $true }
        @{ Category = "AppleSSO"; Host = "login-us.microsoftonline.com"; Port = 443; Description = "US Region Login"; Enabled = $true }
    )

    # Load default endpoints
    foreach ($ep in $defaultGuiEndpoints) {
        $endpointObj = [PSCustomObject]@{
            Enabled = $ep.Enabled
            Category = $ep.Category
            Description = $ep.Description
            Host = $ep.Host
            Port = $ep.Port
        }
        $guiEndpointsList.Add($endpointObj)
    }

    # Load known CAs
    foreach ($ca in $script:KnownMicrosoftRootCAs.GetEnumerator()) {
        $source = if ($script:AdditionalRootCAs.ContainsKey($ca.Key)) { "Config File" } else { "Built-in" }
        $caObj = [PSCustomObject]@{
            Name = $ca.Key
            Thumbprint = $ca.Value
            Source = $source
        }
        $guiKnownCAsList.Add($caObj)
    }

    $dgEndpoints.ItemsSource = $guiEndpointsList
    $dgResults.ItemsSource = $guiResultsList
    $dgKnownCAs.ItemsSource = $guiKnownCAsList

    #endregion

    #region GUI Helper Functions

    function Format-CertificateDetailsGUI {
        param([PSCustomObject]$Result)
        
        $sb = [System.Text.StringBuilder]::new()
        
        [void]$sb.AppendLine("=================================================================")
        [void]$sb.AppendLine("CERTIFICATE DETAILS: $($Result.Hostname):$($Result.Port)")
        [void]$sb.AppendLine("=================================================================")
        [void]$sb.AppendLine("")
        
        if ($Result.Success) {
            $cert = $Result.Certificate
            
            [void]$sb.AppendLine("LEAF CERTIFICATE")
            [void]$sb.AppendLine("-----------------------------------------------------------------")
            [void]$sb.AppendLine("Subject:     $($cert.Subject)")
            [void]$sb.AppendLine("Issuer:      $($cert.Issuer)")
            [void]$sb.AppendLine("Thumbprint:  $($cert.Thumbprint)")
            [void]$sb.AppendLine("Serial:      $($cert.SerialNumber)")
            [void]$sb.AppendLine("Valid From:  $($cert.NotBefore)")
            [void]$sb.AppendLine("Valid To:    $($cert.NotAfter)")
            [void]$sb.AppendLine("")
            
            [void]$sb.AppendLine("CERTIFICATE CHAIN")
            [void]$sb.AppendLine("-----------------------------------------------------------------")
            
            $i = 0
            foreach ($chainCert in $Result.Chain) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("[$i] $($chainCert.Subject)")
                [void]$sb.AppendLine("    Issuer:      $($chainCert.Issuer)")
                [void]$sb.AppendLine("    Thumbprint:  $($chainCert.Thumbprint)")
                [void]$sb.AppendLine("    Valid:       $($chainCert.NotBefore) to $($chainCert.NotAfter)")
                $i++
            }
            
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("ROOT CA ANALYSIS")
            [void]$sb.AppendLine("-----------------------------------------------------------------")
            [void]$sb.AppendLine("Root CA:         $($Result.RootCA)")
            [void]$sb.AppendLine("Root Thumbprint: $($Result.RootThumbprint)")
            [void]$sb.AppendLine("")
            
            if ($Result.IsIntercepted) {
                [void]$sb.AppendLine("[!] WARNING: INTERCEPTION DETECTED!")
                [void]$sb.AppendLine("    $($Result.InterceptionDetails)")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("    The root CA thumbprint does not match any known")
                [void]$sb.AppendLine("    Microsoft or trusted partner certificate authority.")
            }
            else {
                [void]$sb.AppendLine("[OK] Certificate chain is trusted (no interception detected)")
            }
        }
        else {
            [void]$sb.AppendLine("[X] CONNECTION FAILED")
            [void]$sb.AppendLine("-----------------------------------------------------------------")
            [void]$sb.AppendLine("Error: $($Result.Error)")
        }
        
        return $sb.ToString()
    }

    function Update-CategoryCheckboxesGUI {
        $avdEnabled = $guiEndpointsList | Where-Object { $_.Category -eq "AVD" -and $_.Enabled } | Measure-Object | Select-Object -ExpandProperty Count
        $avdTotal = $guiEndpointsList | Where-Object { $_.Category -eq "AVD" } | Measure-Object | Select-Object -ExpandProperty Count
        
        $m365Enabled = $guiEndpointsList | Where-Object { $_.Category -eq "M365" -and $_.Enabled } | Measure-Object | Select-Object -ExpandProperty Count
        $m365Total = $guiEndpointsList | Where-Object { $_.Category -eq "M365" } | Measure-Object | Select-Object -ExpandProperty Count
        
        $azureEnabled = $guiEndpointsList | Where-Object { $_.Category -eq "Azure" -and $_.Enabled } | Measure-Object | Select-Object -ExpandProperty Count
        $azureTotal = $guiEndpointsList | Where-Object { $_.Category -eq "Azure" } | Measure-Object | Select-Object -ExpandProperty Count
        
        $trv2Enabled = $guiEndpointsList | Where-Object { $_.Category -eq "TRv2" -and $_.Enabled } | Measure-Object | Select-Object -ExpandProperty Count
        $trv2Total = $guiEndpointsList | Where-Object { $_.Category -eq "TRv2" } | Measure-Object | Select-Object -ExpandProperty Count
        
        $appleSSOEnabled = $guiEndpointsList | Where-Object { $_.Category -eq "AppleSSO" -and $_.Enabled } | Measure-Object | Select-Object -ExpandProperty Count
        $appleSSOTotal = $guiEndpointsList | Where-Object { $_.Category -eq "AppleSSO" } | Measure-Object | Select-Object -ExpandProperty Count
        
        $chkAVD.IsChecked = ($avdEnabled -eq $avdTotal -and $avdTotal -gt 0)
        $chkM365.IsChecked = ($m365Enabled -eq $m365Total -and $m365Total -gt 0)
        $chkAzure.IsChecked = ($azureEnabled -eq $azureTotal -and $azureTotal -gt 0)
        $chkTRv2.IsChecked = ($trv2Enabled -eq $trv2Total -and $trv2Total -gt 0)
        $chkAppleSSO.IsChecked = ($appleSSOEnabled -eq $appleSSOTotal -and $appleSSOTotal -gt 0)
    }

    function Export-ResultsGUI {
        $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
        $saveDialog.Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $saveDialog.FileName = "SSLInterception_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        
        if ($saveDialog.ShowDialog() -eq $true) {
            $output = @()
            $output += "=" * 80
            $output += "SSL/TLS Interception Detection Results"
            $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $output += "Computer: $env:COMPUTERNAME"
            $output += "User: $env:USERNAME"
            $output += "=" * 80
            $output += ""
            
            $output += "SUMMARY"
            $output += "-" * 40
            $output += "Total Tested: $($txtTotalCount.Text)"
            $output += "Trusted: $($txtTrustedCount.Text)"
            $output += "Intercepted: $($txtInterceptedCount.Text)"
            $output += "Failed: $($txtFailedCount.Text)"
            $output += ""
            
            $output += "DETAILED RESULTS"
            $output += "-" * 40
            
            foreach ($result in $guiResultsList) {
                $output += ""
                $output += "$($result.StatusIcon) $($result.Description)"
                $output += "   Hostname: $($result.Hostname):$($result.Port)"
                $output += "   Root CA: $($result.RootCA)"
                $output += "   Thumbprint: $($result.RootThumbprint)"
                $output += "   Details: $($result.Details)"
            }
            
            $output | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            $txtStatus.Text = "Results exported to: $($saveDialog.FileName)"
        }
    }

    #endregion

    #region Event Handlers

    # Category checkbox handlers
    $chkAVD.Add_Checked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "AVD") { $ep.Enabled = $true }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkAVD.Add_Unchecked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "AVD") { $ep.Enabled = $false }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkM365.Add_Checked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "M365") { $ep.Enabled = $true }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkM365.Add_Unchecked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "M365") { $ep.Enabled = $false }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkAzure.Add_Checked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "Azure") { $ep.Enabled = $true }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkAzure.Add_Unchecked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "Azure") { $ep.Enabled = $false }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkTRv2.Add_Checked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "TRv2") { $ep.Enabled = $true }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkTRv2.Add_Unchecked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "TRv2") { $ep.Enabled = $false }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkAppleSSO.Add_Checked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "AppleSSO") { $ep.Enabled = $true }
        }
        $dgEndpoints.Items.Refresh()
    })

    $chkAppleSSO.Add_Unchecked({
        foreach ($ep in $guiEndpointsList) {
            if ($ep.Category -eq "AppleSSO") { $ep.Enabled = $false }
        }
        $dgEndpoints.Items.Refresh()
    })

    # Select/Deselect All buttons
    $btnSelectAll.Add_Click({
        foreach ($ep in $guiEndpointsList) {
            $ep.Enabled = $true
        }
        $dgEndpoints.Items.Refresh()
        Update-CategoryCheckboxesGUI
    })

    $btnDeselectAll.Add_Click({
        foreach ($ep in $guiEndpointsList) {
            $ep.Enabled = $false
        }
        $dgEndpoints.Items.Refresh()
        Update-CategoryCheckboxesGUI
    })

    # Fetch M365 Endpoints button
    $btnFetchM365.Add_Click({
        $txtFetchStatus.Text = "Fetching M365 endpoints..."
        $txtStatus.Text = "Fetching M365 endpoints from Microsoft..."
        [System.Windows.Forms.Application]::DoEvents()
        
        try {
            $m365Endpoints = Get-M365EndpointsFromMicrosoft
            $addedCount = 0
            
            foreach ($ep in $m365Endpoints) {
                # Check if already exists
                $exists = $guiEndpointsList | Where-Object { $_.Host -eq $ep.Host -and $_.Port -eq $ep.Port }
                if (-not $exists) {
                    $newEndpoint = [PSCustomObject]@{
                        Enabled = $true
                        Category = $ep.Category
                        Description = $ep.Description
                        Host = $ep.Host
                        Port = $ep.Port
                    }
                    $guiEndpointsList.Add($newEndpoint)
                    $addedCount++
                }
            }
            
            $dgEndpoints.Items.Refresh()
            $txtFetchStatus.Text = "Added $addedCount M365 endpoints"
            $txtStatus.Text = "Added $addedCount M365 endpoints from Microsoft feed"
        }
        catch {
            $txtFetchStatus.Text = "Error: $($_.Exception.Message)"
            $txtStatus.Text = "Error fetching M365 endpoints"
        }
    })

    # Fetch Azure Endpoints button
    $btnFetchAzure.Add_Click({
        $txtFetchStatus.Text = "Fetching Azure endpoints..."
        $txtStatus.Text = "Fetching Azure endpoints..."
        [System.Windows.Forms.Application]::DoEvents()
        
        try {
            $azureEndpoints = Get-AzureEndpointsFromMicrosoft
            $addedCount = 0
            
            foreach ($ep in $azureEndpoints) {
                # Check if already exists
                $exists = $guiEndpointsList | Where-Object { $_.Host -eq $ep.Host -and $_.Port -eq $ep.Port }
                if (-not $exists) {
                    $newEndpoint = [PSCustomObject]@{
                        Enabled = $true
                        Category = $ep.Category
                        Description = $ep.Description
                        Host = $ep.Host
                        Port = $ep.Port
                    }
                    $guiEndpointsList.Add($newEndpoint)
                    $addedCount++
                }
            }
            
            $dgEndpoints.Items.Refresh()
            $txtFetchStatus.Text = "Added $addedCount Azure endpoints"
            $txtStatus.Text = "Added $addedCount Azure endpoints"
        }
        catch {
            $txtFetchStatus.Text = "Error: $($_.Exception.Message)"
            $txtStatus.Text = "Error fetching Azure endpoints"
        }
    })

    # Add custom endpoint
    $btnAddEndpoint.Add_Click({
        $host_name = $txtCustomHost.Text.Trim()
        $port = $txtCustomPort.Text.Trim()
        $desc = $txtCustomDesc.Text.Trim()
        
        if ([string]::IsNullOrEmpty($host_name)) {
            [System.Windows.MessageBox]::Show("Please enter a hostname.", "Validation Error", "OK", "Warning")
            return
        }
        
        if (-not [int]::TryParse($port, [ref]$null)) {
            [System.Windows.MessageBox]::Show("Please enter a valid port number.", "Validation Error", "OK", "Warning")
            return
        }
        
        if ([string]::IsNullOrEmpty($desc)) {
            $desc = "Custom: $host_name"
        }
        
        $newEndpoint = [PSCustomObject]@{
            Enabled = $true
            Category = "Custom"
            Description = $desc
            Host = $host_name
            Port = [int]$port
        }
        
        $guiEndpointsList.Add($newEndpoint)
        
        $txtCustomHost.Text = ""
        $txtCustomPort.Text = "443"
        $txtCustomDesc.Text = ""
        
        $txtStatus.Text = "Added custom endpoint: $host_name`:$port"
    })

    # Remove selected endpoints
    $btnRemoveSelected.Add_Click({
        $selectedItems = @($dgEndpoints.SelectedItems)
        if ($selectedItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please select endpoints to remove.", "No Selection", "OK", "Information")
            return
        }
        
        $result = [System.Windows.MessageBox]::Show(
            "Remove $($selectedItems.Count) selected endpoint(s)?",
            "Confirm Remove",
            "YesNo",
            "Question"
        )
        
        if ($result -eq "Yes") {
            foreach ($item in $selectedItems) {
                $guiEndpointsList.Remove($item)
            }
            $txtStatus.Text = "Removed $($selectedItems.Count) endpoint(s)"
        }
    })

    # Import endpoints from file
    $btnImportFile.Add_Click({
        $openDialog = New-Object Microsoft.Win32.OpenFileDialog
        $openDialog.Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*"
        $openDialog.Title = "Select Endpoints File"
        
        if ($openDialog.ShowDialog() -eq $true) {
            try {
                $importedCount = 0
                $lines = Get-Content -Path $openDialog.FileName -ErrorAction Stop
                
                foreach ($line in $lines) {
                    # Skip empty lines and comments
                    $line = $line.Trim()
                    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
                        continue
                    }
                    
                    # Parse CSV format: hostname,port,description
                    $parts = $line -split ","
                    if ($parts.Count -ge 1) {
                        $host_name = $parts[0].Trim()
                        $port = if ($parts.Count -ge 2 -and $parts[1].Trim() -match '^\d+$') { [int]$parts[1].Trim() } else { 443 }
                        $description = if ($parts.Count -ge 3) { ($parts[2..($parts.Count-1)] -join ",").Trim() } else { "Custom: $host_name" }
                        
                        if (-not [string]::IsNullOrWhiteSpace($host_name)) {
                            $newEndpoint = [PSCustomObject]@{
                                Enabled = $true
                                Category = "Custom-Import"
                                Description = $description
                                Host = $host_name
                                Port = $port
                            }
                            $guiEndpointsList.Add($newEndpoint)
                            $importedCount++
                        }
                    }
                }
                
                $txtImportStatus.Text = "Imported $importedCount endpoints"
                $txtStatus.Text = "Imported $importedCount endpoints from file"
            }
            catch {
                $txtImportStatus.Text = "Error: $($_.Exception.Message)"
                $txtStatus.Text = "Error importing file"
            }
        }
    })

    # Results grid selection changed - show certificate details
    $dgResults.Add_SelectionChanged({
        $selected = $dgResults.SelectedItem
        if ($null -ne $selected -and $guiCertificateDetails.ContainsKey("$($selected.Hostname):$($selected.Port)")) {
            $txtCertDetails.Text = $guiCertificateDetails["$($selected.Hostname):$($selected.Port)"]
        }
        else {
            $txtCertDetails.Text = "Select a result from the Results tab to view certificate details."
        }
    })

    # Export button
    $btnExport.Add_Click({
        Export-ResultsGUI
    })

    # Discover Root CAs button
    $btnDiscoverCAs.Add_Click({
        $btnDiscoverCAs.IsEnabled = $false
        $txtCAStatus.Text = "Discovering root CAs..."
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        
        try {
            # Get sample of endpoints for scanning
            $allEndpoints = @()
            $allEndpoints += $script:AVDEndpoints | Where-Object { $_.Port -eq 443 }
            $allEndpoints += $script:Microsoft365Endpoints
            $allEndpoints += $script:AzureEndpoints | Where-Object { $_.Port -eq 443 }
            $sampleEndpoints = $allEndpoints | Select-Object -First 15
            
            $discoveredRootCAs = @{}
            $scannedCount = 0
            $successCount = 0
            
            foreach ($endpoint in $sampleEndpoints) {
                $scannedCount++
                $txtCAStatus.Text = "Scanning [$scannedCount/$($sampleEndpoints.Count)]: $($endpoint.Host)..."
                $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                
                try {
                    $result = Get-CertificateChain -Hostname $endpoint.Host -Port $endpoint.Port -TimeoutMs 5000
                    
                    if ($result.Success -and $result.RootThumbprint) {
                        $successCount++
                        $rootName = $result.RootCA -replace '^CN=', '' -replace ',.*$', ''
                        
                        if (-not $discoveredRootCAs.ContainsKey($rootName)) {
                            $discoveredRootCAs[$rootName] = $result.RootThumbprint
                        }
                    }
                }
                catch { }
            }
            
            # Find new CAs not in current list
            $newCAsAdded = 0
            foreach ($ca in $discoveredRootCAs.GetEnumerator()) {
                if ($script:KnownMicrosoftRootCAs.Values -notcontains $ca.Value) {
                    # Add to the known list
                    $script:KnownMicrosoftRootCAs[$ca.Name] = $ca.Value
                    $script:AdditionalRootCAs[$ca.Name] = $ca.Value
                    
                    # Add to GUI list
                    $caObj = [PSCustomObject]@{
                        Name = $ca.Name
                        Thumbprint = $ca.Value
                        Source = "Discovered"
                    }
                    $guiKnownCAsList.Add($caObj)
                    $newCAsAdded++
                }
            }
            
            # Save to config file
            if ($newCAsAdded -gt 0) {
                try {
                    $allCAsToSave = @{}
                    foreach ($ca in $script:AdditionalRootCAs.GetEnumerator()) {
                        $allCAsToSave[$ca.Name] = $ca.Value
                    }
                    $allCAsToSave | ConvertTo-Json -Depth 10 | Set-Content $script:RootCAConfigFile -Encoding UTF8
                    $txtCAStatus.Text = "Added $newCAsAdded new CA(s). Saved to config file."
                }
                catch {
                    $txtCAStatus.Text = "Added $newCAsAdded new CA(s). Failed to save config: $($_.Exception.Message)"
                }
            }
            else {
                $txtCAStatus.Text = "Discovery complete. All $($discoveredRootCAs.Count) CAs already in list."
            }
        }
        catch {
            $txtCAStatus.Text = "Error: $($_.Exception.Message)"
        }
        finally {
            $btnDiscoverCAs.IsEnabled = $true
        }
    })

    # Hairpin NAT Detection - Auto-Detect IP button
    $btnDetectIP.Add_Click({
        $txtHairpinStatus.Text = "Detecting public IP..."
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        
        try {
            $publicIP = Get-PublicIPAddress
            if ($publicIP) {
                $txtHairpinIP.Text = $publicIP
                $txtHairpinStatus.Text = "Detected: $publicIP"
            }
            else {
                $txtHairpinStatus.Text = "Could not detect public IP"
            }
        }
        catch {
            $txtHairpinStatus.Text = "Error: $($_.Exception.Message)"
        }
    })

    # Hairpin NAT Detection - Run Test button
    $btnRunHairpin.Add_Click({
        $targetIP = $txtHairpinIP.Text.Trim()
        
        if ([string]::IsNullOrWhiteSpace($targetIP)) {
            [System.Windows.MessageBox]::Show("Please enter a target IP address or click 'Auto-Detect' to find your public IP.", "No Target IP", "OK", "Warning")
            return
        }
        
        # Validate IP format
        if ($targetIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            [System.Windows.MessageBox]::Show("Please enter a valid IP address (e.g., 203.0.113.1)", "Invalid IP", "OK", "Warning")
            return
        }
        
        $port = 443
        if ($txtHairpinPort.Text -match '^\d+$') {
            $port = [int]$txtHairpinPort.Text
        }
        
        $internalHost = $txtHairpinInternal.Text.Trim()
        
        # Update UI
        $btnRunHairpin.IsEnabled = $false
        $txtHairpinStatus.Text = "Running hairpin NAT test..."
        $txtHairpinResult.Text = "Testing..."
        $txtHairpinLatency.Text = "-"
        $txtHairpinHops.Text = "-"
        $txtHairpinConfidence.Text = "-"
        $txtHairpinDetails.Text = ""
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        
        try {
            # Run the hairpin test
            $result = Test-HairpinNAT -TargetIP $targetIP -TargetPort $port -InternalHost $internalHost
            
            if ($result.Success) {
                # Update summary cards
                if ($result.IsHairpin) {
                    $txtHairpinResult.Text = "DETECTED"
                    $txtHairpinResult.Foreground = [System.Windows.Media.Brushes]::Orange
                }
                else {
                    $txtHairpinResult.Text = "Not Detected"
                    $txtHairpinResult.Foreground = [System.Windows.Media.Brushes]::LightGreen
                }
                
                $txtHairpinLatency.Text = if ($result.ExternalLatencyMs) { "$($result.ExternalLatencyMs)ms" } else { "N/A" }
                $txtHairpinHops.Text = if ($result.HopCount) { $result.HopCount.ToString() } else { "N/A" }
                $txtHairpinConfidence.Text = $result.HairpinConfidence
                
                # Build detailed output
                $details = @()
                $details += "Target: $($result.TargetIP):$($result.TargetPort)"
                $details += "Test Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                $details += ""
                $details += "=== RESULT ==="
                $details += "Hairpin NAT: $(if($result.IsHairpin){'YES - DETECTED'}else{'No'})"
                $details += "Confidence: $($result.HairpinConfidence)"
                $details += ""
                $details += "=== NETWORK METRICS ==="
                
                if ($result.ExternalLatencyMs) {
                    $details += "Latency to target: $($result.ExternalLatencyMs)ms"
                }
                if ($result.InternalLatencyMs) {
                    $details += "Latency to internal host: $($result.InternalLatencyMs)ms"
                }
                if ($result.TTLToTarget) {
                    $details += "TTL received: $($result.TTLToTarget)"
                }
                if ($result.HopCount) {
                    $details += "Estimated hops: $($result.HopCount)"
                }
                
                if ($result.RoutingDetails) {
                    $details += ""
                    $details += "=== ROUTING PATH ==="
                    $details += $result.RoutingDetails
                }
                
                if ($result.TracerouteHops.Count -gt 0) {
                    $details += ""
                    $details += "=== TRACEROUTE ==="
                    foreach ($hop in $result.TracerouteHops) {
                        $rtt = if ($hop.RTT -ne $null) { "$($hop.RTT)ms" } else { "*" }
                        $details += "  Hop $($hop.Hop): $($hop.Address) ($rtt) - $($hop.Status)"
                    }
                }
                
                if ($result.HairpinIndicators.Count -gt 0) {
                    $details += ""
                    $details += "=== HAIRPIN INDICATORS ==="
                    foreach ($indicator in $result.HairpinIndicators) {
                        $details += "  [!] $indicator"
                    }
                }
                
                if ($result.LocalIPAddresses.Count -gt 0) {
                    $details += ""
                    $details += "=== LOCAL IP ADDRESSES ==="
                    foreach ($ip in $result.LocalIPAddresses) {
                        $details += "  - $ip"
                    }
                }
                
                $txtHairpinDetails.Text = $details -join "`n"
                $txtHairpinStatus.Text = "Test completed"
            }
            else {
                $txtHairpinResult.Text = "Error"
                $txtHairpinResult.Foreground = [System.Windows.Media.Brushes]::Red
                $txtHairpinDetails.Text = "Test failed: $($result.Error)"
                $txtHairpinStatus.Text = "Test failed"
            }
        }
        catch {
            $txtHairpinResult.Text = "Error"
            $txtHairpinResult.Foreground = [System.Windows.Media.Brushes]::Red
            $txtHairpinDetails.Text = "Error: $($_.Exception.Message)"
            $txtHairpinStatus.Text = "Error occurred"
        }
        finally {
            $btnRunHairpin.IsEnabled = $true
        }
    })

    # Teams Jitter Test - Run Test button
    $btnRunJitter.Add_Click({
        # Get ping count from combo box
        $pingCount = switch ($cmbJitterPingCount.SelectedIndex) {
            0 { 25 }
            1 { 50 }
            2 { 100 }
            default { 50 }
        }
        
        $testAllRegions = $chkTestAllRegions.IsChecked
        
        # Update UI
        $btnRunJitter.IsEnabled = $false
        $txtJitterStatus.Text = "Running jitter test..."
        $txtJitterQuality.Text = "Testing..."
        $txtJitterAvg.Text = "-"
        $txtJitterLatency.Text = "-"
        $txtJitterLoss.Text = "-"
        $txtJitterEndpoints.Text = "-"
        $txtJitterDetails.Text = ""
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        
        try {
            # Get endpoints to test
            $endpointsToTest = if ($testAllRegions) {
                $script:TeamsMediaEndpoints
            } else {
                $script:TeamsMediaEndpoints | Where-Object { $_.Region -eq "Global" }
            }
            
            $results = @()
            $endpointCount = $endpointsToTest.Count
            $currentEndpoint = 0
            
            foreach ($endpoint in $endpointsToTest) {
                $currentEndpoint++
                $txtJitterStatus.Text = "Testing [$currentEndpoint/$endpointCount]: $($endpoint.Host)..."
                $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                
                $result = Test-NetworkJitter -Target $endpoint.Host -Description $endpoint.Description -PingCount $pingCount
                $results += $result
            }
            
            # Calculate summary
            $successResults = $results | Where-Object { $_.Success }
            $txtJitterEndpoints.Text = "$($successResults.Count)/$($results.Count)"
            
            if ($successResults.Count -gt 0) {
                $overallJitter = [math]::Round(($successResults | Measure-Object -Property Jitter -Average).Average, 2)
                $overallLatency = [math]::Round(($successResults | Measure-Object -Property AvgLatency -Average).Average, 2)
                $maxPacketLoss = ($successResults | Measure-Object -Property PacketLoss -Maximum).Maximum
                
                $txtJitterAvg.Text = "${overallJitter}ms"
                $txtJitterLatency.Text = "${overallLatency}ms"
                $txtJitterLoss.Text = "${maxPacketLoss}%"
                
                # Determine overall quality
                if ($overallJitter -lt 10 -and $overallLatency -lt 50 -and $maxPacketLoss -lt 0.5) {
                    $txtJitterQuality.Text = "Excellent"
                    $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::LightGreen
                }
                elseif ($overallJitter -lt 20 -and $overallLatency -lt 100 -and $maxPacketLoss -lt 1) {
                    $txtJitterQuality.Text = "Good"
                    $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::LightGreen
                }
                elseif ($overallJitter -lt 30 -and $overallLatency -lt 150 -and $maxPacketLoss -lt 2) {
                    $txtJitterQuality.Text = "Acceptable"
                    $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::Yellow
                }
                elseif ($overallJitter -lt 50 -and $overallLatency -lt 200 -and $maxPacketLoss -lt 5) {
                    $txtJitterQuality.Text = "Poor"
                    $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::Orange
                }
                else {
                    $txtJitterQuality.Text = "Very Poor"
                    $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::Red
                }
                
                # Build detailed output
                $details = @()
                $details += "Microsoft Teams Jitter Test Results"
                $details += "===================================="
                $details += "Test Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                $details += "Pings per endpoint: $pingCount"
                $details += ""
                $details += "=== SUMMARY ==="
                $details += "Average Jitter: ${overallJitter}ms"
                $details += "Average Latency: ${overallLatency}ms"
                $details += "Max Packet Loss: ${maxPacketLoss}%"
                $details += "Endpoints Tested: $($successResults.Count)/$($results.Count)"
                $details += ""
                
                # Quality assessment
                if ($overallJitter -lt 30 -and $overallLatency -lt 100 -and $maxPacketLoss -lt 1) {
                    $details += "[OK] Network quality is suitable for Microsoft Teams calls"
                }
                elseif ($overallJitter -lt 50 -and $overallLatency -lt 150 -and $maxPacketLoss -lt 5) {
                    $details += "[!] Network quality may cause minor Teams call issues"
                }
                else {
                    $details += "[!!] Network quality may cause significant Teams call issues"
                }
                
                $details += ""
                $details += "=== ENDPOINT DETAILS ==="
                
                foreach ($r in $results) {
                    $details += ""
                    $details += "$($r.Description) ($($r.Target))"
                    if ($r.Success) {
                        $details += "  Latency: $($r.AvgLatency)ms (min: $($r.MinLatency)ms, max: $($r.MaxLatency)ms)"
                        $details += "  Jitter: $($r.Jitter)ms - $($r.JitterRating)"
                        $details += "  Packet Loss: $($r.PacketLoss)% ($($r.PingsReceived)/$($r.PingsSent) received)"
                    }
                    else {
                        if ($r.ICMPBlocked) {
                            $details += "  [ICMP BLOCKED] $($r.ICMPBlockedReason)"
                            $details += "  Host reachable via TCP: Yes"
                        }
                        else {
                            $details += "  [FAILED] $($r.Error)"
                            if ($r.ICMPBlockedReason) {
                                $details += "  Note: $($r.ICMPBlockedReason)"
                            }
                        }
                    }
                }
                
                # Check for any ICMP blocked endpoints
                $icmpBlockedCount = ($results | Where-Object { $_.ICMPBlocked }).Count
                if ($icmpBlockedCount -gt 0) {
                    $details += ""
                    $details += "=== ICMP BLOCKING DETECTED ==="
                    $details += "$icmpBlockedCount endpoint(s) are blocking ICMP/ping."
                    $details += "This prevents accurate jitter measurement but does not affect Teams calls."
                    $details += "Teams uses UDP/TCP for media, not ICMP."
                }
                
                $txtJitterDetails.Text = $details -join "`n"
                $txtJitterStatus.Text = "Test completed"
            }
            else {
                $txtJitterQuality.Text = "Failed"
                $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::Red
                $txtJitterDetails.Text = "All endpoint tests failed. Check network connectivity."
                $txtJitterStatus.Text = "Test failed"
            }
        }
        catch {
            $txtJitterQuality.Text = "Error"
            $txtJitterQuality.Foreground = [System.Windows.Media.Brushes]::Red
            $txtJitterDetails.Text = "Error: $($_.Exception.Message)"
            $txtJitterStatus.Text = "Error occurred"
        }
        finally {
            $btnRunJitter.IsEnabled = $true
        }
    })

    # Stop button
    $btnStop.Add_Click({
        $script:guiScanCancelled = $true
        $txtStatus.Text = "Cancelling scan..."
    })

    # Start button - main scan logic
    $btnStart.Add_Click({
        # Get enabled endpoints
        $endpointsToTest = @($guiEndpointsList | Where-Object { $_.Enabled })
        
        if ($endpointsToTest.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please select at least one endpoint to test.", "No Endpoints", "OK", "Warning")
            return
        }
        
        # Reset state
        $script:guiScanCancelled = $false
        $guiResultsList.Clear()
        $guiCertificateDetails.Clear()
        $txtCertDetails.Text = ""
        
        # Update UI
        $btnStart.IsEnabled = $false
        $btnStop.IsEnabled = $true
        $btnExport.IsEnabled = $false
        $progressBar.Value = 0
        $progressBar.Maximum = $endpointsToTest.Count
        
        $trustedCount = 0
        $interceptedCount = 0
        $failedCount = 0
        
        $currentIndex = 0
        
        foreach ($endpoint in $endpointsToTest) {
            if ($script:guiScanCancelled) {
                $txtStatus.Text = "Scan cancelled by user"
                break
            }
            
            $currentIndex++
            $txtStatus.Text = "Testing $currentIndex of $($endpointsToTest.Count): $($endpoint.Host)"
            $progressBar.Value = $currentIndex
            
            # Process UI events
            [System.Windows.Forms.Application]::DoEvents()
            
            # Test the endpoint
            $result = Get-CertificateChain -Hostname $endpoint.Host -Port $endpoint.Port
            
            # Determine status
            $statusIcon = "[FAIL]"
            $details = ""
            $rootCA = ""
            $rootThumb = ""
            $expectedCA = ""
            
            if ($result.Success) {
                $rootCA = if ($result.RootCA) { 
                    $result.RootCA -replace "CN=([^,]+).*", '$1'
                } else { "N/A" }
                $rootThumb = if ($result.RootThumbprint) { $result.RootThumbprint.Substring(0, 16) + "..." } else { "N/A" }
                
                if ($result.IsIntercepted) {
                    $statusIcon = "[WARN]"
                    $details = $result.InterceptionDetails
                    $interceptedCount++
                    # Show expected CAs when interception detected
                    $expectedCA = "DigiCert/Microsoft/Baltimore"
                }
                else {
                    $statusIcon = "[OK]"
                    $details = "Trusted certificate chain"
                    $trustedCount++
                }
            }
            else {
                $statusIcon = "[FAIL]"
                $details = $result.Error
                $failedCount++
                $expectedCA = "Connection failed"
            }
            
            # Add to results
            $resultObj = [PSCustomObject]@{
                StatusIcon = $statusIcon
                Description = $endpoint.Description
                Hostname = $result.Hostname
                Port = $result.Port
                RootCA = $rootCA
                ExpectedCA = $expectedCA
                RootThumbprint = $rootThumb
                Details = $details
            }
            
            $guiResultsList.Add($resultObj)
            
            # Store certificate details
            $guiCertificateDetails["$($result.Hostname):$($result.Port)"] = Format-CertificateDetailsGUI -Result $result
            
            # Update summary counts
            $txtTotalCount.Text = $guiResultsList.Count.ToString()
            $txtTrustedCount.Text = $trustedCount.ToString()
            $txtInterceptedCount.Text = $interceptedCount.ToString()
            $txtFailedCount.Text = $failedCount.ToString()
            
            # Color the intercepted count if > 0
            if ($interceptedCount -gt 0) {
                $txtInterceptedCount.Foreground = [System.Windows.Media.Brushes]::Orange
            }
            
            [System.Windows.Forms.Application]::DoEvents()
        }
        
        # Scan complete
        $btnStart.IsEnabled = $true
        $btnStop.IsEnabled = $false
        $btnExport.IsEnabled = ($guiResultsList.Count -gt 0)
        
        if (-not $script:guiScanCancelled) {
            $txtStatus.Text = "Scan complete. Tested $($guiResultsList.Count) endpoints."
            
            if ($interceptedCount -gt 0) {
                [System.Windows.MessageBox]::Show(
                    "SSL/TLS INTERCEPTION DETECTED!`n`n$interceptedCount endpoint(s) appear to be intercepted by a proxy.`n`nThis can cause authentication and connectivity issues.`n`nCheck the Results tab for details.",
                    "Interception Detected",
                    "OK",
                    "Warning"
                )
            }
        }
    })

    #endregion

    # Show the window
    $window.ShowDialog() | Out-Null
}

#endregion

#region CLI Mode Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-EndpointCLI {
    param(
        [hashtable]$Endpoint,
        [switch]$ShowVerbose
    )
    
    $host_name = $Endpoint.Host
    $port = $Endpoint.Port
    $description = $Endpoint.Description
    
    Write-ColorOutput "`nTesting: $description ($host_name`:$port)" "Cyan"
    
    $result = Get-CertificateChain -Hostname $host_name -Port $port
    
    if ($result.Success) {
        $cert = $result.Certificate
        
        Write-ColorOutput "  Certificate Subject: $($cert.Subject)" "Gray"
        Write-ColorOutput "  Certificate Issuer:  $($cert.Issuer)" "Gray"
        Write-ColorOutput "  Thumbprint:          $($cert.Thumbprint)" "Gray"
        Write-ColorOutput "  Valid From:          $($cert.NotBefore) to $($cert.NotAfter)" "Gray"
        
        if ($ShowVerbose -and $result.Chain.Count -gt 0) {
            Write-ColorOutput "`n  Certificate Chain:" "Yellow"
            $i = 0
            foreach ($chainCert in $result.Chain) {
                Write-ColorOutput "    [$i] $($chainCert.Subject)" "Gray"
                Write-ColorOutput "        Thumbprint: $($chainCert.Thumbprint)" "DarkGray"
                $i++
            }
        }
        
        Write-ColorOutput "`n  Root CA: $($result.RootCA)" "Gray"
        Write-ColorOutput "  Root Thumbprint: $($result.RootThumbprint)" "Gray"
        
        if ($result.IsIntercepted) {
            Write-ColorOutput "`n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"
            Write-ColorOutput "  [!!] INTERCEPTION DETECTED!" "Red"
            Write-ColorOutput "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"
            Write-ColorOutput "  $($result.InterceptionDetails)" "Yellow"
            Write-ColorOutput "  The certificate chain does not end in a known Microsoft/trusted root CA." "Yellow"
        }
        else {
            Write-ColorOutput "`n  [OK] Certificate chain is trusted (no interception detected)" "Green"
        }
    }
    else {
        Write-ColorOutput "  [X] Connection failed: $($result.Error)" "Red"
    }
    
    return $result
}

function Export-ResultsCLI {
    param(
        [array]$Results,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "SSLInterception_Results_$timestamp.txt"
    $filepath = Join-Path $OutputPath $filename
    
    $output = @()
    $output += "=" * 80
    $output += "SSL/TLS Interception Detection Results"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "Computer: $env:COMPUTERNAME"
    $output += "User: $env:USERNAME"
    $output += "=" * 80
    $output += ""
    
    $interceptedCount = ($Results | Where-Object { $_.IsIntercepted }).Count
    $failedCount = ($Results | Where-Object { -not $_.Success }).Count
    $successCount = ($Results | Where-Object { $_.Success -and -not $_.IsIntercepted }).Count
    
    $output += "SUMMARY"
    $output += "-" * 40
    $output += "Total Endpoints Tested: $($Results.Count)"
    $output += "Trusted (No Interception): $successCount"
    $output += "Intercepted: $interceptedCount"
    $output += "Connection Failed: $failedCount"
    $output += ""
    
    if ($interceptedCount -gt 0) {
        $output += "[!] WARNING: SSL/TLS INTERCEPTION DETECTED!"
        $output += "The following endpoints are being intercepted by a proxy:"
        $output += ""
        
        foreach ($result in ($Results | Where-Object { $_.IsIntercepted })) {
            $output += "  - $($result.Hostname):$($result.Port)"
            $output += "    Root CA: $($result.RootCA)"
            $output += "    Root Thumbprint: $($result.RootThumbprint)"
            $output += ""
        }
        
        $output += ""
        $output += "RECOMMENDATION:"
        $output += "SSL/TLS interception can cause issues with applications."
        $output += "Consider excluding critical endpoints from proxy inspection."
        $output += ""
    }
    
    $output += ""
    $output += "DETAILED RESULTS"
    $output += "-" * 40
    
    foreach ($result in $Results) {
        $output += ""
        $output += "Endpoint: $($result.Hostname):$($result.Port)"
        
        if ($result.Success) {
            $cert = $result.Certificate
            $output += "  Status: Connected"
            $output += "  Certificate Subject: $($cert.Subject)"
            $output += "  Certificate Issuer: $($cert.Issuer)"
            $output += "  Thumbprint: $($cert.Thumbprint)"
            $output += "  Valid: $($cert.NotBefore) to $($cert.NotAfter)"
            $output += "  Root CA: $($result.RootCA)"
            $output += "  Root Thumbprint: $($result.RootThumbprint)"
            $output += "  Interception Detected: $($result.IsIntercepted)"
            
            if ($result.IsIntercepted) {
                $output += "  [!] $($result.InterceptionDetails)"
            }
        }
        else {
            $output += "  Status: Failed"
            $output += "  Error: $($result.Error)"
        }
    }
    
    $output += ""
    $output += "=" * 80
    $output += "End of Report"
    $output += "=" * 80
    
    $output | Out-File -FilePath $filepath -Encoding UTF8
    
    return $filepath
}

function Start-CLIMode {
    # Banner
    Write-ColorOutput @"

================================================================================
                     SSL/TLS Interception Detector
================================================================================

"@ "Cyan"

    Write-ColorOutput "Computer: $env:COMPUTERNAME" "Gray"
    Write-ColorOutput "User: $env:USERNAME" "Gray"
    Write-ColorOutput "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Gray"
    Write-ColorOutput ""

    # Determine which endpoints to test
    $endpointsToTest = @()

    if ($TestAll) {
        $endpointsToTest += $script:AVDEndpoints
        $endpointsToTest += $script:Microsoft365Endpoints
        $endpointsToTest += $script:AzureEndpoints
        $endpointsToTest += $script:TRv2Endpoints
        $endpointsToTest += $script:AppleSSOEndpoints
        Write-ColorOutput "Testing ALL endpoint categories..." "Yellow"
    }
    else {
        if ($TestAVD) {
            $endpointsToTest += $script:AVDEndpoints
            Write-ColorOutput "Testing AVD endpoints..." "Yellow"
        }
        if ($TestMicrosoft365) {
            $endpointsToTest += $script:Microsoft365Endpoints
            Write-ColorOutput "Testing Microsoft 365 endpoints..." "Yellow"
        }
        if ($TestAzure) {
            $endpointsToTest += $script:AzureEndpoints
            Write-ColorOutput "Testing Azure endpoints..." "Yellow"
        }
        if ($TestTRv2) {
            $endpointsToTest += $script:TRv2Endpoints
            Write-ColorOutput "Testing TRv2 / Global Secure Access endpoints..." "Yellow"
        }
        if ($TestAppleSSO) {
            $endpointsToTest += $script:AppleSSOEndpoints
            Write-ColorOutput "Testing Apple SSO Extension endpoints..." "Yellow"
        }
    }

    # Fetch live M365 endpoints if requested
    if ($FetchM365Endpoints) {
        Write-ColorOutput "Fetching live M365 endpoints from Microsoft..." "Yellow"
        $liveM365 = Get-M365EndpointsFromMicrosoft
        foreach ($ep in $liveM365) {
            $endpointsToTest += @{
                Host = $ep.Host
                Port = $ep.Port
                Description = $ep.Description
            }
        }
    }

    # Fetch live Azure endpoints if requested
    if ($FetchAzureEndpoints) {
        Write-ColorOutput "Fetching live Azure endpoints..." "Yellow"
        $liveAzure = Get-AzureEndpointsFromMicrosoft
        foreach ($ep in $liveAzure) {
            $endpointsToTest += @{
                Host = $ep.Host
                Port = $ep.Port
                Description = $ep.Description
            }
        }
    }

    # Add custom endpoints if provided
    if ($CustomEndpoints) {
        foreach ($ep in $CustomEndpoints) {
            $parts = $ep -split ':'
            if ($parts.Count -eq 2) {
                $endpointsToTest += @{
                    Host = $parts[0]
                    Port = [int]$parts[1]
                    Description = "Custom: $($parts[0])"
                }
            }
            else {
                $endpointsToTest += @{
                    Host = $ep
                    Port = 443
                    Description = "Custom: $ep"
                }
            }
        }
        Write-ColorOutput "Testing custom endpoints..." "Yellow"
    }

    # If no switches provided, default to TestAVD
    if ($endpointsToTest.Count -eq 0) {
        $endpointsToTest = $script:AVDEndpoints
        Write-ColorOutput "No test category specified. Defaulting to AVD endpoints..." "Yellow"
    }

    Write-ColorOutput "`nTotal endpoints to test: $($endpointsToTest.Count)" "White"
    Write-ColorOutput ("-" * 80) "Gray"

    # Test all endpoints
    $allResults = @()
    $showVerboseOutput = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true
    foreach ($endpoint in $endpointsToTest) {
        $result = Test-EndpointCLI -Endpoint $endpoint -ShowVerbose:$showVerboseOutput
        $allResults += [PSCustomObject]@{
            Hostname = $endpoint.Host
            Port = $endpoint.Port
            Description = $endpoint.Description
            Success = $result.Success
            Certificate = $result.Certificate
            RootCA = $result.RootCA
            RootThumbprint = $result.RootThumbprint
            IsIntercepted = $result.IsIntercepted
            InterceptionDetails = $result.InterceptionDetails
            Error = $result.Error
        }
    }

    # Summary
    Write-ColorOutput "`n" "White"
    Write-ColorOutput ("=" * 80) "Cyan"
    Write-ColorOutput "SUMMARY" "Cyan"
    Write-ColorOutput ("=" * 80) "Cyan"

    $intercepted = $allResults | Where-Object { $_.IsIntercepted }
    $failed = $allResults | Where-Object { -not $_.Success }
    $trusted = $allResults | Where-Object { $_.Success -and -not $_.IsIntercepted }

    Write-ColorOutput "`nTotal Endpoints Tested: $($allResults.Count)" "White"
    Write-ColorOutput "  [OK] Trusted (No Interception): $($trusted.Count)" "Green"
    if ($intercepted.Count -gt 0) {
        Write-ColorOutput "  [!!] INTERCEPTED: $($intercepted.Count)" "Red"
    } else {
        Write-ColorOutput "  [OK] Intercepted: 0" "Green"
    }
    if ($failed.Count -gt 0) {
        Write-ColorOutput "  [X]  Connection Failed: $($failed.Count)" "Yellow"
    } else {
        Write-ColorOutput "  [OK] Connection Failed: 0" "Green"
    }

    if ($intercepted.Count -gt 0) {
        Write-ColorOutput "`n" "White"
        Write-ColorOutput ("!" * 80) "Red"
        Write-ColorOutput "  [!] WARNING: SSL/TLS INTERCEPTION DETECTED!" "Red"
        Write-ColorOutput ("!" * 80) "Red"
        Write-ColorOutput "`nThe following endpoints are being intercepted:" "Yellow"
        
        foreach ($ep in $intercepted) {
            Write-ColorOutput "  >>> $($ep.Description) ($($ep.Hostname):$($ep.Port))" "Red"
            Write-ColorOutput "      Intercepting CA: $($ep.RootCA)" "Yellow"
        }
        
        Write-ColorOutput "`nRECOMMENDATION:" "Cyan"
        Write-ColorOutput "SSL/TLS interception can cause authentication failures and connectivity" "White"
        Write-ColorOutput "issues. Consider configuring your proxy to bypass inspection for" "White"
        Write-ColorOutput "critical endpoints." "White"
    }
    else {
        Write-ColorOutput "`n" "White"
        Write-ColorOutput ("=" * 80) "Green"
        Write-ColorOutput "  [OK] ALL CLEAR - NO INTERCEPTION DETECTED" "Green"
        Write-ColorOutput ("=" * 80) "Green"
        Write-ColorOutput "`nAll tested endpoints are using trusted Microsoft certificate chains." "Green"
    }

    if ($failed.Count -gt 0) {
        Write-ColorOutput "`nEndpoints that failed to connect:" "Yellow"
        foreach ($ep in $failed) {
            Write-ColorOutput "  - $($ep.Description) ($($ep.Hostname):$($ep.Port))" "Yellow"
            Write-ColorOutput "    Error: $($ep.Error)" "Gray"
        }
    }

    # Export results
    Write-ColorOutput "`n" "White"
    $resultsFile = Export-ResultsCLI -Results $allResults -OutputPath $OutputPath
    Write-ColorOutput "Results saved to: $resultsFile" "Green"

    Write-ColorOutput "`n" "White"
    Write-ColorOutput ("=" * 80) "Cyan"
    Write-ColorOutput "Scan Complete" "Cyan"
    Write-ColorOutput ("=" * 80) "Cyan"

    # Return results object for pipeline use
    return $allResults
}

#endregion

#region Main Entry Point

# Load additional root CAs from config file if it exists
if (Test-Path $script:RootCAConfigFile) {
    try {
        $configContent = Get-Content $script:RootCAConfigFile -Raw | ConvertFrom-Json
        foreach ($prop in $configContent.PSObject.Properties) {
            if (-not $script:KnownMicrosoftRootCAs.ContainsKey($prop.Name)) {
                $script:KnownMicrosoftRootCAs[$prop.Name] = $prop.Value
                $script:AdditionalRootCAs[$prop.Name] = $prop.Value
            }
        }
        if ($script:AdditionalRootCAs.Count -gt 0) {
            Write-Host "Loaded $($script:AdditionalRootCAs.Count) additional root CA(s) from config file" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "Warning: Failed to load root CA config: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Determine which mode to run
if ($DiscoverRootCAs) {
    # Run root CA discovery mode
    Invoke-RootCADiscovery -ConfigPath $script:RootCAConfigFile -SaveToConfig
}
elseif ($NoGUI) {
    # NoGUI specified - run in CLI mode if tests are specified, otherwise show help
    if ($TestAVD -or $TestMicrosoft365 -or $TestAzure -or $TestTRv2 -or $TestAppleSSO -or $TestHairpin -or $TestAll -or $CustomEndpoints -or $FetchM365Endpoints -or $FetchAzureEndpoints) {
        if ($TestHairpin) {
            # Run hairpin test in CLI mode
            Invoke-HairpinTest -AutoDetectPublicIP
        }
        if ($TestAVD -or $TestMicrosoft365 -or $TestAzure -or $TestTRv2 -or $TestAppleSSO -or $TestAll -or $CustomEndpoints -or $FetchM365Endpoints -or $FetchAzureEndpoints) {
            Start-CLIMode
        }
    }
    else {
        Write-Host ""
        Write-Host "SSL/TLS Interception Detector" -ForegroundColor Cyan
        Write-Host "=============================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "  (no switches)        Launch graphical user interface (default)"
        Write-Host "  -NoGUI               Suppress GUI and use command-line mode"
        Write-Host "  -TestAVD             Test Azure Virtual Desktop endpoints"
        Write-Host "  -TestMicrosoft365    Test Microsoft 365 endpoints"
        Write-Host "  -TestAzure           Test Azure service endpoints"
        Write-Host "  -TestTRv2            Test Tenant Restriction v2 / Global Secure Access endpoints"
        Write-Host "  -TestAppleSSO        Test Apple SSO Extension endpoints (macOS/iOS)"
        Write-Host "  -TestHairpin         Test for hairpin NAT (NAT loopback) detection"
        Write-Host "  -TestAll             Test all endpoint categories"
        Write-Host "  -FetchM365Endpoints  Fetch live M365 endpoints from Microsoft"
        Write-Host "  -FetchAzureEndpoints Fetch live Azure endpoints from Microsoft"
        Write-Host "  -DiscoverRootCAs     Discover and save current Microsoft root CAs"
        Write-Host "  -RootCAConfigPath    Path to custom root CA config file"
        Write-Host "  -CustomEndpoints     Test custom endpoints (e.g., @('host:port'))"
        Write-Host "  -OutputPath          Path to save results (default: current directory)"
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  .\Detect-Interception.ps1"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAll"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -FetchM365Endpoints"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAVD -FetchAzureEndpoints"
        Write-Host "  .\Detect-Interception.ps1 -DiscoverRootCAs"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestHairpin"
        Write-Host ""
        Write-Host "Note: -NoGUI requires at least one test parameter to be specified." -ForegroundColor Yellow
    }
}
else {
    # Default behavior - launch GUI
    Start-GUIMode
}

#endregion
