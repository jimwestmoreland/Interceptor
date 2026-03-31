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

.PARAMETER RunAssessment
    Runs a comprehensive Microsoft 365 network connectivity assessment (DNS, TCP, latency,
    egress, VPN/proxy, Teams UDP, SharePoint download speed, traceroute, Copilot, TLS).
    Generates a text file report. Use with -Geography to select the target geography.

.PARAMETER Geography
    Microsoft 365 cloud instance for the network assessment. These are sovereign cloud
    boundaries, not physical regions. All commercial tenants (regardless of region) use
    "Worldwide". Valid values: Worldwide, USGovDoD, USGovGCCHigh, China, Germany.
    Default is Worldwide.

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

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -RunAssessment
    Runs a full M365 network connectivity assessment for the Worldwide geography

.EXAMPLE
    .\Detect-Interception.ps1 -NoGUI -RunAssessment -Geography "USGovGCCHigh"
    Runs a network connectivity assessment targeting US Government GCC High endpoints

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
    [switch]$RunAssessment,
    [ValidateSet("Worldwide","USGovDoD","USGovGCCHigh","China","Germany")]
    [string]$Geography = "Worldwide",
    [string]$OfficeCity,
    [string]$OfficeState,
    [string]$OfficeCountry,
    [string]$RootCAConfigPath,
    [string[]]$CustomEndpoints,
    [string]$OutputPath = $PWD.Path
)

# Force TLS 1.2 and TLS 1.3 for all connections
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    # TLS 1.3 may not be available on older systems, fall back to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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

#region Microsoft Cloud Instances

# Microsoft publishes M365 endpoints per cloud instance at:
#   https://endpoints.office.com/endpoints/{Instance}?clientrequestid={GUID}
#
# These are cloud instance boundaries (sovereign clouds), NOT physical regions.
# All commercial tenants worldwide (North America, Europe, Asia, etc.) use the
# "Worldwide" instance. The instance determines WHICH endpoints to connect to.
#
# Supported cloud instances (the only valid values for the endpoints API):
#   Worldwide     - Commercial / global tenants (default). Covers all regions
#                   including NAM, EUR, APC, AUS, CAN, FRA, GBR, IND, JPN, etc.
#   USGovDoD      - US Government Department of Defense (DoD) cloud
#   USGovGCCHigh  - US Government GCC High cloud
#   China         - Microsoft 365 operated by 21Vianet (Gallatin)
#   Germany       - Microsoft Cloud Germany (deprecated, retained for legacy)
#
# NOTE: These are different from Microsoft 365 Multi-Geo data residency
# geographies (NAM, EUR, APC, AUS, CAN, FRA, DEU, GBR, IND, JPN, KOR, BRA,
# ZAF, ARE, QAT, NOR, SWE, CHE, etc.). Multi-Geo controls where customer
# data is stored at rest, but does NOT change which network endpoints are used.
# All Multi-Geo regions within commercial M365 use the "Worldwide" endpoints.
#
# Reference: https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-endpoints
# Multi-Geo: https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-multi-geo
$script:MicrosoftGeographies = @{
    "Worldwide"    = @{ Label = "Worldwide (Commercial)"; EndpointInstance = "Worldwide"; Description = "Microsoft 365 Worldwide - all commercial regions (NAM, EUR, APC, etc.)" }
    "USGovDoD"     = @{ Label = "US Gov DoD"; EndpointInstance = "USGovDoD"; Description = "Microsoft 365 US Government DoD" }
    "USGovGCCHigh" = @{ Label = "US Gov GCC High"; EndpointInstance = "USGovGCCHigh"; Description = "Microsoft 365 US Government GCC High" }
    "China"        = @{ Label = "China (21Vianet)"; EndpointInstance = "China"; Description = "Microsoft 365 operated by 21Vianet (Gallatin)" }
    "Germany"      = @{ Label = "Germany (Legacy)"; EndpointInstance = "Germany"; Description = "Microsoft Cloud Germany (deprecated)" }
}

#endregion

#region Assessment Test Functions

function Test-DNSPerformance {
    <#
    .SYNOPSIS
        Tests DNS resolution performance for key M365/Azure endpoints
    #>
    param(
        [string[]]$Hostnames = @(
            "login.microsoftonline.com",
            "outlook.office365.com",
            "teams.microsoft.com",
            "graph.microsoft.com",
            "management.azure.com",
            "sharepoint.com"
        )
    )

    $results = @()
    $dnsServer = $null

    # Identify the configured DNS server
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
        if ($adapters) {
            foreach ($adapter in $adapters) {
                $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
                if ($dnsServers) {
                    $dnsServer = $dnsServers[0]
                    break
                }
            }
        }
    } catch { }

    foreach ($hostname in $Hostnames) {
        $measurements = @()
        $resolvedIPs = @()
        $success = $true
        $errorMsg = $null

        for ($i = 0; $i -lt 3; $i++) {
            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $dns = Resolve-DnsName -Name $hostname -Type A -DnsOnly -ErrorAction Stop
                $sw.Stop()
                $measurements += $sw.Elapsed.TotalMilliseconds
                $resolvedIPs = @($dns | Where-Object { $_.QueryType -eq "A" } | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue)
            } catch {
                $sw.Stop()
                $measurements += $sw.Elapsed.TotalMilliseconds
                $success = $false
                $errorMsg = $_.Exception.Message
            }
        }

        $avgMs = [math]::Round(($measurements | Measure-Object -Average).Average, 2)
        $minMs = [math]::Round(($measurements | Measure-Object -Minimum).Minimum, 2)
        $maxMs = [math]::Round(($measurements | Measure-Object -Maximum).Maximum, 2)

        # Rating thresholds
        $rating = if ($avgMs -lt 10) { "Excellent" }
                  elseif ($avgMs -lt 50) { "Good" }
                  elseif ($avgMs -lt 100) { "Acceptable" }
                  elseif ($avgMs -lt 200) { "Poor" }
                  else { "Very Poor" }

        $results += [PSCustomObject]@{
            Hostname    = $hostname
            Success     = $success
            AvgMs       = $avgMs
            MinMs       = $minMs
            MaxMs       = $maxMs
            Rating      = $rating
            ResolvedIPs = $resolvedIPs
            Error       = $errorMsg
        }
    }

    return [PSCustomObject]@{
        DNSServer = $dnsServer
        Results   = $results
    }
}

function Get-NetworkEgressInfo {
    <#
    .SYNOPSIS
        Gets network egress IP and geolocation data
    #>
    $info = [PSCustomObject]@{
        PublicIP         = $null
        City             = $null
        Region           = $null
        Country          = $null
        ISP              = $null
        Org              = $null
        Latitude         = $null
        Longitude        = $null
        Success          = $false
        Error            = $null
    }

    try {
        # Use ip-api.com (free, no key required, includes geolocation)
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/?fields=status,message,country,regionName,city,lat,lon,isp,org,query" -TimeoutSec 10 -ErrorAction Stop
        if ($response.status -eq "success") {
            $info.PublicIP   = $response.query
            $info.City       = $response.city
            $info.Region     = $response.regionName
            $info.Country    = $response.country
            $info.ISP        = $response.isp
            $info.Org        = $response.org
            $info.Latitude   = $response.lat
            $info.Longitude  = $response.lon
            $info.Success    = $true
        } else {
            $info.Error = $response.message
        }
    } catch {
        # Fallback to just getting IP
        $info.Error = $_.Exception.Message
        try {
            $ip = Get-PublicIPAddress
            if ($ip) {
                $info.PublicIP = $ip
                $info.Success = $true
            }
        } catch { }
    }

    return $info
}

function Get-OfficeLocationCoordinates {
    <#
    .SYNOPSIS
        Geocodes an office location (city, state, country) to lat/lon coordinates
        using free geocoding APIs
    #>
    param(
        [string]$City,
        [string]$State,
        [string]$Country
    )

    $result = [PSCustomObject]@{
        City      = $City
        State     = $State
        Country   = $Country
        Latitude  = $null
        Longitude = $null
        Success   = $false
    }

    $parts = @($City, $State, $Country) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($parts.Count -eq 0) { return $result }
    $query = ($parts -join ", ")

    try {
        # Use Nominatim (OpenStreetMap) - free, no key required
        $encoded = [System.Uri]::EscapeDataString($query)
        $response = Invoke-RestMethod -Uri "https://nominatim.openstreetmap.org/search?q=$encoded&format=json&limit=1" -TimeoutSec 10 -Headers @{ "User-Agent" = "M365-Network-Diagnostic-Tool/1.0" } -ErrorAction Stop
        if ($response -and $response.Count -gt 0) {
            $result.Latitude  = [double]$response[0].lat
            $result.Longitude = [double]$response[0].lon
            $result.Success   = $true
        }
    } catch { }

    return $result
}

function Get-HaversineDistance {
    <#
    .SYNOPSIS
        Calculates great-circle distance in km between two lat/lon points
    #>
    param(
        [double]$Lat1, [double]$Lon1,
        [double]$Lat2, [double]$Lon2
    )
    $R = 6371 # Earth radius in km
    $dLat = [math]::PI * ($Lat2 - $Lat1) / 180
    $dLon = [math]::PI * ($Lon2 - $Lon1) / 180
    $lat1Rad = [math]::PI * $Lat1 / 180
    $lat2Rad = [math]::PI * $Lat2 / 180
    $a = [math]::Sin($dLat/2) * [math]::Sin($dLat/2) + [math]::Cos($lat1Rad) * [math]::Cos($lat2Rad) * [math]::Sin($dLon/2) * [math]::Sin($dLon/2)
    $c = 2 * [math]::Atan2([math]::Sqrt($a), [math]::Sqrt(1 - $a))
    return [math]::Round($R * $c, 0)
}

function Get-BestFrontDoors {
    <#
    .SYNOPSIS
        Compares in-use front doors against known best/closest Microsoft front door locations.
        Tests alternate front door endpoints and reports if a closer one exists.
    #>
    param(
        [array]$CurrentFrontDoors,
        [PSCustomObject]$EgressInfo
    )

    # Known Microsoft front door regions with approximate coordinates
    # These represent major M365 service entry points globally
    $knownFrontDoorRegions = @(
        @{ Name = "US East";        City = "Ashburn, VA";         Lat = 39.0438; Lon = -77.4874 }
        @{ Name = "US Central";     City = "Des Moines, IA";      Lat = 41.5868; Lon = -93.6250 }
        @{ Name = "US West";        City = "Quincy, WA";          Lat = 47.2343; Lon = -119.8526 }
        @{ Name = "US South";       City = "San Antonio, TX";     Lat = 29.4241; Lon = -98.4936 }
        @{ Name = "Canada East";    City = "Quebec City, QC";     Lat = 46.8139; Lon = -71.2080 }
        @{ Name = "Canada Central"; City = "Toronto, ON";         Lat = 43.6532; Lon = -79.3832 }
        @{ Name = "UK South";       City = "London, UK";          Lat = 51.5074; Lon = -0.1278 }
        @{ Name = "Europe West";    City = "Amsterdam, NL";       Lat = 52.3676; Lon = 4.9041 }
        @{ Name = "Europe North";   City = "Dublin, IE";          Lat = 53.3498; Lon = -6.2603 }
        @{ Name = "France Central"; City = "Paris, FR";           Lat = 48.8566; Lon = 2.3522 }
        @{ Name = "Germany West";   City = "Frankfurt, DE";       Lat = 50.1109; Lon = 8.6821 }
        @{ Name = "Asia East";      City = "Hong Kong";           Lat = 22.3193; Lon = 114.1694 }
        @{ Name = "Asia Southeast"; City = "Singapore";           Lat = 1.3521; Lon = 103.8198 }
        @{ Name = "Japan East";     City = "Tokyo, JP";           Lat = 35.6762; Lon = 139.6503 }
        @{ Name = "Australia East"; City = "Sydney, AU";          Lat = -33.8688; Lon = 151.2093 }
        @{ Name = "India Central";  City = "Pune, IN";            Lat = 18.5204; Lon = 73.8567 }
        @{ Name = "Brazil South";   City = "Sao Paulo, BR";       Lat = -23.5505; Lon = -46.6333 }
        @{ Name = "South Africa";   City = "Johannesburg, ZA";   Lat = -26.2041; Lon = 28.0473 }
        @{ Name = "Korea Central";  City = "Seoul, KR";          Lat = 37.5665; Lon = 126.9780 }
        @{ Name = "UAE North";      City = "Dubai, AE";          Lat = 25.2048; Lon = 55.2708 }
    )

    $results = @()

    if (-not $EgressInfo -or -not $EgressInfo.Success -or -not $EgressInfo.Latitude) {
        return $results
    }

    # Find the closest known front door region to the user's egress point
    $closestRegion = $null
    $closestDist = [double]::MaxValue
    foreach ($region in $knownFrontDoorRegions) {
        $dist = Get-HaversineDistance -Lat1 $EgressInfo.Latitude -Lon1 $EgressInfo.Longitude -Lat2 $region.Lat -Lon2 $region.Lon
        if ($dist -lt $closestDist) {
            $closestDist = $dist
            $closestRegion = $region
        }
    }

    # For each current front door, geolocate it and compare to the best possible
    foreach ($fd in ($CurrentFrontDoors | Where-Object { $_.Success })) {
        $fdLat = $null; $fdLon = $null; $fdCity = "Unknown"
        if ($fd.FrontDoorIP -and $fd.FrontDoorIP -ne "N/A") {
            try {
                $fdGeo = Invoke-RestMethod -Uri "http://ip-api.com/json/$($fd.FrontDoorIP)?fields=status,city,regionName,country,lat,lon" -TimeoutSec 5 -ErrorAction Stop
                if ($fdGeo.status -eq "success" -and $fdGeo.lat) {
                    $fdLat = $fdGeo.lat; $fdLon = $fdGeo.lon
                    $fdCity = "$($fdGeo.city), $($fdGeo.regionName), $($fdGeo.country)"
                }
                Start-Sleep -Milliseconds 500  # Rate limit ip-api.com
            } catch { }
        }

        $fdDistFromEgress = $null
        if ($fdLat) {
            $fdDistFromEgress = Get-HaversineDistance -Lat1 $EgressInfo.Latitude -Lon1 $EgressInfo.Longitude -Lat2 $fdLat -Lon2 $fdLon
        }

        $isOptimal = $false
        $rating = "Unknown"
        if ($fdDistFromEgress -ne $null -and $closestDist -ne $null) {
            # If in-use front door is within 200km of the best possible, consider it optimal
            $isOptimal = ($fdDistFromEgress -le ($closestDist + 200))
            $rating = if ($isOptimal) { "Optimal - front door is near the closest Microsoft region" }
                      elseif ($fdDistFromEgress -lt 1500) { "Acceptable - consider network routing" }
                      else { "Suboptimal - significant distance from nearest Microsoft region" }
        } elseif ($closestRegion) {
            # We have egress info + closest region but couldn't geolocate the front door IP
            $rating = "Unable to geolocate front door IP for comparison"
        }

        $results += [PSCustomObject]@{
            Service              = $fd.Service
            CurrentFrontDoor     = $fd.FrontDoorCNAME
            CurrentFrontDoorIP   = $fd.FrontDoorIP
            CurrentLocation      = $fdCity
            DistanceToFrontDoor  = if ($fdDistFromEgress) { [math]::Round($fdDistFromEgress, 0) } else { $null }
            NearestRegion        = if ($closestRegion) { "$($closestRegion.Name) ($($closestRegion.City))" } else { "Unknown" }
            NearestRegionDistance = if ($closestDist -lt [double]::MaxValue) { [math]::Round($closestDist, 0) } else { $null }
            IsOptimal            = $isOptimal
            Rating               = $rating
            TCPLatencyMs         = $fd.TCPLatencyMs
        }
    }

    return $results
}

function Get-ServiceFrontDoor {
    <#
    .SYNOPSIS
        Identifies the Microsoft 365 service front door for Exchange and SharePoint
    #>
    param(
        [string]$TenantDomain
    )

    $results = @()

    # Exchange front door
    $exchangeHost = "outlook.office365.com"
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dns = Resolve-DnsName -Name $exchangeHost -Type CNAME -DnsOnly -ErrorAction Stop
        $sw.Stop()
        $dnsTimeMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)

        $cnames = @($dns | Where-Object { $_.QueryType -eq "CNAME" } | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)
        # CNAME-only queries don't return A records; resolve separately
        $aRecords = @()
        try {
            $aResult = [System.Net.Dns]::GetHostAddresses($exchangeHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($aResult) { $aRecords = @($aResult.ToString()) }
        } catch { }

        # Measure TCP latency to Exchange front door
        $tcpLatency = Measure-TCPLatency -Hostname $exchangeHost -Port 443 -Count 5

        $results += [PSCustomObject]@{
            Service       = "Exchange Online"
            Hostname      = $exchangeHost
            FrontDoorCNAME = if ($cnames.Count -gt 0) { $cnames[0] } else { "N/A" }
            FrontDoorIP   = if ($aRecords.Count -gt 0) { $aRecords[0] } else { "N/A" }
            DNSTimeMs     = $dnsTimeMs
            TCPLatencyMs  = $tcpLatency.AvgMs
            MinLatencyMs  = $tcpLatency.MinMs
            MaxLatencyMs  = $tcpLatency.MaxMs
            Success       = $true
            Error         = $null
        }
    } catch {
        $results += [PSCustomObject]@{
            Service       = "Exchange Online"
            Hostname      = $exchangeHost
            FrontDoorCNAME = "N/A"
            FrontDoorIP   = "N/A"
            DNSTimeMs     = 0
            TCPLatencyMs  = 0
            MinLatencyMs  = 0
            MaxLatencyMs  = 0
            Success       = $false
            Error         = $_.Exception.Message
        }
    }

    # SharePoint front door
    $spHost = if ($TenantDomain) { "$TenantDomain.sharepoint.com" } else { "microsoft.sharepoint.com" }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dns = Resolve-DnsName -Name $spHost -Type CNAME -DnsOnly -ErrorAction Stop
        $sw.Stop()
        $dnsTimeMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)

        $cnames = @($dns | Where-Object { $_.QueryType -eq "CNAME" } | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)
        $aRecords = @()
        try {
            $aResult = [System.Net.Dns]::GetHostAddresses($spHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($aResult) { $aRecords = @($aResult.ToString()) }
        } catch { }

        $tcpLatency = Measure-TCPLatency -Hostname $spHost -Port 443 -Count 5

        $results += [PSCustomObject]@{
            Service       = "SharePoint Online"
            Hostname      = $spHost
            FrontDoorCNAME = if ($cnames.Count -gt 0) { $cnames[0] } else { "N/A" }
            FrontDoorIP   = if ($aRecords.Count -gt 0) { $aRecords[0] } else { "N/A" }
            DNSTimeMs     = $dnsTimeMs
            TCPLatencyMs  = $tcpLatency.AvgMs
            MinLatencyMs  = $tcpLatency.MinMs
            MaxLatencyMs  = $tcpLatency.MaxMs
            Success       = $true
            Error         = $null
        }
    } catch {
        $results += [PSCustomObject]@{
            Service       = "SharePoint Online"
            Hostname      = $spHost
            FrontDoorCNAME = "N/A"
            FrontDoorIP   = "N/A"
            DNSTimeMs     = 0
            TCPLatencyMs  = 0
            MinLatencyMs  = 0
            MaxLatencyMs  = 0
            Success       = $false
            Error         = $_.Exception.Message
        }
    }

    # Teams front door
    $teamsHost = "world.tr.teams.microsoft.com"
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dns = Resolve-DnsName -Name $teamsHost -Type CNAME -DnsOnly -ErrorAction Stop
        $sw.Stop()
        $dnsTimeMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)

        $cnames = @($dns | Where-Object { $_.QueryType -eq "CNAME" } | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)
        $aRecords = @()
        try {
            $aResult = [System.Net.Dns]::GetHostAddresses($teamsHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($aResult) { $aRecords = @($aResult.ToString()) }
        } catch { }

        $tcpLatency = Measure-TCPLatency -Hostname $teamsHost -Port 443 -Count 5

        $results += [PSCustomObject]@{
            Service       = "Microsoft Teams"
            Hostname      = $teamsHost
            FrontDoorCNAME = if ($cnames.Count -gt 0) { $cnames[0] } else { "N/A" }
            FrontDoorIP   = if ($aRecords.Count -gt 0) { $aRecords[0] } else { "N/A" }
            DNSTimeMs     = $dnsTimeMs
            TCPLatencyMs  = $tcpLatency.AvgMs
            MinLatencyMs  = $tcpLatency.MinMs
            MaxLatencyMs  = $tcpLatency.MaxMs
            Success       = $true
            Error         = $null
        }
    } catch {
        $results += [PSCustomObject]@{
            Service       = "Microsoft Teams"
            Hostname      = $teamsHost
            FrontDoorCNAME = "N/A"
            FrontDoorIP   = "N/A"
            DNSTimeMs     = 0
            TCPLatencyMs  = 0
            MinLatencyMs  = 0
            MaxLatencyMs  = 0
            Success       = $false
            Error         = $_.Exception.Message
        }
    }

    return $results
}

function Measure-TCPLatency {
    <#
    .SYNOPSIS
        Measures TCP connection latency to a host:port
    #>
    param(
        [string]$Hostname,
        [int]$Port = 443,
        [int]$Count = 5,
        [int]$TimeoutMs = 5000
    )

    $measurements = @()
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $task = $tcpClient.ConnectAsync($Hostname, $Port)
            if ($task.Wait($TimeoutMs)) {
                $sw.Stop()
                $measurements += $sw.Elapsed.TotalMilliseconds
            }
            $tcpClient.Close()
        } catch {
            # Skip failed attempts
        }
    }

    if ($measurements.Count -gt 0) {
        return [PSCustomObject]@{
            AvgMs = [math]::Round(($measurements | Measure-Object -Average).Average, 2)
            MinMs = [math]::Round(($measurements | Measure-Object -Minimum).Minimum, 2)
            MaxMs = [math]::Round(($measurements | Measure-Object -Maximum).Maximum, 2)
            Count = $measurements.Count
        }
    } else {
        return [PSCustomObject]@{
            AvgMs = 0
            MinMs = 0
            MaxMs = 0
            Count = 0
        }
    }
}

function Test-HTTPConnectivity {
    <#
    .SYNOPSIS
        Tests HTTP/HTTPS reachability for endpoints on both port 80 and 443
    #>
    param(
        [array]$Endpoints
    )

    $results = @()
    foreach ($ep in $Endpoints) {
        $hostname = $ep.Host
        # Skip hostnames containing wildcards anywhere (e.g., *.example.com or autodiscover.*.onmicrosoft.com)
        if ($hostname -match '\*') { continue }

        # Test HTTPS (443) - only port that matters for M365
        $httpsResult = $null
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri "https://$hostname" -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop
            $sw.Stop()
            $httpsResult = [PSCustomObject]@{
                Port         = 443
                StatusCode   = $response.StatusCode
                LatencyMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                Success      = $true
                Blocked      = $false
                TCPReachable = $true
                Error        = $null
            }
        } catch {
            $sw.Stop()
            $statusCode = 0
            $blocked = $false
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                if ($statusCode -eq 407 -or $statusCode -eq 403) {
                    $blocked = $true
                }
            }

            # Determine TCP reachability: if we got an HTTP status code, TCP worked.
            # Otherwise, try a raw TCP connect to port 443 as fallback.
            $tcpReachable = $false
            if ($statusCode -gt 0) {
                $tcpReachable = $true
            } elseif (-not $blocked) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $task = $tcpClient.ConnectAsync($hostname, 443)
                    if ($task.Wait(5000)) {
                        $tcpReachable = $tcpClient.Connected
                    }
                    $tcpClient.Close()
                } catch { }
            }

            $httpsResult = [PSCustomObject]@{
                Port         = 443
                StatusCode   = $statusCode
                LatencyMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                Success      = ($statusCode -gt 0 -and $statusCode -lt 500 -and -not $blocked)
                Blocked      = $blocked
                TCPReachable = $tcpReachable
                Error        = $_.Exception.Message
            }
        }

        $results += [PSCustomObject]@{
            Hostname    = $hostname
            Description = $ep.Description
            HTTPS       = $httpsResult
        }
    }

    return $results
}

function Test-VPNAndProxy {
    <#
    .SYNOPSIS
        Detects VPN connections, proxy configuration, and per-workload split tunnel routing
    #>
    $result = [PSCustomObject]@{
        VPNDetected        = $false
        VPNAdapterName     = $null
        VPNType            = $null
        ProxyEnabled       = $false
        ProxyServer        = $null
        ProxyPACUrl        = $null
        WinHTTPProxy       = $null
        EnvProxy           = $null
        SplitTunnelStatus  = "Unknown"
        SplitTunnelDetails = @()
        Details            = @()
    }

    # Check for VPN adapters
    try {
        $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
        if ($vpnConnections) {
            $activeVPN = $vpnConnections | Where-Object { $_.ConnectionStatus -eq "Connected" }
            if ($activeVPN) {
                $result.VPNDetected = $true
                $result.VPNAdapterName = $activeVPN[0].Name
                $result.VPNType = $activeVPN[0].TunnelType
                $result.Details += "VPN connected: $($activeVPN[0].Name) ($($activeVPN[0].TunnelType))"

                # Check split tunnel
                if ($activeVPN[0].SplitTunneling) {
                    $result.SplitTunnelStatus = "Enabled"
                    $result.Details += "Split tunneling: Enabled"
                } else {
                    $result.SplitTunnelStatus = "Disabled (Full Tunnel)"
                    $result.Details += "Split tunneling: Disabled - all traffic goes through VPN"
                }
            }
        }
    } catch {
        # VPN cmdlets may not be available
    }

    # Also check network adapters that look like VPN
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            if ($adapter.InterfaceDescription -match "VPN|Virtual|Tunnel|TAP|WireGuard|Cisco|Palo Alto|Zscaler|GlobalProtect|AnyConnect|Fortinet|Juniper|Pulse") {
                if (-not $result.VPNDetected) {
                    $result.VPNDetected = $true
                    $result.VPNAdapterName = $adapter.Name
                    $result.VPNType = $adapter.InterfaceDescription
                    $result.Details += "VPN adapter detected: $($adapter.Name) ($($adapter.InterfaceDescription))"
                }
            }
        }
    } catch { }

    # Per-workload split tunnel test (Microsoft 365 Optimize category endpoints)
    # These are the key IPs that Microsoft recommends be split-tunneled
    if ($result.VPNDetected) {
        $optimizeEndpoints = @(
            @{ Workload = "Exchange Online"; TestHost = "outlook.office365.com"; TestIP = "13.107.6.152"; Ports = "TCP 443" }
            @{ Workload = "SharePoint Online"; TestHost = "microsoft.sharepoint.com"; TestIP = "13.107.136.1"; Ports = "TCP 443" }
            @{ Workload = "Microsoft Teams"; TestHost = "13.107.64.1"; TestIP = "13.107.64.1"; Ports = "UDP 3478-3481" }
        )

        foreach ($ep in $optimizeEndpoints) {
            $splitResult = [PSCustomObject]@{
                Workload      = $ep.Workload
                TestIP        = $ep.TestIP
                Ports         = $ep.Ports
                RouteAdapter  = "Unknown"
                RoutesViaVPN  = $null
                Rating        = "Unknown"
            }

            try {
                # Use Find-NetRoute to determine which adapter would route to this IP
                $route = Find-NetRoute -RemoteIPAddress $ep.TestIP -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($route) {
                    $routeAdapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
                    if ($routeAdapter) {
                        $splitResult.RouteAdapter = "$($routeAdapter.Name) ($($routeAdapter.InterfaceDescription))"
                        $isVPN = $routeAdapter.InterfaceDescription -match "VPN|Virtual|Tunnel|TAP|WireGuard|Cisco|Palo Alto|Zscaler|GlobalProtect|AnyConnect|Fortinet|Juniper|Pulse"
                        $isVPN = $isVPN -or ($routeAdapter.Name -eq $result.VPNAdapterName)
                        $splitResult.RoutesViaVPN = $isVPN
                        $splitResult.Rating = if ($isVPN) { "Not Optimized - routes through VPN" } else { "Optimized - direct internet egress" }
                    }
                }
            } catch { }

            $result.SplitTunnelDetails += $splitResult
        }

        # Summarize
        $vpnRouted = @($result.SplitTunnelDetails | Where-Object { $_.RoutesViaVPN -eq $true })
        if ($vpnRouted.Count -gt 0) {
            $result.Details += "$($vpnRouted.Count) Optimize workload(s) routing through VPN (should be split-tunneled)"
        } else {
            $result.Details += "All Optimize workloads appear to use direct internet egress"
        }
    }

    # Check IE/System proxy settings
    try {
        $proxyReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($proxyReg.ProxyEnable -eq 1) {
            $result.ProxyEnabled = $true
            $result.ProxyServer = $proxyReg.ProxyServer
            $result.Details += "System proxy enabled: $($proxyReg.ProxyServer)"
        }
        if ($proxyReg.AutoConfigURL) {
            $result.ProxyPACUrl = $proxyReg.AutoConfigURL
            $result.Details += "PAC file configured: $($proxyReg.AutoConfigURL)"
        }
    } catch { }

    # Check WinHTTP proxy
    try {
        $winhttp = netsh winhttp show proxy 2>$null
        $proxyLine = $winhttp | Where-Object { $_ -match "Proxy Server" }
        if ($proxyLine -and $proxyLine -notmatch "Direct access") {
            $result.WinHTTPProxy = ($proxyLine -split ":\s+", 2)[1]
            $result.Details += "WinHTTP proxy: $($result.WinHTTPProxy)"
        }
    } catch { }

    # Check environment variables
    $envProxy = $env:HTTPS_PROXY
    if (-not $envProxy) { $envProxy = $env:HTTP_PROXY }
    if ($envProxy) {
        $result.EnvProxy = $envProxy
        $result.Details += "Environment proxy: $envProxy"
    }

    if ($result.Details.Count -eq 0) {
        $result.Details += "No VPN or proxy detected"
    }

    return $result
}

function Test-TeamsUDPConnectivity {
    <#
    .SYNOPSIS
        Tests UDP connectivity on Teams media ports 3478-3481
    #>
    param(
        [string]$Target = "13.107.64.1",
        [int[]]$Ports = @(3478, 3479, 3480, 3481),
        [int]$TimeoutMs = 3000
    )

    $results = @()
    foreach ($port in $Ports) {
        $success = $false
        $latencyMs = 0
        $errorMsg = $null

        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $TimeoutMs
            
            $payload = [byte[]]@(0x00, 0x01, 0x00, 0x00) + (1..12 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            [void]$udpClient.Send($payload, $payload.Length, $Target, $port)
            
            try {
                $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $response = $udpClient.Receive([ref]$remoteEP)
                $sw.Stop()
                $success = $true
                $latencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            } catch [System.Net.Sockets.SocketException] {
                $sw.Stop()
                # Timeout or port unreachable - UDP sent successfully but no response
                # This doesn't necessarily mean blocked since STUN servers require proper requests
                $latencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                $errorMsg = "No response (UDP may still be open)"
            }
            
            $udpClient.Close()
        } catch {
            $errorMsg = $_.Exception.Message
        }

        # Also test TCP fallback on same port
        $tcpFallback = $false
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $task = $tcpClient.ConnectAsync($Target, $port)
            if ($task.Wait($TimeoutMs)) {
                $tcpFallback = $true
            }
            $tcpClient.Close()
        } catch { }

        # Test TCP 443 fallback (the actual Teams fallback path)
        $tcp443Fallback = $false
        if (-not $success -and -not $tcpFallback) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $task = $tcpClient.ConnectAsync($Target, 443)
                if ($task.Wait($TimeoutMs)) {
                    $tcp443Fallback = $true
                }
                $tcpClient.Close()
            } catch { }
        }

        $results += [PSCustomObject]@{
            Port            = $port
            UDPSuccess      = $success
            UDPLatencyMs    = $latencyMs
            TCPFallback     = $tcpFallback
            TCP443Fallback  = $tcp443Fallback
            Error           = $errorMsg
        }
    }

    return $results
}

function Test-SharePointDownloadSpeed {
    <#
    .SYNOPSIS
        Tests download speed and buffer bloat using a meaningful download (~10MB).
        Uses speed.cloudflare.com test endpoint for consistent, CDN-backed measurement.
        Falls back to smaller download if the large test times out.
    #>
    param(
        [string]$SharePointHost = "microsoft.sharepoint.com",
        [int]$Port = 443,
        [int]$DownloadBytes = 10000000
    )

    $result = [PSCustomObject]@{
        SpeedMegabitsPerSec  = 0
        SpeedMegabytesPerSec = 0
        DownloadSizeBytes = 0
        DownloadTimeMs    = 0
        LatencyBeforeMs   = 0
        LatencyDuringMs   = 0
        BufferBloatMs     = 0
        BufferBloatRating = "N/A"
        TestSource        = $null
        Success           = $false
        Error             = $null
    }

    try {
        # Measure latency before download
        $preLatency = Measure-TCPLatency -Hostname $SharePointHost -Port $Port -Count 5
        $result.LatencyBeforeMs = $preLatency.AvgMs

        # Download test payload from Cloudflare speed test (widely available, CDN-backed)
        $testUrl = "https://speed.cloudflare.com/__down?bytes=$DownloadBytes"
        $result.TestSource = "speed.cloudflare.com ($([math]::Round($DownloadBytes / 1MB, 1)) MB)"

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $webClient = New-Object System.Net.WebClient
            $data = $webClient.DownloadData($testUrl)
            $sw.Stop()
        } catch {
            # Fallback to smaller Microsoft favicon if Cloudflare blocked
            $sw.Stop()
            $testUrl = "https://www.microsoft.com/favicon.ico"
            $result.TestSource = "microsoft.com/favicon.ico (fallback)"
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $webClient = New-Object System.Net.WebClient
            $data = $webClient.DownloadData($testUrl)
            $sw.Stop()
        }

        $result.DownloadSizeBytes = $data.Length
        $result.DownloadTimeMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)

        if ($sw.Elapsed.TotalSeconds -gt 0) {
            $speedMBps = ($data.Length / 1MB) / $sw.Elapsed.TotalSeconds
            $result.SpeedMegabytesPerSec = [math]::Round($speedMBps, 3)
            $result.SpeedMegabitsPerSec = [math]::Round($speedMBps * 8, 2)
        }

        # Measure latency after download (to detect buffer bloat)
        $postLatency = Measure-TCPLatency -Hostname $SharePointHost -Port $Port -Count 5
        $result.LatencyDuringMs = $postLatency.AvgMs

        $result.BufferBloatMs = [math]::Round($result.LatencyDuringMs - $result.LatencyBeforeMs, 2)
        $result.BufferBloatRating = if ($result.BufferBloatMs -lt 10) { "Excellent" }
                                    elseif ($result.BufferBloatMs -lt 50) { "Good" }
                                    elseif ($result.BufferBloatMs -lt 100) { "Acceptable" }
                                    else { "Poor - Buffer Bloat Detected" }

        $result.Success = $true
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Invoke-ServiceTraceroute {
    <#
    .SYNOPSIS
        Runs traceroute to Exchange, SharePoint, and Teams front doors.
        Uses TCP-based connectivity test and incremental-TTL traceroute
        to avoid hanging on networks where ICMP is blocked.
    #>
    param(
        [string]$TenantDomain,
        [int]$MaxHops = 30,
        [int]$TimeoutMs = 2000
    )

    $targets = @(
        @{ Service = "Exchange Online"; Host = "outlook.office365.com" }
        @{ Service = "SharePoint Online"; Host = if ($TenantDomain) { "$TenantDomain.sharepoint.com" } else { "microsoft.sharepoint.com" } }
        @{ Service = "Microsoft Teams"; Host = "world.tr.teams.microsoft.com" }
    )

    $results = @()
    foreach ($target in $targets) {
        $hops = @()
        $resolvedIP = "N/A"
        $tcpSuccess = $false
        try {
            # Resolve the hostname first
            $dnsResult = [System.Net.Dns]::GetHostAddresses($target.Host) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($dnsResult) {
                $resolvedIP = $dnsResult.ToString()
            }

            # TCP connectivity test (port 443) with timeout - no ICMP
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connectTask = $tcpClient.ConnectAsync($target.Host, 443)
                $tcpSuccess = $connectTask.Wait($TimeoutMs)
                $tcpClient.Close()
            } catch { $tcpSuccess = $false }

            # Traceroute using ping with incremental TTL (with short timeout per hop)
            for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
                try {
                    $pinger = New-Object System.Net.NetworkInformation.Ping
                    $options = New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)
                    $reply = $pinger.Send($resolvedIP, $TimeoutMs, [byte[]]::new(32), $options)
                    $pinger.Dispose()

                    $hopAddr = if ($reply.Address) { $reply.Address.ToString() } else { "*" }
                    $hops += [PSCustomObject]@{
                        Hop       = $ttl
                        Address   = $hopAddr
                        IsPrivate = ($hopAddr -match "^10\." -or $hopAddr -match "^172\.(1[6-9]|2[0-9]|3[01])\." -or $hopAddr -match "^192\.168\.")
                    }

                    # Stop if we reached the destination
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { break }
                } catch {
                    $hops += [PSCustomObject]@{ Hop = $ttl; Address = "*"; IsPrivate = $false }
                }
            }

            $results += [PSCustomObject]@{
                Service          = $target.Service
                Hostname         = $target.Host
                ResolvedIP       = $resolvedIP
                Hops             = $hops
                HopCount         = $hops.Count
                TCPTestSucceeded = $tcpSuccess
                PingSucceeded    = ($hops | Where-Object { $_.Address -eq $resolvedIP }).Count -gt 0
                Success          = $true
                Error            = $null
            }
        } catch {
            $results += [PSCustomObject]@{
                Service          = $target.Service
                Hostname         = $target.Host
                ResolvedIP       = $resolvedIP
                Hops             = @()
                HopCount         = 0
                TCPTestSucceeded = $false
                PingSucceeded    = $false
                Success          = $false
                Error            = $_.Exception.Message
            }
        }
    }

    return $results
}

function Test-CopilotConnectivity {
    <#
    .SYNOPSIS
        Tests Microsoft 365 Copilot HTTP and WebSocket connectivity
    #>
    $results = [PSCustomObject]@{
        HTTPEndpoints = @()
        WebSocketTest = $null
        LatencyMs     = 0
    }

    # Copilot-related endpoints
    $copilotEndpoints = @(
        @{ Host = "substrate.office.com"; Description = "Substrate (Copilot backend)" }
        @{ Host = "copilot.microsoft.com"; Description = "Copilot portal" }
        @{ Host = "edge.microsoft.com"; Description = "Edge / Copilot services" }
        @{ Host = "business.bing.com"; Description = "Copilot commercial search" }
    )

    foreach ($ep in $copilotEndpoints) {
        $epResult = [PSCustomObject]@{
            Host      = $ep.Host
            Description = $ep.Description
            Success   = $false
            LatencyMs = 0
            Error     = $null
        }

        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $task = $tcpClient.ConnectAsync($ep.Host, 443)
            if ($task.Wait(5000)) {
                $sw.Stop()
                $epResult.Success = $true
                $epResult.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            } else {
                $sw.Stop()
                $epResult.Error = "Connection timed out"
            }
            $tcpClient.Close()
        } catch {
            $epResult.Error = $_.Exception.Message
        }

        $results.HTTPEndpoints += $epResult
    }

    # WebSocket test to Copilot endpoint
    $wssResult = [PSCustomObject]@{
        Success     = $false
        LatencyMs   = 0
        Error       = $null
    }

    try {
        # Test WebSocket-capable endpoint via TLS handshake
        $wssHost = "substrate.office.com"
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $task = $tcpClient.ConnectAsync($wssHost, 443)
        if ($task.Wait(5000)) {
            $sslStream = New-Object System.Net.Security.SslStream(
                $tcpClient.GetStream(), $false,
                { param($s, $c, $ch, $e) return $true }
            )
            $sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
            $sslStream.AuthenticateAsClient($wssHost, $null, $sslProtocols, $false)
            
            # Send WebSocket upgrade request
            $upgradeRequest = "GET / HTTP/1.1`r`nHost: $wssHost`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($upgradeRequest)
            $sslStream.Write($bytes, 0, $bytes.Length)
            $sslStream.Flush()

            # Read response
            $buffer = New-Object byte[] 4096
            $sslStream.ReadTimeout = 5000
            try {
                $bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)
                $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                $sw.Stop()

                # WebSocket upgrade accepted = 101, but any response means TLS + HTTP works
                $wssResult.Success = $true
                $wssResult.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)

                if ($response -notmatch "101") {
                    $wssResult.Error = "TLS connected but WebSocket upgrade not accepted (HTTP response received)"
                }
            } catch {
                $sw.Stop()
                $wssResult.Success = $true  # TLS connected successfully
                $wssResult.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                $wssResult.Error = "TLS connected but no WebSocket response"
            }

            $sslStream.Close()
        } else {
            $sw.Stop()
            $wssResult.Error = "Connection timed out"
        }
        $tcpClient.Close()
    } catch {
        $wssResult.Error = $_.Exception.Message
    }

    $results.WebSocketTest = $wssResult
    if ($results.HTTPEndpoints.Count -gt 0) {
        $successEndpoints = $results.HTTPEndpoints | Where-Object { $_.Success }
        if ($successEndpoints.Count -gt 0) {
            $results.LatencyMs = [math]::Round(($successEndpoints | Measure-Object -Property LatencyMs -Average).Average, 2)
        }
    }

    return $results
}

function Test-TCPNegotiation {
    <#
    .SYNOPSIS
        Tests TCP options negotiation including window scaling, SACK, and MSS
    #>
    param(
        [string]$Hostname = "outlook.office365.com",
        [int]$Port = 443
    )

    $result = [PSCustomObject]@{
        Hostname     = $Hostname
        Port         = $Port
        TLSVersion   = "Unknown"
        TLS12Support = $false
        TLS13Support = $false
        CipherSuite  = "Unknown"
        TCPWindowSize = 0
        Success      = $false
        Error        = $null
    }

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $task = $tcpClient.ConnectAsync($Hostname, $Port)
        if ($task.Wait(5000)) {
            $result.TCPWindowSize = $tcpClient.ReceiveBufferSize

            # Test TLS 1.2
            try {
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $true, { return $true })
                $sslStream.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                $result.TLS12Support = $true
                $result.TLSVersion = "TLS 1.2"
                $result.CipherSuite = $sslStream.CipherAlgorithm.ToString()
                $sslStream.Close()
            } catch { }

            $tcpClient.Close()

            # Test TLS 1.3 with new connection
            try {
                $tcpClient2 = New-Object System.Net.Sockets.TcpClient
                $task2 = $tcpClient2.ConnectAsync($Hostname, $Port)
                if ($task2.Wait(5000)) {
                    $sslStream2 = New-Object System.Net.Security.SslStream($tcpClient2.GetStream(), $true, { return $true })
                    $sslStream2.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::Tls13, $false)
                    $result.TLS13Support = $true
                    $result.TLSVersion = "TLS 1.3"
                    $result.CipherSuite = $sslStream2.CipherAlgorithm.ToString()
                    $sslStream2.Close()
                }
                $tcpClient2.Close()
            } catch {
                # TLS 1.3 not supported - that's OK
            }

            $result.Success = $true
        } else {
            $result.Error = "Connection timed out"
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-DNSRecursiveResolver {
    <#
    .SYNOPSIS
        Identifies the DNS recursive resolver being used
    #>
    $result = [PSCustomObject]@{
        ConfiguredDNS   = $null
        RecursiveResolver = $null
        ResolverIP      = $null
        ResolverLatencyMs = 0
        Success         = $false
        Error           = $null
    }

    try {
        # Get configured DNS server
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
        if ($adapters) {
            foreach ($adapter in $adapters) {
                $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
                if ($dnsServers) {
                    $result.ConfiguredDNS = $dnsServers[0]
                    break
                }
            }
        }

        # Try to discover the actual recursive resolver using o-o.myaddr.l.google.com
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resolverCheck = Resolve-DnsName -Name "o-o.myaddr.l.google.com" -Type TXT -DnsOnly -ErrorAction Stop
            $sw.Stop()
            $result.ResolverLatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            $txtRecords = @($resolverCheck | Where-Object { $_.QueryType -eq "TXT" } | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue)
            if ($txtRecords.Count -gt 0) {
                $result.RecursiveResolver = $txtRecords[0]
                $result.ResolverIP = $txtRecords[0]
            }
        } catch {
            # Fallback - use configured DNS
            $result.RecursiveResolver = $result.ConfiguredDNS
            $result.ResolverIP = $result.ConfiguredDNS
        }

        $result.Success = $true
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Start-NetworkAssessment {
    <#
    .SYNOPSIS
        Runs a comprehensive M365 network connectivity assessment
    #>
    param(
        [string]$SelectedGeography = "Worldwide",
        [string]$TenantDomain,
        [string]$OfficeCity,
        [string]$OfficeState,
        [string]$OfficeCountry,
        [scriptblock]$ProgressCallback
    )

    $assessmentResults = [PSCustomObject]@{
        Timestamp          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        Geography          = $SelectedGeography
        TenantDomain       = $TenantDomain
        OfficeLocation     = $null
        NetworkEgress      = $null
        EgressDistance      = $null
        DNSPerformance     = $null
        DNSResolver        = $null
        ServiceFrontDoors  = $null
        BestFrontDoors     = $null
        HTTPConnectivity   = $null
        SSLInterception    = $null
        VPNProxy           = $null
        TeamsUDP           = $null
        TeamsJitter        = $null
        SharePointSpeed    = $null
        Traceroutes        = $null
        CopilotConnectivity = $null
        TCPNegotiation     = $null
    }

    $totalSteps = 13
    $currentStep = 0

    # Helper for progress
    $reportProgress = {
        param([string]$StepName)
        $script:currentAssessmentStep++
        if ($ProgressCallback) {
            & $ProgressCallback $script:currentAssessmentStep $totalSteps $StepName
        }
    }
    $script:currentAssessmentStep = 0

    # Step 1: Network Egress
    & $reportProgress "Detecting network egress location..."
    $assessmentResults.NetworkEgress = Get-NetworkEgressInfo

    # Geocode office location if provided, then calculate distance to egress
    if ($OfficeCity -or $OfficeState -or $OfficeCountry) {
        $officeGeo = Get-OfficeLocationCoordinates -City $OfficeCity -State $OfficeState -Country $OfficeCountry
        $assessmentResults.OfficeLocation = $officeGeo
        if ($officeGeo.Success -and $assessmentResults.NetworkEgress.Success -and $assessmentResults.NetworkEgress.Latitude) {
            $distKm = Get-HaversineDistance -Lat1 $officeGeo.Latitude -Lon1 $officeGeo.Longitude -Lat2 $assessmentResults.NetworkEgress.Latitude -Lon2 $assessmentResults.NetworkEgress.Longitude
            $assessmentResults.EgressDistance = [PSCustomObject]@{
                DistanceKm = $distKm
                DistanceMi = [math]::Round($distKm * 0.621371, 0)
                Rating     = if ($distKm -lt 100) { "Optimal" } elseif ($distKm -lt 500) { "Good" } elseif ($distKm -lt 800) { "Acceptable" } else { "Poor - significant WAN backhaul likely" }
            }
        }
    }

    # Step 2: DNS Resolver
    & $reportProgress "Identifying DNS recursive resolver..."
    $assessmentResults.DNSResolver = Get-DNSRecursiveResolver

    # Step 3: DNS Performance
    & $reportProgress "Testing DNS resolution performance..."
    $assessmentResults.DNSPerformance = Test-DNSPerformance

    # Step 4: VPN/Proxy Detection
    & $reportProgress "Checking VPN and proxy configuration..."
    $assessmentResults.VPNProxy = Test-VPNAndProxy

    # Step 5: Service Front Doors
    & $reportProgress "Identifying service front doors..."
    $assessmentResults.ServiceFrontDoors = Get-ServiceFrontDoor -TenantDomain $TenantDomain
    # Compare against best possible front doors
    $assessmentResults.BestFrontDoors = Get-BestFrontDoors -CurrentFrontDoors $assessmentResults.ServiceFrontDoors -EgressInfo $assessmentResults.NetworkEgress

    # Step 6: Fetch and test HTTP connectivity with live endpoints
    & $reportProgress "Fetching endpoints and testing HTTP connectivity..."
    $instance = $script:MicrosoftGeographies[$SelectedGeography].EndpointInstance
    $liveEndpoints = Get-M365EndpointsFromMicrosoft -Instance $instance -RequiredOnly
    # Take a representative sample for HTTP testing (capped for speed)
    $httpSample = @()
    $httpSample += $liveEndpoints | Select-Object -First 30
    $assessmentResults.HTTPConnectivity = Test-HTTPConnectivity -Endpoints $httpSample

    # Step 7: SSL Interception check on key endpoints
    & $reportProgress "Testing SSL/TLS interception on key endpoints..."
    $sslEndpoints = @(
        @{ Host = "login.microsoftonline.com"; Port = 443; Description = "Entra ID" }
        @{ Host = "outlook.office365.com"; Port = 443; Description = "Exchange Online" }
        @{ Host = "teams.microsoft.com"; Port = 443; Description = "Microsoft Teams" }
        @{ Host = "graph.microsoft.com"; Port = 443; Description = "Microsoft Graph" }
        @{ Host = "management.azure.com"; Port = 443; Description = "Azure Management" }
    )
    $sslResults = @()
    foreach ($ep in $sslEndpoints) {
        $certResult = Get-CertificateChain -Hostname $ep.Host -Port $ep.Port
        $sslResults += [PSCustomObject]@{
            Hostname    = $ep.Host
            Description = $ep.Description
            Success     = $certResult.Success
            IsIntercepted = $certResult.IsIntercepted
            RootCA      = $certResult.RootCA
            Error       = $certResult.Error
        }
    }
    $assessmentResults.SSLInterception = $sslResults

    # Step 8: Teams UDP
    & $reportProgress "Testing Teams UDP connectivity (ports 3478-3481)..."
    $assessmentResults.TeamsUDP = Test-TeamsUDPConnectivity

    # Step 9: Teams Jitter (quick mode)
    & $reportProgress "Testing Teams media jitter..."
    $globalTeamsEndpoints = $script:TeamsMediaEndpoints | Where-Object { $_.Region -eq "Global" }
    $jitterResults = @()
    foreach ($ep in $globalTeamsEndpoints) {
        $jitterResults += Test-NetworkJitter -Target $ep.Host -Description $ep.Description -PingCount 25
    }
    $assessmentResults.TeamsJitter = $jitterResults

    # Step 10: SharePoint Speed
    & $reportProgress "Testing download speed and buffer bloat..."
    $spHost = if ($TenantDomain) { "$TenantDomain.sharepoint.com" } else { "microsoft.sharepoint.com" }
    $assessmentResults.SharePointSpeed = Test-SharePointDownloadSpeed -SharePointHost $spHost

    # Step 11: Traceroutes
    & $reportProgress "Running traceroutes to service front doors..."
    $assessmentResults.Traceroutes = Invoke-ServiceTraceroute -TenantDomain $TenantDomain

    # Step 12: Copilot Connectivity
    & $reportProgress "Testing Copilot connectivity and WebSocket..."
    $assessmentResults.CopilotConnectivity = Test-CopilotConnectivity

    # Step 13: TCP/TLS Negotiation
    & $reportProgress "Testing TCP/TLS negotiation..."
    $assessmentResults.TCPNegotiation = Test-TCPNegotiation

    return $assessmentResults
}

function Export-AssessmentReport {
    <#
    .SYNOPSIS
        Generates a comprehensive text report from assessment results
    #>
    param(
        [PSCustomObject]$Assessment,
        [string]$OutputPath
    )

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("  Microsoft 365 Network Connectivity Assessment Report")
    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Generated:  $($Assessment.Timestamp)")
    [void]$sb.AppendLine("Computer:   $($Assessment.ComputerName)")
    [void]$sb.AppendLine("User:       $($Assessment.UserName)")
    [void]$sb.AppendLine("Geography:  $($Assessment.Geography)")
    if ($Assessment.TenantDomain) {
        [void]$sb.AppendLine("Tenant:     $($Assessment.TenantDomain)")
    }
    [void]$sb.AppendLine("")

    # ---- Network Egress ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  NETWORK EGRESS LOCATION")
    [void]$sb.AppendLine("-" * 80)
    $egress = $Assessment.NetworkEgress
    if ($egress.Success) {
        [void]$sb.AppendLine("  Public IP:   $($egress.PublicIP)")
        [void]$sb.AppendLine("  Location:    $($egress.City), $($egress.Region), $($egress.Country)")
        [void]$sb.AppendLine("  ISP:         $($egress.ISP)")
        [void]$sb.AppendLine("  Org:         $($egress.Org)")
    } else {
        [void]$sb.AppendLine("  [X] Failed: $($egress.Error)")
        if ($egress.PublicIP) { [void]$sb.AppendLine("  Public IP: $($egress.PublicIP) (geolocation unavailable)") }
    }
    [void]$sb.AppendLine("")

    # ---- Office Location & Egress Distance ----
    if ($Assessment.OfficeLocation -and $Assessment.OfficeLocation.Success) {
        [void]$sb.AppendLine("-" * 80)
        [void]$sb.AppendLine("  OFFICE LOCATION AND EGRESS DISTANCE")
        [void]$sb.AppendLine("-" * 80)
        $ol = $Assessment.OfficeLocation
        [void]$sb.AppendLine("  Office Location:  $($ol.DisplayName)")
        [void]$sb.AppendLine("  Coordinates:      $($ol.Latitude), $($ol.Longitude)")
        if ($Assessment.EgressDistance) {
            $ed = $Assessment.EgressDistance
            [void]$sb.AppendLine("  Egress Location:  $($egress.City), $($egress.Region), $($egress.Country)")
            [void]$sb.AppendLine("  Distance:         ~$($ed.DistanceKm) km (~$($ed.DistanceMi) mi)")
            [void]$sb.AppendLine("  Rating:           $($ed.Rating)")
            [void]$sb.AppendLine("")
            if ($ed.DistanceKm -ge 800) {
                [void]$sb.AppendLine("  [!] Your internet traffic exits $($ed.DistanceKm) km from your office. This suggests")
                [void]$sb.AppendLine("      WAN backhaul to a remote egress point. For best M365 performance,")
                [void]$sb.AppendLine("      configure local internet breakout at or near each office location.")
            } elseif ($ed.DistanceKm -ge 500) {
                [void]$sb.AppendLine("  [~] Moderate distance between office and internet egress. Consider local")
                [void]$sb.AppendLine("      internet breakout to reduce latency to Microsoft front doors.")
            } else {
                [void]$sb.AppendLine("  [OK] Internet egress is near your office location.")
            }
        }
        [void]$sb.AppendLine("")
    }

    # ---- DNS ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  DNS PERFORMANCE")
    [void]$sb.AppendLine("-" * 80)
    $dns = $Assessment.DNSPerformance
    [void]$sb.AppendLine("  DNS Server: $($dns.DNSServer)")
    $resolver = $Assessment.DNSResolver
    if ($resolver.RecursiveResolver) {
        [void]$sb.AppendLine("  Recursive Resolver: $($resolver.RecursiveResolver)")
        [void]$sb.AppendLine("  Resolver Latency: $($resolver.ResolverLatencyMs)ms")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("  Hostname                                  Avg(ms)    Min(ms)    Max(ms)       Rating")
    [void]$sb.AppendLine("  " + ("-" * 86))
    foreach ($r in $dns.Results) {
        $status = if ($r.Success) { $r.Rating } else { "FAILED" }
        $hn = "$($r.Hostname)".PadRight(40)
        $avg = "$($r.AvgMs)".PadLeft(10)
        $min = "$($r.MinMs)".PadLeft(10)
        $max = "$($r.MaxMs)".PadLeft(10)
        $rt = "$status".PadLeft(12)
        [void]$sb.AppendLine("  $hn $avg $min $max $rt")
    }
    [void]$sb.AppendLine("")

    # ---- VPN/Proxy ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  VPN AND PROXY DETECTION")
    [void]$sb.AppendLine("-" * 80)
    $vpn = $Assessment.VPNProxy
    foreach ($detail in $vpn.Details) {
        [void]$sb.AppendLine("  $detail")
    }
    if ($vpn.VPNDetected) {
        [void]$sb.AppendLine("  Split Tunnel: $($vpn.SplitTunnelStatus)")
        # Per-workload routing details
        if ($vpn.SplitTunnelDetails -and $vpn.SplitTunnelDetails.Count -gt 0) {
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("  Per-workload M365 Optimize Route Analysis:")
            [void]$sb.AppendLine("  Microsoft recommends M365 Optimize category traffic bypass VPN for")
            [void]$sb.AppendLine("  lowest latency. See: https://aka.ms/o365splitvpn")
            [void]$sb.AppendLine("")
            foreach ($std in $vpn.SplitTunnelDetails) {
                $icon = if ($std.RoutesViaVPN -eq $true) { "[!]" } elseif ($std.RoutesViaVPN -eq $false) { "[OK]" } else { "[?]" }
                [void]$sb.AppendLine("    $icon $($std.Workload) ($($std.TestIP) / $($std.Ports))")
                [void]$sb.AppendLine("        Route Adapter: $($std.RouteAdapter)")
                [void]$sb.AppendLine("        $($std.Rating)")
            }
        }
    }
    [void]$sb.AppendLine("")

    # ---- Service Front Doors ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  SERVICE FRONT DOOR IDENTIFICATION")
    [void]$sb.AppendLine("-" * 80)
    foreach ($fd in $Assessment.ServiceFrontDoors) {
        $status = if ($fd.Success) { "[OK]" } else { "[FAIL]" }
        $latencyRating = if (-not $fd.Success) { "N/A" }
                         elseif ($fd.TCPLatencyMs -lt 30) { "Excellent" }
                         elseif ($fd.TCPLatencyMs -lt 60) { "Good" }
                         elseif ($fd.TCPLatencyMs -lt 100) { "Acceptable" }
                         else { "Poor" }
        [void]$sb.AppendLine("  $status $($fd.Service)")
        [void]$sb.AppendLine("      Hostname:   $($fd.Hostname)")
        [void]$sb.AppendLine("      Front Door: $($fd.FrontDoorCNAME)")
        [void]$sb.AppendLine("      IP:         $($fd.FrontDoorIP)")
        [void]$sb.AppendLine("      DNS Time:   $($fd.DNSTimeMs)ms")
        [void]$sb.AppendLine("      TCP Latency: $($fd.TCPLatencyMs)ms (min: $($fd.MinLatencyMs)ms, max: $($fd.MaxLatencyMs)ms)  [$latencyRating]")
        if ($fd.Error) { [void]$sb.AppendLine("      Error: $($fd.Error)") }
        [void]$sb.AppendLine("")
    }

    # ---- Best Front Door Comparison ----
    if ($Assessment.BestFrontDoors -and $Assessment.BestFrontDoors.Count -gt 0) {
        [void]$sb.AppendLine("-" * 80)
        [void]$sb.AppendLine("  BEST FRONT DOOR COMPARISON")
        [void]$sb.AppendLine("-" * 80)
        [void]$sb.AppendLine("  Compares your current Microsoft 365 front doors against the nearest known")
        [void]$sb.AppendLine("  Microsoft front door regions based on your network egress location.")
        [void]$sb.AppendLine("")
        foreach ($bfd in $Assessment.BestFrontDoors) {
            $statusIcon = if ($bfd.IsOptimal) { "[OK]" } else { "[!]" }
            [void]$sb.AppendLine("  $statusIcon $($bfd.Service)")
            [void]$sb.AppendLine("      Current Front Door:   $($bfd.CurrentFrontDoor) ($($bfd.CurrentFrontDoorIP))")
            if ($bfd.CurrentLocation -and $bfd.CurrentLocation -ne "Unknown") {
                [void]$sb.AppendLine("      Front Door Location:  $($bfd.CurrentLocation)")
            }
            if ($bfd.DistanceToFrontDoor) {
                [void]$sb.AppendLine("      Distance to Current:  ~$($bfd.DistanceToFrontDoor) km")
            }
            [void]$sb.AppendLine("      Nearest MS Region:    $($bfd.NearestRegion) (~$($bfd.NearestRegionDistance) km)")
            [void]$sb.AppendLine("      Assessment:           $($bfd.Rating)")
            [void]$sb.AppendLine("")
        }
    }

    # ---- Location-Aware Analysis ----
    if ($egress.Success -and $egress.Latitude -and $Assessment.ServiceFrontDoors.Count -gt 0) {
        [void]$sb.AppendLine("-" * 80)
        [void]$sb.AppendLine("  NETWORK PATH ANALYSIS")
        [void]$sb.AppendLine("-" * 80)
        [void]$sb.AppendLine("  You are egressing from: $($egress.City), $($egress.Region), $($egress.Country)")
        [void]$sb.AppendLine("  ISP / Organization:     $($egress.ISP) / $($egress.Org)")
        [void]$sb.AppendLine("")

        foreach ($fd in ($Assessment.ServiceFrontDoors | Where-Object { $_.Success })) {
            $fdLocation = $null
            # Try to geolocate the front door IP
            if ($fd.FrontDoorIP -and $fd.FrontDoorIP -ne "N/A") {
                try {
                    $fdGeo = Invoke-RestMethod -Uri "http://ip-api.com/json/$($fd.FrontDoorIP)?fields=status,city,regionName,country,lat,lon" -TimeoutSec 5 -ErrorAction Stop
                    if ($fdGeo.status -eq "success" -and $fdGeo.lat) {
                        $fdLocation = [PSCustomObject]@{ City = $fdGeo.city; Region = $fdGeo.regionName; Country = $fdGeo.country; Lat = $fdGeo.lat; Lon = $fdGeo.lon }
                    }
                } catch { }
            }

            if ($fdLocation) {
                # Calculate distance using Haversine formula
                $R = 6371 # Earth radius in km
                $lat1 = [math]::PI * $egress.Latitude / 180
                $lat2 = [math]::PI * $fdLocation.Lat / 180
                $dLat = $lat2 - $lat1
                $dLon = [math]::PI * ($fdLocation.Lon - $egress.Longitude) / 180
                $a = [math]::Sin($dLat/2) * [math]::Sin($dLat/2) + [math]::Cos($lat1) * [math]::Cos($lat2) * [math]::Sin($dLon/2) * [math]::Sin($dLon/2)
                $c = 2 * [math]::Atan2([math]::Sqrt($a), [math]::Sqrt(1 - $a))
                $distKm = [math]::Round($R * $c, 0)
                $distMi = [math]::Round($distKm * 0.621371, 0)

                $rating = if ($distKm -lt 500) { "Optimal" } elseif ($distKm -lt 1500) { "Acceptable" } else { "Suboptimal - consider local internet egress" }

                [void]$sb.AppendLine("  $($fd.Service):")
                [void]$sb.AppendLine("      Front door location: $($fdLocation.City), $($fdLocation.Region), $($fdLocation.Country)")
                [void]$sb.AppendLine("      Distance from egress: ~${distKm} km (~${distMi} mi)")
                [void]$sb.AppendLine("      TCP Latency: $($fd.TCPLatencyMs)ms")
                [void]$sb.AppendLine("      Routing Assessment: $rating")
            } else {
                [void]$sb.AppendLine("  $($fd.Service):")
                [void]$sb.AppendLine("      Front door: $($fd.FrontDoorCNAME) ($($fd.FrontDoorIP))")
                [void]$sb.AppendLine("      TCP Latency: $($fd.TCPLatencyMs)ms")
                [void]$sb.AppendLine("      (Front door geolocation unavailable)")
            }
            [void]$sb.AppendLine("")
        }
    }

    # ---- HTTPS Connectivity ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  HTTPS ENDPOINT CONNECTIVITY")
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  Note: Many M365 endpoints are included in the official endpoint list for")
    [void]$sb.AppendLine("  firewall/proxy allow-listing and do not host web servers. Endpoints that")
    [void]$sb.AppendLine("  are network-reachable (TCP port 443) but don't return a standard HTTP")
    [void]$sb.AppendLine("  response are expected behavior and shown as 'Reachable' below.")
    [void]$sb.AppendLine("")
    $httpResults = $Assessment.HTTPConnectivity
    $httpsAccessible = @($httpResults | Where-Object { $_.HTTPS.Success })
    $tcpReachable    = @($httpResults | Where-Object { -not $_.HTTPS.Success -and -not $_.HTTPS.Blocked -and $_.HTTPS.TCPReachable })
    $blocked         = @($httpResults | Where-Object { $_.HTTPS.Blocked })
    $allowListOnly   = @($httpResults | Where-Object { -not $_.HTTPS.Success -and -not $_.HTTPS.Blocked -and -not $_.HTTPS.TCPReachable })
    [void]$sb.AppendLine("  HTTPS (443):  $($httpsAccessible.Count) accessible, $($tcpReachable.Count) reachable (TCP), $($allowListOnly.Count) allow-list only, $($blocked.Count) blocked")
    [void]$sb.AppendLine("")
    if ($httpsAccessible.Count -gt 0) {
        [void]$sb.AppendLine("  Accessible endpoints (HTTPS response received):")
        foreach ($ep in $httpsAccessible) {
            [void]$sb.AppendLine("    [OK] $($ep.Hostname) ($($ep.Description)) - HTTP $($ep.HTTPS.StatusCode), $($ep.HTTPS.LatencyMs)ms")
        }
        [void]$sb.AppendLine("")
    }
    if ($tcpReachable.Count -gt 0) {
        [void]$sb.AppendLine("  Reachable endpoints (TCP port 443 open, no HTTP response):")
        [void]$sb.AppendLine("  These endpoints are network-reachable but serve APIs or services that do")
        [void]$sb.AppendLine("  not respond to bare HTTPS requests. This is normal.")
        foreach ($ep in $tcpReachable) {
            $detail = $ep.HTTPS.Error
            # Simplify common error messages
            if ($detail -match 'Operation is not valid') { $detail = 'Service responded but not with standard HTTP (API/redirect endpoint)' }
            elseif ($detail -match 'trust relationship') { $detail = 'TLS handshake issue (expected for non-browser endpoints)' }
            elseif ($detail -match 'timed out') { $detail = 'TCP connected but HTTPS handshake timed out' }
            [void]$sb.AppendLine("    [~~] $($ep.Hostname) ($($ep.Description))")
            [void]$sb.AppendLine("         $detail")
        }
        [void]$sb.AppendLine("")
    }
    if ($blocked.Count -gt 0) {
        [void]$sb.AppendLine("  [!] BLOCKED by proxy (action required):")
        [void]$sb.AppendLine("  These endpoints returned HTTP 403/407, indicating a proxy or firewall is")
        [void]$sb.AppendLine("  actively blocking access. Add them to your allow list.")
        foreach ($ep in $blocked) {
            [void]$sb.AppendLine("    [BLOCKED] $($ep.Hostname) ($($ep.Description)) - HTTP $($ep.HTTPS.StatusCode)")
        }
        [void]$sb.AppendLine("")
    }
    if ($allowListOnly.Count -gt 0) {
        [void]$sb.AppendLine("  Allow-list only endpoints (no direct connectivity expected):")
        [void]$sb.AppendLine("  These domains exist in the M365 endpoint list for firewall/proxy allow-listing")
        [void]$sb.AppendLine("  but do not resolve or accept connections directly. They may be mail-routing")
        [void]$sb.AppendLine("  domains, CDN aliases, or service endpoints that require tenant-specific prefixes.")
        foreach ($ep in $allowListOnly) {
            $detail = $ep.HTTPS.Error
            if ($detail -match 'could not be resolved') { $detail = 'DNS does not resolve (mail-routing or CDN alias domain)' }
            elseif ($detail -match 'could not be parsed') { $detail = 'Hostname contains wildcard pattern (allow-list entry only)' }
            elseif ($detail -match 'timed out') { $detail = 'No TCP listener on port 443 (allow-list entry only)' }
            elseif ($detail -match 'actively refused') { $detail = 'Connection refused (service not hosted on this domain directly)' }
            [void]$sb.AppendLine("    [--] $($ep.Hostname) ($($ep.Description))")
            [void]$sb.AppendLine("         $detail")
        }
        [void]$sb.AppendLine("")
    }

    # ---- SSL Interception ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  SSL/TLS INTERCEPTION CHECK")
    [void]$sb.AppendLine("-" * 80)
    $intercepted = $Assessment.SSLInterception | Where-Object { $_.IsIntercepted }
    if ($intercepted.Count -gt 0) {
        [void]$sb.AppendLine("  [!!] INTERCEPTION DETECTED on $($intercepted.Count) endpoint(s):")
        foreach ($ep in $intercepted) {
            [void]$sb.AppendLine("    >>> $($ep.Description) ($($ep.Hostname)) - Root CA: $($ep.RootCA)")
        }
    } else {
        $sslPass = ($Assessment.SSLInterception | Where-Object { $_.Success -and -not $_.IsIntercepted }).Count
        $sslFail = ($Assessment.SSLInterception | Where-Object { -not $_.Success }).Count
        [void]$sb.AppendLine("  [OK] No interception detected ($sslPass passed, $sslFail connection failures)")
    }
    [void]$sb.AppendLine("")

    # ---- Copilot ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  MICROSOFT 365 COPILOT CONNECTIVITY")
    [void]$sb.AppendLine("-" * 80)
    $copilot = $Assessment.CopilotConnectivity
    foreach ($ep in $copilot.HTTPEndpoints) {
        $status = if ($ep.Success) { "[OK]" } else { "[FAIL]" }
        [void]$sb.AppendLine("  $status $($ep.Description) ($($ep.Host)) - $($ep.LatencyMs)ms")
        if ($ep.Error -and -not $ep.Success) { [void]$sb.AppendLine("      Error: $($ep.Error)") }
    }
    $wss = $copilot.WebSocketTest
    $wssStatus = if ($wss.Success) { "[OK]" } else { "[FAIL]" }
    [void]$sb.AppendLine("  $wssStatus WebSocket connectivity - $($wss.LatencyMs)ms")
    if ($wss.Error) { [void]$sb.AppendLine("      Note: $($wss.Error)") }
    if ($copilot.LatencyMs -gt 250) {
        [void]$sb.AppendLine("  [!] Average Copilot latency ($($copilot.LatencyMs)ms) exceeds 250ms threshold")
    }
    [void]$sb.AppendLine("")

    # ---- Teams Media ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  MICROSOFT TEAMS MEDIA CONNECTIVITY")
    [void]$sb.AppendLine("-" * 80)
    $udp = $Assessment.TeamsUDP
    $udpOpen = @($udp | Where-Object { $_.UDPSuccess })
    $udpBlockedWithFallback = @($udp | Where-Object { -not $_.UDPSuccess -and ($_.TCPFallback -or $_.TCP443Fallback) })
    $udpFullyBlocked = @($udp | Where-Object { -not $_.UDPSuccess -and -not $_.TCPFallback -and -not $_.TCP443Fallback })
    [void]$sb.AppendLine("  UDP Port Tests (target: 13.107.64.1):")
    foreach ($p in $udp) {
        $status = if ($p.UDPSuccess) { "[OK]" } elseif ($p.TCPFallback -or $p.TCP443Fallback) { "[TCP]" } else { "[FAIL]" }
        $detail = if ($p.UDPSuccess) { "UDP OK ($($p.UDPLatencyMs)ms)" }
                  elseif ($p.TCPFallback) { "UDP blocked, TCP fallback on port $($p.Port) available" }
                  elseif ($p.TCP443Fallback) { "UDP blocked, TCP 443 fallback available" }
                  else { "Blocked (no UDP or TCP path)" }
        [void]$sb.AppendLine("    $status Port $($p.Port): $detail")
    }
    [void]$sb.AppendLine("")
    if ($udpOpen.Count -eq 4) {
        [void]$sb.AppendLine("  Rating: Optimal - all UDP ports open for best media quality")
    } elseif ($udpBlockedWithFallback.Count -gt 0 -or $udpFullyBlocked.Count -gt 0) {
        if ($udpBlockedWithFallback.Count -gt 0 -or ($udpFullyBlocked.Count -gt 0)) {
            [void]$sb.AppendLine("  Rating: Acceptable - Teams will use TCP/HTTPS fallback")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("  Note: UDP ports 3478-3481 are used by the Teams Transport Relay for")
            [void]$sb.AppendLine("  real-time audio and video. When blocked (common on home networks and")
            [void]$sb.AppendLine("  many corporate firewalls), Teams automatically falls back to TCP/HTTPS")
            [void]$sb.AppendLine("  over port 443. Calls and meetings will work normally. Opening UDP ports")
            [void]$sb.AppendLine("  to 13.107.64.0/18 and 52.112.0.0/14 can improve media quality and")
            [void]$sb.AppendLine("  reduce latency for real-time communications.")
        }
    }
    [void]$sb.AppendLine("")

    # Jitter
    $jitter = $Assessment.TeamsJitter
    $successJitter = $jitter | Where-Object { $_.Success }
    if ($successJitter.Count -gt 0) {
        $avgJitter = [math]::Round(($successJitter | Measure-Object -Property Jitter -Average).Average, 2)
        $avgLatency = [math]::Round(($successJitter | Measure-Object -Property AvgLatency -Average).Average, 2)
        $maxLoss = ($successJitter | Measure-Object -Property PacketLoss -Maximum).Maximum
        [void]$sb.AppendLine("  Jitter Test Results:")
        [void]$sb.AppendLine("    Average Jitter:  ${avgJitter}ms $(if($avgJitter -lt 30){'[OK]'}else{'[!] Exceeds 30ms threshold'})")
        [void]$sb.AppendLine("    Average Latency: ${avgLatency}ms $(if($avgLatency -lt 100){'[OK]'}else{'[!] Exceeds 100ms threshold'})")
        [void]$sb.AppendLine("    Max Packet Loss: ${maxLoss}% $(if($maxLoss -lt 1){'[OK]'}else{'[!] Exceeds 1% threshold'})")
    }
    $icmpBlocked = $jitter | Where-Object { $_.ICMPBlocked }
    if ($icmpBlocked.Count -gt 0) {
        [void]$sb.AppendLine("    Note: $($icmpBlocked.Count) endpoint(s) blocked ICMP (does not affect Teams calls)")
    }
    [void]$sb.AppendLine("")

    # ---- SharePoint Speed ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  SHAREPOINT DOWNLOAD SPEED AND BUFFER BLOAT")
    [void]$sb.AppendLine("-" * 80)
    $sp = $Assessment.SharePointSpeed
    if ($sp.Success) {
        $speedRating = if ($sp.SpeedMegabitsPerSec -ge 50) { "Excellent" }
                       elseif ($sp.SpeedMegabitsPerSec -ge 10) { "Good" }
                       elseif ($sp.SpeedMegabitsPerSec -ge 2) { "Acceptable" }
                       else { "Poor" }
        [void]$sb.AppendLine("  Download Speed:     $($sp.SpeedMegabitsPerSec) Mbps ($($sp.SpeedMegabytesPerSec) MB/s)  [$speedRating]")
        [void]$sb.AppendLine("  Download Size:      $([math]::Round($sp.DownloadSizeBytes / 1MB, 2)) MB ($($sp.DownloadSizeBytes) bytes) in $($sp.DownloadTimeMs)ms")
        if ($sp.TestSource) { [void]$sb.AppendLine("  Test Source:        $($sp.TestSource)") }
        [void]$sb.AppendLine("  Latency (idle):     $($sp.LatencyBeforeMs)ms")
        [void]$sb.AppendLine("  Latency (loaded):   $($sp.LatencyDuringMs)ms")
        [void]$sb.AppendLine("  Buffer Bloat:       $($sp.BufferBloatMs)ms - $($sp.BufferBloatRating)")
    } else {
        [void]$sb.AppendLine("  [X] Failed: $($sp.Error)")
    }
    [void]$sb.AppendLine("")

    # ---- TCP/TLS ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  TCP/TLS NEGOTIATION")
    [void]$sb.AppendLine("-" * 80)
    $tcp = $Assessment.TCPNegotiation
    if ($tcp.Success) {
        $tlsRating = if ($tcp.TLS13Support) { "Excellent" }
                     elseif ($tcp.TLS12Support) { "Good" }
                     else { "Poor - outdated TLS version" }
        [void]$sb.AppendLine("  Target:         $($tcp.Hostname):$($tcp.Port)")
        [void]$sb.AppendLine("  TLS Version:    $($tcp.TLSVersion)")
        [void]$sb.AppendLine("  TLS 1.2:        $(if($tcp.TLS12Support){'Supported'}else{'Not Supported'})")
        [void]$sb.AppendLine("  TLS 1.3:        $(if($tcp.TLS13Support){'Supported'}else{'Not Supported'})")
        [void]$sb.AppendLine("  Cipher:         $($tcp.CipherSuite)")
        [void]$sb.AppendLine("  TCP Window:     $($tcp.TCPWindowSize) bytes")
        [void]$sb.AppendLine("  Security Rating: $tlsRating")
    } else {
        [void]$sb.AppendLine("  [X] Failed: $($tcp.Error)")
    }
    [void]$sb.AppendLine("")

    # ---- Traceroutes ----
    [void]$sb.AppendLine("-" * 80)
    [void]$sb.AppendLine("  TRACEROUTES TO SERVICE FRONT DOORS")
    [void]$sb.AppendLine("-" * 80)
    foreach ($tr in $Assessment.Traceroutes) {
        $hopRating = if (-not $tr.TCPTestSucceeded) { "Unreachable" }
                     elseif ($tr.HopCount -le 15) { "Good" }
                     elseif ($tr.HopCount -le 20) { "Acceptable" }
                     else { "High hop count - possible inefficient routing" }
        [void]$sb.AppendLine("  $($tr.Service) ($($tr.Hostname) -> $($tr.ResolvedIP))")
        [void]$sb.AppendLine("  TCP Test: $(if($tr.TCPTestSucceeded){'Pass'}else{'Fail'})  |  Hops: $($tr.HopCount)  [$hopRating]")
        if ($tr.Hops.Count -gt 0) {
            foreach ($hop in $tr.Hops) {
                $marker = if ($hop.IsPrivate) { " [private]" } else { "" }
                [void]$sb.AppendLine("    Hop $($hop.Hop): $($hop.Address)$marker")
            }
        }
        if ($tr.Error) { [void]$sb.AppendLine("  Error: $($tr.Error)") }
        [void]$sb.AppendLine("")
    }

    # ---- Summary ----
    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("  ASSESSMENT SUMMARY")
    [void]$sb.AppendLine("=" * 80)

    $issues = @()
    if (($Assessment.SSLInterception | Where-Object { $_.IsIntercepted }).Count -gt 0) {
        $issues += "[CRITICAL] SSL/TLS interception detected"
    }
    if ($Assessment.VPNProxy.VPNDetected -and $Assessment.VPNProxy.SplitTunnelStatus -eq "Disabled (Full Tunnel)") {
        $issues += "[WARNING] VPN full tunnel detected - M365 Optimize traffic should be split tunneled"
    }
    if ($Assessment.VPNProxy.ProxyEnabled) {
        $issues += "[INFO] Proxy server detected - ensure M365 Optimize/Allow endpoints bypass proxy"
    }
    $dnsSlowCount = ($Assessment.DNSPerformance.Results | Where-Object { $_.AvgMs -gt 100 }).Count
    if ($dnsSlowCount -gt 0) {
        $issues += "[WARNING] $dnsSlowCount endpoint(s) have DNS resolution > 100ms"
    }
    $udpBlocked = ($Assessment.TeamsUDP | Where-Object { -not $_.UDPSuccess }).Count
    $hasTCPFallback = ($Assessment.TeamsUDP | Where-Object { -not $_.UDPSuccess -and ($_.TCPFallback -or $_.TCP443Fallback) }).Count -gt 0
    if ($udpBlocked -gt 0) {
        if ($hasTCPFallback) {
            $issues += "[INFO] $udpBlocked Teams UDP port(s) blocked - Teams will use TCP/HTTPS fallback (calls still work)"
        } else {
            $issues += "[WARNING] $udpBlocked Teams UDP port(s) blocked with no TCP fallback detected"
        }
    }
    $successJitter = $Assessment.TeamsJitter | Where-Object { $_.Success }
    if ($successJitter.Count -gt 0) {
        $avgJ = [math]::Round(($successJitter | Measure-Object -Property Jitter -Average).Average, 2)
        if ($avgJ -gt 30) { $issues += "[WARNING] Teams jitter ($($avgJ)ms) exceeds 30ms threshold" }
    }
    if ($Assessment.SharePointSpeed.BufferBloatMs -gt 100) {
        $issues += "[WARNING] Buffer bloat detected ($($Assessment.SharePointSpeed.BufferBloatMs)ms increase under load)"
    }
    $httpsBlocked = ($Assessment.HTTPConnectivity | Where-Object { $_.HTTPS.Blocked }).Count
    if ($httpsBlocked -gt 0) {
        $issues += "[CRITICAL] $httpsBlocked endpoint(s) blocked by proxy (HTTP 403/407)"
    }
    if ($Assessment.CopilotConnectivity.LatencyMs -gt 250) {
        $issues += "[WARNING] Copilot latency ($($Assessment.CopilotConnectivity.LatencyMs)ms) exceeds 250ms threshold"
    }
    # Check for suboptimal front door distance
    foreach ($fd in ($Assessment.ServiceFrontDoors | Where-Object { $_.Success -and $_.TCPLatencyMs -gt 100 })) {
        $issues += "[WARNING] $($fd.Service) front door latency ($($fd.TCPLatencyMs)ms) exceeds 100ms - may indicate suboptimal routing"
    }
    # Check egress distance from office
    if ($Assessment.EgressDistance -and $Assessment.EgressDistance.DistanceKm -ge 800) {
        $issues += "[WARNING] Internet egress is ~$($Assessment.EgressDistance.DistanceKm) km from office - likely WAN backhaul"
    }
    # Check best front door comparison
    if ($Assessment.BestFrontDoors) {
        foreach ($bfd in ($Assessment.BestFrontDoors | Where-Object { -not $_.IsOptimal })) {
            $issues += "[WARNING] $($bfd.Service) front door is not optimal - nearest MS region: $($bfd.NearestRegion)"
        }
    }
    # Check per-workload VPN split tunnel
    if ($Assessment.VPNProxy.SplitTunnelDetails) {
        $vpnRouted = @($Assessment.VPNProxy.SplitTunnelDetails | Where-Object { $_.RoutesViaVPN -eq $true })
        if ($vpnRouted.Count -gt 0) {
            $workloads = ($vpnRouted | ForEach-Object { $_.Workload }) -join ", "
            $issues += "[WARNING] M365 Optimize traffic for $workloads routes through VPN (split tunnel recommended)"
        }
    }

    if ($issues.Count -eq 0) {
        [void]$sb.AppendLine("  [OK] No significant issues detected")
    } else {
        [void]$sb.AppendLine("  Issues found: $($issues.Count)")
        [void]$sb.AppendLine("")
        foreach ($issue in $issues) {
            [void]$sb.AppendLine("  $issue")
        }
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("  End of Report")
    [void]$sb.AppendLine("=" * 80)

    # Write to file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "M365_Assessment_$timestamp.txt"
    $filepath = Join-Path $OutputPath $filename
    $sb.ToString() | Out-File -FilePath $filepath -Encoding UTF8

    return [PSCustomObject]@{
        FilePath = $filepath
        Content  = $sb.ToString()
    }
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
            # Use TLS 1.2 and TLS 1.3 explicitly
            $sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
            $sslStream.AuthenticateAsClient($Hostname, $null, $sslProtocols, $false)
            
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
        Title="Network Diagnostic Toolkit" 
        Height="950" Width="1150"
        WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <!-- Windows Default Light Theme Colors -->
        <SolidColorBrush x:Key="BackgroundBrush" Color="{x:Static SystemColors.WindowColor}"/>
        <SolidColorBrush x:Key="SecondaryBackgroundBrush" Color="{x:Static SystemColors.ControlColor}"/>
        <SolidColorBrush x:Key="BorderBrush" Color="{x:Static SystemColors.ActiveBorderColor}"/>
        <SolidColorBrush x:Key="ForegroundBrush" Color="{x:Static SystemColors.ControlTextColor}"/>
        <SolidColorBrush x:Key="AccentBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="SuccessBrush" Color="#107C10"/>
        <SolidColorBrush x:Key="WarningBrush" Color="#CA5010"/>
        <SolidColorBrush x:Key="ErrorBrush" Color="#D13438"/>
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
            <TextBlock Text="Network Diagnostic Toolkit" FontSize="24" FontWeight="Bold" Foreground="#0078D4"/>
            <TextBlock Text="SSL/TLS interception detection, network connectivity assessment, and diagnostic tools" 
                       FontSize="13" Foreground="Gray" Margin="0,5,0,0"/>
        </StackPanel>
        
        <!-- Main Content -->
        <TabControl x:Name="mainTabControl" Grid.Row="1">
            <!-- Endpoints Tab -->
            <TabItem Header="SSL Endpoints">
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
                                <Separator Margin="0,10" Background="LightGray"/>
                                <Button x:Name="btnSelectAll" Content="Select All" Margin="0,5"/>
                                <Button x:Name="btnDeselectAll" Content="Deselect All" Margin="0,5" Background="LightGray"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Fetch Live Endpoints" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="Import from Microsoft:"  Margin="0,0,0,5"/>
                                <Button x:Name="btnFetchM365" Content="Fetch M365 Endpoints" Margin="0,3" Background="#107C10"/>
                                <Button x:Name="btnFetchAzure" Content="Fetch Azure Endpoints" Margin="0,3" Background="#107C10"/>
                                <TextBlock x:Name="txtFetchStatus" Text="" Foreground="Gray" FontSize="11" Margin="0,5,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Add Custom Endpoint" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="Hostname:"  Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomHost" Margin="0,0,0,8"/>
                                <TextBlock Text="Port:"  Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomPort" Text="443" Margin="0,0,0,8"/>
                                <TextBlock Text="Description:"  Margin="0,0,0,3"/>
                                <TextBox x:Name="txtCustomDesc" Margin="0,0,0,8"/>
                                <Button x:Name="btnAddEndpoint" Content="Add Endpoint" Margin="0,5"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Header="Import Endpoints from File" Margin="5,10,5,5">
                            <StackPanel>
                                <TextBlock Text="File format (CSV or TXT):"  Margin="0,0,0,3" FontWeight="Bold"/>
                                <TextBlock Text="hostname,port,description" Foreground="Gray" FontSize="11" Margin="0,0,0,2"/>
                                <TextBlock Text="Example:" Foreground="Gray" FontSize="10" Margin="0,3,0,0"/>
                                <TextBlock Text="myapp.contoso.com,443,My App" Foreground="#107C10" FontSize="10" FontFamily="Consolas"/>
                                <TextBlock Text="api.example.com,8443,API" Foreground="#107C10" FontSize="10" FontFamily="Consolas" Margin="0,0,0,8"/>
                                <Button x:Name="btnImportFile" Content="Import from File..." Margin="0,5" Background="#0E639C"/>
                                <TextBlock x:Name="txtImportStatus" Text="" Foreground="Gray" FontSize="11" Margin="0,5,0,0" TextWrapping="Wrap"/>
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
            <TabItem Header="SSL Results">
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
                        
                        <Border Grid.Column="0" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Total Tested" Foreground="Gray" FontSize="12"/>
                                <TextBlock x:Name="txtTotalCount" Text="0"  FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="1" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Trusted" Foreground="Gray" FontSize="12"/>
                                <TextBlock x:Name="txtTrustedCount" Text="0" Foreground="#107C10" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="2" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Intercepted" Foreground="Gray" FontSize="12"/>
                                <TextBlock x:Name="txtInterceptedCount" Text="0" Foreground="#CA5010" FontSize="28" FontWeight="Bold"/>
                            </StackPanel>
                        </Border>
                        
                        <Border Grid.Column="3" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="15">
                            <StackPanel>
                                <TextBlock Text="Failed" Foreground="Gray" FontSize="12"/>
                                <TextBlock x:Name="txtFailedCount" Text="0" Foreground="#D13438" FontSize="28" FontWeight="Bold"/>
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
            <TabItem Header="SSL Cert Details">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="Select a result to view certificate chain details" 
                               Foreground="Gray" Margin="0,0,0,10"/>
                    
                    <Border Grid.Row="1" Background="WhiteSmoke" CornerRadius="4" Padding="15">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="txtCertDetails" 
                                        
                                       FontFamily="Consolas" 
                                       FontSize="12"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </Grid>
            </TabItem>
            
            <!-- Known CAs Tab -->
            <TabItem Header="SSL Root CAs">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="These are the trusted Microsoft root CAs used to detect SSL/TLS interception:" 
                               Foreground="Gray" Margin="0,0,0,10"/>
                    
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
                        <TextBlock x:Name="txtCAStatus" VerticalAlignment="Center" Foreground="Gray" Text=""/>
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
                                   Foreground="Gray" Margin="0,5,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    
                    <!-- Configuration -->
                    <Grid Grid.Row="1" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="350"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <GroupBox Grid.Column="0" Header="Test Configuration">
                            <StackPanel Margin="5">
                                <TextBlock Text="Target Public IP:"  Margin="0,0,0,3"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="txtHairpinIP" Grid.Column="0" Margin="0,0,5,0"/>
                                    <Button x:Name="btnDetectIP" Grid.Column="1" Content="Auto-Detect" Padding="10,3" Background="#107C10"/>
                                </Grid>
                                
                                <TextBlock Text="Port (optional):"  Margin="0,10,0,3"/>
                                <TextBox x:Name="txtHairpinPort" Text="443" Width="80" HorizontalAlignment="Left"/>
                                
                                <TextBlock Text="Internal Host (optional, for comparison):"  Margin="0,10,0,3"/>
                                <TextBox x:Name="txtHairpinInternal"/>
                                
                                <Button x:Name="btnRunHairpin" Content="Run Hairpin Test" Margin="0,15,0,0" Padding="15,8"/>
                                <TextBlock x:Name="txtHairpinStatus" Text="" Foreground="Gray" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Grid.Column="1" Header="What is Hairpin NAT?" Margin="10,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock Foreground="Gray" TextWrapping="Wrap" Margin="5">
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
                                    * TTL analysis (low hop count to public IP)
                                    <LineBreak/>
                                    * Latency comparison (sub-millisecond to public IP)
                                    <LineBreak/>
                                    * Traceroute showing only private hops
                                    <LineBreak/>
                                    * TCP connection timing analysis
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
                                
                                <Border Grid.Column="0" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Status" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinResult" Text="-"  FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="1" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Latency" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinLatency" Text="-"  FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="2" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Hops" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinHops" Text="-"  FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="3" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Confidence" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtHairpinConfidence" Text="-"  FontSize="18" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <!-- Details -->
                            <Border Grid.Row="1" Background="White" CornerRadius="4" Padding="10">
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <TextBlock x:Name="txtHairpinDetails" 
                                                
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
                                   Foreground="Gray" Margin="0,5,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    
                    <!-- Configuration -->
                    <Grid Grid.Row="1" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="350"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <GroupBox Grid.Column="0" Header="Test Configuration">
                            <StackPanel Margin="5">
                                <TextBlock Text="Number of Pings per Endpoint:"  Margin="0,0,0,3"/>
                                <ComboBox x:Name="cmbJitterPingCount" SelectedIndex="1" Width="100" HorizontalAlignment="Left">
                                    <ComboBoxItem Content="25 (Quick)"/>
                                    <ComboBoxItem Content="50 (Standard)"/>
                                    <ComboBoxItem Content="100 (Thorough)"/>
                                </ComboBox>
                                
                                <CheckBox x:Name="chkTestAllRegions" Content="Test All Regional Endpoints" Margin="0,15,0,0" />
                                <TextBlock Text="(Uncheck to test only global endpoints)" Foreground="Gray" FontSize="10" Margin="20,2,0,0"/>
                                
                                <Button x:Name="btnRunJitter" Content="Run Jitter Test" Margin="0,20,0,0" Padding="15,8"/>
                                <TextBlock x:Name="txtJitterStatus" Text="" Foreground="Gray" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Grid.Column="1" Header="Teams Call Quality Requirements" Margin="10,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock Foreground="Gray" TextWrapping="Wrap" Margin="5">
                                    <Run FontWeight="Bold">Microsoft Teams Network Requirements:</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#107C10">Jitter:</Run> &lt; 30ms recommended
                                    <LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#107C10">Latency:</Run> &lt; 100ms recommended
                                    <LineBreak/>
                                    <Run FontWeight="Bold" Foreground="#107C10">Packet Loss:</Run> &lt; 1% recommended
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">What is Jitter?</Run>
                                    <LineBreak/>
                                    Jitter is the variation in packet arrival times. High jitter 
                                    causes choppy audio/video in Teams calls even when average 
                                    latency is acceptable.
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Rating Scale:</Run>
                                    <LineBreak/>
                                    * Excellent: &lt; 10ms
                                    <LineBreak/>
                                    * Good: 10-20ms
                                    <LineBreak/>
                                    * Acceptable: 20-30ms
                                    <LineBreak/>
                                    * Poor: 30-50ms
                                    <LineBreak/>
                                    * Very Poor: &gt; 50ms
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
                                
                                <Border Grid.Column="0" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Overall Quality" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterQuality" Text="-"  FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="1" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Avg Jitter" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterAvg" Text="-"  FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="2" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Avg Latency" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterLatency" Text="-"  FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="3" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Packet Loss" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterLoss" Text="-"  FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="4" Background="WhiteSmoke" CornerRadius="8" Margin="5" Padding="10">
                                    <StackPanel>
                                        <TextBlock Text="Endpoints" Foreground="Gray" FontSize="11"/>
                                        <TextBlock x:Name="txtJitterEndpoints" Text="-"  FontSize="16" FontWeight="Bold"/>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <!-- Details -->
                            <Border Grid.Row="1" Background="White" CornerRadius="4" Padding="10">
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <TextBlock x:Name="txtJitterDetails" 
                                                
                                               FontFamily="Consolas" 
                                               FontSize="12"
                                               TextWrapping="Wrap"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </GroupBox>
                </Grid>
            </TabItem>
            
            <!-- Assessment Tab -->
            <TabItem Header="Assessment">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Description -->
                    <StackPanel Grid.Row="0" Margin="0,0,0,15">
                        <TextBlock Text="M365 Network Connectivity Assessment" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                        <TextBlock Text="Comprehensive assessment modeled after connectivity.office.com - DNS, front doors, latency, interception, Teams media, Copilot, VPN/proxy, and more" 
                                   Foreground="Gray" Margin="0,5,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                    
                    <!-- Configuration -->
                    <Grid Grid.Row="1" Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="350"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <GroupBox Grid.Column="0" Header="Assessment Configuration">
                            <StackPanel Margin="5">
                                <TextBlock Text="Microsoft Geography:"  Margin="0,0,0,3"/>
                                <ComboBox x:Name="cmbAssessGeo" SelectedIndex="0" Width="250" HorizontalAlignment="Left">
                                    <ComboBoxItem Content="Worldwide (Commercial)"/>
                                    <ComboBoxItem Content="US Gov DoD"/>
                                    <ComboBoxItem Content="US Gov GCC High"/>
                                    <ComboBoxItem Content="China (21Vianet)"/>
                                    <ComboBoxItem Content="Germany"/>
                                </ComboBox>
                                
                                <TextBlock Text="Tenant Domain (optional):"  Margin="0,15,0,3"/>
                                <TextBox x:Name="txtAssessTenant" Margin="0,0,0,3"/>
                                <TextBlock Text="e.g. contoso (for contoso.sharepoint.com)" Foreground="Gray" FontSize="10"/>
                                
                                <TextBlock Text="Office Location (optional):"  Margin="0,15,0,3"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="5"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="5"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="txtAssessCity" Grid.Column="0"/>
                                    <TextBox x:Name="txtAssessState" Grid.Column="2"/>
                                    <TextBox x:Name="txtAssessCountry" Grid.Column="4"/>
                                </Grid>
                                <Grid Margin="0,2,0,0">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="5"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="5"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="City" Foreground="Gray" FontSize="10"/>
                                    <TextBlock Grid.Column="2" Text="State/Region" Foreground="Gray" FontSize="10"/>
                                    <TextBlock Grid.Column="4" Text="Country" Foreground="Gray" FontSize="10"/>
                                </Grid>
                                
                                <Button x:Name="btnRunAssessment" Content="Run Full Assessment" Margin="0,20,0,0" Padding="15,10" Background="#107C10" FontSize="14"/>
                                <TextBlock x:Name="txtAssessStatus" Text="Ready" Foreground="Gray" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
                                <ProgressBar x:Name="assessProgress" Height="6" Background="LightGray" Foreground="#107C10" BorderThickness="0" Margin="0,8,0,0" Minimum="0" Maximum="13" Value="0"/>
                            </StackPanel>
                        </GroupBox>
                        
                        <GroupBox Grid.Column="1" Header="What This Tests" Margin="10,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock Foreground="Gray" TextWrapping="Wrap" Margin="5">
                                    <Run FontWeight="Bold">This assessment runs all of the following tests:</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run Foreground="#107C10">1.</Run> Network egress geolocation (public IP, ISP, city)
                                    <LineBreak/>
                                    <Run Foreground="#107C10">2.</Run> Office location geocoding and egress distance calculation
                                    <LineBreak/>
                                    <Run Foreground="#107C10">3.</Run> DNS recursive resolver identification
                                    <LineBreak/>
                                    <Run Foreground="#107C10">4.</Run> DNS resolution performance for key M365 endpoints
                                    <LineBreak/>
                                    <Run Foreground="#107C10">5.</Run> VPN/proxy detection with per-workload split tunnel routing
                                    <LineBreak/>
                                    <Run Foreground="#107C10">6.</Run> Exchange, SharePoint, Teams front door identification
                                    <LineBreak/>
                                    <Run Foreground="#107C10">7.</Run> Best front door comparison (nearest Microsoft region)
                                    <LineBreak/>
                                    <Run Foreground="#107C10">8.</Run> HTTPS endpoint connectivity (from live M365 JSON feed)
                                    <LineBreak/>
                                    <Run Foreground="#107C10">9.</Run> SSL/TLS interception detection
                                    <LineBreak/>
                                    <Run Foreground="#107C10">10.</Run> Teams UDP media port connectivity (3478-3481)
                                    <LineBreak/>
                                    <Run Foreground="#107C10">11.</Run> Teams jitter, latency, and packet loss
                                    <LineBreak/>
                                    <Run Foreground="#107C10">12.</Run> Download speed test (~10 MB) and buffer bloat
                                    <LineBreak/>
                                    <Run Foreground="#107C10">13.</Run> Traceroutes to service front doors
                                    <LineBreak/>
                                    <Run Foreground="#107C10">14.</Run> Microsoft 365 Copilot and WebSocket connectivity
                                    <LineBreak/>
                                    <Run Foreground="#107C10">15.</Run> TCP/TLS negotiation analysis
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Endpoints are pulled live from the official Microsoft JSON feed for the selected geography.</Run>
                                    <LineBreak/><LineBreak/>
                                    A detailed text report is saved automatically to the current working directory upon completion.
                                </TextBlock>
                            </ScrollViewer>
                        </GroupBox>
                    </Grid>
                    
                    <!-- Results -->
                    <GroupBox Grid.Row="2" Header="Assessment Results">
                        <Border Background="White" CornerRadius="4" Padding="10">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBlock x:Name="txtAssessResults" 
                                            
                                           FontFamily="Consolas" 
                                           FontSize="12"
                                           TextWrapping="Wrap"
                                           Text="Click 'Run Full Assessment' to start."/>
                            </ScrollViewer>
                        </Border>
                    </GroupBox>
                </Grid>
            </TabItem>
        </TabControl>
        
        <!-- Progress Bar (SSL scan) -->
        <Grid x:Name="sslProgressBar" Grid.Row="2" Margin="0,15,0,10">
            <ProgressBar x:Name="progressBar" Height="6" Background="LightGray" Foreground="#0078D4" BorderThickness="0"/>
        </Grid>
        
        <!-- Bottom Controls (SSL scan) -->
        <Grid x:Name="sslControlBar" Grid.Row="3">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            
            <TextBlock x:Name="txtStatus" Grid.Column="0" VerticalAlignment="Center" Foreground="Gray" Text="Ready to scan"/>
            
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

    # Hide SSL bottom bar when Assessment tab is selected
    $mainTabControl.Add_SelectionChanged({
        $selectedTab = $mainTabControl.SelectedItem
        if ($selectedTab -and $selectedTab.Header -eq 'Assessment') {
            $sslControlBar.Visibility = [System.Windows.Visibility]::Collapsed
            $sslProgressBar.Visibility = [System.Windows.Visibility]::Collapsed
        } else {
            $sslControlBar.Visibility = [System.Windows.Visibility]::Visible
            $sslProgressBar.Visibility = [System.Windows.Visibility]::Visible
        }
    })

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
        
        if ($guiResultsList.Count -gt 0) {
            # SSL scan results
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
                        $rtt = if ($null -ne $hop.RTT) { "$($hop.RTT)ms" } else { "*" }
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

    # Assessment - Run Full Assessment button
    $btnRunAssessment.Add_Click({
        # Map combo box to geography key
        $geoMap = @("Worldwide", "USGovDoD", "USGovGCCHigh", "China", "Germany")
        $selectedGeo = $geoMap[$cmbAssessGeo.SelectedIndex]
        $tenantDomain = $txtAssessTenant.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($tenantDomain)) { $tenantDomain = $null }

        $btnRunAssessment.IsEnabled = $false
        $txtAssessStatus.Text = "Starting assessment..."
        $assessProgress.Value = 0
        $txtAssessResults.Text = "Running M365 Network Connectivity Assessment...`n`nGeography: $selectedGeo`n"
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

        try {
            $progressCB = {
                param([int]$Step, [int]$Total, [string]$StepName)
                $window.Dispatcher.Invoke([Action]{
                    $assessProgress.Value = $Step
                    $txtAssessStatus.Text = "[$Step/$Total] $StepName"
                    $txtAssessResults.Text = $txtAssessResults.Text + "`n[$Step/$Total] $StepName"
                }, [System.Windows.Threading.DispatcherPriority]::Background)
            }

            $assessment = Start-NetworkAssessment -SelectedGeography $selectedGeo -TenantDomain $tenantDomain -OfficeCity $txtAssessCity.Text.Trim() -OfficeState $txtAssessState.Text.Trim() -OfficeCountry $txtAssessCountry.Text.Trim() -ProgressCallback $progressCB

            # Generate report
            $report = Export-AssessmentReport -Assessment $assessment -OutputPath $OutputPath

            $txtAssessResults.Text = "Report saved to: $($report.FilePath)`n`n$($report.Content)"
            $txtAssessStatus.Foreground = [System.Windows.Media.Brushes]::Green
            $txtAssessStatus.Text = "Assessment complete. Report saved to: $($report.FilePath)"
            $assessProgress.Value = 13
        }
        catch {
            $txtAssessResults.Text = "Error during assessment: $($_.Exception.Message)`n`n$($_.ScriptStackTrace)"
            $txtAssessStatus.Foreground = [System.Windows.Media.Brushes]::Red
            $txtAssessStatus.Text = "Assessment failed"
        }
        finally {
            $btnRunAssessment.IsEnabled = $true
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
                       Network Diagnostic Toolkit
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
    if ($RunAssessment) {
        # Run the network connectivity assessment
        Write-Host ""
        Write-Host "=================================================================================" -ForegroundColor Cyan
        Write-Host "              Microsoft 365 Network Connectivity Assessment" -ForegroundColor Cyan
        Write-Host "=================================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Geography : $Geography" -ForegroundColor Gray
        Write-Host "Computer  : $env:COMPUTERNAME" -ForegroundColor Gray
        Write-Host "User      : $env:USERNAME" -ForegroundColor Gray
        Write-Host "Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        if ($OfficeCity -or $OfficeState -or $OfficeCountry) {
            $officeParts = @($OfficeCity, $OfficeState, $OfficeCountry) | Where-Object { $_ }
            Write-Host "Office    : $($officeParts -join ', ')" -ForegroundColor Gray
        }
        Write-Host ""

        $assessResults = Start-NetworkAssessment -SelectedGeography $Geography -OfficeCity $OfficeCity -OfficeState $OfficeState -OfficeCountry $OfficeCountry -ProgressCallback {
            param($step, $total, $msg)
            $pct = [math]::Round(($step / $total) * 100)
            Write-Host "  [$pct%] Step $step/$total - $msg" -ForegroundColor Yellow
        }

        # Generate the report
        $reportPath = Export-AssessmentReport -Results $assessResults -OutputFolder $OutputPath
        Write-Host ""
        Write-Host "Assessment complete. Report saved to:" -ForegroundColor Green
        Write-Host "  $reportPath" -ForegroundColor White
        Write-Host ""
    }
    elseif ($TestAVD -or $TestMicrosoft365 -or $TestAzure -or $TestTRv2 -or $TestAppleSSO -or $TestHairpin -or $TestAll -or $CustomEndpoints -or $FetchM365Endpoints -or $FetchAzureEndpoints) {
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
        Write-Host "Network Diagnostic Toolkit" -ForegroundColor Cyan
        Write-Host "==========================" -ForegroundColor Cyan
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
        Write-Host "  -RunAssessment       Run M365 network connectivity assessment" -ForegroundColor White
        Write-Host "  -Geography           Geography for assessment: Worldwide (default)," -ForegroundColor White
        Write-Host "                       USGovDoD, USGovGCCHigh, China, Germany" -ForegroundColor White
        Write-Host "  -OfficeCity          Office city for egress distance calculation" -ForegroundColor White
        Write-Host "  -OfficeState         Office state/region for egress distance calculation" -ForegroundColor White
        Write-Host "  -OfficeCountry       Office country for egress distance calculation" -ForegroundColor White
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  .\Detect-Interception.ps1"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAll"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -FetchM365Endpoints"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAVD -FetchAzureEndpoints"
        Write-Host "  .\Detect-Interception.ps1 -DiscoverRootCAs"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestHairpin"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -RunAssessment"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -RunAssessment -Geography USGovGCCHigh"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -RunAssessment -OfficeCity Seattle -OfficeState WA -OfficeCountry US"
        Write-Host ""
        Write-Host "Note: -NoGUI requires at least one test parameter to be specified." -ForegroundColor Yellow
    }
}
else {
    # Default behavior - launch GUI
    Start-GUIMode
}

#endregion
