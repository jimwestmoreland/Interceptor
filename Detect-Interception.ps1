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

.PARAMETER TestAll
    Tests all endpoint categories

.PARAMETER FetchM365Endpoints
    Fetches the current Microsoft 365 endpoint list from the official Microsoft JSON feed

.PARAMETER FetchAzureEndpoints
    Fetches the current Azure endpoint list from the official Microsoft JSON feed

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
    [switch]$TestAll,
    [switch]$FetchM365Endpoints,
    [switch]$FetchAzureEndpoints,
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
                    <DataGrid x:Name="dgKnownCAs"
                              AutoGenerateColumns="False" 
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              HeadersVisibility="Column"
                              VerticalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Root CA Name" Binding="{Binding Name}" Width="350"/>
                            <DataGridTextColumn Header="Thumbprint" Binding="{Binding Thumbprint}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
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
        $caObj = [PSCustomObject]@{
            Name = $ca.Key
            Thumbprint = $ca.Value
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
        
        $chkAVD.IsChecked = ($avdEnabled -eq $avdTotal -and $avdTotal -gt 0)
        $chkM365.IsChecked = ($m365Enabled -eq $m365Total -and $m365Total -gt 0)
        $chkAzure.IsChecked = ($azureEnabled -eq $azureTotal -and $azureTotal -gt 0)
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
            Write-ColorOutput "`n  [!] INTERCEPTION DETECTED!" "Red"
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
    Write-ColorOutput "  [!] Intercepted: $($intercepted.Count)" "$(if ($intercepted.Count -gt 0) { 'Red' } else { 'Green' })"
    Write-ColorOutput "  [X] Connection Failed: $($failed.Count)" "$(if ($failed.Count -gt 0) { 'Yellow' } else { 'Green' })"

    if ($intercepted.Count -gt 0) {
        Write-ColorOutput "`n" "White"
        Write-ColorOutput ("!" * 80) "Red"
        Write-ColorOutput "WARNING: SSL/TLS INTERCEPTION DETECTED!" "Red"
        Write-ColorOutput ("!" * 80) "Red"
        Write-ColorOutput "`nThe following endpoints are being intercepted:" "Yellow"
        
        foreach ($ep in $intercepted) {
            Write-ColorOutput "  - $($ep.Description) ($($ep.Hostname):$($ep.Port))" "Yellow"
            Write-ColorOutput "    Intercepting CA: $($ep.RootCA)" "Gray"
        }
        
        Write-ColorOutput "`nRECOMMENDATION:" "Cyan"
        Write-ColorOutput "SSL/TLS interception can cause authentication failures and connectivity" "White"
        Write-ColorOutput "issues. Consider configuring your proxy to bypass inspection for" "White"
        Write-ColorOutput "critical endpoints." "White"
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

# Determine which mode to run
if ($NoGUI) {
    # NoGUI specified - run in CLI mode if tests are specified, otherwise show help
    if ($TestAVD -or $TestMicrosoft365 -or $TestAzure -or $TestAll -or $CustomEndpoints -or $FetchM365Endpoints -or $FetchAzureEndpoints) {
        Start-CLIMode
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
        Write-Host "  -TestAll             Test all endpoint categories"
        Write-Host "  -FetchM365Endpoints  Fetch live M365 endpoints from Microsoft"
        Write-Host "  -FetchAzureEndpoints Fetch live Azure endpoints from Microsoft"
        Write-Host "  -CustomEndpoints     Test custom endpoints (e.g., @('host:port'))"
        Write-Host "  -OutputPath          Path to save results (default: current directory)"
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  .\Detect-Interception.ps1"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAll"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -FetchM365Endpoints"
        Write-Host "  .\Detect-Interception.ps1 -NoGUI -TestAVD -FetchAzureEndpoints"
        Write-Host ""
        Write-Host "Note: -NoGUI requires at least one test parameter to be specified." -ForegroundColor Yellow
    }
}
else {
    # Default behavior - launch GUI
    Start-GUIMode
}

#endregion
