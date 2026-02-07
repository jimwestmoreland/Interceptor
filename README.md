# Detect-Interception

A PowerShell tool that detects SSL/TLS interception by comparing certificate thumbprints and issuer chains against known Microsoft endpoints.

## Overview

This script tests endpoints commonly used by Azure Virtual Desktop (AVD), Microsoft 365, and Azure services. It compares certificate thumbprints and issuer chains against expected values to detect if traffic is being intercepted by a proxy performing SSL/TLS inspection (MITM).

## Features

- **GUI and CLI modes** - Interactive graphical interface or command-line automation
- **Pre-configured endpoint categories:**
  - Azure Virtual Desktop (RDP Gateway, Broker, Diagnostics, KMS)
  - Microsoft 365 (Outlook, Teams, SharePoint, OneDrive, Graph API)
  - Azure (Entra ID, Management API, Key Vault, Blob Storage, SQL)
- **Live endpoint fetching** - Pull current M365 and Azure endpoint lists from official Microsoft JSON feeds
- **Custom endpoint testing** - Test your own endpoints
- **Certificate chain analysis** - Full certificate chain inspection with thumbprint verification
- **Known CA validation** - Validates against Microsoft, DigiCert, Baltimore, and GlobalSign root CAs
- **Export results** - Save test results to file

## Usage

### GUI Mode
```powershell
.\Detect-Interception.ps1 -GUI
```

### Command Line
```powershell
# Test AVD endpoints
.\Detect-Interception.ps1 -TestAVD

# Test Microsoft 365 endpoints
.\Detect-Interception.ps1 -TestMicrosoft365

# Test Azure endpoints
.\Detect-Interception.ps1 -TestAzure

# Test all categories
.\Detect-Interception.ps1 -TestAll

# Test custom endpoints
.\Detect-Interception.ps1 -CustomEndpoints @("myapp.contoso.com:443", "api.example.com:443")

# Fetch live endpoint lists
.\Detect-Interception.ps1 -FetchM365Endpoints
.\Detect-Interception.ps1 -FetchAzureEndpoints

# Save results to specific path
.\Detect-Interception.ps1 -TestAll -OutputPath "C:\Logs"
```

## Detection Logic

The tool identifies interception by checking:
1. **Certificate thumbprint** - Compares against known Microsoft root CA thumbprints
2. **Issuer chain** - Validates the certificate issuer matches known Microsoft/partner CAs
3. **Chain integrity** - Ensures the full certificate chain is trusted

If the certificate presented doesn't match known Microsoft root CAs (Microsoft, DigiCert, Baltimore, GlobalSign), the connection is likely being intercepted by a TLS-inspecting proxy.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Network access to target endpoints
- GUI mode requires Windows Forms (.NET)

## License

MIT
