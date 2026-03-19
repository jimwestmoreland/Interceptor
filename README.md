# Detect-Interception

A PowerShell tool that detects SSL/TLS interception by comparing certificate thumbprints and issuer chains against known Microsoft endpoints.

## Overview

This script tests endpoints commonly used by Azure Virtual Desktop (AVD), Microsoft 365, and Azure services. It compares certificate thumbprints and issuer chains against expected values to detect if traffic is being intercepted by a proxy performing SSL/TLS inspection (MITM).

## Features

- **GUI and CLI modes** - Interactive graphical interface (default) or command-line automation
- **Pre-configured endpoint categories:**
  - Azure Virtual Desktop (RDP Gateway, Broker, Diagnostics, KMS)
  - Microsoft 365 (Outlook, Teams, SharePoint, OneDrive, Graph API)
  - Azure (Entra ID, Management API, Key Vault, Blob Storage, SQL)
  - Tenant Restriction v2 / Global Secure Access (Device Registration, Seamless SSO, GSA Tunnel)
  - Apple SSO Extension (Associated Domains, STS endpoints for Enterprise SSO on macOS/iOS)
- **Live endpoint fetching** - Pull current M365 and Azure endpoint lists from official Microsoft JSON feeds
- **Custom endpoint testing** - Test your own endpoints
- **Certificate chain analysis** - Full certificate chain inspection with thumbprint verification
- **Known CA validation** - Validates against Microsoft, DigiCert, Baltimore, and GlobalSign root CAs
- **Root CA discovery** - Automatically detect and update the trusted root CA list
- **Network Jitter Testing** - Measures latency variation, packet loss, and network quality for Microsoft Teams media endpoints
- **Hairpin NAT Detection** - Detects NAT loopback scenarios by analyzing TTL, latency, and traceroute patterns
- **Export results** - Save test results to file

## Usage

### GUI Mode (Default)
```powershell
# Simply run the script - GUI launches by default
.\Detect-Interception.ps1
```

### Command Line Mode
Use the `-NoGUI` switch to run in command-line mode:

```powershell
# Test AVD endpoints
.\Detect-Interception.ps1 -NoGUI -TestAVD

# Test Microsoft 365 endpoints
.\Detect-Interception.ps1 -NoGUI -TestMicrosoft365

# Test Azure endpoints
.\Detect-Interception.ps1 -NoGUI -TestAzure

# Test TRv2 / Global Secure Access endpoints
.\Detect-Interception.ps1 -NoGUI -TestTRv2

# Test Apple SSO Extension endpoints (for macOS/iOS Enterprise SSO)
.\Detect-Interception.ps1 -NoGUI -TestAppleSSO

# Test for Hairpin NAT (NAT loopback detection)
.\Detect-Interception.ps1 -NoGUI -TestHairpin

# Test all categories
.\Detect-Interception.ps1 -NoGUI -TestAll

# Test custom endpoints
.\Detect-Interception.ps1 -NoGUI -CustomEndpoints @("myapp.contoso.com:443", "api.example.com:443")

# Fetch live endpoint lists
.\Detect-Interception.ps1 -NoGUI -FetchM365Endpoints
.\Detect-Interception.ps1 -NoGUI -FetchAzureEndpoints

# Save results to specific path
.\Detect-Interception.ps1 -NoGUI -TestAll -OutputPath "C:\Logs"
```

### Network Jitter Testing

The script includes a jitter test for Microsoft Teams media endpoints to assess network quality for real-time communications:

```powershell
# Test jitter to Teams media endpoints (via GUI Network Tests tab)
# Measures: latency, jitter (standard deviation), packet loss
# Provides Teams call quality assessment
```

**Jitter ratings:**
- **Excellent** (< 10ms): Optimal for Teams calls
- **Good** (10-20ms): Suitable for Teams calls
- **Acceptable** (20-30ms): May experience minor issues
- **Poor** (30-50ms): Likely to experience call quality issues
- **Very Poor** (> 50ms): Significant call quality problems expected

### Hairpin NAT Detection

Hairpin NAT (NAT loopback) occurs when internal traffic destined for a public IP is routed back to an internal server. The script detects this by:

1. **TTL Analysis** - Low hop counts with low latency indicate local routing
2. **Latency Measurement** - Sub-millisecond latency suggests the target is on the local network
3. **Traceroute Analysis** - Examines intermediate hops for private IP patterns
4. **TCP Connection Testing** - Measures actual connection establishment time

```powershell
# Test for hairpin NAT
.\Detect-Interception.ps1 -NoGUI -TestHairpin
```

### Root CA Discovery

The script includes a built-in list of known Microsoft root CAs. You can discover and update this list:

**Command Line:**
```powershell
# Discover current root CAs and save to TrustedRootCAs.json
.\Detect-Interception.ps1 -DiscoverRootCAs

# Use a custom config file path
.\Detect-Interception.ps1 -DiscoverRootCAs -RootCAConfigPath "C:\Config\MyRootCAs.json"
```

**GUI:**
1. Open the **Known Root CAs** tab
2. Click **Discover & Update Root CAs**
3. The script scans Microsoft endpoints, finds new root CAs, and saves them

Discovered CAs are:
- Immediately available for the current session
- Saved to `TrustedRootCAs.json` in the script directory
- Automatically loaded on future runs

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-NoGUI` | Suppress GUI and run in command-line mode |
| `-TestAVD` | Test Azure Virtual Desktop endpoints |
| `-TestMicrosoft365` | Test Microsoft 365 endpoints |
| `-TestAzure` | Test Azure service endpoints |
| `-TestTRv2` | Test Tenant Restriction v2 / Global Secure Access endpoints |
| `-TestAppleSSO` | Test Apple SSO Extension endpoints (macOS/iOS Enterprise SSO) |
| `-TestHairpin` | Test for hairpin NAT (NAT loopback) routing |
| `-TestAll` | Test all endpoint categories |
| `-FetchM365Endpoints` | Fetch live M365 endpoints from Microsoft |
| `-FetchAzureEndpoints` | Fetch live Azure endpoints from Microsoft |
| `-DiscoverRootCAs` | Discover and save current Microsoft root CAs |
| `-RootCAConfigPath` | Path to custom root CA config file |
| `-CustomEndpoints` | Array of custom endpoints to test |
| `-OutputPath` | Path to save results (default: current directory) |

## Detection Logic

The tool identifies interception by checking:
1. **Certificate thumbprint** - Compares against known Microsoft root CA thumbprints
2. **Issuer chain** - Validates the certificate issuer matches known Microsoft/partner CAs
3. **Chain integrity** - Ensures the full certificate chain is trusted

If the certificate presented doesn't match known Microsoft root CAs (Microsoft, DigiCert, Baltimore, GlobalSign), the connection is likely being intercepted by a TLS-inspecting proxy.

## Configuration Files

### TrustedRootCAs.json
Additional trusted root CAs are stored in this JSON file in the script directory. This file is:
- Created automatically when using `-DiscoverRootCAs` or the GUI discovery button
- Loaded automatically on script startup
- Merged with the built-in CA list

Example format:
```json
{
  "DigiCert Global Root G2": "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
  "Custom Enterprise CA": "YOUR_THUMBPRINT_HERE"
}
```

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Network access to target endpoints
- GUI mode requires Windows Presentation Foundation (WPF)

## License

MIT
