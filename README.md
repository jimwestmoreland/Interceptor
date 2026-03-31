# Network Diagnostic Toolkit

A comprehensive PowerShell tool for Microsoft 365 network connectivity assessment, SSL/TLS interception detection, and network diagnostics. Modeled after [connectivity.office.com](https://connectivity.office.com) with additional deep-inspection capabilities.

## Overview

This tool provides two main capabilities:

1. **SSL/TLS Interception Detection** — Tests endpoints used by Azure Virtual Desktop, Microsoft 365, and Azure services. Compares certificate thumbprints and issuer chains against expected values to detect TLS-inspecting proxies (MITM).

2. **M365 Network Connectivity Assessment** — A comprehensive assessment covering DNS, front door identification, latency, download speed, Teams media, Copilot connectivity, VPN/proxy analysis, and more. Generates a detailed text report.

## Features

### SSL/TLS Interception Detection

- **GUI and CLI modes** — Interactive graphical interface (default) or command-line automation
- **Pre-configured endpoint categories:**
  - Azure Virtual Desktop (RDP Gateway, Broker, Diagnostics, KMS)
  - Microsoft 365 (Outlook, Teams, SharePoint, OneDrive, Graph API)
  - Azure (Entra ID, Management API, Key Vault, Blob Storage, SQL)
  - Tenant Restriction v2 / Global Secure Access (Device Registration, Seamless SSO, GSA Tunnel)
  - Apple SSO Extension (Associated Domains, STS endpoints for Enterprise SSO on macOS/iOS)
- **Live endpoint fetching** — Pull current M365 and Azure endpoint lists from official Microsoft JSON feeds
- **Custom endpoint testing** — Test your own endpoints
- **Certificate chain analysis** — Full certificate chain inspection with thumbprint verification
- **Known CA validation** — Validates against Microsoft, DigiCert, Baltimore, and GlobalSign root CAs
- **Root CA discovery** — Automatically detect and update the trusted root CA list
- **Export results** — Save test results to file

### M365 Network Connectivity Assessment

A comprehensive assessment that runs 15 diagnostic tests:

| # | Test | Description |
| --- | --- | --- |
| 1 | Network Egress Geolocation | Public IP, ISP, city/region/country via ip-api.com |
| 2 | Office Location & Egress Distance | Geocodes your office via Nominatim API, calculates distance to internet egress to detect WAN backhaul |
| 3 | DNS Recursive Resolver | Identifies your DNS resolver and measures resolver latency |
| 4 | DNS Performance | Resolution timing for key M365 hostnames with ratings |
| 5 | VPN & Proxy Detection | Detects active VPN, proxy settings, PAC files, and per-workload split tunnel routing |
| 6 | Service Front Door Identification | Discovers Exchange, SharePoint, and Teams front door IPs, CNAMEs, and TCP latency |
| 7 | Best Front Door Comparison | Compares in-use front doors against 20 known Microsoft front door regions |
| 8 | HTTPS Endpoint Connectivity | Tests connectivity to live M365 endpoints from official JSON feed |
| 9 | SSL/TLS Interception Check | Verifies certificate chains on critical M365 endpoints |
| 10 | Teams UDP Media Ports | Tests UDP 3478-3481 connectivity with TCP 443 fallback detection |
| 11 | Teams Jitter & Packet Loss | Measures jitter, latency, and packet loss to Teams media relay endpoints |
| 12 | Download Speed & Buffer Bloat | ~10 MB download test via Cloudflare CDN with latency-under-load measurement |
| 13 | Traceroutes | TCP-based traceroutes to Exchange, SharePoint, and Teams front doors |
| 14 | Copilot Connectivity | Tests Microsoft 365 Copilot HTTP and WebSocket endpoints |
| 15 | TCP/TLS Negotiation | TLS version, cipher suite, and TCP window size analysis |

### Additional Network Tests

- **Network Jitter Testing** — Measures latency variation, packet loss, and network quality for Teams media endpoints
- **Hairpin NAT Detection** — Detects NAT loopback scenarios by analyzing TTL, latency, and traceroute patterns

## Usage

### GUI Mode (Default)

```powershell
# Simply run the script - GUI launches by default
.\Detect-Interception.ps1
```

The GUI has seven tabs:

- **SSL Endpoints** — Configure and run SSL/TLS interception tests
- **SSL Results** — View interception scan results
- **SSL Cert Details** — Inspect individual certificate chains
- **SSL Root CAs** — Manage and discover trusted root CAs
- **Hairpin NAT** — Test for NAT loopback
- **Teams Jitter** — Measure network quality for Teams media
- **Assessment** — Run the full M365 connectivity assessment

### M365 Assessment (CLI)

```powershell
# Run assessment for Worldwide (commercial) geography
.\Detect-Interception.ps1 -NoGUI -RunAssessment

# Target a sovereign cloud
.\Detect-Interception.ps1 -NoGUI -RunAssessment -Geography USGovGCCHigh

# Include office location for egress distance calculation
.\Detect-Interception.ps1 -NoGUI -RunAssessment -OfficeCity Seattle -OfficeState WA -OfficeCountry US
```

### SSL/TLS Interception (CLI)

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

### Hairpin NAT Detection

```powershell
.\Detect-Interception.ps1 -NoGUI -TestHairpin
```

Detects NAT loopback by:

1. **TTL Analysis** — Low hop counts with low latency indicate local routing
2. **Latency Measurement** — Sub-millisecond latency suggests the target is on the local network
3. **Traceroute Analysis** — Examines intermediate hops for private IP patterns
4. **TCP Connection Testing** — Measures actual connection establishment time

### Root CA Discovery

```powershell
# Discover current root CAs and save to TrustedRootCAs.json
.\Detect-Interception.ps1 -DiscoverRootCAs

# Use a custom config file path
.\Detect-Interception.ps1 -DiscoverRootCAs -RootCAConfigPath "C:\Config\MyRootCAs.json"
```

## Parameters

| Parameter | Description |
| --- | --- |
| `-NoGUI` | Suppress GUI and run in command-line mode |
| `-RunAssessment` | Run M365 network connectivity assessment |
| `-Geography` | Cloud instance: `Worldwide` (default), `USGovDoD`, `USGovGCCHigh`, `China`, `Germany` |
| `-OfficeCity` | Office city for egress distance calculation |
| `-OfficeState` | Office state/region for egress distance calculation |
| `-OfficeCountry` | Office country for egress distance calculation |
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

## Assessment Report Sections

The generated text report includes:

- **Network Egress Location** — Public IP, ISP, organization, and geolocation
- **Office Location & Egress Distance** — Distance between office and internet egress point with WAN backhaul detection
- **DNS Performance** — Resolution times with ratings for each M365 hostname
- **VPN and Proxy Detection** — Active VPN, proxy settings, and per-workload M365 Optimize split tunnel routing analysis
- **Service Front Door Identification** — Exchange, SharePoint, and Teams front door IPs with TCP latency
- **Best Front Door Comparison** — Current front doors vs. 20 nearest known Microsoft regions
- **Network Path Analysis** — Geolocation-based distance calculation from egress to each front door
- **HTTPS Endpoint Connectivity** — Categorized results: accessible, reachable (TCP), allow-list only, blocked
- **SSL/TLS Interception Check** — Certificate chain validation on critical endpoints
- **Microsoft 365 Copilot Connectivity** — HTTP and WebSocket endpoint testing
- **Teams Media Connectivity** — UDP port tests with TCP fallback detection
- **Teams Jitter Test** — Jitter, latency, and packet loss measurement
- **Download Speed & Buffer Bloat** — ~10 MB download with latency-under-load measurement
- **TCP/TLS Negotiation** — TLS version, cipher suite, and window size
- **Traceroutes** — Hop-by-hop path to service front doors
- **Assessment Summary** — Consolidated list of issues and recommendations

## External APIs Used

| API | Purpose | Data Sent |
| --- | --- | --- |
| [ip-api.com](http://ip-api.com) | Geolocation of public IPs (egress and front doors) | Public IP address |
| [endpoints.office.com](https://endpoints.office.com) | Live M365 endpoint list | Cloud instance name |
| [speed.cloudflare.com](https://speed.cloudflare.com) | Download speed test payload | None (download only) |
| [nominatim.openstreetmap.org](https://nominatim.openstreetmap.org) | Office location geocoding | City/state/country text |

## Detection Logic

The SSL interception detector checks:

1. **Certificate thumbprint** — Compares against known Microsoft root CA thumbprints
2. **Issuer chain** — Validates the certificate issuer matches known Microsoft/partner CAs
3. **Chain integrity** — Ensures the full certificate chain is trusted

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
- No modules or dependencies to install

## License

MIT
