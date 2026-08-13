# Windows 11 STIG Hardening & Vulnerability Management

## Executive Summary

This project documents the end-to-end vulnerability assessment, compliance benchmarking, and programmatic hardening of an enterprise Windows 11 asset. Using **Tenable Vulnerability Management**, an initial audit scan was conducted against the **DISA Windows 11 Security Technical Implementation Guide (STIG)** benchmark (`BM-STIGIFACATION`). Misconfigurations and non-compliant policy settings were systematically remediated through automated PowerShell scripts targeting registry keys, local group policies, and Windows audit subcategories.

---

## Environment & Architecture

* **Vulnerability Management Platform:** Tenable Vulnerability Management
* **Target Operating System:** Windows 11 Enterprise (`10.2.0.41`)
* **Compliance Framework:** DISA Windows 11 STIG (263 Total Evaluated Controls)
* **Automation Engine:** PowerShell 5.1 / 7.x (Elevated Administrator Context)
* **Policy Enforcement:** Windows Registry (`HKLM`), Advanced Audit Policy (`auditpol`), and Local Group Policy (`gpupdate /force`)

---

## Baseline Compliance Metrics

An initial baseline compliance assessment established the system's security posture prior to remediation:

| Compliance Status | Control Count | Percentage |
| --- | --- | --- |
| **Passed** | 99 | 37.6% |
| **Failed** | 152 | 57.8% |
| **Warning** | 12 | 4.6% |
| **Total Evaluated** | **263** | **100.0%** |

<img width="1024" height="766" alt="4d1e61d2-2f1a-46eb-8991-543cfb8a0187" src="https://github.com/user-attachments/assets/a7f358a6-337d-4027-9696-60493bd3c361" />

---

## Remediated STIG Controls (15 Total Successfully Applied)

The following 15 DISA STIG controls were successfully remediated and verified across Batch 1 and Batch 2 automation executions:

### Batch 1 Remediations (Successfully Applied Controls)

| STIG ID | Control Description | Registry / Policy Path | Applied Target Value |
| --- | --- | --- | --- |
| **`WN11-CC-000315`** | Disable Always Install Elevated | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` | `AlwaysInstallElevated = 0` |
| **`WN11-CC-000110`** | Disable HTTP Printing | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers` | `DisableHTTPPrinting = 1` |
| **`WN11-CC-000197`** | Turn Off Consumer Experiences | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsConsumerFeatures = 1` |
| **`WN11-CC-000285`** | RDP Require Secure RPC | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | `fRequireSecureRPCRequests = 1` |
| **`WN11-CC-000345`** | WinRM Disable Basic Authentication | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client` & `\Service` | `AllowBasic = 0` |

---

### Batch 2 Remediations (Successfully Applied Controls)

| STIG ID | Control Description | Registry / Policy Subcategory | Applied Target Value |
| --- | --- | --- | --- |
| **`WN11-CC-000326`** | Enable PowerShell Script Block Logging | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging = 1` |
| **`WN11-CC-000185`** | Disable Autorun for all drives | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoDriveTypeAutoRun = 255` |
| **`WN11-SO-000075`** | Enforce Legal Notice Caption & Banner | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | US DoD Warning Banner Text |
| **`WN11-CC-000204`** | Limit Telemetry & Diagnostic Data | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `AllowTelemetry = 0` |
| **`WN11-SO-000190`** | Restrict Kerberos Encryption Types | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` | `SupportedEncryptionTypes = 2147483640` |
| **`WN11-00-000210`** | Disable Bluetooth Discovery & Advertising | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth` | `AllowDiscoverableMode = 0` |
| **`WN11-AU-000575`** | Audit MPSSVC Rule-Level Policy Change | Audit Category: Policy Change | Success & Failure |
| **`WN11-AU-000582`** | Audit File System Access | Audit Category: Object Access | Success & Failure |
| **`WN11-AU-000583`** | Audit Handle Manipulation | Audit Category: Object Access | Success & Failure |
| **`WN11-AU-000588`** | Audit Sensitive Privilege Use | Audit Category: Privilege Use | Success & Failure |

---

## Consolidated Automation Script

The consolidated PowerShell script below incorporates all 15 applied STIG remediations for direct deployment in target environments:

```powershell
<#
.SYNOPSIS
    Master DISA STIG Windows 11 Automated Remediation Script
.DESCRIPTION
    Enforces registry policies, system telemetry restrictions, RDP/WinRM hardening,
    PowerShell logging, and Advanced Audit Policies to satisfy DISA STIG compliance.
#>

# Helper function to set or create registry DWORD values
function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
}

# Helper function to set or create registry String values
function Set-RegString {
    param([string]$Path, [string]$Name, [string]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force
}

Write-Host "Applying Master STIG Remediations..." 

# --- BATCH 1 CONTROLS ---
# WN11-CC-000315: Disable Always Install Elevated
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

# WN11-CC-000110: Disable HTTP Printing
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1

# WN11-CC-000197: Turn Off Consumer Experiences
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

# WN11-CC-000285: RDP Require Secure RPC
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fRequireSecureRPCRequests" -Value 1

# WN11-CC-000345: WinRM Disable Basic Auth
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0

# --- BATCH 2 CONTROLS ---
# WN11-CC-000326: Enable PowerShell Script Block Logging
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# WN11-CC-000185: Disable Autorun for all drives
Set-RegDword -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# WN11-SO-000075: Legal Notice Banner
Set-RegString -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "US Government Department of Defense Warning"
Set-RegString -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "You are accessing a U.S. Government Information System..."

# WN11-CC-000204: Limit Telemetry
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

# WN11-SO-000190: Kerberos Encryption Types
Set-RegDword -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640

# WN11-00-000210: Disable Bluetooth Advertising/Discovery
Set-RegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth" -Name "AllowDiscoverableMode" -Value 0

# WN11-AU-000575, WN11-AU-000582, WN11-AU-000583, WN11-AU-000588: Advanced Audit Policies
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null

# Refresh Group Policy
Write-Host "Refreshing Group Policy..." 
gpupdate /force

```
## Compliance Metrics & Risk Reduction

An initial baseline compliance assessment was conducted prior to remediation, followed by a post-remediation audit after executing the master automation script:

| Compliance Status | Baseline Audit | Post-Remediation Audit | Delta |
| :--- | :--- | :--- | :--- |
| **Passed** | 99 (37.6%) | **114 (43.3%)** | **+15** |
| **Failed** | 152 (57.8%) | **137 (52.1%)** | **-15** |
| **Warning** | 12 (4.6%) | 12 (4.6%) | 0 |
| **Total Evaluated** | **263 (100.0%)** | **263 (100.0%)** | **--** |

> **Key Achievement:** Improved overall STIG baseline compliance by **5.7%** and reduced non-compliant findings by **15 high-risk control failures**.
<img width="1024" height="874" alt="7d023788-8d64-4bf4-b1e3-e6e43d7fca3c" src="https://github.com/user-attachments/assets/8980c6e4-2170-441e-bd34-9af148f1c8d5" />
---

## Verification & Impact Analysis

1. **Automation Execution:** The PowerShell scripts were executed under an elevated Administrator context, successfully modifying registry values and Advanced Audit policies.
2. **Policy Enforcement:** A forced Group Policy update (`gpupdate /force`) confirmed successful completion for both User and Computer policies.
3. **Scan Validation:** A re-scan executed within Tenable Vulnerability Management under the `BM-STIGIFACATION` task verified the transition of 15 non-compliant findings into a **Passed** state, reducing overall system risk.
