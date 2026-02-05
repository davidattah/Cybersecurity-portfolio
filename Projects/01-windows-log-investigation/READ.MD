# Windows Log Investigation 


## Overview
This project documents a SOC-style investigation using Sysmon logs in a Windows environment.  
The objective was to identify suspicious activity through process creation, network connections, and persistence indicators.


## Tools Used
- Sysmon
- Windows Event Viewer 
- MITRE ATT&CK Framework
- Powershell 
- Microsoft Powershell Documentation 

## Key Sysmon Event IDs Used
- Event ID 1 – Process creation
- Event ID 3 – Network connection
- Event ID 7 – Image loaded
- Event ID 10 - Process Access 
- Event ID 11– File create
- Event ID 13 – Registry value set


## Investigation Summary
During analysis, suspicious behavior was observed involving:
- Abnormal PowerShell execution
- Potential command-and-control (C2) communication
- Indicators consistent with post-exploitation activity


## Investigation Walkthrough

## 🔎 Investigation 1 — Registry Activity & USB Device Detection

### 🎯 Objective

The goal of Investigation 1 was to analyze Sysmon registry events to determine whether any suspicious registry modifications occurred on the system, with a focus on identifying evidence of removable media usage.

### 🔍 Step 1 — Identify Relevant Sysmon Event Types

Sysmon logs multiple event types, each identified by an Event ID.
For this investigation, I focused on Sysmon Event ID 13, which indicates that a registry value was set or modified.

Registry events are important in investigations because:

They can show evidence of hardware connections

They may indicate persistence mechanisms

They often remain on a system even after activity stops

### 🔎 Step 2 — Query the Sysmon Log File Using PowerShell

The Sysmon data was stored in a saved event log file named: Investigation-1.evtx

![full_registry_key_usb_svchost.png](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/full_registry_key_usb_svchost.png)

The query returned a Sysmon Event ID 13 indicating that a registry value had been modified using a removable device

### 🔍 Step 3 — Analyze the Registry Modification Event

![raw_accessed_read.png](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/raw_accessed_read.png)

This event shows that a SYSTEM-level process accessed \Device\HarddiskVolume3. When correlated with registry modification events at the same timestamp, this activity is associated with svchost.exe

### Step 4 — Identify USB Device Evidence

Upon reviewing the registry path, I observed keywords such as:

USBSTOR

VEN_SANDISK

These values indicate that a USB storage device was connected to the system.
Windows creates registry entries under this path when removable USB devices are inserted.

### 🚨 Why This Activity Was Suspicious

In the context of this lab environment, USB device usage was not expected.
Because of this, the registry modification indicating a USB connection was treated as suspicious and flagged for further analysis.

Additionally, the registry modification was performed by svchost.exe, a legitimate Windows system process that attackers sometimes abuse to blend malicious activity with normal system behavior.

### 📌 What I Learned from Investigation 1

How Sysmon records registry modifications (Event ID 13)

How USB device connections appear in the Windows registry

How to use PowerShell to filter Sysmon logs

Why removable media artifacts are important in security investigation
To analyze this file, I used PowerShell’s Get-WinEvent cmdlet, which allows filtering and reviewing Windows event logs.

I filtered the log to identify registry activity associated with a system process:

## 🔎 Investigation 2 — Suspicious Process Activity

### 🎯 Objective

The goal of Investigation 2 was to analyze process creation events in Sysmon to identify potentially suspicious or abnormal executables.

### 🔍 Step 1 — Focus on Process Creation Events

Sysmon Event ID 1 logs process creation. These events show:

The process name

Original File Name

The full path of the exectuable 

This information helps determine whether a process was expected or unusual.

![path_of_exectuable](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/path_of_exectuable.png)

### 🔎 Step 2 — Identify the Suspicious Process

While reviewing process creation events, I identified a process that stood out due to:

Its unexpected execution

Its location on disk

The execution payload path masking behind a legitimate path 

Processes running from user-writable directories or unusual paths are often investigated further because malware frequently executes from these locations.

![Payload_masking](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/payload_masking.png)

### 🧠 Why This Was Suspicious

In normal environments:

Legitimate Windows binaries usually run from C:\Windows\System32

Unknown executables in user directories may indicate malicious activity

Because this process did not align with normal system behavior, it was flagged for further investigation.

Furthemore, the host 10.0.2.13 (IEWIN7) is likely compromised, and mshta.exe initiated an outbound TCP connection to 10.0.2.18:4443, which may be the attacker's command and control infrastucture(c2).

![destination_ip_address.png](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/destination_ip_address.png)

### 📌 What I Learned

How to identify process creation events in Sysmon

How command-line arguments provide context

Why parent-child process relationships matter

## 🔎 Investigation 3 — Network Connections
### 🎯 Objective

The goal of Investigation 3 was to analyze network connections recorded by Sysmon to identify potentially malicious communication.

### 🔍 Step 1 — Review Network Connection Events

Sysmon Event ID 3 logs network connections, including:

Source IP

Destination IP

Destination port

Process initiating the connection

Network activity is critical in investigations because malware often communicates with external servers.

![c2_server_anme](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/c2_server_name.png)

### 🔎 Step 2 — Identify Suspicious Network Traffic

I reviewed Sysmon network events to identify potentially malicious outbound connections, focusing on:

Connections to unusual external IP addresses

Non-standard destination ports

Unexpected processes initiating outbound network activity

Processes that are not typically network-facing but initiate external connections are commonly flagged for investigation.

### 🧠 Why This Activity Was Suspicious

The outbound network activity was considered suspicious for several reasons:

Malware commonly establishes outbound connections to command-and-control (C2) servers to receive instructions or exfiltrate data

The destination IP address and connection pattern were not consistent with expected system behavior

The process initiating the connection was not expected to communicate externally in this lab environment

In addition to the network activity, further analysis revealed a registry modification associated with the same activity. The payload was stored under:
HKLM\SOFTWARE\Microsoft\Network\Debug

![query_to_get_events](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/query_to_get_registry_events.png)

![registry_event_1](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/registry_event_1.png)

Registry keys in this location are unusual and can be abused by attackers to store payloads, configuration data, or persistence mechanisms.

The combination of:

Suspicious outbound network traffic

Evidence of communication with a potential C2 server

A registry modification used to store payload data

![registry_event_2](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/registry_event_2.png)

Strongly suggested malicious behavior and warranted deeper investigation.
### 📌 What I Learned

How Sysmon records network connections

How to identify abnormal outbound traffic

Why correlating processes with network activity matters

## 🔎 Investigation 4 — Correlating Events & Building a Timeline
### 🎯 Objective


## ✅ Final Conclusion

Across all three investigations, I used Sysmon logs and PowerShell to:

Identify suspicious processes

Detect registry changes related to USB devices

Analyze outbound network connections

Correlate events into a meaningful timeline

This investigation demonstrated how Sysmon provides detailed visibility into system activity and how analysts use that data to detect potential security threats.






























