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

### 🔍 Step 3 — Analyze the Registry Modification Event

The query returned a Sysmon Event ID 13 indicating that a registry value had been modified.

![raw_accessed_read.png](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/01-windows-log-investigation/screenshots/Projects/01-windows-log-investigation/screenshots/raw_accessed_read.png)
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

Command-line arguments

Parent process

Timestamp

This information helps determine whether a process was expected or unusual.

📸 Screenshot: Sysmon Event ID 1 example

### 🔎 Step 2 — Identify the Suspicious Process

While reviewing process creation events, I identified a process that stood out due to:

Its unexpected execution

Its location on disk

Its command-line usage

Processes running from user-writable directories or unusual paths are often investigated further because malware frequently executes from these locations.

📸 Screenshot: Suspicious process execution

### 🧠 Why This Was Suspicious

In normal environments:

Legitimate Windows binaries usually run from C:\Windows\System32

Unknown executables in user directories may indicate malicious activity

Because this process did not align with normal system behavior, it was flagged for further investigation.

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

📸 Screenshot: Sysmon Event ID 3 network connection

### 🔎 Step 2 — Identify Suspicious Network Traffic

I reviewed network events to identify:

Connections to unusual external IP addresses

Non-standard ports

Unexpected processes making outbound connections

Processes that are not normally network-facing but initiate connections are commonly investigated.

📸 Screenshot: Suspicious outbound connection

### 🧠 Why This Was Suspicious

Outbound connections are reviewed because:

Malware often communicates with command-and-control servers

Unexpected destinations can indicate compromise

The combination of:

The process name

The destination IP

The timing of the connection

made this activity worth further analysis.

### 📌 What I Learned

How Sysmon records network connections

How to identify abnormal outbound traffic

Why correlating processes with network activity matters

## 🔎 Investigation 4 — Correlating Events & Building a Timeline
### 🎯 Objective

The goal of Investigation 4 was to correlate multiple Sysmon events to understand the sequence of activity on the system.

### 🔍 Step 1 — Correlate Process, Registry, and Network Events

Rather than viewing events in isolation, I reviewed:

Process creation (Event ID 1)

Registry modification (Event ID 13)

Network connections (Event ID 3)

By comparing timestamps, I was able to build a timeline of activity.

📸 Screenshot: Timeline correlation example

🔎 Step 2 — Identify the Attack Flow

By correlating events, I observed:

A process executed on the system

A registry value was modified

A network connection was established shortly afterward

This pattern is commonly reviewed in investigations because it can indicate:

Initial execution

Persistence setup

External communication

### 🧠 Why Correlation Matters

Single events can look harmless on their own, but when combined:

They provide context

They show intent

They help distinguish normal activity from malicious behavior

This is a core skill for SOC analysts.

## ✅ Final Conclusion

Across all four investigations, I used Sysmon logs and PowerShell to:

Identify suspicious processes

Detect registry changes related to USB devices

Analyze outbound network connections

Correlate events into a meaningful timeline

This investigation demonstrated how Sysmon provides detailed visibility into system activity and how analysts use that data to detect potential security threats.











